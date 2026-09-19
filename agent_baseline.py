"""
agent_baseline.py — Layer 9 baseline: per-agent-identity behavioral
envelope for AI agents (tool calls, targets, volumes, rates).

Grounded in real, current 2026 research on AI-agent lateral movement,
checked before this module was written rather than assumed:

  - "Behavioral baselines fail to detect AI agent intent drift" because
    "pods recycle before models" finish learning. The stated fix is to
    "attach behavioural profiles and policy decisions to Deployments and
    ServiceAccounts so that pod recycling does not reset security state."
    So this baseline is keyed on a DURABLE agent identity, never on the
    ephemeral session/instance id. That is the whole reason the event
    format carries both.

  - "Measure action chains, not isolated events" — so the baseline
    records what a normal chain looks like (tools, targets, rates), and
    the detector (agent_detector.py) scores sequences, not single calls.

  - Real reported logging requirement per agent action: "input
    provenance (source system and trust label), tool invocation (tool
    name, arguments, result size), policy decision (allowed or blocked),
    human approval events, and cross-system side effects (any write
    actions)." The normalized event format below carries each of these.

This mirrors auth_baseline.py's structure deliberately: same shape of
per-identity "known set" plus numeric stats, so the same privilege-aware
lessons already learned on the identity side (see APIS Part 4) carry
over instead of being rediscovered.
"""

import json
import math
import os

AGENT_BASELINE_PATH = "agent_baseline.json"

# Real 2026 guidance treats a write/execute side effect as materially
# more dangerous than a read, so they are tracked separately rather than
# collapsed into one "touched this target" set.
WRITE_ACTIONS = {"write", "execute", "delete"}


def parse_agent_event(raw):
    """
    Normalizes one agent tool-call event. Accepts a dict (already
    parsed) or a JSON string. Returns None for anything unusable, the
    same defensive contract parse_auth_row() uses.

    Required fields: time, agent_id, tool, action.
    Optional: session_id, target, input_provenance, result_size, success.
    """
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return None

    if not isinstance(raw, dict):
        return None

    for field in ("time", "agent_id", "tool", "action"):
        if raw.get(field) in (None, ""):
            return None

    try:
        time_value = float(raw["time"])
    except (TypeError, ValueError):
        return None

    provenance = str(raw.get("input_provenance", "unknown")).lower()
    if provenance not in ("trusted", "untrusted", "unknown"):
        provenance = "unknown"

    try:
        result_size = int(raw.get("result_size") or 0)
    except (TypeError, ValueError):
        result_size = 0

    return {
        "time": time_value,
        "agent_id": str(raw["agent_id"]),
        # Ephemeral instance/session. Deliberately NOT used as the
        # baseline key - that is the documented failure mode.
        "session_id": str(raw.get("session_id") or ""),
        "tool": str(raw["tool"]),
        "target": str(raw.get("target") or ""),
        "action": str(raw["action"]).lower(),
        "input_provenance": provenance,
        "result_size": result_size,
        "success": bool(raw.get("success", True)),
        # Set by the adapter, which knows the agent's workspace. Used
        # only by the refined TAINTED_SCOPE_EXPANSION rule. Absent or
        # False means "not known to be outside", never "definitely
        # outside" - missing information must not manufacture signal.
        "external": bool(raw.get("external", False)),
    }


def load_agent_events(path):
    """Reads a JSON-lines file of agent tool-call events."""
    events = []
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            event = parse_agent_event(line)
            if event is not None:
                events.append(event)
    events.sort(key=lambda e: e["time"])
    return events


def build_agent_baseline(events):
    """
    Builds the per-durable-identity behavioral envelope from a window of
    events assumed clean (same assumption, and same stated caveat, as
    every other baseline in this project).
    """
    acc = {}
    for event in events:
        if not event.get("success", True):
            # A blocked/failed call says what the agent TRIED, not what
            # is normal for it. Excluded from "normal", exactly as failed
            # logons are excluded on the identity side.
            continue

        agent = event["agent_id"]
        profile = acc.setdefault(agent, {
            "known_tools": set(),
            "known_targets": set(),
            "write_targets": set(),
            "sizes": [],
            "times": [],
        })
        profile["known_tools"].add(event["tool"])
        if event["target"]:
            profile["known_targets"].add(event["target"])
            if event["action"] in WRITE_ACTIONS:
                profile["write_targets"].add(event["target"])
        profile["sizes"].append(event["result_size"])
        profile["times"].append(event["time"])

    baseline = {}
    for agent, profile in acc.items():
        sizes = profile["sizes"]
        mean = sum(sizes) / len(sizes) if sizes else 0.0
        if len(sizes) > 1:
            var = sum((s - mean) ** 2 for s in sizes) / (len(sizes) - 1)
            std = math.sqrt(var)
        else:
            std = 0.0

        # Busy-minute rate, not wall-clock average.
        #
        # Found necessary by a real end-to-end run, not assumed: computing
        # this as total_calls / total_span dilutes the rate to near zero
        # across any window containing idle periods (a 3-day clean window
        # gave 0.123 calls/min for an agent that actually makes 3 calls in
        # the minute it is working). Compared against an instantaneous
        # 60-second count, that made CALL_RATE_SPIKE fire on completely
        # normal traffic.
        #
        # This is the same failure this project already hit and fixed once
        # on the flow side, where one flat repetition threshold was applied
        # to every device regardless of its own normal chattiness (see
        # APIS Part 3.4). The fix is the same in principle: measure what
        # busy looks like FOR THIS IDENTITY, then compare like with like.
        # Here that means bucketing clean activity into one-minute bins,
        # discarding empty bins, and taking a high percentile of the rest.
        minute_counts = {}
        for ts in profile["times"]:
            bucket = int(ts // 60)
            minute_counts[bucket] = minute_counts.get(bucket, 0) + 1
        active = sorted(minute_counts.values())
        if active:
            idx = min(int(len(active) * 0.95), len(active) - 1)
            calls_per_minute = float(active[idx])
        else:
            calls_per_minute = 0.0

        baseline[agent] = {
            "known_tools": sorted(profile["known_tools"]),
            "known_targets": sorted(profile["known_targets"]),
            "write_targets": sorted(profile["write_targets"]),
            "avg_result_size": round(mean, 2),
            "std_result_size": round(max(std, 1.0), 2),
            "avg_calls_per_minute": round(calls_per_minute, 3),
            "observed_calls": len(sizes),
        }
    return baseline


def save_agent_baseline(baseline, path=AGENT_BASELINE_PATH):
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)


def load_agent_baseline(path=AGENT_BASELINE_PATH):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


if __name__ == "__main__":
    import sys

    events_path = sys.argv[1] if len(sys.argv) > 1 else "agent_events.txt"
    events = load_agent_events(events_path)
    baseline = build_agent_baseline(events)
    save_agent_baseline(baseline)

    print(f"Read {len(events)} valid agent events from {events_path}")
    print(f"Built baseline for {len(baseline)} durable agent identity/identities -> {AGENT_BASELINE_PATH}\n")
    for agent, profile in sorted(baseline.items()):
        print(f"  {agent}: {profile['observed_calls']} calls, "
              f"{len(profile['known_tools'])} tools, "
              f"{len(profile['known_targets'])} targets "
              f"({len(profile['write_targets'])} written), "
              f"{profile['avg_calls_per_minute']}/min")
