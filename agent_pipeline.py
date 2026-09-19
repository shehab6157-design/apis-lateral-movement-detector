"""
agent_pipeline.py — Layer 9 (Agent Behavior Detection), unified onto the
SAME shared infrastructure the flow-side (detector.py) and identity-side
(auth_pipeline.py) pipelines already use.

Built for the same reason auth_pipeline.py was: a detection layer that
runs beside the system rather than inside it is not really part of it.
Layer 9 originally had its own baseline and its own signal logic and
nothing else - no shared quorum, no analyst suppression, no SIEM export,
no audit trail, no confidence scoring. This closes that gap.

Everything below is imported, not reimplemented:
  - QuorumCoordinator        (Layer 4)   - no signal is actionable alone
  - feedback.is_suppressed   - same analyst suppression as both other domains
  - refine_actions           - same AUTONOMOUS_ACTION_OK / ESCALATE logic
  - report_confirmed_pair    - same CEF/SIEM export
  - build_audit_record       - same tamper-evident hash-chained provenance
  - annotate_summary_with_attack - MITRE ATLAS mappings for agent signals

The pair identity for an agent is (durable agent identity -> target
touched), mirroring (src -> dst) on the network side. The durable
identity is deliberately never the session: see agent_baseline.py.

Usage:
    python agent_pipeline.py agent_events.txt
    python agent_pipeline.py agent_events.txt --no-adapt
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime

from agent_baseline import (
    load_agent_events,
    build_agent_baseline,
    load_agent_baseline,
    AGENT_BASELINE_PATH,
)
from agent_detector import AgentBehaviorDetector, AGENT_SIGNAL_TYPES
from quorum import QuorumCoordinator
from feedback import is_suppressed
from detector import refine_actions
from mitre_mapping import annotate_summary_with_attack
from audit_trail import build_audit_record, save_audit_record
from drift_monitor import DriftMonitor

ADAPTIVE_AGENT_BASELINE_FILE = "adaptive_agent_baseline_state.json"


def adapt_baseline(baseline, safe_events):
    """
    Absorbs confirmed-safe activity into the agent's envelope.

    Same poisoning-safety guarantee enforced on both other domains: only
    events that produced ZERO raw signals, or that a human explicitly
    suppressed, are ever learned from. A confirmed, unsuppressed
    detection is never fed back.
    """
    learned = 0
    for event in safe_events:
        profile = baseline.get(event["agent_id"])
        if profile is None:
            continue
        if event["tool"] not in profile["known_tools"]:
            profile["known_tools"].append(event["tool"])
            learned += 1
        if event["target"] and event["target"] not in profile["known_targets"]:
            profile["known_targets"].append(event["target"])
            learned += 1
        if event["action"] in ("write", "execute", "delete") and event["target"]:
            if event["target"] not in profile["write_targets"]:
                profile["write_targets"].append(event["target"])
                learned += 1
    return learned


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    no_adapt = "--no-adapt" in sys.argv

    events_path = argv[0] if argv else "agent_events.txt"

    if os.path.exists(ADAPTIVE_AGENT_BASELINE_FILE) and not no_adapt:
        with open(ADAPTIVE_AGENT_BASELINE_FILE, encoding="utf-8-sig") as f:
            baseline = json.load(f)
        print(f"[ADAPTIVE AGENT BASELINE] Resumed from {ADAPTIVE_AGENT_BASELINE_FILE} "
              f"({len(baseline)} agent identities)")
    elif os.path.exists(AGENT_BASELINE_PATH):
        baseline = load_agent_baseline()
        print(f"[AGENT BASELINE] Loaded {AGENT_BASELINE_PATH} ({len(baseline)} agent identities)")
    else:
        print(f"No baseline found. Build one first:\n  python agent_baseline.py {events_path}")
        sys.exit(1)

    events = load_agent_events(events_path)
    print(f"\nLoaded {len(events)} agent tool calls from {events_path}\n")

    agent_detector = AgentBehaviorDetector(baseline=baseline)
    events_by_pair = defaultdict(list)
    all_signals = []
    zero_signal_events = []

    for event in events:
        signals = agent_detector.process_event(event)
        pair = (event["agent_id"], event["target"] or "(no-target)")
        if signals:
            enriched = dict(event)
            enriched["signals"] = signals
            enriched["timestamp"] = datetime.fromtimestamp(event["time"]).isoformat()
            all_signals.append((event, signals))
            events_by_pair[pair].append(enriched)
        else:
            zero_signal_events.append(event)

    print(f"=== {len(all_signals)} raw signal event(s) (Layer 9, Agent Behavior Detection) ===\n")
    if not all_signals:
        print("  (none)")
    for event, signals in all_signals[:20]:
        ts = datetime.fromtimestamp(event["time"]).isoformat()
        print(f"  [{ts}] {event['agent_id']} -> {event['target']} "
              f"({event['tool']}) | {', '.join(signals)}")
    if len(all_signals) > 20:
        print(f"  ... and {len(all_signals) - 20} more")

    coordinator = QuorumCoordinator(active_detector_types=AGENT_SIGNAL_TYPES)
    confirmed = {}

    def on_quorum(src, dst, summary, path):
        confirmed.setdefault((src, dst), (summary, path))

    coordinator.on_quorum_reached = on_quorum
    for event, signals in all_signals:
        coordinator.record_batch(
            signals, event["agent_id"], event["target"] or "(no-target)",
            timestamp=datetime.fromtimestamp(event["time"]),
        )

    active_confirmed = {}
    suppressed_confirmed = {}
    for pair, (summary, path) in confirmed.items():
        if is_suppressed(pair[0], pair[1], summary, path):
            suppressed_confirmed[pair] = (summary, path)
        else:
            active_confirmed[pair] = (summary, path)

    refined = refine_actions(active_confirmed)

    print(f"\n=== {len(refined)} pair(s) reached QUORUM (Layer 4, shared coordinator) ===\n")
    if not refined:
        print("  (none)")
    for (agent, target), (summary, path, action) in refined.items():
        label = "AUTONOMOUS ACTION OK" if action == "AUTONOMOUS_ACTION_OK" else "ESCALATE FOR REVIEW"
        print(f"  {agent} -> {target}  |  counts: {summary}  |  path: {path}  |  "
              f"{label}  |  MITRE: {annotate_summary_with_attack(summary)}")

    if refined:
        print("\n=== Reporting to SIEM/webhook (shared CEF export) ===\n")
        from contain import report_confirmed_pair
        for (agent, target), (summary, path, action) in refined.items():
            report_confirmed_pair(agent, target, summary, path, action)

    if refined or suppressed_confirmed:
        print("\n=== Writing audit trail (shared tamper-evident format) ===\n")
        count = 0
        for (agent, target), (summary, path, action) in refined.items():
            save_audit_record(build_audit_record(
                src=agent, dst=target, summary=summary, path=path, action=action,
                contributing_alerts=events_by_pair.get((agent, target), []),
                baseline=baseline, suppressed=False,
                mitre_techniques=annotate_summary_with_attack(summary),
            ))
            count += 1
        for (agent, target), (summary, path) in suppressed_confirmed.items():
            save_audit_record(build_audit_record(
                src=agent, dst=target, summary=summary, path=path, action="SUPPRESSED",
                contributing_alerts=events_by_pair.get((agent, target), []),
                baseline=baseline, suppressed=True,
                mitre_techniques=annotate_summary_with_attack(summary),
            ))
            count += 1
        print(f"  Wrote {count} record(s) to audit_trail.jsonl")

    if suppressed_confirmed:
        print(f"\n=== {len(suppressed_confirmed)} pair(s) SUPPRESSED (previously reviewed) ===\n")
        for (agent, target), (summary, path) in suppressed_confirmed.items():
            print(f"  {agent} -> {target}  |  counts: {summary}  |  path: {path}")

    if not no_adapt:
        print("\n=== Adaptive agent baseline update ===\n")
        suppressed_events = []
        for pair in suppressed_confirmed:
            suppressed_events.extend(events_by_pair.get(pair, []))

        learned_zero = adapt_baseline(baseline, zero_signal_events)
        learned_suppressed = adapt_baseline(baseline, suppressed_events)

        print(f"  Learned from {len(zero_signal_events)} zero-signal events "
              f"({learned_zero} envelope additions)")
        print(f"  Learned from {len(suppressed_events)} human-suppressed events "
              f"({learned_suppressed} envelope additions)")

        with open(ADAPTIVE_AGENT_BASELINE_FILE, "w") as f:
            json.dump(baseline, f, indent=2)
        print(f"  Saved to {ADAPTIVE_AGENT_BASELINE_FILE} ({len(baseline)} identities)")

        drift = DriftMonitor()
        alerts = []
        for agent, profile in baseline.items():
            status = drift.observe(agent, float(len(profile.get("known_targets", []))))
            if status.get("drift_alert"):
                alerts.append((agent, status))
        if alerts:
            print(f"\n=== \u26a0 {len(alerts)} AGENT ENVELOPE DRIFT ALERT(S) ===\n")
            for agent, status in alerts:
                print(f"  {agent}: {status['reason']}")
