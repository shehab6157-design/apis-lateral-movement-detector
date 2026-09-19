"""
calibrate_agent_overwhelm.py — measures Layer 8 (Collective Overwhelm)
parameters for the agent domain against REAL traces.

Why this exists: wiring Layer 8 into Layer 9 closed two real detection
gaps (horizontal scans and recon-only pivots, neither of which per-pair
quorum can see). But on real Claude Code traces it also produced 11
collective escalations on benign activity - against 1 quorum false
positive. Counting Layer 8 as a detection in the attack scenarios while
ignoring its cost on benign data would be scoring the benefit without
the cost.

Layer 8's defaults were calibrated for NETWORK conversations, where it
is fed already-corroborated repetition bursts. The agent domain feeds it
raw per-event signals across a target namespace that legitimately grows
all day, which is a materially different input. Reusing network
thresholds unexamined is the mistake; measuring them here is the fix.

Two parameters are swept:
  pair_threshold  - how many DISTINCT targets must show signals in the
                    window before a collective escalation fires
  min_signals     - how many signals one event must carry to be fed to
                    Layer 8 at all. min_signals=2 approximates the
                    network side's behaviour of only forwarding
                    already-corroborated events.

Usage:
    python calibrate_agent_overwhelm.py agent_events.txt
"""

import sys
from datetime import datetime

from agent_baseline import load_agent_events, build_agent_baseline
from agent_detector import AgentBehaviorDetector
from overwhelm import OverwhelmMonitor
from agent_attack_scenarios import build_scenarios


def count_escalations(events, baseline, pair_threshold, window_seconds, min_signals):
    detector = AgentBehaviorDetector(baseline)
    escalations = []
    monitor = OverwhelmMonitor(
        pair_threshold=pair_threshold,
        correlation_window_seconds=window_seconds,
        on_collective_threat=lambda evs: escalations.append(1),
    )
    for event in events:
        signals = detector.process_event(event)
        if len(signals) < min_signals:
            continue
        monitor.notify_repetition_burst(
            event["agent_id"], event["target"] or "(no-target)",
            {s: 1 for s in signals},
            timestamp=datetime.fromtimestamp(event["time"]),
        )
    return len(escalations)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "agent_events.txt"
    events = load_agent_events(path)
    if len(events) < 50:
        print(f"Only {len(events)} events - not enough to calibrate anything.")
        return 1

    cut = int(len(events) * 0.6)
    baseline = build_agent_baseline(events[:cut])
    benign = events[cut:]
    agent_id = next(iter(baseline))
    scenarios = {s["name"]: s["events"]
                 for s in build_scenarios(baseline, agent_id,
                                          max(e["time"] for e in events) + 3600)}

    print(f"Calibrating Layer 8 for the agent domain on {len(events)} real tool calls")
    print(f"  baseline window: {cut}   evaluation window: {len(benign)}\n")
    print("Goal: zero escalations on real BENIGN activity, while still catching the")
    print("two shapes per-pair quorum structurally cannot see.\n")

    print(f"{'min_sig':>7} {'pairs':>6} {'window':>7} | {'BENIGN FP':>9} | "
          f"{'scan':>5} {'recon':>6} | verdict")
    print("-" * 74)

    viable_both = []
    viable_scan = []
    for min_signals in (1, 2):
        for pair_threshold in (3, 5, 8, 12, 20):
            for window in (60, 300):
                fp = count_escalations(benign, baseline, pair_threshold, window, min_signals)
                scan = count_escalations(scenarios["machine_speed_burst"], baseline,
                                         pair_threshold, window, min_signals)
                recon = count_escalations(scenarios["recon_only"], baseline,
                                          pair_threshold, window, min_signals)
                if fp == 0 and scan > 0 and recon > 0:
                    verdict = "BOTH caught, no FP"
                    viable_both.append((min_signals, pair_threshold, window, scan, recon))
                elif fp == 0 and scan > 0:
                    verdict = "scan caught, no FP"
                    viable_scan.append((min_signals, pair_threshold, window, scan))
                elif fp == 0:
                    verdict = "no FP, catches nothing"
                else:
                    verdict = f"{fp} false positive(s)"
                print(f"{min_signals:>7} {pair_threshold:>6} {window:>7} | {fp:>9} | "
                      f"{scan:>5} {recon:>6} | {verdict}")

    print()
    if viable_both:
        best = sorted(viable_both, key=lambda v: (v[1], v[0]))[0]
        print(f"RECOMMENDED: min_signals={best[0]}, pair_threshold={best[1]}, window={best[2]}s")
        print(f"  zero false positives; catches scan ({best[3]}) and recon-only ({best[4]})")
    elif viable_scan:
        # Prefer the LOWEST threshold that still costs nothing - the most
        # sensitive free setting.
        best = sorted(viable_scan, key=lambda v: (v[1], v[0]))[0]
        print(f"RECOMMENDED: min_signals={best[0]}, pair_threshold={best[1]}, window={best[2]}s")
        print(f"  zero false positives on real benign activity")
        print(f"  catches the horizontal scan ({best[3]} escalations)")
        print()
        print("  PARTIAL RESULT, stated plainly: no setting catches recon-only without")
        print("  a false-positive cost. That shape touches only a handful of distinct")
        print("  targets, which is indistinguishable from a benign agent touching a few")
        print("  new files. It is a real limit of this approach, not a tuning failure,")
        print("  and recon-only should be documented as EVADING.")
    else:
        print("NO SETTING catches anything at zero false-positive cost.")
        print("That is a real negative result: Layer 8 would not be usable in the")
        print("agent domain, and should be reported that way rather than tuned around.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
