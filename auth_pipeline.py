"""
auth_pipeline.py — Layer 7 (Chemical-Mimicry Detection), unified onto
the SAME shared infrastructure the flow-side pipeline (detector.py)
already uses, rather than running as its own separate system:

  - Same QuorumCoordinator class for corroboration (repetition_burst /
    type_diversity), instead of treating any single PTH/PTT hit as
    instantly actionable.
  - Same feedback.py suppression system - an analyst reviews and
    suppresses a Windows false positive exactly the same way as a
    flow-side one.
  - Same refine_actions()/report_confirmed_pair() for CEF/SIEM export,
    carrying the real T1550.002/T1550.003 MITRE mappings already built.
  - Same adaptive-learning principle as rolling_baseline.py, via
    adaptive_auth_baseline.py, with the identical poisoning-safety
    guarantee: only zero-signal or human-confirmed-safe events are
    ever learned from.

Usage:
    python3 auth_pipeline.py <auth_events_file> [--no-adapt]
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime

from auth_detector import parse_auth_row, ChemicalMimicryDetector
from adaptive_auth_baseline import AdaptiveAuthBaseline
from quorum import QuorumCoordinator
from feedback import is_suppressed
from detector import refine_actions
from mitre_mapping import annotate_summary_with_attack

AUTH_ACTIVE_TYPES = {"PTH_SUSPECTED", "PTT_SUSPECTED"}
AUTH_BASELINE_PATH = "auth_baseline.json"
ADAPTIVE_AUTH_BASELINE_FILE = "adaptive_auth_baseline_state.json"


def load_static_auth_baseline(path=AUTH_BASELINE_PATH):
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    return {}


if __name__ == "__main__":
    argv = sys.argv[1:]
    no_adapt = "--no-adapt" in argv
    if no_adapt:
        argv.remove("--no-adapt")

    events_path = argv[0] if argv else "auth_events.txt"

    static_baseline = load_static_auth_baseline()

    if not no_adapt and os.path.exists(ADAPTIVE_AUTH_BASELINE_FILE):
        with open(ADAPTIVE_AUTH_BASELINE_FILE, encoding="utf-8-sig") as f:
            persisted = json.load(f)
        adaptive = AdaptiveAuthBaseline(initial_baseline=persisted)
        print(f"[ADAPTIVE AUTH BASELINE] Resumed from {ADAPTIVE_AUTH_BASELINE_FILE} "
              f"({len(persisted)} users with prior adaptation)")
    else:
        adaptive = AdaptiveAuthBaseline(initial_baseline=static_baseline)
        if not no_adapt:
            print("[ADAPTIVE AUTH BASELINE] No prior state found - starting fresh from the static baseline")

    baseline = adaptive.export() if not no_adapt else static_baseline
    print()

    events = []
    with open(events_path, encoding="utf-8-sig") as f:
        for line in f:
            event = parse_auth_row(line)
            if event is not None:
                events.append(event)
    events.sort(key=lambda e: e["time"])
    print(f"Loaded {len(events)} valid auth events from {events_path}\n")

    chem_detector = ChemicalMimicryDetector(baseline=baseline)
    raw_events_by_pair = defaultdict(list)
    all_signals = []

    for event in events:
        signals = chem_detector.process_event(event)
        pair = (event["src_computer"], event["dst_computer"])
        if signals:
            enriched_event = dict(event)
            enriched_event["signals"] = signals
            enriched_event["timestamp"] = datetime.fromtimestamp(event["time"]).isoformat()
            all_signals.append((event, signals))
            raw_events_by_pair[pair].append(enriched_event)

    print(f"=== {len(all_signals)} raw signal(s) (Layer 7, Chemical-Mimicry Detection) ===\n")
    for event, signals in all_signals:
        print(f"  [{event['time']}] {event['src_computer']} -> {event['dst_computer']} "
              f"(user={event['src_user']}) | {', '.join(signals)}")

    coordinator = QuorumCoordinator(active_detector_types=AUTH_ACTIVE_TYPES)
    confirmed = {}

    def on_quorum(src, dst, summary, path):
        if (src, dst) not in confirmed:
            confirmed[(src, dst)] = (summary, path)

    coordinator.on_quorum_reached = on_quorum
    for event, signals in all_signals:
        ts = datetime.fromtimestamp(event["time"])
        coordinator.record_batch(signals, event["src_computer"], event["dst_computer"], timestamp=ts)

    active_confirmed = {}
    suppressed_confirmed = {}
    for (src, dst), (summary, path) in confirmed.items():
        if is_suppressed(src, dst, summary, path):
            suppressed_confirmed[(src, dst)] = (summary, path)
        else:
            active_confirmed[(src, dst)] = (summary, path)

    refined = refine_actions(active_confirmed)

    print(f"\n=== {len(refined)} pair(s) reached QUORUM (Layer 4, shared coordinator) ===\n")
    if not refined:
        print("  (none)")
    for (src, dst), (summary, path, action) in refined.items():
        action_label = "AUTONOMOUS ACTION OK" if action == "AUTONOMOUS_ACTION_OK" else "ESCALATE FOR REVIEW"
        technique_ids = annotate_summary_with_attack(summary)
        print(f"  {src} -> {dst}  |  counts: {summary}  |  path: {path}  |  "
              f"{action_label}  |  MITRE: {technique_ids}")

    if refined:
        print("\n=== Reporting to SIEM/webhook (shared CEF export) ===\n")
        from contain import report_confirmed_pair
        for (src, dst), (summary, path, action) in refined.items():
            report_confirmed_pair(src, dst, summary, path, action)

    if refined or suppressed_confirmed:
        print("\n=== Writing audit trail (shared provenance format) ===\n")
        from audit_trail import build_audit_record, save_audit_record

        audit_count = 0
        for (src, dst), (summary, path, action) in refined.items():
            record = build_audit_record(
                src=src, dst=dst, summary=summary, path=path, action=action,
                contributing_alerts=raw_events_by_pair.get((src, dst), []),
                baseline=baseline, suppressed=False,
                mitre_techniques=annotate_summary_with_attack(summary),
            )
            save_audit_record(record)
            audit_count += 1
        for (src, dst), (summary, path) in suppressed_confirmed.items():
            record = build_audit_record(
                src=src, dst=dst, summary=summary, path=path, action="SUPPRESSED",
                contributing_alerts=raw_events_by_pair.get((src, dst), []),
                baseline=baseline, suppressed=True,
                mitre_techniques=annotate_summary_with_attack(summary),
            )
            save_audit_record(record)
            audit_count += 1
        print(f"  Wrote {audit_count} record(s) to audit_trail.jsonl")

    if suppressed_confirmed:
        print(f"\n=== {len(suppressed_confirmed)} pair(s) SUPPRESSED (previously reviewed by a human) ===\n")
        for (src, dst), (summary, path) in suppressed_confirmed.items():
            print(f"  {src} -> {dst}  |  counts: {summary}  |  path: {path}  |  (not re-escalated)")

    if not no_adapt:
        print("\n=== Adaptive auth baseline update ===\n")
        signaled_pairs = set()
        for event, signals in all_signals:
            signaled_pairs.add((event["src_computer"], event["dst_computer"]))

        learned_from_suppression = 0
        for pair in suppressed_confirmed:
            for event in raw_events_by_pair.get(pair, []):
                adaptive.observe_safe(event)
                learned_from_suppression += 1

        learned_from_zero_signal = 0
        for event in events:
            pair = (event["src_computer"], event["dst_computer"])
            if pair not in signaled_pairs and event["src_user"] in baseline:
                adaptive.observe_safe(event)
                learned_from_zero_signal += 1

        print(f"  Learned from {learned_from_zero_signal} zero-signal events (automatic)")
        print(f"  Learned from {learned_from_suppression} events via human-confirmed suppression")

        with open(ADAPTIVE_AUTH_BASELINE_FILE, "w") as f:
            json.dump(adaptive.export(), f, indent=2)
        print(f"  Saved adapted baseline to {ADAPTIVE_AUTH_BASELINE_FILE} "
              f"({len(adaptive.export())} users) - future runs will resume from this state.")
