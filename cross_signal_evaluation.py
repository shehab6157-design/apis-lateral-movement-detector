"""
cross_signal_evaluation.py — evaluates the real Layer 8 extension
(cross-domain correlation) against the real LANL dataset, using the
SAME flow-side and auth-side evaluation pipelines and the SAME real,
independently-labeled ground truth already used throughout this
project.

Honest scope: reuses the already-extracted lanl_eval_traffic.csv,
lanl_baseline_traffic.csv, auth_eval_events.txt, and auth_baseline.json
files already built by lanl_evaluation.py and auth_lanl_evaluation.py -
run those first if they don't exist yet.

Usage:
    python3 cross_signal_evaluation.py
"""

import gzip
import json
from datetime import datetime

import baseline as baseline_module
import detector
from auth_detector import parse_auth_row, ChemicalMimicryDetector
from cross_signal_correlator import correlate

EVAL_WINDOW = (691200, 777600)
REFERENCE_START = datetime(2013, 1, 1)


def get_flow_confirmations_with_timestamps():
    rows = baseline_module.load_traffic("lanl_baseline_traffic.csv")
    baseline = baseline_module.build_baseline(rows)
    eval_rows = detector.load_traffic("lanl_eval_traffic.csv")
    alerts = detector.detect(eval_rows, baseline)

    confirmed_with_ts = {}
    from quorum import QuorumCoordinator
    coordinator = QuorumCoordinator(
        active_detector_types=detector.ACTIVE_DETECTOR_TYPES,
        repetition_threshold_fn=detector.make_repetition_threshold_fn(baseline, detector.QUORUM_REPETITION),
        type_diversity_excluded_types=detector.QUORUM_EXCLUDED_SIGNALS,
    )

    def on_quorum(src, dst, summary, path):
        if (src, dst) not in confirmed_with_ts:
            confirmed_with_ts[(src, dst)] = (summary, path, current_ts["value"])

    coordinator.on_quorum_reached = on_quorum
    current_ts = {"value": None}
    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        ts = datetime.fromisoformat(alert["timestamp"])
        current_ts["value"] = ts
        coordinator.record_batch(alert["signals"], alert["src_ip"], alert["dst_ip"], timestamp=ts)

    refined = detector.refine_actions({k: (v[0], v[1]) for k, v in confirmed_with_ts.items()})
    return {pair: (v[0], v[1], confirmed_with_ts[pair][2]) for pair, v in refined.items()}


def get_auth_confirmations_with_timestamps():
    with open("auth_baseline.json") as f:
        auth_baseline = json.load(f)

    detector_auth = ChemicalMimicryDetector(baseline=auth_baseline)
    confirmed = {}
    with open("auth_eval_events.txt") as f:
        for line in f:
            event = parse_auth_row(line)
            if event is None:
                continue
            signals = detector_auth.process_event(event)
            if not signals:
                continue
            if event["time"] < EVAL_WINDOW[0]:
                continue
            pair = (event["src_computer"], event["dst_computer"])
            from datetime import timedelta
            ts = REFERENCE_START + timedelta(seconds=event["time"])
            summary = {}
            for s in signals:
                summary[s] = summary.get(s, 0) + 1
            if pair in confirmed:
                for s, c in summary.items():
                    confirmed[pair][0][s] = confirmed[pair][0].get(s, 0) + c
            else:
                confirmed[pair] = [summary, ts]

    return {pair: (v[0], v[1]) for pair, v in confirmed.items()}


def load_redteam_for_eval_window():
    labeled_pairs = set()
    with gzip.open("redteam.txt.gz", "rt") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            time_s, user, src, dst = parts
            time_s = int(time_s)
            if EVAL_WINDOW[0] <= time_s < EVAL_WINDOW[1]:
                labeled_pairs.add((src, dst))
    return labeled_pairs


if __name__ == "__main__":
    print("Building flow-side confirmations (with timestamps)...")
    flow_confirmations = {p: (v[0], v[1], v[2]) for p, v in get_flow_confirmations_with_timestamps().items()}
    print(f"  {len(flow_confirmations)} flow-side confirmed pairs\n")

    print("Building auth-side confirmations (with timestamps)...")
    auth_confirmations = get_auth_confirmations_with_timestamps()
    print(f"  {len(auth_confirmations)} auth-side confirmed pairs\n")

    print("Correlating across domains (30-minute window)...")
    correlated = correlate(
        {p: (v[0], v[1], v[2]) for p, v in flow_confirmations.items()},
        auth_confirmations,
        window_minutes=30,
    )
    print(f"  {len(correlated)} pairs correlated across BOTH domains\n")

    print("Loading real ground truth...")
    labeled_pairs = load_redteam_for_eval_window()
    print(f"  {len(labeled_pairs)} distinct labeled malicious pairs in window\n")

    correlated_set = set(correlated.keys())
    true_positives = correlated_set & labeled_pairs
    false_positives = correlated_set - labeled_pairs

    precision = len(true_positives) / len(correlated_set) if correlated_set else 0.0
    recall = len(true_positives) / len(labeled_pairs) if labeled_pairs else 0.0

    print("=" * 70)
    print("HONEST EVALUATION RESULT - cross-domain correlation, real LANL data")
    print("=" * 70)
    print(f"Pairs correlated across both domains : {len(correlated_set)}")
    print(f"True positives                        : {len(true_positives)}")
    print(f"False positives                       : {len(false_positives)}")
    print(f"Precision of correlated subset         : {precision:.1%}")
    print(f"Recall (of all {len(labeled_pairs)} labeled attacks)      : {recall:.1%}")
    print()
    print("For comparison, recall this project's single-domain results:")
    print("  Flow-side alone:  603 FP, 13 TP,  2.11% precision")
    print("  Auth-side alone:  7,991 FP, 166 TP, 2.03% precision")
