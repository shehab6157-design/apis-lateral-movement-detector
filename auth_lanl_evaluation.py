"""
auth_lanl_evaluation.py — evaluates the real Layer 7 (Chemical-Mimicry
Detection) pipeline against the real LANL auth.txt dataset, using the
SAME real, independently-labeled ground truth (redteam.txt) already
used for the network-flow evaluation.

Honest scope:
  - Scoped to the SAME ~305 computers used in the flow-side evaluation.
  - Baseline is built from days 0, 3, and 4 - the SAME three verified
    clean days already used for the flow-side baseline, learning a
    per-user "known destinations" profile (see auth_baseline.py).
  - Evaluates day 8, with a 1-hour lookback buffer before it.
  - Both the baseline days and the eval day are extracted in a SINGLE
    pass through the 7.2GB auth.txt.gz file.

Usage:
    python3 auth_lanl_evaluation.py extract
    python3 auth_lanl_evaluation.py evaluate
"""

import gzip
import json
import sys

from auth_detector import parse_auth_row, ChemicalMimicryDetector
from auth_baseline import load_auth_events, build_auth_baseline, save_auth_baseline

AUTH_GZ = "auth.txt.gz"
REDTEAM_GZ = "redteam.txt.gz"

BASELINE_WINDOWS = [
    (0, 86400),
    (259200, 432000),
]
EVAL_WINDOW = (691200, 777600)
LOOKBACK_SECONDS = 3600
EXTRACT_START = EVAL_WINDOW[0] - LOOKBACK_SECONDS
EXTRACT_END = EVAL_WINDOW[1]

AUTH_BASELINE_TRAFFIC_FILE = "auth_baseline_traffic.txt"
AUTH_EVAL_FILE = "auth_eval_events.txt"
AUTH_BASELINE_JSON = "auth_baseline.json"


def load_attack_involved_computers():
    computers = set()
    with gzip.open(REDTEAM_GZ, "rt") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            computers.add(parts[2])
            computers.add(parts[3])
    return computers


def extract():
    attack_computers = load_attack_involved_computers()
    print(f"Scoping to {len(attack_computers)} computers involved in any labeled red-team event.")
    print(f"Streaming {AUTH_GZ} once (7.2GB compressed - extracting BOTH baseline "
          f"days and eval day in a single pass)...")

    baseline_rows = 0
    eval_rows = 0
    total_read = 0

    with gzip.open(AUTH_GZ, "rt") as fin, \
         open(AUTH_BASELINE_TRAFFIC_FILE, "w") as fbase, \
         open(AUTH_EVAL_FILE, "w") as feval:

        for line in fin:
            total_read += 1
            if total_read % 10_000_000 == 0:
                print(f"  ...{total_read:,} lines read so far "
                      f"(baseline: {baseline_rows:,}, eval: {eval_rows:,})")

            parts = line.strip().split(",")
            if len(parts) != 9:
                continue
            try:
                time_s = int(parts[0])
            except ValueError:
                continue

            if time_s > EXTRACT_END:
                break

            src_computer, dst_computer = parts[3], parts[4]
            if src_computer not in attack_computers and dst_computer not in attack_computers:
                continue

            if any(start <= time_s < end for start, end in BASELINE_WINDOWS):
                fbase.write(line)
                baseline_rows += 1
            elif EXTRACT_START <= time_s <= EXTRACT_END:
                feval.write(line)
                eval_rows += 1

    print(f"\nDone. Read {total_read:,} total lines from {AUTH_GZ}.")
    print(f"  Baseline traffic (days 0,3-4, scoped): {baseline_rows:,} rows -> {AUTH_BASELINE_TRAFFIC_FILE}")
    print(f"  Eval traffic (day 8 + 1hr lookback, scoped): {eval_rows:,} rows -> {AUTH_EVAL_FILE}")

    print(f"\nBuilding the per-user baseline from {AUTH_BASELINE_TRAFFIC_FILE}...")
    events = load_auth_events(AUTH_BASELINE_TRAFFIC_FILE)
    baseline = build_auth_baseline(events)
    save_auth_baseline(baseline, AUTH_BASELINE_JSON)
    print(f"  Learned baseline for {len(baseline)} users -> {AUTH_BASELINE_JSON}")


def load_redteam_for_eval_window():
    labeled_pairs = set()
    with gzip.open(REDTEAM_GZ, "rt") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            time_s, user, src, dst = parts
            time_s = int(time_s)
            if EVAL_WINDOW[0] <= time_s < EVAL_WINDOW[1]:
                labeled_pairs.add((src, dst))
    return labeled_pairs


def evaluate():
    print(f"Loading the per-user baseline from {AUTH_BASELINE_JSON}...")
    with open(AUTH_BASELINE_JSON) as f:
        baseline = json.load(f)
    print(f"  {len(baseline)} users in baseline.\n")

    print(f"Streaming events from {AUTH_EVAL_FILE} (no full-file load or sort)...")
    detector = ChemicalMimicryDetector(baseline=baseline)
    detected_pairs = {}
    total_events = 0

    with open(AUTH_EVAL_FILE) as f:
        for line in f:
            event = parse_auth_row(line)
            if event is None:
                continue
            total_events += 1

            signals = detector.process_event(event)
            if not signals:
                continue
            if event["time"] < EVAL_WINDOW[0]:
                continue
            pair = (event["src_computer"], event["dst_computer"])
            detected_pairs.setdefault(pair, set()).update(signals)

    print(f"  {total_events:,} valid events processed.")
    print(f"  {len(detected_pairs)} distinct (src, dst) computer pairs flagged.\n")

    print("Loading real ground truth from redteam.txt for the same window...")
    labeled_pairs = load_redteam_for_eval_window()
    print(f"  {len(labeled_pairs)} distinct (src, dst) pairs genuinely labeled malicious in this window.\n")

    detected_set = set(detected_pairs.keys())
    true_positives = detected_set & labeled_pairs
    false_positives = detected_set - labeled_pairs
    false_negatives = labeled_pairs - detected_set

    detection_rate = len(true_positives) / len(labeled_pairs) if labeled_pairs else 0.0
    fp_rate = len(false_positives) / len(detected_set) if detected_set else 0.0

    print("=" * 70)
    print("HONEST EVALUATION RESULT - Layer 7 + per-user baseline, real LANL data")
    print("=" * 70)
    print(f"Labeled malicious pairs in window : {len(labeled_pairs)}")
    print(f"Pairs Layer 7 flagged                : {len(detected_set)}")
    print(f"True positives  (correctly caught)   : {len(true_positives)}")
    print(f"False negatives (missed)             : {len(false_negatives)}")
    print(f"False positives (wrongly flagged)    : {len(false_positives)}")
    print(f"Detection rate on labeled attacks    : {detection_rate:.1%}")
    print(f"False-positive rate of flagged pairs : {fp_rate:.1%}")

    with open("auth_evaluation_results.json", "w") as f:
        json.dump({
            "labeled_pairs": len(labeled_pairs),
            "flagged_pairs": len(detected_set),
            "true_positives": len(true_positives),
            "false_negatives": len(false_negatives),
            "false_positives": len(false_positives),
            "detection_rate": detection_rate,
            "false_positive_rate": fp_rate,
            "true_positive_pairs": sorted(list(true_positives)),
            "false_positive_pairs": sorted(list(false_positives))[:50],
            "false_negative_pairs": sorted(list(false_negatives))[:50],
        }, f, indent=2)
    print("\nFull results saved to auth_evaluation_results.json")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("extract", "evaluate"):
        print("Usage: python3 auth_lanl_evaluation.py [extract|evaluate]")
        sys.exit(1)

    if sys.argv[1] == "extract":
        extract()
    else:
        evaluate()
