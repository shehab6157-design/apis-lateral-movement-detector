"""
lanl_evaluation.py — evaluates the actual detector.py pipeline against
a real, independently-labeled dataset (LANL "Comprehensive Multi-Source
Cyber-Security Events"), instead of only against data this project
generated itself.

Honest scope, stated up front:
  - Only flows.txt is used - the format closest to what this detector
    was built for. auth.txt/proc.txt/dns.txt describe Windows-specific
    events this detector was never built to understand.
  - UNKNOWN_SSH_CLIENT will never fire here - flow records carry no
    protocol banner at all. Honest, expected gap, not a bug.
  - dst_port values matching LANL's anonymized "N#####" scheme are
    treated as port 0 - GUARD_BLOCKED_PORT is not meaningful for those.
  - Extraction is scoped to the ~305 computers that appear in ANY
    labeled red-team event across the whole dataset.
  - Baseline is built from days 0, 3, and 4 combined - the ONLY three
    days before day 8 with zero labeled attacks (days 1,2,5,6,7 all
    contain real attacker activity and are excluded to avoid training
    on attacker behavior). A 50% increase in clean baseline data over
    the original 2-day window, without contaminating it.
  - Evaluates against day 8 - highest concentration of real labeled
    events.

Usage:
    python3 lanl_evaluation.py extract
    python3 lanl_evaluation.py evaluate
"""

import csv
import gzip
import json
import sys
from datetime import datetime, timedelta

FLOWS_GZ = "flows.txt.gz"
REDTEAM_GZ = "redteam.txt.gz"

BASELINE_WINDOWS = [
    (0, 86400),          # day 0: verified clean, zero labeled attacks
    (259200, 432000),    # days 3-4: verified clean, zero labeled attacks
]                        # days 1,2,5,6,7 all contain real labeled attacks - excluded
EVAL_WINDOW = (691200, 777600)       # day 8: highest concentration of real labeled attacks

BASELINE_CSV = "lanl_baseline_traffic.csv"
EVAL_CSV = "lanl_eval_traffic.csv"
REFERENCE_START = datetime(2013, 1, 1)


def parse_port(raw):
    try:
        return int(raw)
    except ValueError:
        return 0


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
    print(f"Streaming {FLOWS_GZ} once (this reads the whole file once)...")

    baseline_rows = 0
    eval_rows = 0
    total_read = 0

    with gzip.open(FLOWS_GZ, "rt") as fin, \
         open(BASELINE_CSV, "w", newline="") as fbase, \
         open(EVAL_CSV, "w", newline="") as feval:

        base_writer = csv.writer(fbase)
        eval_writer = csv.writer(feval)
        base_writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "ssh_banner"])
        eval_writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "ssh_banner"])

        for line in fin:
            total_read += 1
            if total_read % 5_000_000 == 0:
                print(f"  ...{total_read:,} lines read so far "
                      f"(baseline: {baseline_rows:,}, eval: {eval_rows:,})")

            parts = line.strip().split(",")
            if len(parts) != 9:
                continue
            time_s, duration, src, sport, dst, dport, proto, pkts, byte_count = parts
            time_s = int(time_s)

            if time_s > EVAL_WINDOW[1]:
                break

            if src not in attack_computers and dst not in attack_computers:
                continue

            ts = (REFERENCE_START + timedelta(seconds=time_s)).isoformat()
            row = [ts, src, dst, parse_port(dport), proto, byte_count, ""]

            if any(start <= time_s < end for start, end in BASELINE_WINDOWS):
                base_writer.writerow(row)
                baseline_rows += 1
            elif EVAL_WINDOW[0] <= time_s < EVAL_WINDOW[1]:
                eval_writer.writerow(row)
                eval_rows += 1

    print(f"\nDone. Read {total_read:,} total lines from flows.txt.gz.")
    print(f"  Baseline window (days 0,3-4 combined, clean, scoped): {baseline_rows:,} rows -> {BASELINE_CSV}")
    print(f"  Eval window (day 8, real attacks, scoped): {eval_rows:,} rows -> {EVAL_CSV}")


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
    import baseline as baseline_module
    import detector

    print(f"Building baseline from {BASELINE_CSV} (days 0,3-4 combined, clean)...")
    rows = baseline_module.load_traffic(BASELINE_CSV)
    baseline = baseline_module.build_baseline(rows)
    print(f"  Learned baseline for {len(baseline)} computers.\n")

    print(f"Running the real detection pipeline against {EVAL_CSV} (day 8, real attack day)...")
    eval_rows = detector.load_traffic(EVAL_CSV)
    alerts = detector.detect(eval_rows, baseline)
    confirmed, collective_threats = detector.apply_quorum(alerts, baseline=baseline)
    refined = detector.refine_actions(confirmed)
    print(f"  {len(alerts)} raw alerts, {len(refined)} pairs reached quorum.\n")

    print("Loading real ground truth from redteam.txt for the same window...")
    labeled_pairs = load_redteam_for_eval_window()
    print(f"  {len(labeled_pairs)} distinct (src, dst) pairs genuinely labeled malicious in this window.\n")

    detected_pairs = set(refined.keys())

    true_positives = detected_pairs & labeled_pairs
    false_positives = detected_pairs - labeled_pairs
    false_negatives = labeled_pairs - detected_pairs

    detection_rate = len(true_positives) / len(labeled_pairs) if labeled_pairs else 0.0
    fp_rate_of_confirmed = len(false_positives) / len(detected_pairs) if detected_pairs else 0.0

    print("=" * 70)
    print("HONEST EVALUATION RESULT - real LANL data, real independent labels")
    print("=" * 70)
    print(f"Labeled malicious pairs in window : {len(labeled_pairs)}")
    print(f"Pairs this detector confirmed       : {len(detected_pairs)}")
    print(f"True positives  (correctly caught)  : {len(true_positives)}")
    print(f"False negatives (missed)            : {len(false_negatives)}")
    print(f"False positives (wrongly flagged)   : {len(false_positives)}")
    print(f"Detection rate on labeled attacks   : {detection_rate:.1%}")
    print(f"False-positive rate of confirmations: {fp_rate_of_confirmed:.1%}")
    print()
    print("NOTE: false positives here may include real attacker pivot points")
    print("that redteam.txt didn't specifically label (redteam.txt marks the")
    print("known compromise path, not necessarily every host an attacker")
    print("touched) - a manual look at false positives is worth doing before")
    print("treating this number as final.")

    with open("lanl_evaluation_results.json", "w") as f:
        json.dump({
            "labeled_pairs": len(labeled_pairs),
            "confirmed_pairs": len(detected_pairs),
            "true_positives": len(true_positives),
            "false_negatives": len(false_negatives),
            "false_positives": len(false_positives),
            "detection_rate": detection_rate,
            "false_positive_rate_of_confirmed": fp_rate_of_confirmed,
            "true_positive_pairs": sorted(list(true_positives)),
            "false_negative_pairs": sorted(list(false_negatives))[:50],
            "false_positive_pairs": sorted(list(false_positives))[:50],
        }, f, indent=2)
    print("\nFull results saved to lanl_evaluation_results.json")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("extract", "evaluate"):
        print("Usage: python3 lanl_evaluation.py [extract|evaluate]")
        sys.exit(1)

    if sys.argv[1] == "extract":
        extract()
    else:
        evaluate()
