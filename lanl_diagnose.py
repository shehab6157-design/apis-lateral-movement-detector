"""
lanl_diagnose.py — breaks down exactly which signals are driving the
false positives found in the LANL evaluation, instead of guessing.
"""

import json
from collections import Counter

import baseline as baseline_module
import detector

print("Rebuilding the same baseline and detection run to inspect signal details...")
rows = baseline_module.load_traffic("lanl_baseline_traffic.csv")
baseline = baseline_module.build_baseline(rows)

eval_rows = detector.load_traffic("lanl_eval_traffic.csv")
alerts = detector.detect(eval_rows, baseline)
confirmed, _ = detector.apply_quorum(alerts)

with open("lanl_evaluation_results.json") as f:
    results = json.load(f)

false_positive_pairs = set(tuple(p) for p in results["false_positive_pairs"])

print(f"\nAnalyzing signal combinations for {len(false_positive_pairs)} sampled false positives...\n")

signal_combo_counts = Counter()
path_counts = Counter()

for pair in false_positive_pairs:
    if pair in confirmed:
        summary, path = confirmed[pair]
        combo = tuple(sorted(summary.keys()))
        signal_combo_counts[combo] += 1
        path_counts[path] += 1

print("=== Signal combinations behind false positives (top 10) ===")
for combo, count in signal_combo_counts.most_common(10):
    print(f"  {combo}: {count} pairs")

print()
print("=== Confirmation path behind false positives ===")
for path, count in path_counts.most_common():
    print(f"  {path}: {count} pairs")

print()
print("=== Signal combinations across ALL confirmed pairs (for comparison) ===")
all_combo_counts = Counter()
for (src, dst), (summary, path) in confirmed.items():
    combo = tuple(sorted(summary.keys()))
    all_combo_counts[combo] += 1
for combo, count in all_combo_counts.most_common(10):
    print(f"  {combo}: {count} pairs")
