"""
lanl_inspect_examples.py — pulls out full, real detail on a handful of
actual false-positive pairs from the LANL evaluation, instead of
reasoning about the problem abstractly.
"""

import csv
import json
from collections import defaultdict

with open("lanl_evaluation_results.json") as f:
    results = json.load(f)

false_positive_pairs = [tuple(p) for p in results["false_positive_pairs"][:5]]

print(f"Inspecting the first {len(false_positive_pairs)} false-positive pairs in full detail:\n")

rows_by_pair = defaultdict(list)
with open("lanl_eval_traffic.csv", newline="", encoding="utf-8-sig") as f:
    for row in csv.DictReader(f):
        pair = (row["src_ip"], row["dst_ip"])
        if pair in false_positive_pairs:
            rows_by_pair[pair].append(row)

for pair in false_positive_pairs:
    rows = rows_by_pair.get(pair, [])
    print(f"=== {pair[0]} -> {pair[1]} ({len(rows)} flow records in the eval window) ===")
    for r in rows[:10]:
        print(f"    {r['timestamp']}  port={r['dst_port']}  proto={r['protocol']}  bytes={r['bytes']}")
    if len(rows) > 10:
        print(f"    ... and {len(rows) - 10} more")
    print()
