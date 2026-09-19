"""
lanl_inspect_volume_examples.py — pulls real, full detail on false
positives specifically involving VOLUME_OUTLIER.
"""

import csv
import json
from collections import defaultdict

import baseline as baseline_module
import detector

print("Rebuilding baseline and detection to identify VOLUME_OUTLIER-driven false positives...")
rows = baseline_module.load_traffic("lanl_baseline_traffic.csv")
baseline = baseline_module.build_baseline(rows)

eval_rows = detector.load_traffic("lanl_eval_traffic.csv")
alerts = detector.detect(eval_rows, baseline)
confirmed, _ = detector.apply_quorum(alerts, baseline=baseline)

with open("lanl_evaluation_results.json") as f:
    results = json.load(f)
false_positive_pairs = set(tuple(p) for p in results["false_positive_pairs"])

volume_fp_pairs = []
for pair in false_positive_pairs:
    if pair in confirmed:
        summary, path = confirmed[pair]
        if "VOLUME_OUTLIER" in summary:
            volume_fp_pairs.append(pair)

print(f"\n{len(volume_fp_pairs)} of the sampled false positives involve VOLUME_OUTLIER.\n")
print("Inspecting the first 5 in full detail:\n")

rows_by_pair = defaultdict(list)
with open("lanl_eval_traffic.csv", newline="", encoding="utf-8-sig") as f:
    for row in csv.DictReader(f):
        pair = (row["src_ip"], row["dst_ip"])
        if pair in volume_fp_pairs[:5]:
            rows_by_pair[pair].append(row)

for pair in volume_fp_pairs[:5]:
    src, dst = pair
    profile = baseline.get(src, {})
    print(f"=== {src} -> {dst} ===")
    print(f"    Baseline: avg_bytes={profile.get('avg_bytes')}  std_bytes={profile.get('std_bytes')}  "
          f"avg_flows_per_hour={profile.get('avg_flows_per_hour')}")
    flows = rows_by_pair.get(pair, [])
    print(f"    {len(flows)} flow record(s) to this destination in eval window:")
    for r in flows[:8]:
        print(f"      {r['timestamp']}  bytes={r['bytes']}  port={r['dst_port']}")
    if len(flows) > 8:
        print(f"      ... and {len(flows) - 8} more")
    print()
