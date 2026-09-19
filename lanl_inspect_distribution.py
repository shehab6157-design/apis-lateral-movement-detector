"""
lanl_inspect_distribution.py — pulls the REAL full byte-value distribution
for the specific devices behind our VOLUME_OUTLIER false positives.
"""

import baseline as baseline_module

print("Loading full baseline traffic to inspect real distributions...")
rows = baseline_module.load_traffic("lanl_baseline_traffic.csv")

for device in ["C10", "C1015"]:
    byte_values = sorted(r["bytes"] for r in rows if r["src_ip"] == device)
    if not byte_values:
        print(f"{device}: no baseline data")
        continue
    n = len(byte_values)
    percentiles = {p: byte_values[int(n * p / 100)] for p in [10, 25, 50, 75, 90, 95, 99, 99.5, 99.9]}
    print(f"\n=== {device} ({n} baseline flow records) ===")
    for p, v in percentiles.items():
        print(f"  p{p}: {v} bytes")
    print(f"  min: {byte_values[0]}  max: {byte_values[-1]}")
