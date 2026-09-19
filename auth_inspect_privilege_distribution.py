"""
auth_inspect_privilege_distribution.py — checks the real distribution
of known_destinations counts across all users in the baseline.
"""

import json

with open("auth_baseline.json") as f:
    baseline = json.load(f)

counts = sorted(len(profile["known_destinations"]) for profile in baseline.values())
n = len(counts)

print(f"Total users in baseline: {n}\n")
print("Known-destination-count distribution:")
for p in [50, 75, 90, 95, 97, 99, 99.5, 99.9]:
    idx = min(int(n * p / 100), n - 1)
    print(f"  p{p}: {counts[idx]} known destinations")
print(f"  min: {counts[0]}  max: {counts[-1]}")

for user in ["U66@DOM1", "U293@DOM1", "U4448@DOM1"]:
    if user in baseline:
        count = len(baseline[user]["known_destinations"])
        percentile_rank = sum(1 for c in counts if c <= count) / n * 100
        print(f"\n{user}: {count} known destinations (~{percentile_rank:.1f}th percentile)")
