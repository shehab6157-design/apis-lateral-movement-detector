"""
lanl_inspect_lost_true_positives.py — identifies the specific labeled
attacks lost due to the type_diversity VOLUME_OUTLIER exclusion.
"""

import baseline as baseline_module
import detector
from quorum import QuorumCoordinator

print("Building baseline and running detection WITH the current exclusion...")
rows = baseline_module.load_traffic("lanl_baseline_traffic.csv")
baseline = baseline_module.build_baseline(rows)

eval_rows = detector.load_traffic("lanl_eval_traffic.csv")
alerts = detector.detect(eval_rows, baseline)

confirmed_with_exclusion, _ = detector.apply_quorum(alerts, baseline=baseline)

print("Running the SAME detection WITHOUT the exclusion (for comparison)...")
coordinator_no_exclusion = QuorumCoordinator(
    active_detector_types=detector.ACTIVE_DETECTOR_TYPES,
)
confirmed_no_exclusion = {}
def on_quorum(src, dst, summary, path):
    if (src, dst) not in confirmed_no_exclusion:
        confirmed_no_exclusion[(src, dst)] = (summary, path)
coordinator_no_exclusion.on_quorum_reached = on_quorum
for alert in sorted(alerts, key=lambda a: a["timestamp"]):
    from datetime import datetime as dt
    ts = dt.fromisoformat(alert["timestamp"])
    coordinator_no_exclusion.record_batch(alert["signals"], alert["src_ip"], alert["dst_ip"], timestamp=ts)

import gzip
labeled_pairs = set()
EVAL_WINDOW = (691200, 777600)
with gzip.open("redteam.txt.gz", "rt") as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) != 4:
            continue
        time_s, user, src, dst = parts
        time_s = int(time_s)
        if EVAL_WINDOW[0] <= time_s < EVAL_WINDOW[1]:
            labeled_pairs.add((src, dst))

tp_with = set(confirmed_with_exclusion.keys()) & labeled_pairs
tp_without = set(confirmed_no_exclusion.keys()) & labeled_pairs
lost = tp_without - tp_with

print(f"\nTrue positives WITHOUT exclusion: {len(tp_without)}")
print(f"True positives WITH exclusion: {len(tp_with)}")
print(f"Lost true positives: {len(lost)}\n")

for pair in lost:
    summary, path = confirmed_no_exclusion[pair]
    print(f"  {pair[0]} -> {pair[1]}: signals={summary}, path={path}")
