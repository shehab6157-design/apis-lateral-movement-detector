"""
auth_inspect_lost_detections.py — identifies the real labeled attacks
lost due to the per-user baseline, and checks whether the compromised
user already had legitimate baseline access to the target.
"""

import json

from auth_detector import parse_auth_row, ChemicalMimicryDetector

with open("auth_baseline.json") as f:
    baseline = json.load(f)

detector_raw = ChemicalMimicryDetector(baseline=None)
detector_with_baseline = ChemicalMimicryDetector(baseline=baseline)

detected_raw = {}
detected_with_baseline = {}

with open("auth_eval_events.txt") as f:
    for line in f:
        event = parse_auth_row(line)
        if event is None:
            continue

        signals_raw = detector_raw.process_event(event)
        signals_wb = detector_with_baseline.process_event(event)

        pair = (event["src_computer"], event["dst_computer"])
        if signals_raw:
            detected_raw.setdefault(pair, []).append(event)
        if signals_wb:
            detected_with_baseline.setdefault(pair, []).append(event)

import gzip
EVAL_WINDOW = (691200, 777600)
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

caught_raw = set(detected_raw.keys()) & labeled_pairs
caught_with_baseline = set(detected_with_baseline.keys()) & labeled_pairs
lost = caught_raw - caught_with_baseline

print(f"Real attacks caught WITHOUT baseline: {len(caught_raw)}")
print(f"Real attacks caught WITH baseline: {len(caught_with_baseline)}")
print(f"Lost due to the baseline: {len(lost)}\n")

for pair in list(lost)[:8]:
    src, dst = pair
    events = detected_raw.get(pair, [])
    print(f"=== {src} -> {dst} ===")
    for event in events[:2]:
        user = event["src_user"]
        user_profile = baseline.get(user)
        known = user_profile["known_destinations"] if user_profile else None
        was_known = dst in known if known else False
        print(f"    user={user}  dst_in_their_baseline={was_known}  "
              f"their_known_destination_count={len(known) if known else 0}")
    print()
