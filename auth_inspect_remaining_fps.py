"""
auth_inspect_remaining_fps.py — real examples of the remaining Layer 7
false positives after the machine-account/ANONYMOUS LOGON exclusion.
"""

import json
from collections import Counter

from auth_detector import parse_auth_row, ChemicalMimicryDetector

with open("auth_evaluation_results.json") as f:
    results = json.load(f)

false_positive_pairs = set(tuple(p) for p in results["false_positive_pairs"][:10])

print(f"Inspecting {len(false_positive_pairs)} remaining false-positive pairs:\n")

events_by_pair = {}
signal_counts = Counter()
event_counts_per_pair = Counter()

detector = ChemicalMimicryDetector()
with open("auth_eval_events.txt") as f:
    for line in f:
        event = parse_auth_row(line)
        if event is None:
            continue
        signals = detector.process_event(event)
        if not signals:
            continue
        pair = (event["src_computer"], event["dst_computer"])
        event_counts_per_pair[pair] += 1
        for s in signals:
            signal_counts[s] += 1
        if pair in false_positive_pairs:
            events_by_pair.setdefault(pair, []).append((event, signals))

print("=== Overall signal breakdown (post-exclusion) ===")
for signal, count in signal_counts.most_common():
    print(f"  {signal}: {count:,}")
print()

print("=== How many events does the TYPICAL flagged pair have? ===")
counts = sorted(event_counts_per_pair.values())
n = len(counts)
print(f"  min={counts[0]}  median={counts[n//2]}  p90={counts[int(n*0.9)]}  max={counts[-1]}")
print()

for pair in false_positive_pairs:
    events = events_by_pair.get(pair, [])
    print(f"=== {pair[0]} -> {pair[1]} ({len(events)} flagged event(s)) ===")
    for event, signals in events[:4]:
        print(f"    t={event['time']} user={event['src_user']} auth={event['auth_type']} "
              f"logon={event['logon_type']} signals={signals}")
    print()
