"""
auth_inspect_false_positives.py — pulls real, full detail on Layer 7
false positives, so we understand precisely what's driving them.
"""

import json
from collections import Counter

from auth_detector import parse_auth_row, ChemicalMimicryDetector

with open("auth_evaluation_results.json") as f:
    results = json.load(f)

false_positive_pairs = set(tuple(p) for p in results["false_positive_pairs"][:10])

print(f"Inspecting the first {len(false_positive_pairs)} false-positive pairs in full detail:\n")

events_by_pair = {}
signal_counts = Counter()

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
        if pair in false_positive_pairs:
            events_by_pair.setdefault(pair, []).append((event, signals))
        for s in signals:
            signal_counts[s] += 1

print("=== Overall signal breakdown across ALL flagged pairs ===")
for signal, count in signal_counts.most_common():
    print(f"  {signal}: {count:,}")
print()

for pair in false_positive_pairs:
    events = events_by_pair.get(pair, [])
    print(f"=== {pair[0]} -> {pair[1]} ({len(events)} flagged event(s)) ===")
    for event, signals in events[:5]:
        print(f"    t={event['time']} user={event['src_user']} auth={event['auth_type']} "
              f"logon={event['logon_type']} signals={signals}")
    print()
