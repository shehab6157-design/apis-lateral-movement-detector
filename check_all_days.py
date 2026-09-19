import gzip
from collections import Counter

day_counts = Counter()
with gzip.open('redteam.txt.gz', 'rt') as f:
    for line in f:
        parts = line.strip().split(',')
        seconds = int(parts[0])
        day = seconds // 86400
        day_counts[day] += 1

print("Day-by-day labeled attack count, days 0 through 8:")
for day in range(9):
    count = day_counts.get(day, 0)
    status = "CLEAN" if count == 0 else f"{count} labeled events"
    print(f"  Day {day}: {status}")
