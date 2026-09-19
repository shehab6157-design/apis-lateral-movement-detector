"""
simulate.py
-------------
Generates synthetic internal network traffic for a handful of
devices, mimicking a small office/corporate LAN over several days of
"normal" activity. Then injects a fake lateral-movement attack: one
device (the "compromised host") suddenly contacts many new internal
peers it's never talked to before, in a short burst, outside its
normal hours - the textbook signature of an attacker moving between
machines using legitimate protocols.

Output: traffic.csv with columns:
    timestamp, src_ip, dst_ip, dst_port, protocol, bytes

This is what baseline.py learns from, and what detector.py is tested
against - a stand-in for real captured traffic until real VM traffic
(via capture.py) is available.
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(42)

BASELINE_TRAFFIC_PATH = "traffic.csv"       # normal-only, for baseline.py
TEST_TRAFFIC_PATH = "test_traffic.csv"      # normal + injected attack, for detector.py

# A small simulated office LAN: 6 normal devices with their own
# regular peers and typical active hours.
DEVICES = {
    "10.0.0.10": {"peers": ["10.0.0.20", "10.0.0.21"], "active_hours": range(8, 18)},
    "10.0.0.11": {"peers": ["10.0.0.20", "10.0.0.30"], "active_hours": range(8, 18)},
    "10.0.0.12": {"peers": ["10.0.0.20", "10.0.0.21", "10.0.0.30"], "active_hours": range(9, 17)},
    "10.0.0.20": {"peers": ["10.0.0.10", "10.0.0.11", "10.0.0.12"], "active_hours": range(0, 24)},  # server, always on
    "10.0.0.21": {"peers": ["10.0.0.10", "10.0.0.12"], "active_hours": range(0, 24)},  # server
    "10.0.0.30": {"peers": ["10.0.0.11", "10.0.0.12"], "active_hours": range(0, 24)},  # server
}

PORTS_PROTOCOLS = [
    (445, "SMB"), (3389, "RDP"), (22, "SSH"), (80, "HTTP"), (443, "HTTPS"),
]

START_DATE = datetime(2026, 7, 1, 0, 0, 0)
NUM_DAYS = 5


def normal_bytes():
    # Typical flow size, log-normal-ish spread
    return max(200, int(random.gauss(4000, 1200)))


def generate_normal_traffic():
    rows = []
    for day in range(NUM_DAYS):
        for device, profile in DEVICES.items():
            active_hours = list(profile["active_hours"])
            # 6-12 flows per device per day, only during its active hours
            for _ in range(random.randint(6, 12)):
                hour = random.choice(active_hours)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts = START_DATE + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
                dst = random.choice(profile["peers"])
                port, proto = random.choice(PORTS_PROTOCOLS)
                rows.append([ts.isoformat(), device, dst, port, proto, normal_bytes()])
    return rows


def inject_attack(rows):
    """
    Simulates 10.0.0.12 being compromised on day 4, at 2 AM (off-hours),
    and rapidly contacting 5 internal hosts it has never talked to
    before - a fan-out spike combined with new peers and off-hours
    activity, all at once. This is deliberately the hardest pattern
    for a signature-based / perimeter tool to catch, since it uses
    normal internal protocols (SMB/RDP) the whole time.
    """
    attacker = "10.0.0.12"
    attack_day = 3  # day index (0-based) - one of the days already in traffic.csv
    attack_start_hour = 2  # 2 AM - off hours for this device's normal 9-17 profile
    new_targets = ["10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.16", "10.0.0.17"]

    for i, target in enumerate(new_targets):
        ts = START_DATE + timedelta(days=attack_day, hours=attack_start_hour, minutes=i * 3)
        # Unusually large transfer (attacker pulling data / moving tools)
        size = random.randint(50000, 120000)
        rows.append([ts.isoformat(), attacker, target, 445, "SMB", size])

    return rows


def write_csv(rows, path):
    rows.sort(key=lambda r: r[0])  # chronological order
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes"])
        writer.writerows(rows)


if __name__ == "__main__":
    normal_rows = generate_normal_traffic()
    print(f"Generated {len(normal_rows)} normal traffic rows across {len(DEVICES)} devices "
          f"over {NUM_DAYS} days.")
    write_csv(list(normal_rows), BASELINE_TRAFFIC_PATH)
    print(f"Saved normal-only traffic to {BASELINE_TRAFFIC_PATH} (use this to build the baseline)")

    attack_rows = inject_attack(list(normal_rows))
    print(f"\nInjected 5 attack rows (10.0.0.12 -> 5 new peers, off-hours, oversized transfers).")
    print(f"Total rows in test set: {len(attack_rows)}")
    write_csv(attack_rows, TEST_TRAFFIC_PATH)
    print(f"Saved normal+attack traffic to {TEST_TRAFFIC_PATH} (use this to test the detector)")
