"""
baseline.py
-------------
Learns a per-device behavioral baseline from a traffic CSV.
"""

import csv
import json
import math
import sys
import statistics
from collections import defaultdict
from datetime import datetime

BASELINE_PATH = "baseline.json"


def load_traffic(path):
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["bytes"] = int(row["bytes"])
            row["ssh_banner"] = row.get("ssh_banner", "") or ""
            rows.append(row)
    return rows


def fit_byte_mixture_model(byte_values, min_samples_for_mixture=30):
    """
    Fits a Gaussian Mixture Model to a device's LOG-transformed byte
    values, choosing between 1 and 2 components via BIC. Built after
    THREE single-parameter approaches (raw z-score, log-space z-score,
    percentile) were each tried and measured against the real LANL
    dataset and none beat the plain raw z-score - because real device
    traffic can be genuinely BIMODAL. A mixture model learns each
    device's actual number of distinct normal behaviors and only flags
    a value that doesn't fit near EITHER of them.
    """
    if len(byte_values) < min_samples_for_mixture:
        return None

    from sklearn.mixture import GaussianMixture
    import numpy as np

    log_values = np.array([[math.log(b + 1)] for b in byte_values])

    best_model = None
    best_bic = None
    for n_components in (1, 2):
        try:
            gmm = GaussianMixture(n_components=n_components, random_state=42, n_init=3)
            gmm.fit(log_values)
            bic = gmm.bic(log_values)
        except Exception:
            continue
        if best_bic is None or bic < best_bic:
            best_bic = bic
            best_model = gmm

    if best_model is None:
        return None

    means = best_model.means_.flatten().tolist()
    stds = [max(float(s ** 0.5), 0.05) for s in best_model.covariances_.flatten().tolist()]
    weights = best_model.weights_.tolist()

    # Safety check: BIC can occasionally select 2 components for
    # genuinely unimodal data if there's minor structure in the sample.
    # Collapse back to a single component if the two means are too
    # close together to represent genuine bimodality.
    if len(means) == 2:
        pooled_std = (stds[0] + stds[1]) / 2
        if abs(means[0] - means[1]) < 2 * pooled_std:
            log_values_flat = log_values.flatten().tolist()
            overall_mean = sum(log_values_flat) / len(log_values_flat)
            overall_std = max((sum((v - overall_mean) ** 2 for v in log_values_flat) / len(log_values_flat)) ** 0.5, 0.05)
            means = [overall_mean]
            stds = [overall_std]
            weights = [1.0]

    return {
        "n_components": len(means),
        "component_means": [round(m, 4) for m in means],
        "component_stds": [round(s, 4) for s in stds],
        "component_weights": [round(w, 4) for w in weights],
    }


def build_baseline(rows):
    per_device_peers = defaultdict(set)
    per_device_hours = defaultdict(set)
    per_device_bytes = defaultdict(list)
    per_device_hourly_peers = defaultdict(lambda: defaultdict(set))
    per_device_hourly_flow_count = defaultdict(lambda: defaultdict(int))
    per_device_banners = defaultdict(set)

    for row in rows:
        src = row["src_ip"]
        dst = row["dst_ip"]
        ts = row["timestamp"]
        hour_bucket = (ts.date().isoformat(), ts.hour)

        per_device_peers[src].add(dst)
        per_device_hours[src].add(ts.hour)
        per_device_bytes[src].append(row["bytes"])
        per_device_hourly_peers[src][hour_bucket].add(dst)
        per_device_hourly_flow_count[src][hour_bucket] += 1

        if row["ssh_banner"]:
            per_device_banners[src].add(row["ssh_banner"])

    baseline = {}
    for device in per_device_peers:
        byte_values = per_device_bytes[device]
        fanout_values = [len(peers) for peers in per_device_hourly_peers[device].values()]
        flow_count_values = list(per_device_hourly_flow_count[device].values())

        avg_bytes = statistics.mean(byte_values)
        std_bytes = statistics.stdev(byte_values) if len(byte_values) > 1 else avg_bytes * 0.3

        log_byte_values = [math.log(b + 1) for b in byte_values]
        avg_log_bytes = statistics.mean(log_byte_values)
        std_log_bytes = statistics.stdev(log_byte_values) if len(log_byte_values) > 1 else avg_log_bytes * 0.3

        sorted_bytes = sorted(byte_values)
        p999_idx = min(int(len(sorted_bytes) * 0.999), len(sorted_bytes) - 1)
        p999_bytes = sorted_bytes[p999_idx]

        byte_mixture_model = fit_byte_mixture_model(byte_values)

        avg_fanout = statistics.mean(fanout_values)
        raw_std_fanout = statistics.stdev(fanout_values) if len(fanout_values) > 1 else avg_fanout * 0.5
        std_fanout = max(raw_std_fanout, 1.0)

        avg_flows_per_hour = statistics.mean(flow_count_values)

        baseline[device] = {
            "known_peers": sorted(per_device_peers[device]),
            "active_hours": sorted(per_device_hours[device]),
            "avg_bytes": round(avg_bytes, 1),
            "std_bytes": round(std_bytes, 1),
            "avg_log_bytes": round(avg_log_bytes, 4),
            "std_log_bytes": round(std_log_bytes, 4),
            "p999_bytes": p999_bytes,
            "byte_mixture_model": byte_mixture_model,
            "avg_fanout_per_hour": round(avg_fanout, 2),
            "std_fanout_per_hour": round(std_fanout, 2),
            "avg_flows_per_hour": round(avg_flows_per_hour, 2),
            "known_ssh_banners": sorted(per_device_banners[device]),
        }

    return baseline


def save_baseline(baseline, path=BASELINE_PATH):
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)


if __name__ == "__main__":
    traffic_path = sys.argv[1] if len(sys.argv) > 1 else "traffic.csv"

    rows = load_traffic(traffic_path)
    print(f"Loaded {len(rows)} traffic rows from {traffic_path}")

    baseline = build_baseline(rows)
    print(f"Learned baseline for {len(baseline)} devices:\n")
    for device, profile in baseline.items():
        print(f"  {device}:")
        print(f"    known peers: {profile['known_peers']}")
        print(f"    active hours: {profile['active_hours']}")
        print(f"    avg bytes/flow: {profile['avg_bytes']} (std {profile['std_bytes']})")
        print(f"    avg fan-out/hour: {profile['avg_fanout_per_hour']} (std {profile['std_fanout_per_hour']})")
        print(f"    avg flows/hour: {profile['avg_flows_per_hour']}")
        print(f"    known SSH banners: {profile['known_ssh_banners']}")
        print()

    save_baseline(baseline)
    print(f"Saved baseline to {BASELINE_PATH}")
