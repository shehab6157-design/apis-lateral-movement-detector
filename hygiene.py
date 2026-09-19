"""
hygiene.py — Layer 5 of the APIS project (Adaptive Protective Immune System)

Proactive, scheduled maintenance - audits baseline.json for stale or
never-observed "known_peers" trust relationships. Deliberately a
RECOMMENDATION layer, not an auto-revoke layer.

staleness_days default now comes from config.py.
"""

from datetime import datetime

from config import CONFIG

DEFAULT_STALENESS_DAYS = CONFIG["hygiene"]["default_staleness_days"]


def last_seen_per_peer(rows):
    last_seen = {}
    for row in rows:
        key = (row["src_ip"], row["dst_ip"])
        ts = row["timestamp"]
        if key not in last_seen or ts > last_seen[key]:
            last_seen[key] = ts
    return last_seen


def audit_baseline(baseline, rows, staleness_days=DEFAULT_STALENESS_DAYS, now=None):
    now = now or datetime.now()
    last_seen = last_seen_per_peer(rows)
    findings = []

    for device, profile in baseline.items():
        for peer in profile.get("known_peers", []):
            key = (device, peer)
            seen_at = last_seen.get(key)

            if seen_at is None:
                findings.append({
                    "device": device,
                    "peer": peer,
                    "issue": "NEVER_OBSERVED_IN_PROVIDED_TRAFFIC",
                    "recommendation": ("This peer relationship exists in the baseline but was never "
                                       "seen in the traffic used for this audit - verify it's still legitimate."),
                })
                continue

            age_days = (now - seen_at).total_seconds() / 86400
            if age_days > staleness_days:
                findings.append({
                    "device": device,
                    "peer": peer,
                    "issue": "STALE_TRUST",
                    "last_seen": seen_at.isoformat(),
                    "age_days": round(age_days, 1),
                    "recommendation": (f"Not observed in {round(age_days)} days "
                                       f"(threshold: {staleness_days}) - review before continuing "
                                       f"to trust automatically."),
                })

    return findings


def explain_finding(f):
    if f["issue"] == "STALE_TRUST":
        return f"  [{f['issue']}] {f['device']} -> {f['peer']}  |  last seen {f['age_days']} days ago  |  {f['recommendation']}"
    return f"  [{f['issue']}] {f['device']} -> {f['peer']}  |  {f['recommendation']}"


if __name__ == "__main__":
    import sys
    import json
    import csv

    baseline_path = sys.argv[1] if len(sys.argv) > 1 else "baseline.json"
    traffic_path = sys.argv[2] if len(sys.argv) > 2 else "traffic.csv"
    staleness_days = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_STALENESS_DAYS

    with open(baseline_path) as f:
        baseline = json.load(f)

    rows = []
    with open(traffic_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            rows.append(row)

    findings = audit_baseline(baseline, rows, staleness_days=staleness_days)

    print(f"=== Hygiene audit: {len(findings)} finding(s) (staleness threshold: {staleness_days} days) ===\n")
    if not findings:
        print("  (none - all known_peers relationships are actively corroborated)")
    for f_ in findings:
        print(explain_finding(f_))
