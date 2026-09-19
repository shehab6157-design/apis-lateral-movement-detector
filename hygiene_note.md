# hygiene.py — Purpose

`hygiene.py` is Layer 5 ("hygiene") of the APIS project (Adaptive Protective Immune System), a lateral-movement detector. It performs proactive, scheduled maintenance on the trust baseline rather than real-time detection.

## What it does

- Loads a `baseline.json` file describing each device's `known_peers` (trusted relationships) and a `traffic.csv` log of observed connections (`src_ip`, `dst_ip`, `timestamp`).
- For every `(device, peer)` pair in the baseline, it checks the traffic log to find when that relationship was last actually observed (`last_seen_per_peer`).
- `audit_baseline` flags two kinds of findings:
  - **NEVER_OBSERVED_IN_PROVIDED_TRAFFIC** — a trusted peer relationship in the baseline that never shows up in the traffic sample at all.
  - **STALE_TRUST** — a relationship not seen within a configurable staleness window (`staleness_days`, default from `config.py`).
- Each finding includes a human-readable recommendation to manually review the relationship.
- `explain_finding` formats a finding as a one-line printable string.
- When run as a script, it takes `baseline.json`, `traffic.csv`, and an optional staleness threshold as CLI args, runs the audit, and prints all findings.

## Key design note

It is explicitly a **recommendation layer, not an auto-revoke layer** — it surfaces stale or unverified trust relationships for a human to review, but never removes or modifies the baseline itself.
