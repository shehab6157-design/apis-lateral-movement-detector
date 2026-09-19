"""
feedback.py — human-feedback suppression, closing the loop on the one
genuinely unresolved case in this project: fast, legitimate bursts that
are statistically indistinguishable from an attack using the features
available.

Safety rules, deliberately conservative:
  - Only applies to repetition_burst (ESCALATE FOR REVIEW) confirmations.
    type_diversity confirmations can NEVER be suppressed.
  - Scoped to the EXACT signal-type combination reviewed, not the whole pair.
  - Entries expire (default from config.py, 90 days) - re-validated
    periodically, not trusted forever.
  - Every suppression is logged and still shows up in output, never
    silently disappears.
"""

import json
from datetime import datetime, timedelta

from config import CONFIG

SUPPRESSIONS_PATH = "suppressions.json"
DEFAULT_EXPIRES_DAYS = CONFIG["feedback"]["default_expires_days"]


def load_suppressions(path=SUPPRESSIONS_PATH):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def save_suppressions(suppressions, path=SUPPRESSIONS_PATH):
    with open(path, "w") as f:
        json.dump(suppressions, f, indent=2)


def _signature(src, dst, summary):
    return f"{src}->{dst}|{','.join(sorted(summary.keys()))}"


def suppress(src, dst, summary, reviewer, reason, expires_days=DEFAULT_EXPIRES_DAYS, path=SUPPRESSIONS_PATH):
    suppressions = load_suppressions(path)
    entry = {
        "signature": _signature(src, dst, summary),
        "src": src,
        "dst": dst,
        "signal_types": sorted(summary.keys()),
        "reviewer": reviewer,
        "reason": reason,
        "reviewed_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=expires_days)).isoformat(),
    }
    suppressions.append(entry)
    save_suppressions(suppressions, path)
    return entry


def is_suppressed(src, dst, summary, path_type, now=None, suppressions_path=SUPPRESSIONS_PATH):
    if path_type != "repetition_burst":
        return False

    now = now or datetime.now()
    sig = _signature(src, dst, summary)
    suppressions = load_suppressions(suppressions_path)

    for entry in suppressions:
        if entry["signature"] != sig:
            continue
        expires_at = datetime.fromisoformat(entry["expires_at"])
        if now <= expires_at:
            return True
    return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 6 or sys.argv[1] != "suppress":
        print("Usage: python3 feedback.py suppress <src> <dst> <signal_types_comma_separated> <reviewer> <reason>")
        sys.exit(1)

    _, _, src, dst, types_csv, reviewer, *reason_parts = sys.argv
    reason = " ".join(reason_parts) if reason_parts else "(no reason given)"
    summary = {t: 1 for t in types_csv.split(",")}

    entry = suppress(src, dst, summary, reviewer, reason)
    print(f"Suppressed: {entry['signature']}")
    print(f"  Reviewed by: {entry['reviewer']}")
    print(f"  Reason: {entry['reason']}")
    print(f"  Expires: {entry['expires_at']}")
