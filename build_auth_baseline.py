"""
build_auth_baseline.py — command-line entry point for building the
identity-side baseline from a window of known-clean authentication events.

auth_baseline.py holds the logic but is a module with no __main__ block,
so there was no way to build auth_baseline.json from the command line.
This adds that entry point without changing the existing module.

Usage:
    python build_auth_baseline.py samples/sample_auth_clean.txt
"""

import sys

from auth_baseline import (
    load_auth_events,
    build_auth_baseline,
    save_auth_baseline,
    AUTH_BASELINE_PATH,
)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "auth_clean.txt"
    events = load_auth_events(path)
    baseline = build_auth_baseline(events)
    save_auth_baseline(baseline)

    print(f"Read {len(events)} clean authentication events from {path}")
    print(f"Built baseline for {len(baseline)} user(s) -> {AUTH_BASELINE_PATH}\n")
    for user, profile in sorted(baseline.items())[:10]:
        dests = profile["known_destinations"]
        print(f"  {user}: {len(dests)} known destination(s) - {', '.join(dests[:6])}")
