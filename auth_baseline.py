"""
auth_baseline.py — learns a per-user authentication baseline from real
LANL auth.txt data, mirroring baseline.py's per-device approach for the
network-flow side of this project.

Built after real evaluation found the exact same "chatty entity"
problem already solved once tonight on the flow side (a device like
C10 whose entire job is touching many machines, wrongly flagged for
doing its normal job) - here it's users, not devices: a real admin,
helpdesk, or service account (e.g. U5481@DOM1 touching six different
destination computers within ~10 hours) whose job routinely involves
authenticating to many different machines. The fix follows the same
principle already proven on the flow side: personalize against each
entity's own established norm rather than applying one flat rule to
everyone - specifically, learn which destination computers a user has
legitimately authenticated to before, so only a genuinely NEW
destination gets flagged (the same role NEW_PEER already plays for
devices in baseline.py).
"""

import json
from collections import defaultdict

from auth_detector import parse_auth_row, _is_excluded_account

AUTH_BASELINE_PATH = "auth_baseline.json"


def load_auth_events(path):
    """Loads a file of raw LANL auth.txt lines into parsed event dicts,
    skipping malformed lines and excluded accounts (machine accounts,
    ANONYMOUS LOGON) - the baseline should reflect real human/service
    user behavior, not routine machine-to-machine noise."""
    events = []
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            event = parse_auth_row(line)
            if event is None:
                continue
            if _is_excluded_account(event["src_user"]):
                continue
            if event["orientation"] != "LogOn" or event["success"] != "Success":
                continue
            events.append(event)
    return events


def build_auth_baseline(events):
    """
    Learns, per user, the set of destination computers they have
    legitimately authenticated to during the (clean) baseline period -
    directly mirroring known_peers in baseline.py. A destination NOT
    in this set for a given user is what makes a future PTH/PTT signal
    meaningful, rather than routine, expected behavior for that user.
    """
    known_destinations = defaultdict(set)

    for event in events:
        known_destinations[event["src_user"]].add(event["dst_computer"])

    baseline = {
        user: {"known_destinations": sorted(destinations)}
        for user, destinations in known_destinations.items()
    }
    return baseline


def save_auth_baseline(baseline, path=AUTH_BASELINE_PATH):
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)


def load_auth_baseline(path=AUTH_BASELINE_PATH):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)
