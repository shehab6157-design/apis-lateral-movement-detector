"""
auth_detector.py — Layer 7 of the APIS project (Adaptive Protective
Immune System): Chemical-Mimicry Detection.

Biological basis, verified against real published research: Varroa
mites achieve "an almost perfect colony specific mimicry" of the
cuticular hydrocarbons honeybee guards use to verify identity - a
strategy described as "widespread in social insect parasites mimicking
the host chemical profile." Parallels Pass-the-Hash (T1550.002) and
Pass-the-Ticket (T1550.003): the attacker presents a stolen-but-valid
credential and is admitted like a legitimate identity.

HONEST SCOPE: built against the real, public LANL auth.txt format.
This dataset's fields do NOT map one-to-one onto real Windows Event
IDs - the official MITRE-documented detection logic is ADAPTED here.
"""

from collections import defaultdict
from datetime import timedelta

NTLM_AUTH_TYPES = {"NTLM"}
NETWORK_LOGON_TYPES = {"Network"}

KERBEROS_AUTH_TYPES = {"Kerberos"}
PTT_LOOKBACK_HOURS = 1

EXCLUDED_ACCOUNT_SUFFIX = "$"
EXCLUDED_ACCOUNT_NAMES = {"ANONYMOUS LOGON"}


def _is_excluded_account(user_field):
    if user_field in ("?", ""):
        return True
    account_name = user_field.split("@")[0]
    if account_name in EXCLUDED_ACCOUNT_NAMES:
        return True
    if account_name.endswith(EXCLUDED_ACCOUNT_SUFFIX):
        return True
    return False


def parse_auth_row(line):
    parts = line.strip().split(",")
    if len(parts) != 9:
        return None
    (time_s, src_user, dst_user, src_computer, dst_computer,
     auth_type, logon_type, orientation, success) = parts
    try:
        time_s = int(time_s)
    except ValueError:
        return None
    return {
        "time": time_s,
        "src_user": src_user,
        "dst_user": dst_user,
        "src_computer": src_computer,
        "dst_computer": dst_computer,
        "auth_type": auth_type,
        "logon_type": logon_type,
        "orientation": orientation,
        "success": success,
    }


class ChemicalMimicryDetector:
    """
    Processes authentication events in chronological order and flags
    PTH_SUSPECTED and PTT_SUSPECTED - stateful, so it can run
    incrementally over a stream.
    """

    def __init__(self, baseline=None, high_privilege_threshold=13):
        self._user_auth_history = defaultdict(list)
        # Optional per-user baseline (see auth_baseline.py) - when
        # provided, a destination the user has legitimately
        # authenticated to before during a clean baseline period is
        # NOT flagged, mirroring NEW_PEER's role on the flow side of
        # this project. None (the default) preserves the exact
        # original unconditional behavior for full backward
        # compatibility.
        self.baseline = baseline
        self.high_privilege_threshold = high_privilege_threshold

    def _is_novel_destination(self, user, dst_computer):
        """Returns True if this destination should be treated as NOT
        established/routine for this user. With no baseline at all,
        every destination is novel (original behavior preserved). With
        a baseline, an unknown user is treated conservatively
        (everything still novel); a known user's previously-seen
        destination is NOT novel."""
        if self.baseline is None:
            return True
        user_profile = self.baseline.get(user)
        if user_profile is None:
            return True
        known_destinations = user_profile.get("known_destinations", [])
        if len(known_destinations) > self.high_privilege_threshold:
            return True
        return dst_computer not in known_destinations

    def process_event(self, event):
        if event["orientation"] != "LogOn" or event["success"] != "Success":
            return []

        if _is_excluded_account(event["src_user"]):
            return []

        signals = []

        if (event["auth_type"] in NTLM_AUTH_TYPES
                and event["logon_type"] in NETWORK_LOGON_TYPES
                and event["src_computer"] != "?"
                and event["dst_computer"] != "?"
                and event["src_computer"] != event["dst_computer"]
                and self._is_novel_destination(event["src_user"], event["dst_computer"])):
            signals.append("PTH_SUSPECTED")

        if event["auth_type"] in KERBEROS_AUTH_TYPES and event["src_user"] != "?":
            history = self._user_auth_history[event["src_user"]]
            cutoff = event["time"] - int(timedelta(hours=PTT_LOOKBACK_HOURS).total_seconds())
            recent = [h for h in history if h[0] >= cutoff]
            if not recent and self._is_novel_destination(event["src_user"], event["dst_computer"]):
                signals.append("PTT_SUSPECTED")

        if event["src_user"] != "?":
            self._user_auth_history[event["src_user"]].append((event["time"], event["src_computer"]))

        return signals
