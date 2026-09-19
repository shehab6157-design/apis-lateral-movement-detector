"""
adaptive_auth_baseline.py — the auth-side counterpart to
rolling_baseline.py, extending the same adaptive-learning and
poisoning-safety principle to Layer 7 (Windows credential-theft
detection).

Same critical safety principle as rolling_baseline.py: never updates
from a raw event directly - only via observe_safe(), which the caller
must only invoke for events established as safe (zero raw signals, or
a human-confirmed suppression).
"""


class AdaptiveAuthBaseline:
    def __init__(self, initial_baseline=None):
        self._profiles = {}
        if initial_baseline:
            for user, profile in initial_baseline.items():
                self._profiles[user] = {
                    "known_destinations": set(profile.get("known_destinations", [])),
                }

    def get_profile(self, user):
        profile = self._profiles.get(user)
        if profile is None:
            return None
        return {"known_destinations": sorted(profile["known_destinations"])}

    def export(self):
        return {user: self.get_profile(user) for user in self._profiles}

    def observe_safe(self, event):
        user = event["src_user"]
        dst = event["dst_computer"]
        profile = self._profiles.setdefault(user, {"known_destinations": set()})
        profile["known_destinations"].add(dst)
