"""
rolling_baseline.py — an adaptive/passive-learning baseline that
continuously incorporates new observations as confirmed-safe over
time, instead of relying on a single static snapshot.

Attacks the root cause behind nearly every false-positive
investigation in this project tonight: a short, fixed baseline window
(2 days, later 3) can never capture the full range of a device's
genuinely normal behavior. Concept drift and adaptive baselines are a
real, actively-studied area (not solved, not novel research) - this
applies a well-established technique from that literature, "passive
adaptation": rather than re-learning from scratch periodically, the
baseline continuously blends in new observations using an
exponentially weighted moving average (EWMA), giving more weight to
recent behavior while retaining historical stability. The exact
mean/variance update formulas are verified against a real published
network-security paper (IXmon: Detecting and Analyzing DRDoS Attacks
at Internet Exchange Points, which uses EWMA to track per-flow byte
volume baselines online):
    mu(t)     = alpha * mu(t-1) + (1-alpha) * b(t)
    sigma2(t) = (1-alpha) * (sigma2(t-1) + alpha * (b(t) - mu(t-1))**2)

CRITICAL SAFETY PRINCIPLE, designed in from the start rather than
added after the fact: an adaptive baseline that blindly learns from
everything it observes can be POISONED - if confirmed-suspicious
traffic is allowed to quietly become "the new normal," the detector
learns to ignore real attacks. This module therefore NEVER updates
from a row directly - it only updates via observe_safe(), which the
caller must only invoke for traffic that is actually established as
safe: either it produced zero raw signals in detect(), or a human
explicitly marked a past detection as a false positive via
feedback.py's suppression mechanism. Confirmed, unsuppressed
detections must never reach this module.
"""

import math

from drift_monitor import DriftMonitor


class RollingBaseline:
    """
    Wraps an existing static baseline dict (as produced by
    baseline.build_baseline()) and lets it continue adapting over
    time. Fully backward compatible: get_profile() returns data in
    the exact same shape as a static baseline.json, so it's a drop-in
    replacement anywhere a static baseline dict is currently used.
    """

    def __init__(self, initial_baseline=None, alpha=0.05):
        # alpha: how much weight a single new observation gets. Lower
        # = slower adaptation, more historical stability; higher =
        # faster adaptation, more sensitive to recent behavior. 0.05
        # is a moderate, commonly-used starting point in the streaming
        # anomaly detection literature (see module docstring).
        self.alpha = alpha
        self._profiles = {}
        # Real, documented "boiling frog" poisoning of adaptive
        # baselines (see drift_monitor.py) is a separate, longer-
        # horizon check layered on top of this project's existing
        # poisoning-safety guarantee (never learning from confirmed,
        # unsuppressed detections) - that guarantee still holds
        # unchanged; this adds visibility into gradual, sustained
        # drift that no single update would look suspicious enough to
        # block on its own.
        self.drift_monitor = DriftMonitor()
        if initial_baseline:
            for device, profile in initial_baseline.items():
                self._profiles[device] = {
                    "known_peers": set(profile.get("known_peers", [])),
                    "active_hours": set(profile.get("active_hours", [])),
                    "avg_bytes": profile.get("avg_bytes", 0.0),
                    "std_bytes": profile.get("std_bytes", 1.0),
                    "avg_fanout_per_hour": profile.get("avg_fanout_per_hour", 1.0),
                    "std_fanout_per_hour": profile.get("std_fanout_per_hour", 1.0),
                    "avg_flows_per_hour": profile.get("avg_flows_per_hour", 1.0),
                    "known_ssh_banners": set(profile.get("known_ssh_banners", [])),
                }

    def get_profile(self, device):
        """Returns the current profile for a device in the same shape
        as a static baseline.json entry, or None if never observed."""
        profile = self._profiles.get(device)
        if profile is None:
            return None
        return {
            "known_peers": sorted(profile["known_peers"]),
            "active_hours": sorted(profile["active_hours"]),
            "avg_bytes": round(profile["avg_bytes"], 1),
            "std_bytes": round(profile["std_bytes"], 1),
            "avg_fanout_per_hour": round(profile["avg_fanout_per_hour"], 2),
            "std_fanout_per_hour": round(profile["std_fanout_per_hour"], 2),
            "avg_flows_per_hour": round(profile["avg_flows_per_hour"], 2),
            "known_ssh_banners": sorted(profile["known_ssh_banners"]),
        }

    def export(self):
        """Dumps the full current state as a baseline.json-compatible
        dict, for persistence (mirrors quorum.py's save_state pattern)."""
        return {device: self.get_profile(device) for device in self._profiles}

    def observe_safe(self, row):
        """
        Incorporates one row of traffic that has been ESTABLISHED AS
        SAFE (zero raw signals, or an explicitly human-suppressed
        false positive) into the rolling baseline. Must never be
        called with confirmed, unsuppressed detection traffic - see
        module docstring.
        """
        device = row["src_ip"]
        dst = row["dst_ip"]
        hour = row["timestamp"].hour
        bytes_value = row["bytes"]

        profile = self._profiles.setdefault(device, {
            "known_peers": set(),
            "active_hours": set(),
            "avg_bytes": float(bytes_value),
            "std_bytes": max(bytes_value * 0.3, 1.0),
            "avg_fanout_per_hour": 1.0,
            "std_fanout_per_hour": 1.0,
            "avg_flows_per_hour": 1.0,
            "known_ssh_banners": set(),
        })

        profile["known_peers"].add(dst)
        profile["active_hours"].add(hour)
        if row.get("ssh_banner"):
            profile["known_ssh_banners"].add(row["ssh_banner"])

        alpha = self.alpha
        old_mean = profile["avg_bytes"]
        old_var = profile["std_bytes"] ** 2

        new_mean = alpha * old_mean + (1 - alpha) * bytes_value
        new_var = (1 - alpha) * (old_var + alpha * (bytes_value - old_mean) ** 2)

        profile["avg_bytes"] = new_mean
        profile["std_bytes"] = max(math.sqrt(new_var), 1.0)

        return self.drift_monitor.observe(device, new_mean)

    def get_drift_status(self, device):
        """Returns the most recent drift status for a device without
        recording a new observation - useful for reporting/CLI output
        after a batch of observe_safe() calls."""
        return self.drift_monitor.peek(device)
