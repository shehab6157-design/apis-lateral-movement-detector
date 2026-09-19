"""
streaming_detector.py — a genuinely incremental version of detect(),
built for live traffic instead of a completed file.

REAL ARCHITECTURAL ISSUE FOUND while building this: detector.py's
batch detect() precomputes hourly_peers by scanning ALL rows before
its main loop runs. That means FANOUT_SPIKE's fan-out count for a
given hour is already the COMPLETE, FINAL count for that hour, even
when checking the very FIRST packet in it - the batch version secretly
knows about packets that haven't "happened" yet relative to that row.
A live system genuinely cannot know the future. StreamingDetector
builds hourly_peers INCREMENTALLY instead - a peer only counts toward
that hour's fan-out once it has actually been observed so far.

Every other signal (NEW_PEER, OFF_HOURS, VOLUME_OUTLIER, SLOW_FANOUT,
UNKNOWN_SSH_CLIENT) does NOT depend on look-ahead and is reproduced
here with IDENTICAL logic - verified by a direct equivalence test
against detect() using the same data, row by row.
"""

from collections import defaultdict
from datetime import timedelta

from config import CONFIG

VOLUME_ZSCORE_THRESHOLD = CONFIG["detection"]["volume_zscore_threshold"]
FANOUT_ZSCORE_THRESHOLD = CONFIG["detection"]["fanout_zscore_threshold"]
SLOW_FANOUT_WINDOW_HOURS = CONFIG["detection"]["slow_fanout_window_hours"]
SLOW_FANOUT_BASE_THRESHOLD = CONFIG["detection"]["slow_fanout_base_threshold"]
SLOW_FANOUT_MULTIPLIER = CONFIG["detection"]["slow_fanout_multiplier"]


def zscore(value, mean, std):
    if std == 0:
        return 0.0
    return (value - mean) / std


class StreamingDetector:
    def __init__(self):
        self.hourly_peers = defaultdict(lambda: defaultdict(set))
        self.fanout_alerted = set()
        self.slow_fanout_alerted = set()
        self.device_new_peer_events = defaultdict(list)

    def process_row(self, row, baseline):
        device = row["src_ip"]
        dst = row["dst_ip"]
        hour = row["timestamp"].hour
        bucket = (row["timestamp"].date().isoformat(), hour)

        profile = baseline.get(device)
        if profile is None:
            return None

        self.hourly_peers[device][bucket].add(dst)

        signals = []

        is_new_peer = dst not in profile["known_peers"]
        if is_new_peer:
            signals.append("NEW_PEER")

        if hour not in profile["active_hours"]:
            signals.append("OFF_HOURS")

        z = zscore(row["bytes"], profile["avg_bytes"], profile["std_bytes"])
        if z >= VOLUME_ZSCORE_THRESHOLD:
            signals.append("VOLUME_OUTLIER")

        fanout_key = (device, bucket)
        if fanout_key not in self.fanout_alerted:
            current_fanout = len(self.hourly_peers[device][bucket])
            fz = zscore(current_fanout, profile["avg_fanout_per_hour"], profile["std_fanout_per_hour"])
            if fz >= FANOUT_ZSCORE_THRESHOLD:
                signals.append("FANOUT_SPIKE")
                self.fanout_alerted.add(fanout_key)

        if is_new_peer:
            events = self.device_new_peer_events[device]
            events.append((row["timestamp"], dst))
            cutoff = row["timestamp"] - timedelta(hours=SLOW_FANOUT_WINDOW_HOURS)
            recent_new_peers = {p for (t, p) in events if t >= cutoff}

            device_threshold = max(
                SLOW_FANOUT_BASE_THRESHOLD,
                round(profile.get("avg_fanout_per_hour", 1.0) * SLOW_FANOUT_MULTIPLIER),
            )

            if len(recent_new_peers) >= device_threshold:
                if device not in self.slow_fanout_alerted:
                    signals.append("SLOW_FANOUT")
                    self.slow_fanout_alerted.add(device)
            else:
                self.slow_fanout_alerted.discard(device)

        banner = row.get("ssh_banner", "")
        known_banners = profile.get("known_ssh_banners", [])
        if banner and known_banners and banner not in known_banners:
            signals.append("UNKNOWN_SSH_CLIENT")

        return signals
