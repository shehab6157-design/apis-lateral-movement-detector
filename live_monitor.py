"""
live_monitor.py — real live traffic monitoring, not batch replay.

Every prior test in this project worked the same way: capture traffic,
convert to CSV, run the script, read the output afterward. This is the
one piece that actually watches traffic AS IT HAPPENS, using scapy's
live sniff() instead of a completed .pcap/.csv file, feeding each
packet into StreamingDetector (see its module docstring for the real
look-ahead issue found and fixed while building this) and the same
QuorumCoordinator used everywhere else in this project - so a live
detection goes through the exact same guard/quorum/refine_actions/
containment pipeline already proven throughout this project, just
fed continuously instead of from a file.

State persistence (quorum.py's save_state/load_state) is used so a
restart doesn't silently lose partially-accumulated evidence.

Usage:
    python3 live_monitor.py                       # sniff on default interface
    python3 live_monitor.py --interface eth0       # sniff on a specific interface
    python3 live_monitor.py --enforce              # actually isolate confirmed threats
"""

import argparse
import sys
from datetime import datetime, timezone

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

from streaming_detector import StreamingDetector
from quorum import QuorumCoordinator
from guard import guard_check
from overwhelm import OverwhelmMonitor
from feedback import is_suppressed
from config import CONFIG
from rolling_baseline import RollingBaseline
import detector as detector_module  # for refine_actions, ACTIVE_DETECTOR_TYPES

STATE_FILE = "quorum_state.json"
ROLLING_BASELINE_FILE = "rolling_baseline_state.json"


def protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return str(packet[IP].proto) if packet.haslayer(IP) else "UNKNOWN"


def dest_port(packet):
    if packet.haslayer(TCP):
        return packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].dport
    return 0


def ssh_banner(packet):
    if not packet.haslayer("Raw"):
        return None
    payload = bytes(packet["Raw"].load)
    if payload.startswith(b"SSH-"):
        try:
            return payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


def packet_to_row(packet):
    """Mirrors capture.py's pcap_to_rows() conversion exactly, but for
    one live packet instead of one line of a completed file."""
    if not packet.haslayer(IP):
        return None
    ts = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).replace(tzinfo=None)
    return {
        "timestamp": ts,
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "dst_port": dest_port(packet),
        "bytes": len(packet),
        "ssh_banner": ssh_banner(packet) or "",
    }


class LiveMonitor:
    def __init__(self, baseline, enforce=False, state_file=STATE_FILE,
                 adapt=True, rolling_baseline_file=ROLLING_BASELINE_FILE):
        # Adaptive baseline, wired in to close the last gap listed in this
        # project's own limitations: rolling_baseline was live in the batch
        # CLI and the API, but live_monitor.py still ran on a frozen
        # snapshot - so the one component that watches real traffic as it
        # happens was the one component that never learned from it.
        #
        # The poisoning-safety guarantee is unchanged and is the reason
        # observe_safe() is the ONLY learning entry point: a row is learned
        # from strictly when it produced zero signals, or when a human
        # explicitly suppressed a confirmation involving it. A confirmed,
        # unsuppressed detection is never fed back.
        self.adapt = adapt
        self.rolling_baseline_file = rolling_baseline_file
        self.rolling = RollingBaseline(initial_baseline=baseline) if adapt else None
        self.baseline = self.rolling.export() if adapt else baseline
        self.rows_learned = 0
        self.enforce = enforce
        self.streaming_detector = StreamingDetector()
        self.coordinator = QuorumCoordinator(
            active_detector_types=detector_module.ACTIVE_DETECTOR_TYPES,
            type_diversity_excluded_types=detector_module.QUORUM_EXCLUDED_SIGNALS,
        )
        loaded = self.coordinator.load_state(state_file)
        if loaded:
            print(f"[STATE] Restored pending evidence from {state_file}")
        self.state_file = state_file

        self.confirmed = {}
        # Rows behind signalling pairs, held so that if a human later
        # suppresses the confirmation, the underlying rows can be learned
        # from. Held, never learned from, until that suppression happens.
        self._pending_rows = {}
        self.overwhelm = OverwhelmMonitor(
            on_collective_threat=lambda events: self._on_collective_threat(events)
        )
        self.coordinator.on_quorum_reached = self._on_quorum

    def _on_quorum(self, src, dst, summary, path):
        if (src, dst) in self.confirmed:
            return
        self.confirmed[(src, dst)] = (summary, path)
        if is_suppressed(src, dst, summary, path):
            print(f"[SUPPRESSED] {src} -> {dst} | {summary} | previously reviewed by a human")
            # A human has reviewed this exact pattern and called it safe, so
            # the rows behind it are legitimate training data - the same
            # rule the batch pipeline applies.
            self._learn_from_suppressed(src, dst)
            return
        if path == "repetition_burst":
            self.overwhelm.notify_repetition_burst(src, dst, summary, timestamp=datetime.now())

        refined = detector_module.refine_actions({(src, dst): (summary, path)})
        _, _, action = refined[(src, dst)]
        action_label = "AUTONOMOUS ACTION OK" if action == "AUTONOMOUS_ACTION_OK" else "ESCALATE FOR REVIEW"
        print(f"[QUORUM] {src} -> {dst} | {summary} | path: {path} | {action_label}")

        from contain import report_confirmed_pair
        report_confirmed_pair(src, dst, summary, path, action)

        if self.enforce:
            from contain import handle_confirmed_pair
            handle_confirmed_pair(src, dst, summary, action)

    def _on_collective_threat(self, events):
        pairs = sorted({(e["src"], e["dst"]) for e in events})
        print(f"[COLLECTIVE THREAT] {len(pairs)} unrelated conversations simultaneously ambiguous -> {pairs}")

    def handle_packet(self, packet):
        row = packet_to_row(packet)
        if row is None:
            return

        guard_flags = guard_check(row)
        if guard_flags:
            print(f"[GUARD] {row['src_ip']} -> {row['dst_ip']} | {guard_flags}")
            if self.enforce:
                from contain import isolate_container
                isolate_container(row["src_ip"], reason=f"guard checkpoint violation: {guard_flags}")

        signals = self.streaming_detector.process_row(row, self.baseline)
        if signals:
            print(f"[ALERT] {row['timestamp']} {row['src_ip']} -> {row['dst_ip']} | {signals}")
            self.coordinator.record_batch(signals, row["src_ip"], row["dst_ip"], timestamp=row["timestamp"])
            self.coordinator.save_state(self.state_file)
            if self.adapt:
                self._pending_rows.setdefault((row["src_ip"], row["dst_ip"]), []).append(row)
        elif self.adapt:
            # Zero signals: safe by the same definition the batch pipeline
            # uses, so it can be learned from immediately.
            self._observe_safe(row)

    def _observe_safe(self, row):
        drift = self.rolling.observe_safe(row)
        self.rows_learned += 1
        if drift and drift.get("drift_alert"):
            print(f"[DRIFT] {row['src_ip']}: {drift['reason']}")
        # Refresh the snapshot the detector reads, so learning actually
        # takes effect on subsequent packets rather than only on restart.
        self.baseline = self.rolling.export()
        if self.rows_learned % 100 == 0:
            self._persist_baseline()

    def _learn_from_suppressed(self, src, dst):
        rows = self._pending_rows.pop((src, dst), [])
        for row in rows:
            self._observe_safe(row)
        if rows:
            print(f"[ADAPT] Learned from {len(rows)} human-suppressed row(s) for {src} -> {dst}")
        self._persist_baseline()

    def _persist_baseline(self):
        if not self.adapt:
            return
        import json
        with open(self.rolling_baseline_file, "w") as f:
            json.dump(self.rolling.export(), f, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live traffic monitoring for lateral movement detection.")
    parser.add_argument("--interface", default=None, help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("--enforce", action="store_true", help="Actually isolate confirmed threats via Docker")
    parser.add_argument("--baseline", default="baseline.json", help="Path to baseline.json")
    parser.add_argument("--no-adapt", action="store_true",
                        help="Disable adaptive baseline learning (run on a frozen snapshot)")
    args = parser.parse_args()

    import os
    import json

    if not args.no_adapt and os.path.exists(ROLLING_BASELINE_FILE):
        with open(ROLLING_BASELINE_FILE, encoding="utf-8-sig") as f:
            baseline = json.load(f)
        print(f"[ADAPTIVE BASELINE] Resumed from {ROLLING_BASELINE_FILE} "
              f"({len(baseline)} devices with prior adaptation)")
    else:
        baseline = detector_module.load_baseline(args.baseline)
        if not args.no_adapt:
            print("[ADAPTIVE BASELINE] No prior state - starting from the static baseline")

    monitor = LiveMonitor(baseline, enforce=args.enforce, adapt=not args.no_adapt)

    print(f"Live monitoring started{' on ' + args.interface if args.interface else ''}. "
          f"Enforce: {args.enforce}. Adapt: {not args.no_adapt}. Press Ctrl+C to stop.\n")

    try:
        sniff(iface=args.interface, prn=monitor.handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopped.")
        if not args.no_adapt:
            monitor._persist_baseline()
            print(f"Learned from {monitor.rows_learned} safe row(s); "
                  f"baseline saved to {ROLLING_BASELINE_FILE}")
        sys.exit(0)
