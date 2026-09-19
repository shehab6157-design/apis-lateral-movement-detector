"""
detector.py
-------------
See quorum.py for the full history of how the quorum logic evolved
through real testing (v1 -> v6). This file wires that logic onto the
existing signal detection, plus:
  - guard.py (layer 1): a fast, baseline-free pre-filter.
  - overwhelm.py (layer 8): cross-conversation correlation of ambiguous bursts.
  - contain.py (layer 6): real containment action + webhook alerts via --enforce.
  - config.py: every tunable threshold below now comes from config.json
    (falling back to the same defaults already verified throughout this
    project), instead of being hardcoded here.
  - Optional --state-file: persists the quorum coordinator's pending
    evidence across runs/restarts, so partial progress isn't silently
    lost.
"""

import csv
import json
import math
import sys
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

from quorum import QuorumCoordinator
from guard import guard_check
from overwhelm import OverwhelmMonitor
from feedback import is_suppressed
from config import CONFIG

BASELINE_PATH = "baseline.json"

VOLUME_ZSCORE_THRESHOLD = CONFIG["detection"]["volume_zscore_threshold"]
FANOUT_ZSCORE_THRESHOLD = CONFIG["detection"]["fanout_zscore_threshold"]
HEAVY_TAIL_CV_THRESHOLD = CONFIG["detection"]["heavy_tail_cv_threshold"]

ACTIVE_DETECTOR_TYPES = set(CONFIG["detection"]["active_signal_types"])
QUORUM_EXCLUDED_SIGNALS = set(CONFIG["quorum"]["excluded_from_confirmation"])


def filter_quorum_signals(signals):
    """
    Kept for reference/testing, but NOT used to filter what gets
    recorded - see the type_diversity_excluded_types wiring below for
    why. Returns signals with QUORUM_EXCLUDED_SIGNALS removed.
    """
    return [s for s in signals if s not in QUORUM_EXCLUDED_SIGNALS]
SLOW_FANOUT_WINDOW_HOURS = CONFIG["detection"]["slow_fanout_window_hours"]
SLOW_FANOUT_BASE_THRESHOLD = CONFIG["detection"]["slow_fanout_base_threshold"]
SLOW_FANOUT_MULTIPLIER = CONFIG["detection"]["slow_fanout_multiplier"]
QUORUM_RATIO = CONFIG["quorum"]["quorum_ratio"]
QUORUM_REPETITION = CONFIG["quorum"]["repetition_threshold"]
QUORUM_BURST_WINDOW_SECONDS = CONFIG["quorum"]["burst_window_seconds"]
QUORUM_WINDOW_SECONDS = CONFIG["quorum"]["window_seconds"]
REPETITION_VOLUME_MULTIPLIER = CONFIG["quorum"]["repetition_volume_multiplier"]


def make_repetition_threshold_fn(baseline, base_threshold):
    """
    Personalizes repetition_burst's threshold per source device, using
    each device's own avg_flows_per_hour (total flow volume, regardless
    of destination) - added after a real evaluation against the public
    LANL dataset found that infrastructure/management hosts making many
    small, automated, repetitive connections (e.g. a domain controller)
    were flagged as bursting attackers, because a single flat threshold
    doesn't distinguish "this device is unusually bursty right now"
    from "this device is always this chatty, this is just its 47th new
    contact of the hour." Uses a SQUARE ROOT relationship (not the
    linear one used for SLOW_FANOUT) specifically to avoid an absurdly
    high threshold for extremely high-volume infrastructure hosts,
    while still meaningfully raising the bar above the base/floor for
    genuinely quiet, low-volume devices. The exact multiplier is a
    reasoned starting point informed by real evidence, not a precisely
    validated constant - the same honest framing as every other tuned
    constant in this project.
    """
    import math

    def fn(device):
        profile = baseline.get(device, {})
        avg_flows = profile.get("avg_flows_per_hour", 0)
        return max(base_threshold, round(math.sqrt(max(avg_flows, 0)) * REPETITION_VOLUME_MULTIPLIER))

    return fn


def load_baseline(path=BASELINE_PATH):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def load_traffic(path):
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["bytes"] = int(row["bytes"])
            row["ssh_banner"] = row.get("ssh_banner", "") or ""
            rows.append(row)
    return rows


def zscore(value, mean, std):
    if std == 0:
        return 0.0
    return (value - mean) / std


def run_guard(rows):
    guard_alerts = []
    for row in rows:
        flags = guard_check(row)
        if flags:
            guard_alerts.append({
                "timestamp": row["timestamp"].isoformat(),
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "bytes": row["bytes"],
                "flags": flags,
            })
    return guard_alerts


def detect(rows, baseline):
    alerts = []

    hourly_peers = defaultdict(lambda: defaultdict(set))
    for row in rows:
        bucket = (row["timestamp"].date().isoformat(), row["timestamp"].hour)
        hourly_peers[row["src_ip"]][bucket].add(row["dst_ip"])

    fanout_alerted = set()
    slow_fanout_alerted = set()
    device_new_peer_events = defaultdict(list)

    for row in sorted(rows, key=lambda r: r["timestamp"]):
        device = row["src_ip"]
        dst = row["dst_ip"]
        hour = row["timestamp"].hour
        bucket = (row["timestamp"].date().isoformat(), hour)

        profile = baseline.get(device)
        if profile is None:
            continue

        signals = []

        is_new_peer = dst not in profile["known_peers"]
        if is_new_peer:
            signals.append("NEW_PEER")

        if hour not in profile["active_hours"]:
            signals.append("OFF_HOURS")

        # VOLUME_OUTLIER: uses a per-device Gaussian Mixture Model when
        # available (byte_mixture_model) - the most sophisticated of
        # four approaches tried against the real LANL dataset. Real
        # device traffic can be genuinely BIMODAL (95% tiny heartbeats
        # plus a separate cluster of legitimate large transfers, almost
        # nothing in between), which breaks any SINGLE mean/std or
        # single-percentile assumption - a mixture model instead learns
        # each device's actual number of distinct normal behaviors (via
        # BIC model selection, so a genuinely unimodal device does not
        # get an unwarranted second cluster) and flags a value only if
        # it doesn't fit near ANY of that device's learned clusters.
        # Falls back to p999_bytes, then the raw z-score, for any
        # baseline that doesn't have a fitted mixture model (e.g. too
        # little data, or an existing hand-built test baseline) - so
        # nothing existing changes behavior unless it explicitly opts in.
        # REVERTED after real testing against the LANL dataset: FOUR
        # approaches were tried and measured (raw z-score, log-space
        # z-score, percentile bound, Gaussian Mixture Model) and NONE
        # beat the plain raw z-score (1337 false positives). The GMM
        # approach specifically made things worse (2628 FPs) due to a
        # real, concrete failure mode: many real devices repeat the
        # EXACT SAME byte value thousands of times, and fitting a
        # 2-component mixture to essentially-1-value data produces
        # numerically unstable, degenerate fits (confirmed via repeated
        # sklearn ConvergenceWarnings during real evaluation) that make
        # detection hypersensitive rather than more accurate. This is a
        # real, honestly-documented open problem, not a quick fix.
        z = zscore(row["bytes"], profile["avg_bytes"], profile["std_bytes"])
        if z >= VOLUME_ZSCORE_THRESHOLD:
            signals.append("VOLUME_OUTLIER")

        fanout_key = (device, bucket)
        if fanout_key not in fanout_alerted:
            current_fanout = len(hourly_peers[device][bucket])
            fz = zscore(current_fanout, profile["avg_fanout_per_hour"], profile["std_fanout_per_hour"])
            if fz >= FANOUT_ZSCORE_THRESHOLD:
                signals.append("FANOUT_SPIKE")
                fanout_alerted.add(fanout_key)

        if is_new_peer:
            events = device_new_peer_events[device]
            events.append((row["timestamp"], dst))
            cutoff = row["timestamp"] - timedelta(hours=SLOW_FANOUT_WINDOW_HOURS)
            recent_new_peers = {p for (t, p) in events if t >= cutoff}

            device_threshold = max(
                SLOW_FANOUT_BASE_THRESHOLD,
                round(profile.get("avg_fanout_per_hour", 1.0) * SLOW_FANOUT_MULTIPLIER),
            )

            if len(recent_new_peers) >= device_threshold:
                if device not in slow_fanout_alerted:
                    signals.append("SLOW_FANOUT")
                    slow_fanout_alerted.add(device)
            else:
                slow_fanout_alerted.discard(device)

        banner = row.get("ssh_banner", "")
        known_banners = profile.get("known_ssh_banners", [])
        if banner and known_banners and banner not in known_banners:
            signals.append("UNKNOWN_SSH_CLIENT")

        if signals:
            alerts.append({
                "timestamp": row["timestamp"].isoformat(),
                "src_ip": device,
                "dst_ip": dst,
                "bytes": row["bytes"],
                "signals": signals,
            })

    return alerts


def apply_quorum(alerts, quorum_ratio=QUORUM_RATIO, repetition_threshold=QUORUM_REPETITION,
                  burst_window_seconds=QUORUM_BURST_WINDOW_SECONDS,
                  window_seconds=QUORUM_WINDOW_SECONDS, state_file=None, baseline=None):
    # baseline is optional and defaults to None, preserving the exact
    # prior flat-threshold behavior for every existing caller. Only
    # callers that explicitly pass a baseline (e.g. the real LANL
    # evaluation) get the personalized-by-device-volume threshold.
    repetition_threshold_fn = (
        make_repetition_threshold_fn(baseline, repetition_threshold) if baseline is not None else None
    )

    coordinator = QuorumCoordinator(
        active_detector_types=ACTIVE_DETECTOR_TYPES,
        quorum_ratio=quorum_ratio,
        repetition_threshold_fn=repetition_threshold_fn,
        repetition_threshold=repetition_threshold,
        burst_window_seconds=burst_window_seconds,
        window_seconds=window_seconds,
        type_diversity_excluded_types=QUORUM_EXCLUDED_SIGNALS,
    )

    if state_file:
        loaded = coordinator.load_state(state_file)
        if loaded:
            print(f"  [STATE] Restored pending evidence from {state_file}")

    confirmed = {}
    collective_threats = []

    overwhelm = OverwhelmMonitor(on_collective_threat=lambda events: collective_threats.append(events))

    current_ts = {"value": None}

    def on_quorum(src, dst, summary, path):
        if (src, dst) in confirmed:
            return
        confirmed[(src, dst)] = (summary, path)
        if path == "repetition_burst":
            overwhelm.notify_repetition_burst(src, dst, summary, timestamp=current_ts["value"])

    coordinator.on_quorum_reached = on_quorum

    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        ts = datetime.fromisoformat(alert["timestamp"])
        current_ts["value"] = ts
        coordinator.record_batch(alert["signals"], alert["src_ip"], alert["dst_ip"], timestamp=ts)

    if state_file:
        coordinator.save_state(state_file)

    return confirmed, collective_threats


CIRCUMSTANTIAL_SIGNALS = {"OFF_HOURS", "UNKNOWN_SSH_CLIENT"}


def refine_actions(confirmed):
    """
    SAFETY CHECK found via a real banner-spoofing test: a type_diversity
    confirmation based ONLY on circumstantial signals is only trusted for
    autonomous action if the REVERSE direction of the same conversation
    was ALSO independently confirmed at type_diversity.
    """
    result = {}
    for (src, dst), (summary, path) in confirmed.items():
        if path != "type_diversity":
            result[(src, dst)] = (summary, path, "ESCALATE_FOR_REVIEW")
            continue

        has_unambiguous_signal = any(t not in CIRCUMSTANTIAL_SIGNALS for t in summary)
        if has_unambiguous_signal:
            result[(src, dst)] = (summary, path, "AUTONOMOUS_ACTION_OK")
            continue

        reverse = confirmed.get((dst, src))
        if reverse is not None and reverse[1] == "type_diversity":
            result[(src, dst)] = (summary, path, "AUTONOMOUS_ACTION_OK")
        else:
            result[(src, dst)] = (summary, path, "ESCALATE_FOR_REVIEW")

    return result


def explain(alert):
    return (f"[{alert['timestamp']}] {alert['src_ip']} -> {alert['dst_ip']} "
            f"({alert['bytes']} bytes) | {', '.join(alert['signals'])}")


def explain_guard(alert):
    return (f"[{alert['timestamp']}] {alert['src_ip']} -> {alert['dst_ip']} "
            f"({alert['bytes']} bytes) | {', '.join(alert['flags'])}")


if __name__ == "__main__":
    import os
    from rolling_baseline import RollingBaseline

    argv = sys.argv[1:]
    enforce = "--enforce" in argv
    if enforce:
        argv.remove("--enforce")

    state_file = None
    if "--state-file" in argv:
        idx = argv.index("--state-file")
        state_file = argv[idx + 1]
        del argv[idx:idx + 2]

    rolling_baseline_file = "rolling_baseline_state.json"
    if "--rolling-baseline-file" in argv:
        idx = argv.index("--rolling-baseline-file")
        rolling_baseline_file = argv[idx + 1]
        del argv[idx:idx + 2]
    no_adapt = "--no-adapt" in argv
    if no_adapt:
        argv.remove("--no-adapt")

    traffic_path = argv[0] if argv else "test_traffic.csv"

    static_baseline = load_baseline()
    rows = load_traffic(traffic_path)
    print(f"Loaded static baseline for {len(static_baseline)} devices, "
          f"{len(rows)} traffic rows from {traffic_path}")

    # Adaptive baseline (Layer 2 extension): if a previously-adapted
    # state exists on disk, resume from it instead of the static
    # snapshot - so genuinely normal behavior learned in past runs
    # (via zero-signal traffic or human-confirmed suppressions) is not
    # lost each time this tool is re-run against new data. --no-adapt
    # disables this entirely, using the static baseline exactly as
    # before (useful for a clean, repeatable comparison run).
    if not no_adapt and os.path.exists(rolling_baseline_file):
        with open(rolling_baseline_file, encoding="utf-8-sig") as f:
            persisted = json.load(f)
        rolling = RollingBaseline(initial_baseline=persisted)
        print(f"[ADAPTIVE BASELINE] Resumed from {rolling_baseline_file} "
              f"({len(persisted)} devices with prior adaptation)")
    else:
        rolling = RollingBaseline(initial_baseline=static_baseline)
        if not no_adapt:
            print(f"[ADAPTIVE BASELINE] No prior state found - starting fresh from the static baseline")

    baseline = rolling.export() if not no_adapt else static_baseline
    print()

    guard_alerts = run_guard(rows)
    guard_sources = set()
    print(f"=== {len(guard_alerts)} guard alert(s) (layer 1 - fast path, bypasses quorum) ===\n")
    if not guard_alerts:
        print("  (none)")
    for ga in guard_alerts:
        print("  " + explain_guard(ga))
        guard_sources.add(ga["src_ip"])

    alerts = detect(rows, baseline)

    print(f"\n=== {len(alerts)} raw alert(s) (layer 2 - Queen, baseline-based) ===\n")
    for alert in alerts:
        print(explain(alert))

    confirmed, collective_threats = apply_quorum(alerts, state_file=state_file, baseline=baseline)

    active_confirmed = {}
    suppressed_confirmed = {}
    for (src, dst), (summary, path) in confirmed.items():
        if is_suppressed(src, dst, summary, path):
            suppressed_confirmed[(src, dst)] = (summary, path)
        else:
            active_confirmed[(src, dst)] = (summary, path)

    refined = refine_actions(active_confirmed)

    print(f"\n=== {len(refined)} pair(s) reached QUORUM (layer 4) ===\n")
    if not refined:
        print("  (none)")
    for (src, dst), (summary, path, action) in refined.items():
        action_label = "AUTONOMOUS ACTION OK" if action == "AUTONOMOUS_ACTION_OK" else "ESCALATE FOR REVIEW"
        print(f"  {src} -> {dst}  |  counts: {summary}  |  path: {path}  |  {action_label}")

    if refined:
        print("\n=== Reporting to SIEM/webhook (always runs, independent of --enforce) ===\n")
        from contain import report_confirmed_pair
        for (src, dst), (summary, path, action) in refined.items():
            report_confirmed_pair(src, dst, summary, path, action)

    if refined or suppressed_confirmed:
        print("\n=== Writing audit trail (structured provenance for every decision) ===\n")
        from audit_trail import build_audit_record, save_audit_record
        from mitre_mapping import annotate_summary_with_attack

        alerts_by_pair = defaultdict(list)
        for alert in alerts:
            alerts_by_pair[(alert["src_ip"], alert["dst_ip"])].append(alert)

        audit_count = 0
        for (src, dst), (summary, path, action) in refined.items():
            record = build_audit_record(
                src=src, dst=dst, summary=summary, path=path, action=action,
                contributing_alerts=alerts_by_pair.get((src, dst), []),
                baseline=baseline, suppressed=False,
                mitre_techniques=annotate_summary_with_attack(summary),
            )
            save_audit_record(record)
            audit_count += 1
        for (src, dst), (summary, path) in suppressed_confirmed.items():
            record = build_audit_record(
                src=src, dst=dst, summary=summary, path=path, action="SUPPRESSED",
                contributing_alerts=alerts_by_pair.get((src, dst), []),
                baseline=baseline, suppressed=True,
                mitre_techniques=annotate_summary_with_attack(summary),
            )
            save_audit_record(record)
            audit_count += 1
        print(f"  Wrote {audit_count} record(s) to audit_trail.jsonl")

    if suppressed_confirmed:
        print(f"\n=== {len(suppressed_confirmed)} pair(s) SUPPRESSED (previously reviewed by a human) ===\n")
        for (src, dst), (summary, path) in suppressed_confirmed.items():
            print(f"  {src} -> {dst}  |  counts: {summary}  |  path: {path}  |  (not re-escalated - see suppressions.json)")

    confirmed = refined

    print(f"\n=== {len(collective_threats)} collective overwhelm escalation(s) (layer 8) ===\n")
    if not collective_threats:
        print("  (none - no unrelated ambiguous bursts occurred close enough together to correlate)")
    for events in collective_threats:
        pairs = sorted({(e["src"], e["dst"]) for e in events})
        print(f"  COLLECTIVE THREAT: {len(pairs)} unrelated pairs simultaneously ambiguous -> {pairs}")
        print("  Recommendation: treat as a coordinated event - escalate ALL involved pairs together, "
              "even though none individually reached autonomous-action confidence.")

    if enforce:
        from contain import isolate_container, handle_confirmed_pair

        if guard_sources:
            print("\n=== --enforce flag set: acting on GUARD alerts immediately (bypasses quorum) ===\n")
            for src in guard_sources:
                isolate_container(src, reason="guard checkpoint violation (layer 1) - no quorum needed")

        if confirmed:
            print("\n=== --enforce flag set: acting on QUORUM-confirmed pairs (layer 4 -> layer 6) ===\n")
            for (src, dst), (summary, path, action) in confirmed.items():
                handle_confirmed_pair(src, dst, summary, action)

    elif confirmed or guard_alerts:
        print("\n(Run with --enforce to actually isolate confirmed/guard-flagged sources via Docker. "
              "Without it, this is a dry run - no real action taken.)")

    if not no_adapt:
        print(f"\n=== Adaptive baseline update (layer 2 extension) ===\n")
        # Which rows contributed to which confirmed (src, dst) pair, so
        # a pair that turns out to be SUPPRESSED can have its actual
        # contributing rows replayed into the rolling baseline - a
        # human confirming "this was a false positive" is exactly the
        # trigger this system uses to learn that pattern as safe going
        # forward, rather than needing the same suppression forever.
        rows_by_pair = defaultdict(list)
        alerted_row_keys = set()
        for alert in alerts:
            pair = (alert["src_ip"], alert["dst_ip"])
            rows_by_pair[pair].append(alert)
            alerted_row_keys.add((alert["src_ip"], alert["dst_ip"], alert["timestamp"]))

        learned_from_suppression = 0
        for pair in suppressed_confirmed:
            for alert in rows_by_pair.get(pair, []):
                matching_rows = [
                    r for r in rows
                    if r["src_ip"] == alert["src_ip"] and r["dst_ip"] == alert["dst_ip"]
                    and r["timestamp"].isoformat() == alert["timestamp"]
                ]
                for row in matching_rows:
                    rolling.observe_safe(row)
                    learned_from_suppression += 1

        learned_from_zero_signal = 0
        for row in rows:
            key = (row["src_ip"], row["dst_ip"], row["timestamp"].isoformat())
            if key not in alerted_row_keys and row["src_ip"] in baseline:
                rolling.observe_safe(row)
                learned_from_zero_signal += 1

        print(f"  Learned from {learned_from_zero_signal} zero-signal rows (automatic)")
        print(f"  Learned from {learned_from_suppression} rows via human-confirmed suppression")

        with open(rolling_baseline_file, "w") as f:
            json.dump(rolling.export(), f, indent=2)
        print(f"  Saved adapted baseline to {rolling_baseline_file} "
              f"({len(rolling.export())} devices) - future runs will resume from this state.")

        drift_alerts = []
        for device in rolling.export():
            status = rolling.get_drift_status(device)
            if status.get("drift_alert"):
                drift_alerts.append((device, status))

        if drift_alerts:
            print(f"\n=== \u26a0 {len(drift_alerts)} BASELINE DRIFT ALERT(S) (boiling-frog poisoning check) ===\n")
            for device, status in drift_alerts:
                print(f"  {device}: {status['reason']}")
            print("  This does NOT block anything automatically - it flags devices whose")
            print("  learned baseline has shifted unusually far, in one sustained direction,")
            print("  for a human to review: is this a real, legitimate change, or gradual poisoning?")
