"""
test_apis.py — automated regression suite for the APIS project.

Built after a real lesson: during manual testing, a code patch silently
failed to write to disk twice, and both times it took real debugging
to notice, because "does this still work" meant re-running a dozen
scenarios by hand. This file converts every scenario this project has
actually verified - including every real bug found and fixed along the
way - into tests that run in seconds and fail loudly if anything
regresses.

Run with:
    python3 -m pytest test_apis.py -v
"""

from datetime import datetime, timedelta
import json
import os
import pytest

from quorum import QuorumCoordinator
from guard import guard_check
from overwhelm import OverwhelmMonitor
from feedback import suppress, is_suppressed, load_suppressions
import detector
import hygiene


TYPES = {"NEW_PEER", "OFF_HOURS", "VOLUME_OUTLIER", "FANOUT_SPIKE", "SLOW_FANOUT", "UNKNOWN_SSH_CLIENT"}


def test_quorum_type_diversity_confirms():
    results = []
    c = QuorumCoordinator(active_detector_types=TYPES,
                           on_quorum_reached=lambda s, d, summary, path: results.append((s, d, summary, path)))
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    c.record_batch(["NEW_PEER", "OFF_HOURS"], "A", "B", timestamp=t0)
    assert len(results) == 1
    assert results[0][3] == "type_diversity"


def test_quorum_single_signal_never_confirms_alone():
    results = []
    c = QuorumCoordinator(active_detector_types=TYPES,
                           on_quorum_reached=lambda s, d, summary, path: results.append((s, d, summary, path)))
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    reached = c.record_batch(["NEW_PEER"], "A", "B", timestamp=t0)
    assert reached is False
    assert results == []


def test_quorum_repetition_burst_confirms_when_tight():
    results = []
    c = QuorumCoordinator(active_detector_types=TYPES, repetition_threshold=5, burst_window_seconds=60,
                           on_quorum_reached=lambda s, d, summary, path: results.append((s, d, summary, path)))
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(5):
        c.record_batch(["VOLUME_OUTLIER"], "A", "B", timestamp=t0 + timedelta(seconds=i * 6))
    assert len(results) == 1
    assert results[0][3] == "repetition_burst"


def test_quorum_repetition_burst_rejects_slow_spread():
    results = []
    c = QuorumCoordinator(active_detector_types=TYPES, repetition_threshold=5, burst_window_seconds=60,
                           on_quorum_reached=lambda s, d, summary, path: results.append((s, d, summary, path)))
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(5):
        c.record_batch(["VOLUME_OUTLIER"], "A", "B", timestamp=t0 + timedelta(minutes=i * 5))
    assert results == []


def test_quorum_record_batch_preserves_all_simultaneous_signals():
    results = []
    c = QuorumCoordinator(active_detector_types=TYPES,
                           on_quorum_reached=lambda s, d, summary, path: results.append((s, d, summary, path)))
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    c.record_batch(["NEW_PEER", "OFF_HOURS", "FANOUT_SPIKE"], "A", "B", timestamp=t0)
    assert set(results[0][2].keys()) == {"NEW_PEER", "OFF_HOURS", "FANOUT_SPIKE"}


def test_quorum_threshold_fixed_at_two_regardless_of_type_count():
    c = QuorumCoordinator(active_detector_types=TYPES)
    assert c.threshold == 2


def test_guard_passes_normal_traffic():
    assert guard_check({"dst_port": 22, "bytes": 1602}) == []


def test_guard_catches_blocked_port():
    flags = guard_check({"dst_port": 23, "bytes": 500})
    assert "GUARD_BLOCKED_PORT_23" in flags


def test_guard_catches_malformed_size():
    flags = guard_check({"dst_port": 80, "bytes": 0})
    assert "GUARD_MALFORMED_SIZE" in flags


def test_overwhelm_correlates_close_unrelated_pairs():
    threats = []
    m = OverwhelmMonitor(pair_threshold=2, correlation_window_seconds=120,
                          on_collective_threat=lambda events: threats.append(events))
    t0 = datetime(2026, 1, 1, 21, 0, 0)
    m.notify_repetition_burst("A", "B", {"VOLUME_OUTLIER": 5}, timestamp=t0)
    m.notify_repetition_burst("C", "D", {"VOLUME_OUTLIER": 6}, timestamp=t0 + timedelta(seconds=45))
    assert len(threats) == 1


def test_overwhelm_does_not_correlate_distant_pairs():
    threats = []
    m = OverwhelmMonitor(pair_threshold=2, correlation_window_seconds=120,
                          on_collective_threat=lambda events: threats.append(events))
    t0 = datetime(2026, 1, 1, 21, 0, 0)
    m.notify_repetition_burst("A", "B", {"VOLUME_OUTLIER": 16}, timestamp=t0)
    m.notify_repetition_burst("C", "D", {"VOLUME_OUTLIER": 20}, timestamp=t0 + timedelta(hours=2))
    assert threats == []


def test_overwhelm_does_not_double_count_bidirectional_conversation():
    threats = []
    m = OverwhelmMonitor(pair_threshold=2, correlation_window_seconds=120,
                          on_collective_threat=lambda events: threats.append(events))
    t0 = datetime(2026, 1, 1, 21, 0, 0)
    m.notify_repetition_burst("A", "B", {"OFF_HOURS": 5}, timestamp=t0)
    m.notify_repetition_burst("B", "A", {"OFF_HOURS": 3}, timestamp=t0 + timedelta(seconds=10))
    assert threats == []


def test_overwhelm_still_correlates_distinct_conversations_sharing_a_host():
    threats = []
    m = OverwhelmMonitor(pair_threshold=2, correlation_window_seconds=120,
                          on_collective_threat=lambda events: threats.append(events))
    t0 = datetime(2026, 1, 1, 21, 0, 0)
    m.notify_repetition_burst("A", "B", {"VOLUME_OUTLIER": 5}, timestamp=t0)
    m.notify_repetition_burst("A", "C", {"VOLUME_OUTLIER": 6}, timestamp=t0 + timedelta(seconds=20))
    assert len(threats) == 1


SUPPRESSIONS_TEST_PATH = "test_suppressions.json"


def teardown_module(module):
    if os.path.exists(SUPPRESSIONS_TEST_PATH):
        os.remove(SUPPRESSIONS_TEST_PATH)


def test_suppression_applies_to_repetition_burst():
    if os.path.exists(SUPPRESSIONS_TEST_PATH):
        os.remove(SUPPRESSIONS_TEST_PATH)
    suppress("A", "B", {"VOLUME_OUTLIER": 5}, "tester", "known legitimate pattern", path=SUPPRESSIONS_TEST_PATH)
    assert is_suppressed("A", "B", {"VOLUME_OUTLIER": 5}, "repetition_burst",
                          suppressions_path=SUPPRESSIONS_TEST_PATH) is True


def test_suppression_never_applies_to_type_diversity():
    if os.path.exists(SUPPRESSIONS_TEST_PATH):
        os.remove(SUPPRESSIONS_TEST_PATH)
    suppress("A", "B", {"NEW_PEER": 1, "OFF_HOURS": 1}, "tester", "attempted bypass", path=SUPPRESSIONS_TEST_PATH)
    assert is_suppressed("A", "B", {"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity",
                          suppressions_path=SUPPRESSIONS_TEST_PATH) is False


BASELINE = {
    "10.0.2.10": {"known_peers": ["10.0.2.11", "10.0.2.12"], "active_hours": [21, 23],
                  "avg_bytes": 144.2, "std_bytes": 276.4, "avg_fanout_per_hour": 2, "std_fanout_per_hour": 1.0,
                  "known_ssh_banners": ["SSH-2.0-OpenSSH_8.2p1"]},
    "10.0.2.11": {"known_peers": ["10.0.2.10", "10.0.2.12"], "active_hours": [21, 23],
                  "avg_bytes": 735.5, "std_bytes": 1729.3, "avg_fanout_per_hour": 2.5, "std_fanout_per_hour": 1.0,
                  "known_ssh_banners": ["SSH-2.0-OpenSSH_8.9p1"]},
    "10.0.2.12": {"known_peers": ["10.0.2.10", "10.0.2.11"], "active_hours": [21, 23],
                  "avg_bytes": 216.1, "std_bytes": 350.4, "avg_fanout_per_hour": 1.5, "std_fanout_per_hour": 1.0,
                  "known_ssh_banners": ["SSH-2.0-OpenSSH_8.2p1"]},
}


def _row(ts, src, dst, size, banner=""):
    return {"timestamp": ts, "src_ip": src, "dst_ip": dst, "bytes": size, "ssh_banner": banner}


def test_real_attack_pattern_escalates_not_autonomous():
    t0 = datetime(2026, 7, 28, 23, 32, 21)
    rows = [_row(t0 + timedelta(seconds=i * 6), "10.0.2.10", "10.0.2.11", 1602) for i in range(7)]
    alerts = detector.detect(rows, BASELINE)
    confirmed, _ = detector.apply_quorum(alerts)
    refined = detector.refine_actions(confirmed)
    assert ("10.0.2.10", "10.0.2.11") in refined
    assert refined[("10.0.2.10", "10.0.2.11")][2] == "ESCALATE_FOR_REVIEW"


def test_real_fanout_attack_fully_confirmed_autonomous():
    t0 = datetime(2026, 9, 12, 13, 30, 15)
    rows = [_row(t0, "10.0.2.10", t, 74) for t in ["10.0.2.13", "10.0.2.14", "10.0.2.15", "10.0.2.16", "10.0.2.17"]]
    alerts = detector.detect(rows, BASELINE)
    confirmed, _ = detector.apply_quorum(alerts)
    refined = detector.refine_actions(confirmed)
    assert len(refined) == 5
    assert all(v[2] == "AUTONOMOUS_ACTION_OK" for v in refined.values())


def test_slow_fanout_catches_patient_attacker_with_realistic_threshold():
    base = datetime(2026, 9, 12, 21, 0, 0)
    targets = [f"10.0.2.9{i}" for i in range(6)]
    rows = [_row(base + timedelta(hours=i * 3), "10.0.2.10", t, 500) for i, t in enumerate(targets)]
    alerts = detector.detect(rows, BASELINE)
    confirmed, _ = detector.apply_quorum(alerts)
    last_pair = ("10.0.2.10", targets[-1])
    assert last_pair in confirmed
    assert "SLOW_FANOUT" in confirmed[last_pair][0]


def test_slow_fanout_does_not_flood_high_diversity_role():
    server_baseline = {
        "10.10.0.5": {"known_peers": [f"203.0.113.{i}" for i in range(30)], "active_hours": list(range(9, 17)),
                      "avg_bytes": 800, "std_bytes": 100, "avg_fanout_per_hour": 3.75, "std_fanout_per_hour": 1.0,
                      "known_ssh_banners": []}
    }
    t0 = datetime(2026, 9, 6, 9, 0, 0)
    rows = [_row(t0 + timedelta(minutes=i * 15), "10.10.0.5", f"198.51.100.{i}", 800) for i in range(10)]
    alerts = detector.detect(rows, server_baseline)
    slow_fanout_hits = sum(1 for a in alerts if "SLOW_FANOUT" in a["signals"])
    assert slow_fanout_hits <= 1


def test_unknown_ssh_client_promotes_weak_evidence_to_strong():
    t0 = datetime(2026, 9, 12, 15, 16, 34)
    rows = [
        _row(t0, "10.0.2.10", "10.0.2.11", 90, banner="SSH-2.0-paramiko_5.0.0"),
        _row(t0 + timedelta(milliseconds=200), "10.0.2.10", "10.0.2.11", 90, banner="SSH-2.0-paramiko_5.0.0"),
    ]
    alerts = detector.detect(rows, BASELINE)
    confirmed, _ = detector.apply_quorum(alerts)
    assert ("10.0.2.10", "10.0.2.11") in confirmed
    assert confirmed[("10.0.2.10", "10.0.2.11")][1] == "type_diversity"


def test_banner_spoofing_defeats_signal_but_not_detection():
    t0 = datetime(2026, 9, 12, 22, 19, 23)
    rows = [_row(t0 + timedelta(seconds=i * 6), "10.0.2.10", "10.0.2.11", 90,
                 banner="SSH-2.0-OpenSSH_8.2p1") for i in range(5)]
    alerts = detector.detect(rows, BASELINE)
    unknown_client_hits = sum(1 for a in alerts if "UNKNOWN_SSH_CLIENT" in a["signals"] and a["src_ip"] == "10.0.2.10")
    assert unknown_client_hits == 0
    confirmed, _ = detector.apply_quorum(alerts)
    assert ("10.0.2.10", "10.0.2.11") in confirmed
    assert confirmed[("10.0.2.10", "10.0.2.11")][1] == "repetition_burst"


def test_refine_actions_protects_innocent_reverse_party():
    confirmed = {
        ("10.0.2.10", "10.0.2.11"): ({"OFF_HOURS": 5}, "repetition_burst"),
        ("10.0.2.11", "10.0.2.10"): ({"OFF_HOURS": 3, "UNKNOWN_SSH_CLIENT": 1}, "type_diversity"),
    }
    refined = detector.refine_actions(confirmed)
    assert refined[("10.0.2.11", "10.0.2.10")][2] == "ESCALATE_FOR_REVIEW"


def test_refine_actions_preserves_symmetric_strong_detection():
    confirmed = {
        ("10.0.2.10", "10.0.2.11"): ({"OFF_HOURS": 4, "UNKNOWN_SSH_CLIENT": 1}, "type_diversity"),
        ("10.0.2.11", "10.0.2.10"): ({"OFF_HOURS": 3, "UNKNOWN_SSH_CLIENT": 1}, "type_diversity"),
    }
    refined = detector.refine_actions(confirmed)
    assert refined[("10.0.2.10", "10.0.2.11")][2] == "AUTONOMOUS_ACTION_OK"
    assert refined[("10.0.2.11", "10.0.2.10")][2] == "AUTONOMOUS_ACTION_OK"


def test_refine_actions_unambiguous_signal_skips_reverse_check():
    confirmed = {
        ("A", "B"): ({"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity"),
    }
    refined = detector.refine_actions(confirmed)
    assert refined[("A", "B")][2] == "AUTONOMOUS_ACTION_OK"


def test_no_false_positives_on_pure_normal_traffic():
    rows = [_row(datetime(2026, 1, 1, 21, 30, 0), "10.0.2.10", "10.0.2.11", 150)]
    alerts = detector.detect(rows, BASELINE)
    assert alerts == []


def test_guard_catches_device_the_queen_cannot_see():
    rows = [_row(datetime(2026, 1, 1, 10, 0, 0), "10.0.2.199", "10.0.2.11", 300)]
    guard_flags = [guard_check({"dst_port": 23, "bytes": 300})]
    alerts = detector.detect(rows, BASELINE)
    assert alerts == []
    assert "GUARD_BLOCKED_PORT_23" in guard_flags[0]


def test_hygiene_flags_never_observed_peer():
    baseline = {"A": {"known_peers": ["B", "C"]}}
    rows = [_row(datetime(2026, 1, 1, 10, 0, 0), "A", "B", 100)]
    findings = hygiene.audit_baseline(baseline, rows, staleness_days=30, now=datetime(2026, 1, 1, 12, 0, 0))
    peers_flagged = {f["peer"] for f in findings}
    assert "C" in peers_flagged
    assert "B" not in peers_flagged


def test_hygiene_flags_stale_but_not_fresh():
    baseline = {"A": {"known_peers": ["B", "C"]}}
    now = datetime(2026, 3, 1, 12, 0, 0)
    rows = [
        _row(now - timedelta(days=1), "A", "B", 100),
        _row(now - timedelta(days=60), "A", "C", 100),
    ]
    findings = hygiene.audit_baseline(baseline, rows, staleness_days=30, now=now)
    peers_flagged = {f["peer"] for f in findings}
    assert "C" in peers_flagged
    assert "B" not in peers_flagged


# ---------------------------------------------------------------------------
# config.py — centralized tunable thresholds
# ---------------------------------------------------------------------------

def test_config_loads_verified_defaults_with_no_config_file():
    from config import load_config
    cfg = load_config(path="nonexistent_config_for_test.json")
    assert cfg["quorum"]["repetition_threshold"] == 5
    assert cfg["detection"]["slow_fanout_multiplier"] == 3
    assert cfg["guard"]["blocked_ports"] == [23]


def test_config_merges_user_overrides_without_wiping_section():
    from config import load_config
    test_path = "test_config_override.json"
    with open(test_path, "w") as f:
        json.dump({"quorum": {"repetition_threshold": 10}}, f)
    try:
        cfg = load_config(path=test_path)
        assert cfg["quorum"]["repetition_threshold"] == 10
        assert cfg["quorum"]["burst_window_seconds"] == 60
    finally:
        os.remove(test_path)


# ---------------------------------------------------------------------------
# quorum.py — state persistence across restarts
# ---------------------------------------------------------------------------

def test_quorum_state_survives_save_and_load():
    state_path = "test_quorum_state.json"
    if os.path.exists(state_path):
        os.remove(state_path)
    try:
        c1 = QuorumCoordinator(active_detector_types=TYPES)
        t0 = datetime(2026, 1, 1, 21, 0, 0)
        c1.record_batch(["NEW_PEER"], "A", "B", timestamp=t0)
        c1.save_state(state_path)

        c2 = QuorumCoordinator(active_detector_types=TYPES)
        loaded = c2.load_state(state_path)
        assert loaded is True

        results = []
        c2.on_quorum_reached = lambda s, d, summary, path: results.append((s, d, summary, path))
        c2.record_batch(["OFF_HOURS"], "A", "B", timestamp=t0 + timedelta(seconds=5))
        assert len(results) == 1
        assert set(results[0][2].keys()) == {"NEW_PEER", "OFF_HOURS"}
    finally:
        if os.path.exists(state_path):
            os.remove(state_path)


def test_quorum_load_state_returns_false_when_no_file_exists():
    c = QuorumCoordinator(active_detector_types=TYPES)
    assert c.load_state("definitely_does_not_exist.json") is False


# ---------------------------------------------------------------------------
# notify.py — real webhook delivery (mocked, no real network calls in tests)
# ---------------------------------------------------------------------------

def test_notify_no_webhook_configured_is_a_safe_noop():
    from notify import send_webhook_alert
    ok, detail = send_webhook_alert("test message", webhook_url=None)
    assert ok is False
    assert "no webhook configured" in detail


def test_notify_successful_delivery(monkeypatch):
    from notify import send_webhook_alert
    import notify as notify_module

    class FakeResponse:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(notify_module.urllib.request, "urlopen", lambda req, timeout=5: FakeResponse())
    ok, detail = send_webhook_alert("test message", webhook_url="https://example.com/webhook")
    assert ok is True
    assert "delivered" in detail


def test_notify_failed_delivery_does_not_raise(monkeypatch):
    from notify import send_webhook_alert
    import notify as notify_module
    import urllib.error

    def raise_error(req, timeout=5):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(notify_module.urllib.request, "urlopen", raise_error)
    ok, detail = send_webhook_alert("test message", webhook_url="https://example.com/webhook")
    assert ok is False
    assert "delivery failed" in detail


# ---------------------------------------------------------------------------
# mitre_mapping.py — ATT&CK/D3FEND technique mapping
# ---------------------------------------------------------------------------

def test_mitre_mapping_identifies_lateral_movement_and_discovery():
    from mitre_mapping import annotate_summary_with_attack
    techniques = annotate_summary_with_attack({"NEW_PEER": 1, "FANOUT_SPIKE": 1})
    assert "T1021.004" in techniques
    assert "T1018" in techniques


def test_mitre_mapping_off_hours_alone_maps_to_nothing():
    from mitre_mapping import annotate_summary_with_attack
    assert annotate_summary_with_attack({"OFF_HOURS": 5}) == []


def test_mitre_mapping_unknown_ssh_client_includes_masquerading():
    from mitre_mapping import annotate_summary_with_attack
    techniques = annotate_summary_with_attack({"OFF_HOURS": 1, "UNKNOWN_SSH_CLIENT": 1})
    assert "T1036" in techniques
    assert "T1021.004" in techniques


def test_mitre_mapping_guard_blocked_port_maps_to_parent_remote_services():
    from mitre_mapping import get_attack_mapping
    mapping = get_attack_mapping("GUARD_BLOCKED_PORT")
    assert mapping["technique_id"] == "T1021"


# ---------------------------------------------------------------------------
# siem_export.py — CEF formatting and syslog delivery (mocked)
# ---------------------------------------------------------------------------

def test_cef_format_matches_arcsight_specification():
    from siem_export import to_cef
    cef = to_cef("10.0.2.10", "10.0.2.11", {"NEW_PEER": 1, "FANOUT_SPIKE": 1},
                 "type_diversity", "AUTONOMOUS_ACTION_OK")
    assert cef.startswith("CEF:0|APIS|LateralMovementDetector|1.0|")
    assert "src=10.0.2.10" in cef
    assert "dst=10.0.2.11" in cef
    assert "cs1Label=MITRE_ATTACK_TECHNIQUES" in cef


def test_cef_includes_correct_mitre_technique_ids():
    from siem_export import to_cef
    cef = to_cef("A", "B", {"NEW_PEER": 1, "FANOUT_SPIKE": 1}, "type_diversity", "AUTONOMOUS_ACTION_OK")
    assert "T1021.004" in cef
    assert "T1018" in cef


def test_cef_severity_reflects_action_confidence():
    from siem_export import to_cef
    autonomous_cef = to_cef("A", "B", {"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity", "AUTONOMOUS_ACTION_OK")
    escalate_cef = to_cef("A", "B", {"VOLUME_OUTLIER": 5}, "repetition_burst", "ESCALATE_FOR_REVIEW")
    autonomous_severity = int(autonomous_cef.split("|")[6])
    escalate_severity = int(escalate_cef.split("|")[6])
    assert autonomous_severity > escalate_severity


def test_cef_escapes_pipes_in_header_fields():
    from siem_export import _cef_escape_header
    assert _cef_escape_header("value|with|pipes") == "value\\|with\\|pipes"


def test_cef_escapes_equals_in_extension_values():
    from siem_export import _cef_escape_extension
    assert _cef_escape_extension("a=b") == "a\\=b"


def test_syslog_send_failure_does_not_raise(monkeypatch):
    from siem_export import send_syslog_cef
    import siem_export as siem_module

    class FailingSocket:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def sendto(self, *a): raise OSError("network unreachable")
        def sendall(self, *a): raise OSError("network unreachable")

    monkeypatch.setattr(siem_module.socket, "socket", lambda *a, **k: FailingSocket())
    ok, detail = send_syslog_cef("CEF:0|test", host="10.255.255.1")
    assert ok is False
    assert "failed to send" in detail


# ---------------------------------------------------------------------------
# streaming_detector.py — live/incremental detection vs batch detect()
# ---------------------------------------------------------------------------

STREAMING_BASELINE = {
    "10.0.2.10": {"known_peers": ["10.0.2.11", "10.0.2.12"], "active_hours": [21, 23],
                  "avg_bytes": 144.2, "std_bytes": 276.4, "avg_fanout_per_hour": 2, "std_fanout_per_hour": 1.0,
                  "known_ssh_banners": ["SSH-2.0-OpenSSH_8.2p1"]},
}


def test_streaming_matches_batch_for_non_fanout_signals():
    from streaming_detector import StreamingDetector

    base = datetime(2026, 9, 12, 21, 0, 0)
    rows = [
        _row(base, "10.0.2.10", "10.0.2.11", 150),
        _row(base + timedelta(seconds=5), "10.0.2.10", "10.0.2.11", 1602),
        _row(base + timedelta(seconds=10), "10.0.2.10", "10.0.2.11", 90, banner="SSH-2.0-paramiko_5.0.0"),
        _row(base + timedelta(hours=5), "10.0.2.10", "10.0.2.99", 100),
    ]

    batch_alerts = {a["timestamp"]: set(a["signals"]) for a in detector.detect(rows, STREAMING_BASELINE)}

    sd = StreamingDetector()
    for row in rows:
        signals = sd.process_row(row, STREAMING_BASELINE)
        batch_signals = batch_alerts.get(row["timestamp"].isoformat(), set())
        stream_signals = set(signals) if signals else set()
        batch_core = batch_signals - {"FANOUT_SPIKE", "SLOW_FANOUT"}
        stream_core = stream_signals - {"FANOUT_SPIKE", "SLOW_FANOUT"}
        assert batch_core == stream_core


def test_streaming_fanout_spike_fires_later_than_batch():
    from streaming_detector import StreamingDetector

    base = datetime(2026, 9, 12, 21, 0, 0)
    targets = ["10.0.2.13", "10.0.2.14", "10.0.2.15", "10.0.2.16", "10.0.2.17"]
    rows = [_row(base, "10.0.2.10", t, 74) for t in targets]

    batch_alerts = detector.detect(rows, STREAMING_BASELINE)
    batch_fanout_row = next(a for a in batch_alerts if "FANOUT_SPIKE" in a["signals"])
    assert batch_fanout_row["dst_ip"] == targets[0]

    sd = StreamingDetector()
    stream_fanout_target = None
    for row in rows:
        signals = sd.process_row(row, STREAMING_BASELINE)
        if signals and "FANOUT_SPIKE" in signals:
            stream_fanout_target = row["dst_ip"]
            break

    assert stream_fanout_target is not None
    assert stream_fanout_target != targets[0]


# ---------------------------------------------------------------------------
# live_monitor.py — full pipeline with real scapy packet objects
# ---------------------------------------------------------------------------

def test_live_monitor_processes_real_scapy_packets_end_to_end():
    from scapy.all import IP, TCP, Raw
    from live_monitor import LiveMonitor

    state_path = "test_live_monitor_state.json"
    if os.path.exists(state_path):
        os.remove(state_path)

    try:
        monitor = LiveMonitor(STREAMING_BASELINE, enforce=False, state_file=state_path)
        confirmed_pairs = []
        monitor.coordinator.on_quorum_reached = lambda s, d, summary, path: confirmed_pairs.append((s, d))

        pkt = IP(src="10.0.2.10", dst="10.0.2.50") / TCP(dport=22, sport=50000) / Raw(load=b"X" * 60)
        # Pinned to a fixed, known off-hour (STREAMING_BASELINE's
        # active_hours is only [21, 23]) - found necessary after this
        # test failed on a real run because it silently relied on
        # whatever the real wall-clock hour happened to be when the
        # test ran, rather than a deterministic timestamp. A synthetic
        # scapy packet''.time defaults to real time-of-construction
        # unless explicitly set.
        pkt.time = datetime(2026, 1, 1, 9, 0, 0).timestamp()
        monitor.handle_packet(pkt)

        assert ("10.0.2.10", "10.0.2.50") in confirmed_pairs
    finally:
        if os.path.exists(state_path):
            os.remove(state_path)


def test_repetition_threshold_suppresses_high_volume_device_false_positive():
    busy_baseline = {
        "C10": {"known_peers": ["C1", "C2"], "active_hours": list(range(24)),
                "avg_bytes": 500, "std_bytes": 200, "avg_fanout_per_hour": 2, "std_fanout_per_hour": 1.0,
                "avg_flows_per_hour": 500, "known_ssh_banners": []}
    }
    t0 = datetime(2026, 1, 1, 9, 0, 0)
    rows = [_row(t0 + timedelta(seconds=i * 5), "C10", "C999", 250) for i in range(10)]
    alerts = detector.detect(rows, busy_baseline)

    confirmed_without_fix, _ = detector.apply_quorum(alerts)
    assert len(confirmed_without_fix) == 1

    confirmed_with_fix, _ = detector.apply_quorum(alerts, baseline=busy_baseline)
    assert len(confirmed_with_fix) == 0


def test_repetition_threshold_still_catches_burst_on_quiet_device():
    quiet_baseline = {
        "C99": {"known_peers": ["C1", "C2"], "active_hours": list(range(24)),
                "avg_bytes": 500, "std_bytes": 200, "avg_fanout_per_hour": 2, "std_fanout_per_hour": 1.0,
                "avg_flows_per_hour": 10, "known_ssh_banners": []}
    }
    t0 = datetime(2026, 1, 1, 9, 0, 0)
    rows = [_row(t0 + timedelta(seconds=i * 5), "C99", "C999", 250) for i in range(10)]
    alerts = detector.detect(rows, quiet_baseline)

    confirmed, _ = detector.apply_quorum(alerts, baseline=quiet_baseline)
    assert len(confirmed) == 1


def test_repetition_threshold_defaults_to_flat_when_no_baseline_given():
    baseline = {
        "A": {"known_peers": ["B"], "active_hours": list(range(24)),
              "avg_bytes": 500, "std_bytes": 200, "avg_fanout_per_hour": 1, "std_fanout_per_hour": 1.0,
              "known_ssh_banners": []}
    }
    t0 = datetime(2026, 1, 1, 9, 0, 0)
    rows = [_row(t0 + timedelta(seconds=i * 5), "A", "C999", 250) for i in range(5)]
    alerts = detector.detect(rows, baseline)
    confirmed, _ = detector.apply_quorum(alerts)
    assert len(confirmed) == 1


def test_baseline_computes_log_space_byte_stats():
    import baseline as baseline_module
    rows = [
        _row(datetime(2026, 1, 1, 9, 0, i), "C10", "C1", size)
        for i, size in enumerate([46, 60, 94, 4412, 839225, 13012, 49513, 3491, 235])
    ]
    learned = baseline_module.build_baseline(rows)
    assert "avg_log_bytes" in learned["C10"]
    assert "std_log_bytes" in learned["C10"]


def test_log_space_byte_stats_exist_but_are_not_currently_used():
    """Real finding from LANL evaluation: TWO different log-space
    approaches for VOLUME_OUTLIER were built and measured against real
    data - both made total false positives WORSE than the plain raw
    z-score (1337 -> 1722, then 1735). VOLUME_OUTLIER was reverted to
    the simple raw z-score, which empirically performed best.
    avg_log_bytes/std_log_bytes are still computed and stored by
    baseline.py but detect() does not currently consult them - this
    test documents that honestly, rather than leaving a misleading test
    that implies log-space is active when it isn't."""
    import baseline as baseline_module
    rows = [
        _row(datetime(2026, 1, 1, 9, 0, i), "C10", "C1", size)
        for i, size in enumerate([46, 60, 94, 4412, 839225, 13012, 49513, 3491, 235])
    ]
    learned = baseline_module.build_baseline(rows)
    assert "avg_log_bytes" in learned["C10"]
    assert "std_log_bytes" in learned["C10"]

    profile_without_log_fields = dict(learned["C10"])
    del profile_without_log_fields["avg_log_bytes"]
    del profile_without_log_fields["std_log_bytes"]

    row = [_row(datetime(2026, 1, 1, 10, 0, 0), "C10", "C1", 46000)]
    alerts_with_log_fields = detector.detect(row, {"C10": learned["C10"]})
    alerts_without_log_fields = detector.detect(row, {"C10": profile_without_log_fields})
    assert alerts_with_log_fields == alerts_without_log_fields


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))










def test_advanced_byte_stats_exist_but_are_not_currently_used():
    """Real, honest finding from a real LANL dataset evaluation: FOUR
    approaches to VOLUME_OUTLIER were built and measured - none beat
    the plain raw z-score (1337 false positives). The GMM attempt
    specifically made things WORSE (2628 FPs) due to a real failure
    mode: many real devices repeat the exact same byte value thousands
    of times, and fitting a 2-component mixture to essentially-1-value
    data produces numerically unstable, degenerate fits. All the
    advanced fields are still computed and stored by baseline.py but
    detect() does not currently consult any of them."""
    import baseline as baseline_module
    rows = [
        _row(datetime(2026, 1, 1, 9, 0, i), "C10", "C1", size)
        for i, size in enumerate([46, 60, 94, 4412, 839225, 13012, 49513, 3491, 235])
    ]
    learned = baseline_module.build_baseline(rows)
    assert "avg_log_bytes" in learned["C10"]
    assert "p999_bytes" in learned["C10"]
    assert "byte_mixture_model" in learned["C10"]

    profile_stripped = {
        k: v for k, v in learned["C10"].items()
        if k not in ("avg_log_bytes", "std_log_bytes", "p999_bytes", "byte_mixture_model")
    }

    row = [_row(datetime(2026, 1, 1, 10, 0, 0), "C10", "C1", 46000)]
    alerts_with_fields = detector.detect(row, {"C10": learned["C10"]})
    alerts_without_fields = detector.detect(row, {"C10": profile_stripped})
    assert alerts_with_fields == alerts_without_fields


def test_mixture_model_not_fitted_with_too_few_samples():
    import baseline as baseline_module
    t0 = datetime(2026, 1, 1, 9, 0, 0)
    rows = [_row(t0 + timedelta(seconds=i), "C60", "C1", 100) for i in range(5)]
    learned = baseline_module.build_baseline(rows)
    assert learned["C60"]["byte_mixture_model"] is None


def test_type_diversity_excludes_volume_outlier():
    baseline = {
        "A": {"known_peers": ["B"], "active_hours": list(range(24)),
              "avg_bytes": 150, "std_bytes": 50, "avg_fanout_per_hour": 1, "std_fanout_per_hour": 1.0,
              "known_ssh_banners": []}
    }
    row = [_row(datetime(2026, 1, 1, 9, 0, 0), "A", "C999", 1602)]
    alerts = detector.detect(row, baseline)
    confirmed, _ = detector.apply_quorum(alerts)
    assert len(confirmed) == 0


def test_repetition_burst_still_uses_volume_outlier():
    baseline = {
        "10.0.2.10": {"known_peers": ["10.0.2.11"], "active_hours": list(range(24)),
                      "avg_bytes": 150, "std_bytes": 50, "avg_fanout_per_hour": 1, "std_fanout_per_hour": 1.0,
                      "known_ssh_banners": []}
    }
    t0 = datetime(2026, 7, 28, 23, 32, 21)
    rows = [_row(t0 + timedelta(seconds=i * 6), "10.0.2.10", "10.0.2.11", 1602) for i in range(7)]
    alerts = detector.detect(rows, baseline)
    confirmed, _ = detector.apply_quorum(alerts)
    assert ("10.0.2.10", "10.0.2.11") in confirmed
