"""
test_live_monitor_adaptive.py — verifies the adaptive baseline is wired
into the LIVE monitor with the same poisoning-safety guarantee the batch
pipeline enforces.

This closes the last item on the project's own limitations list: the one
component that watches real traffic as it happens was the one component
that never learned from it.
"""

import json
from datetime import datetime

import pytest

pytest.importorskip("scapy", reason="live_monitor requires scapy")

from live_monitor import LiveMonitor


INITIAL = {
    "10.0.0.12": {
        "known_peers": ["10.0.0.13"],
        "active_hours": list(range(0, 24)),
        "avg_bytes": 150.0, "std_bytes": 50.0,
        "avg_fanout_per_hour": 1.0, "std_fanout_per_hour": 1.0,
        "known_ssh_banners": [],
    }
}


def _row(ts, src="10.0.0.12", dst="10.0.0.13", size=150):
    return {"timestamp": ts, "src_ip": src, "dst_ip": dst,
            "dst_port": 443, "bytes": size, "ssh_banner": ""}


@pytest.fixture
def monitor(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return LiveMonitor(json.loads(json.dumps(INITIAL)), enforce=False,
                       state_file=str(tmp_path / "quorum.json"),
                       rolling_baseline_file=str(tmp_path / "rolling.json"))


def test_adaptive_baseline_is_active_by_default(monitor):
    assert monitor.adapt is True
    assert monitor.rolling is not None


def test_no_adapt_flag_leaves_baseline_frozen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    m = LiveMonitor(json.loads(json.dumps(INITIAL)), adapt=False,
                    state_file=str(tmp_path / "q.json"))
    before = json.dumps(m.baseline, sort_keys=True)
    m._observe_safe(_row(datetime(2026, 1, 1, 9, 0, 0), size=9999)) if m.adapt else None
    assert json.dumps(m.baseline, sort_keys=True) == before
    assert m.rolling is None


def test_zero_signal_rows_are_learned_from(monitor):
    start = monitor.baseline["10.0.0.12"]["avg_bytes"]
    for i in range(30):
        monitor._observe_safe(_row(datetime(2026, 1, 1, 9, i % 60, 0), size=400))
    assert monitor.rows_learned == 30
    assert monitor.baseline["10.0.0.12"]["avg_bytes"] > start


def test_learning_takes_effect_on_the_live_snapshot(monitor):
    """The snapshot the detector reads must be refreshed, or learning
    would only apply after a restart."""
    monitor._observe_safe(_row(datetime(2026, 1, 1, 9, 0, 0), dst="10.0.0.99"))
    assert "10.0.0.99" in monitor.baseline["10.0.0.12"]["known_peers"]


def test_signalling_rows_are_held_not_learned(monitor):
    """The poisoning-safety guarantee: a row behind a signal is buffered
    pending human review, never learned from on its own."""
    before = json.dumps(monitor.baseline, sort_keys=True)
    monitor._pending_rows.setdefault(("10.0.0.12", "10.0.0.99"), []).append(
        _row(datetime(2026, 1, 1, 9, 0, 0), dst="10.0.0.99", size=99999))
    assert monitor.rows_learned == 0
    assert json.dumps(monitor.baseline, sort_keys=True) == before


def test_human_suppression_releases_held_rows_for_learning(monitor):
    pair = ("10.0.0.12", "10.0.0.99")
    monitor._pending_rows[pair] = [
        _row(datetime(2026, 1, 1, 9, i, 0), dst="10.0.0.99", size=400) for i in range(5)
    ]
    monitor._learn_from_suppressed(*pair)
    assert monitor.rows_learned == 5
    assert "10.0.0.99" in monitor.baseline["10.0.0.12"]["known_peers"]
    assert pair not in monitor._pending_rows


def test_attack_rows_are_never_learned_without_suppression(monitor):
    """An unsuppressed confirmation must leave the baseline untouched,
    no matter how many times the pattern repeats."""
    pair = ("10.0.0.12", "10.0.0.66")
    for i in range(20):
        monitor._pending_rows.setdefault(pair, []).append(
            _row(datetime(2026, 1, 1, 9, i, 0), dst="10.0.0.66", size=99999))
    assert monitor.rows_learned == 0
    assert "10.0.0.66" not in monitor.baseline["10.0.0.12"]["known_peers"]


def test_baseline_persists_to_disk(monitor, tmp_path):
    for i in range(3):
        monitor._observe_safe(_row(datetime(2026, 1, 1, 9, i, 0), size=300))
    monitor._persist_baseline()
    saved = json.loads((tmp_path / "rolling.json").read_text())
    assert "10.0.0.12" in saved


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
