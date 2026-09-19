"""
test_drift_monitor.py — real tests for the boiling-frog drift monitor,
grounded in a documented, actively-researched attack class against
adaptive/continual-learning baselines.
"""

import random

import pytest

from drift_monitor import DriftMonitor


def test_insufficient_history_never_alerts():
    dm = DriftMonitor(window_size=50)
    result = dm.observe("C1", 150.0)
    assert result["drift_alert"] is False
    assert "insufficient history" in result["reason"]


def test_normal_fluctuation_never_alerts():
    random.seed(1)
    dm = DriftMonitor(window_size=50, drift_ratio_threshold=1.5)
    result = None
    for _ in range(60):
        result = dm.observe("C1", 150 + random.uniform(-20, 20))
    assert result["drift_alert"] is False


def test_one_time_legitimate_jump_does_not_alert():
    """A genuine, discrete change (e.g. a device's role legitimately
    changing) is NOT the sustained, gradual signature this monitor
    targets - it should show low consistency, not a drift alert."""
    dm = DriftMonitor(window_size=50, drift_ratio_threshold=1.5)
    result = None
    for i in range(60):
        value = 150 if i < 5 else 400
        result = dm.observe("C1", value)
    assert result["drift_alert"] is False
    assert result["consistency"] < 0.1


def test_genuine_boiling_frog_pattern_is_detected():
    """Real, simulated gradual poisoning: many small, consistently
    one-directional nudges - individually unremarkable, cumulatively
    a large, sustained shift."""
    random.seed(1)
    dm = DriftMonitor(window_size=50, drift_ratio_threshold=1.5)
    result = None
    value = 150.0
    for _ in range(60):
        value += random.uniform(2, 5)
        result = dm.observe("C1", value)
    assert result["drift_alert"] is True
    assert result["consistency"] >= 0.7


def test_downward_drift_also_detected():
    """The signature is symmetric - a sustained downward shift is
    exactly as suspicious as an upward one."""
    dm = DriftMonitor(window_size=50, drift_ratio_threshold=1.5)
    result = None
    value = 400.0
    for _ in range(60):
        value -= 4
        result = dm.observe("C1", value)
    assert result["drift_alert"] is True


def test_different_entities_tracked_independently():
    dm = DriftMonitor(window_size=10, drift_ratio_threshold=1.5)
    for i in range(10):
        dm.observe("C1", 150 + i * 20)  # C1 drifts a lot
    result_c2 = None
    for i in range(10):
        result_c2 = dm.observe("C2", 150)  # C2 stays flat
    assert result_c2["drift_alert"] is False


def test_zero_starting_value_handled_safely():
    dm = DriftMonitor(window_size=5)
    result = None
    for i in range(5):
        result = dm.observe("C1", 0 if i == 0 else 100)
    assert result["drift_alert"] is False
    assert "zero" in result["reason"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
