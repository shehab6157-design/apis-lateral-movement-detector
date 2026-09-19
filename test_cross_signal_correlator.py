"""
test_cross_signal_correlator.py — real behavioral tests for the
Layer 8 extension correlating network-flow and Windows credential-
theft evidence.
"""

from datetime import datetime

import pytest

from cross_signal_correlator import correlate


def test_correlates_pair_confirmed_in_both_domains_within_window():
    flow = {("A", "B"): ({"VOLUME_OUTLIER": 1}, "repetition_burst", datetime(2026, 1, 1, 9, 0, 0))}
    auth = {("A", "B"): ({"PTH_SUSPECTED": 1}, datetime(2026, 1, 1, 9, 10, 0))}
    result = correlate(flow, auth, window_minutes=30)
    assert ("A", "B") in result
    assert result[("A", "B")]["confidence"] == "CROSS_DOMAIN_CORRELATED"


def test_does_not_correlate_pair_only_seen_in_one_domain():
    flow = {("A", "B"): ({"VOLUME_OUTLIER": 1}, "repetition_burst", datetime(2026, 1, 1, 9, 0, 0))}
    auth = {("C", "D"): ({"PTH_SUSPECTED": 1}, datetime(2026, 1, 1, 9, 5, 0))}
    result = correlate(flow, auth)
    assert result == {}


def test_does_not_correlate_when_outside_time_window():
    flow = {("A", "B"): ({"VOLUME_OUTLIER": 1}, "repetition_burst", datetime(2026, 1, 1, 9, 0, 0))}
    auth = {("A", "B"): ({"PTH_SUSPECTED": 1}, datetime(2026, 1, 1, 11, 0, 0))}
    result = correlate(flow, auth, window_minutes=30)
    assert result == {}


def test_window_boundary_is_inclusive():
    flow = {("A", "B"): ({"VOLUME_OUTLIER": 1}, "repetition_burst", datetime(2026, 1, 1, 9, 0, 0))}
    auth = {("A", "B"): ({"PTH_SUSPECTED": 1}, datetime(2026, 1, 1, 9, 30, 0))}
    result = correlate(flow, auth, window_minutes=30)
    assert ("A", "B") in result


def test_empty_inputs_produce_no_correlations():
    assert correlate({}, {}) == {}
    assert correlate({("A", "B"): ({}, "repetition_burst", datetime(2026, 1, 1))}, {}) == {}


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
