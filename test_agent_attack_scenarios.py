"""
test_agent_attack_scenarios.py — locks in which structural pivot shapes
Layer 9 catches and which it does not.

These tests deliberately assert the EVASIONS as well as the detections.
A future change that silently starts catching recon_only would be good
news, but a future change that silently stops catching classic_exfil
would not - and without these, neither would be noticed.
"""

import pytest

from agent_baseline import build_agent_baseline
from agent_detector import AgentBehaviorDetector, AGENT_SIGNAL_TYPES
from agent_attack_scenarios import build_scenarios, CAUGHT, EVADES
from quorum import QuorumCoordinator
from overwhelm import OverwhelmMonitor
from agent_evaluation import (
    AGENT_OVERWHELM_PAIR_THRESHOLD, AGENT_OVERWHELM_WINDOW_SECONDS)
from datetime import datetime


AGENT = "svc/bot"


def _clean_events():
    """A plausible benign envelope for a reporting agent."""
    events = []
    t = 1_770_000_000.0
    for i in range(30):
        events.append({
            "time": t + i * 60, "agent_id": AGENT, "session_id": f"s{i // 10}",
            "tool": "Read", "target": "/work/report.csv", "action": "read",
            "input_provenance": "trusted", "result_size": 1000, "success": True,
            "external": False,
        })
        events.append({
            "time": t + i * 60 + 20, "agent_id": AGENT, "session_id": f"s{i // 10}",
            "tool": "Write", "target": "/work/out.md", "action": "write",
            "input_provenance": "trusted", "result_size": 1000, "success": True,
            "external": False,
        })
    return events


@pytest.fixture
def baseline():
    return build_agent_baseline(_clean_events())


def _detections(events, baseline):
    """Returns (quorum_confirmations, collective_escalations).

    Layer 8 is included because quorum is per-pair and cannot see a
    horizontal scan across many distinct targets - a structural gap
    found by measurement, not design.
    """
    detector = AgentBehaviorDetector(baseline)
    coordinator = QuorumCoordinator(active_detector_types=AGENT_SIGNAL_TYPES)
    confirmed = {}
    collective = []
    coordinator.on_quorum_reached = lambda s, d, summ, p: confirmed.setdefault((s, d), (summ, p))
    overwhelm = OverwhelmMonitor(
        pair_threshold=AGENT_OVERWHELM_PAIR_THRESHOLD,
        correlation_window_seconds=AGENT_OVERWHELM_WINDOW_SECONDS,
        on_collective_threat=lambda evs: collective.append(list(evs)))
    for event in events:
        signals = detector.process_event(event)
        if not signals:
            continue
        target = event["target"] or "(no-target)"
        ts = datetime.fromtimestamp(event["time"])
        coordinator.record_batch(signals, event["agent_id"], target, timestamp=ts)
        overwhelm.notify_repetition_burst(event["agent_id"], target,
                                          {s: 1 for s in signals}, timestamp=ts)
    return confirmed, collective


def _detected(events, baseline):
    confirmed, collective = _detections(events, baseline)
    return len(confirmed) > 0 or len(collective) > 0


def _pivot_fired(events, baseline):
    detector = AgentBehaviorDetector(baseline)
    return any("TAINTED_SCOPE_EXPANSION" in detector.process_event(e) for e in events)


def _scenario(baseline, name):
    for s in build_scenarios(baseline, AGENT, 1_770_500_000.0):
        if s["name"] == name:
            return s
    raise AssertionError(f"scenario {name} not found")


def test_every_scenario_matches_its_documented_prediction(baseline):
    """The suite's own predictions must stay honest. If this fails, the
    documentation in agent_attack_scenarios.py is wrong and must be
    corrected rather than the assertion loosened."""
    for scenario in build_scenarios(baseline, AGENT, 1_770_500_000.0):
        detected = _detected(scenario["events"], baseline)
        expected_detection = scenario["expected"] == CAUGHT
        assert detected == expected_detection, (
            f"{scenario['name']}: documented as {scenario['expected']} "
            f"but detection was {detected}")


def test_classic_exfil_is_caught_and_raises_the_pivot_signal(baseline):
    s = _scenario(baseline, "classic_exfil")
    assert _detected(s["events"], baseline) is True
    assert _pivot_fired(s["events"], baseline) is True


def test_recon_only_evades_at_the_calibrated_threshold(baseline):
    """Calibration on 484 real tool calls showed Layer 8 only catches
    this at pair_threshold=3, which costs 3-12 false positives on real
    benign activity. At the calibrated threshold of 8 it does not fire.
    Touching three distinct targets is indistinguishable from a benign
    agent touching three new files."""
    s = _scenario(baseline, "recon_only")
    assert _pivot_fired(s["events"], baseline) is False
    assert _detected(s["events"], baseline) is False


def test_in_workspace_poison_evades_entirely(baseline):
    """The stated limitation of workspace-relative trust."""
    s = _scenario(baseline, "in_workspace_poison")
    assert _pivot_fired(s["events"], baseline) is False
    assert _detected(s["events"], baseline) is False


def test_slow_pivot_evades_the_signal_but_not_the_layer(baseline):
    """Measurement corrected the original prediction: taint expires, so
    the pivot signal stays silent - but the other signals still confirm.
    This is the argument for not resting on one signal."""
    s = _scenario(baseline, "slow_pivot")
    assert _pivot_fired(s["events"], baseline) is False
    assert _detected(s["events"], baseline) is True


def test_horizontal_scan_is_caught_by_layer_8_not_by_quorum(baseline):
    """The structural finding: a scan across many distinct targets gives
    each pair exactly ONE signal, so per-pair quorum can never confirm
    it regardless of thresholds. Layer 8 correlates across pairs."""
    s = _scenario(baseline, "machine_speed_burst")
    assert _pivot_fired(s["events"], baseline) is False
    _, collective = _detections(s["events"], baseline)
    assert len(collective) > 0


def test_detection_is_not_keyed_to_one_specific_tool(baseline):
    """credential_write_out uses a file destination and a different tool
    than classic_exfil's URL/WebFetch."""
    s = _scenario(baseline, "credential_write_out")
    assert _detected(s["events"], baseline) is True
    assert _pivot_fired(s["events"], baseline) is True


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
