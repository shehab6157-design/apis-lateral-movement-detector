"""
test_agent_integration.py — verifies Layer 9 is genuinely wired into the
shared system, not running beside it: shared quorum, shared suppression,
MITRE ATLAS mapping, tamper-evident audit records, the API endpoint, and
three-domain correlation.
"""

import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from mitre_mapping import annotate_summary_with_attack
from audit_trail import explain_signal, build_audit_record, verify_chain
from cross_signal_correlator import correlate_three_domains, explain_tri_correlation


BASELINE = {
    "svc/bot": {
        "known_tools": ["Read", "Write"],
        "known_targets": ["/work/a.py", "/work/b.py"],
        "write_targets": ["/work/a.py"],
        "avg_result_size": 1000.0,
        "std_result_size": 100.0,
        "avg_calls_per_minute": 5.0,
        "observed_calls": 50,
    }
}


# ----------------------------------------------------------- MITRE ATLAS

def test_agent_signals_map_to_atlas_not_attack_enterprise():
    ids = annotate_summary_with_attack({"TAINTED_SCOPE_EXPANSION": 1})
    assert ids == ["AML.T0051.001"]


def test_exfiltration_signal_maps_to_agent_tool_invocation():
    assert "AML.T0086" in annotate_summary_with_attack({"RESULT_SIZE_OUTLIER": 1})


def test_privilege_escalation_cites_both_frameworks():
    """The subversion is an ATLAS concern; the mechanism is the agent's
    own valid credentials, which is ATT&CK T1078."""
    ids = annotate_summary_with_attack({"PRIVILEGE_ESCALATION": 1})
    assert "AML.T0051" in ids and "T1078" in ids


# --------------------------------------------------------- audit evidence

def test_audit_explains_tainted_scope_expansion_with_real_detail():
    row = {"tool": "WebFetch", "target": "https://exfil.example",
           "action": "write", "external": True}
    ev = explain_signal("TAINTED_SCOPE_EXPANSION", row, BASELINE["svc/bot"])
    assert ev["observed_target"] == "https://exfil.example"
    assert ev["external"] is True
    assert "outward" in ev["explanation"].lower()


def test_audit_explains_result_size_with_computed_zscore():
    row = {"result_size": 5000}
    ev = explain_signal("RESULT_SIZE_OUTLIER", row, BASELINE["svc/bot"])
    assert ev["zscore"] == 40.0  # (5000 - 1000) / 100


def test_agent_audit_record_is_hash_chained(tmp_path):
    from audit_trail import save_audit_record
    path = str(tmp_path / "chain.jsonl")
    record = build_audit_record(
        src="svc/bot", dst="https://exfil.example",
        summary={"TAINTED_SCOPE_EXPANSION": 1}, path="type_diversity",
        action="AUTONOMOUS_ACTION_OK",
        contributing_alerts=[{"timestamp": "2026-09-18T14:00:00",
                              "signals": ["TAINTED_SCOPE_EXPANSION"],
                              "tool": "WebFetch", "target": "https://exfil.example",
                              "action": "write", "external": True}],
        baseline=BASELINE, suppressed=False,
        mitre_techniques=annotate_summary_with_attack({"TAINTED_SCOPE_EXPANSION": 1}),
    )
    save_audit_record(record, path=path)
    intact, broken_at, total = verify_chain(path)
    assert intact is True and total == 1


# ------------------------------------------------ three-domain correlation

def _ts(minute):
    return datetime(2026, 9, 18, 12, minute, 0)


def test_two_domain_result_is_preserved_when_no_agent_data():
    flow = {("C1", "C2"): ({"NEW_PEER": 1}, "type_diversity", _ts(0))}
    auth = {("C1", "C2"): ({"PTH_SUSPECTED": 1}, _ts(5))}
    out = correlate_three_domains(flow, auth, {})
    assert out[("C1", "C2")]["domains"] == ["flow", "auth"]


def test_agent_domain_reported_unavailable_without_resolver():
    """Agent identities are a different namespace. Silently returning
    nothing would look like 'no correlation found' rather than 'these
    domains do not share an identifier'."""
    flow = {("C1", "C2"): ({"NEW_PEER": 1}, "type_diversity", _ts(0))}
    auth = {("C1", "C2"): ({"PTH_SUSPECTED": 1}, _ts(5))}
    agent = {("claude-code:lab", "/etc/x"): ({"NEW_TOOL": 1}, "type_diversity", _ts(6))}
    out = correlate_three_domains(flow, auth, agent)
    assert "UNAVAILABLE" in out[("C1", "C2")]["agent_domain"]


def test_tri_domain_correlation_when_resolver_maps_identities():
    flow = {("C1", "C2"): ({"NEW_PEER": 1}, "type_diversity", _ts(0))}
    auth = {("C1", "C2"): ({"PTH_SUSPECTED": 1}, _ts(5))}
    agent = {("claude-code:lab", "/etc/creds"): ({"TAINTED_SCOPE_EXPANSION": 1},
                                                  "type_diversity", _ts(6))}
    out = correlate_three_domains(flow, auth, agent,
                                  identity_resolver=lambda a: "C1")
    info = out[("C1", "C2")]
    assert info["domains"] == ["flow", "auth", "agent"]
    assert info["confidence"] == "TRI_DOMAIN_CORRELATED"
    assert "TRI-DOMAIN" in explain_tri_correlation(("C1", "C2"), info)


def test_agent_outside_window_does_not_upgrade_tier():
    flow = {("C1", "C2"): ({"NEW_PEER": 1}, "type_diversity", _ts(0))}
    auth = {("C1", "C2"): ({"PTH_SUSPECTED": 1}, _ts(5))}
    agent = {("claude-code:lab", "/etc/creds"): ({"NEW_TOOL": 1}, "type_diversity",
                                                  _ts(0) + timedelta(hours=3))}
    out = correlate_three_domains(flow, auth, agent, identity_resolver=lambda a: "C1")
    assert out[("C1", "C2")]["domains"] == ["flow", "auth"]


# -------------------------------------------------------------- API layer

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with open("agent_baseline.json", "w") as f:
        json.dump(BASELINE, f)
    import importlib
    import api_server
    importlib.reload(api_server)
    return TestClient(api_server.app)


def _agent_event(t, tool, target, action="read", provenance="trusted",
                 size=1000, external=False):
    return {"time": t, "agent_id": "svc/bot", "session_id": "s1", "tool": tool,
            "target": target, "action": action, "input_provenance": provenance,
            "result_size": size, "success": True, "external": external}


def test_agent_endpoint_accepts_events_and_stays_silent_on_normal_work(client):
    r = client.post("/ingest/agent", json=[
        _agent_event(1000, "Read", "/work/a.py"),
        _agent_event(1010, "Write", "/work/a.py", action="write"),
    ])
    assert r.status_code == 200
    assert r.json()["newly_confirmed"] == []


def test_agent_endpoint_confirms_a_real_pivot(client):
    r = client.post("/ingest/agent", json=[
        _agent_event(2000, "Read", "/data/feed.csv", provenance="untrusted", external=True),
        _agent_event(2008, "WebFetch", "https://exfil.example", action="write",
                     size=900000, external=True),
    ])
    body = r.json()
    assert len(body["newly_confirmed"]) == 1
    confirmed = body["newly_confirmed"][0]
    assert "TAINTED_SCOPE_EXPANSION" in confirmed["summary"]


def test_agent_confirmation_appears_in_shared_alerts_feed(client):
    client.post("/ingest/agent", json=[
        _agent_event(3000, "Read", "/data/feed.csv", provenance="untrusted", external=True),
        _agent_event(3008, "WebFetch", "https://exfil.example", action="write",
                     size=900000, external=True),
    ])
    alerts = client.get("/alerts").json()
    assert alerts["count"] >= 1
    assert any("AML.T0051.001" in a.get("mitre_techniques", []) for a in alerts["alerts"])


def test_agent_records_pass_shared_tamper_verification(client):
    client.post("/ingest/agent", json=[
        _agent_event(4000, "Read", "/data/feed.csv", provenance="untrusted", external=True),
        _agent_event(4008, "WebFetch", "https://exfil.example", action="write",
                     size=900000, external=True),
    ])
    assert client.get("/audit/verify").json()["intact"] is True


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
