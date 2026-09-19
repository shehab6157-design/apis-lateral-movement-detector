"""
test_api_server.py — real tests for the FastAPI service, using
FastAPI's TestClient against the actual app (no mocking of the
detection pipeline itself).
"""

import os

import pytest
from fastapi.testclient import TestClient


BASELINE = {
    "C10": {"known_peers": ["C1"], "active_hours": list(range(9, 18)),
            "avg_bytes": 150, "std_bytes": 50, "avg_fanout_per_hour": 1.0,
            "std_fanout_per_hour": 1.0, "known_ssh_banners": []}
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A fresh app instance per test, working in an isolated temp
    directory so tests never interfere with each other or with real
    project files."""
    monkeypatch.chdir(tmp_path)
    import json
    with open("baseline.json", "w") as f:
        json.dump(BASELINE, f)

    import importlib
    import api_server
    importlib.reload(api_server)
    return TestClient(api_server.app)


def _burst_rows(n=5, dst="C1", bytes_val=1602):
    return [{"timestamp": f"2026-01-01T09:00:{i * 6:02d}", "src_ip": "C10", "dst_ip": dst, "bytes": bytes_val}
            for i in range(n)]


def test_health_check(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ingest_confirms_real_repetition_burst(client):
    r = client.post("/ingest/flow", json=_burst_rows())
    assert r.status_code == 200
    body = r.json()
    assert body["rows_processed"] == 5
    assert len(body["newly_confirmed"]) == 1
    assert body["newly_confirmed"][0]["path"] == "repetition_burst"
    assert body["newly_confirmed"][0]["action"] == "ESCALATE_FOR_REVIEW"


def test_evidence_accumulates_across_separate_calls(client):
    """Critical: quorum state must persist across separate requests,
    exactly like a real running service."""
    r1 = client.post("/ingest/flow", json=_burst_rows(n=2))
    assert r1.json()["newly_confirmed"] == []

    r2 = client.post("/ingest/flow", json=_burst_rows(n=3)[2:] if False else
                      [{"timestamp": f"2026-01-01T09:00:{i * 6:02d}", "src_ip": "C10", "dst_ip": "C1", "bytes": 1602}
                       for i in range(2, 5)])
    assert len(r2.json()["newly_confirmed"]) == 1


def test_get_alerts_returns_confirmed_detection(client):
    client.post("/ingest/flow", json=_burst_rows())
    r = client.get("/alerts")
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["alerts"][0]["pair"]["src"] == "C10"


def test_get_alerts_filters_by_action(client):
    client.post("/ingest/flow", json=_burst_rows())
    r = client.get("/alerts", params={"action": "AUTONOMOUS_ACTION_OK"})
    assert r.json()["count"] == 0

    r2 = client.get("/alerts", params={"action": "ESCALATE_FOR_REVIEW"})
    assert r2.json()["count"] == 1


def test_get_alert_detail_returns_full_provenance(client):
    client.post("/ingest/flow", json=_burst_rows())
    r = client.get("/alerts/0")
    assert r.status_code == 200
    body = r.json()
    assert "signal_evidence" in body
    assert len(body["signal_evidence"]) == 5
    assert body["signal_evidence"][0]["zscore"] > 0


def test_get_alert_detail_404_for_missing_index(client):
    r = client.get("/alerts/999")
    assert r.status_code == 404


def test_ingest_with_no_confirmation_returns_empty_lists(client):
    rows = [{"timestamp": "2026-01-01T09:00:00", "src_ip": "C10", "dst_ip": "C1", "bytes": 150}]
    r = client.post("/ingest/flow", json=rows)
    assert r.json()["raw_signals"] == 0
    assert r.json()["newly_confirmed"] == []


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
