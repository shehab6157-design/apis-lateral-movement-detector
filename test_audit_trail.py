"""
test_audit_trail.py — real tests verifying the audit trail
reconstructs accurate evidence using the SAME thresholds detector.py
itself applies, so it can never silently drift out of sync with what
the detector actually does.
"""

import json
import os

import pytest

import detector
from audit_trail import explain_signal, build_quorum_reasoning, build_audit_record, save_audit_record, load_audit_records, verify_chain


PROFILE = {
    "known_peers": ["C1"], "active_hours": list(range(9, 18)),
    "avg_bytes": 150.0, "std_bytes": 50.0, "avg_fanout_per_hour": 1.0,
    "std_fanout_per_hour": 1.0, "known_ssh_banners": ["SSH-2.0-OpenSSH_8.2p1"],
}


def test_volume_outlier_zscore_matches_detector_exactly():
    """The audit trail's z-score must be bit-for-bit consistent with
    detect()'s own computation, using the same zscore() function."""
    row = {"bytes": 1602}
    evidence = explain_signal("VOLUME_OUTLIER", row, PROFILE)
    expected_z = detector.zscore(1602, PROFILE["avg_bytes"], PROFILE["std_bytes"])
    assert evidence["zscore"] == round(expected_z, 2)
    assert evidence["threshold"] == detector.VOLUME_ZSCORE_THRESHOLD


def test_new_peer_evidence_shows_known_peers():
    row = {"dst_ip": "C99"}
    evidence = explain_signal("NEW_PEER", row, PROFILE)
    assert evidence["observed_destination"] == "C99"
    assert evidence["known_peers"] == ["C1"]


def test_off_hours_evidence_shows_actual_hour():
    from datetime import datetime
    row = {"timestamp": datetime(2026, 1, 1, 23, 0, 0)}
    evidence = explain_signal("OFF_HOURS", row, PROFILE)
    assert evidence["observed_hour"] == 23
    assert 23 not in PROFILE["active_hours"]


def test_unknown_ssh_client_shows_observed_and_known_banners():
    row = {"ssh_banner": "SSH-2.0-Evil_1.0"}
    evidence = explain_signal("UNKNOWN_SSH_CLIENT", row, PROFILE)
    assert evidence["observed_banner"] == "SSH-2.0-Evil_1.0"
    assert evidence["known_banners"] == ["SSH-2.0-OpenSSH_8.2p1"]


def test_quorum_reasoning_type_diversity():
    reasoning = build_quorum_reasoning({"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity")
    assert reasoning["distinct_signal_types"] == 2
    assert reasoning["threshold_required"] == 2


def test_quorum_reasoning_repetition_burst():
    reasoning = build_quorum_reasoning({"VOLUME_OUTLIER": 5}, "repetition_burst")
    assert reasoning["signal_type"] == "VOLUME_OUTLIER"
    assert reasoning["occurrences"] == 5


def test_full_audit_record_structure():
    baseline = {"C10": PROFILE}
    alerts = [{"timestamp": "2026-01-01T09:00:00", "src_ip": "C10", "dst_ip": "C1",
               "bytes": 1602, "signals": ["VOLUME_OUTLIER"]}]
    record = build_audit_record(
        src="C10", dst="C1", summary={"VOLUME_OUTLIER": 5}, path="repetition_burst",
        action="ESCALATE_FOR_REVIEW", contributing_alerts=alerts, baseline=baseline,
        mitre_techniques=["T1570"],
    )
    assert record["pair"] == {"src": "C10", "dst": "C1"}
    assert record["action"] == "ESCALATE_FOR_REVIEW"
    assert record["suppressed"] is False
    assert record["cross_domain_correlation"]["applied"] is False
    assert record["mitre_techniques"] == ["T1570"]
    assert len(record["signal_evidence"]) == 1


def test_audit_records_persist_as_jsonl(tmp_path):
    path = str(tmp_path / "audit_test.jsonl")
    record1 = {"pair": {"src": "A", "dst": "B"}, "action": "ESCALATE_FOR_REVIEW"}
    record2 = {"pair": {"src": "C", "dst": "D"}, "action": "AUTONOMOUS_ACTION_OK"}
    save_audit_record(record1, path=path)
    save_audit_record(record2, path=path)

    loaded = load_audit_records(path=path)
    assert len(loaded) == 2
    assert loaded[0]["pair"]["src"] == "A"
    assert loaded[1]["pair"]["src"] == "C"


def test_load_audit_records_missing_file_returns_empty_list():
    assert load_audit_records(path="does_not_exist.jsonl") == []


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


# ---------------------------------------------------------------------------
# Tamper-evident hash chain (real, current regulatory requirement -
# EU AI Act Article 12, enforceable August 2, 2026)
# ---------------------------------------------------------------------------

def test_legitimate_chain_verifies_as_intact(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    for i in range(5):
        save_audit_record({"pair": {"src": f"C{i}", "dst": "C99"}, "action": "ESCALATE_FOR_REVIEW"}, path=path)

    intact, broken_at, total = verify_chain(path)
    assert intact is True
    assert broken_at is None
    assert total == 5


def test_modifying_a_past_record_is_detected(tmp_path):
    """Real, realistic scenario: an insider or attacker quietly
    downgrading a real escalation to cover up an incident."""
    path = str(tmp_path / "chain.jsonl")
    for i in range(5):
        save_audit_record({"pair": {"src": f"C{i}", "dst": "C99"}, "action": "ESCALATE_FOR_REVIEW"}, path=path)

    lines = open(path).readlines()
    tampered = json.loads(lines[2])
    tampered["action"] = "AUTONOMOUS_ACTION_OK"
    lines[2] = json.dumps(tampered) + "\n"
    open(path, "w").writelines(lines)

    intact, broken_at, total = verify_chain(path)
    assert intact is False
    assert broken_at == 2


def test_deleting_a_past_record_is_detected(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    for i in range(5):
        save_audit_record({"pair": {"src": f"C{i}", "dst": "C99"}, "action": "ESCALATE_FOR_REVIEW"}, path=path)

    lines = open(path).readlines()
    del lines[3]
    open(path, "w").writelines(lines)

    intact, broken_at, total = verify_chain(path)
    assert intact is False
    assert total == 4


def test_reordering_records_is_detected(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    for i in range(5):
        save_audit_record({"pair": {"src": f"C{i}", "dst": "C99"}, "action": "ESCALATE_FOR_REVIEW"}, path=path)

    lines = open(path).readlines()
    lines[1], lines[2] = lines[2], lines[1]
    open(path, "w").writelines(lines)

    intact, broken_at, total = verify_chain(path)
    assert intact is False


def test_empty_log_verifies_as_intact(tmp_path):
    path = str(tmp_path / "empty.jsonl")
    intact, broken_at, total = verify_chain(path)
    assert intact is True
    assert total == 0


def test_genesis_entry_chains_to_all_zero_hash(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    save_audit_record({"pair": {"src": "A", "dst": "B"}, "action": "ESCALATE_FOR_REVIEW"}, path=path)
    record = json.loads(open(path).readline())
    assert record["_prev_hash"] == "0" * 64


def test_off_hours_evidence_handles_string_timestamp():
    """Real bug found via the flood-detection integration test:
    detector.py's alerts store timestamp as an ISO string, not a
    datetime object - explain_signal must handle both."""
    row = {"timestamp": "2026-01-01T23:00:00"}
    evidence = explain_signal("OFF_HOURS", row, PROFILE)
    assert evidence["observed_hour"] == 23
