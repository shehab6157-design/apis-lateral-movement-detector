"""
test_auth_detector.py — real behavioral tests for Layer 7
(Chemical-Mimicry Detection), covering Pass-the-Hash and
Pass-the-Ticket pattern detection against the real, verified LANL
auth.txt row format.
"""

import pytest

from auth_detector import parse_auth_row, ChemicalMimicryDetector


def _row(time_s, src_user, dst_user, src_computer, dst_computer,
         auth_type, logon_type, orientation="LogOn", success="Success"):
    line = f"{time_s},{src_user},{dst_user},{src_computer},{dst_computer},{auth_type},{logon_type},{orientation},{success}"
    return parse_auth_row(line)


def test_parse_auth_row_matches_real_lanl_format():
    event = parse_auth_row("1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success")
    assert event["time"] == 1
    assert event["src_user"] == "C625$@DOM1"
    assert event["dst_user"] == "U147@DOM1"
    assert event["src_computer"] == "C625"
    assert event["dst_computer"] == "C625"
    assert event["auth_type"] == "Negotiate"
    assert event["logon_type"] == "Batch"
    assert event["orientation"] == "LogOn"
    assert event["success"] == "Success"


def test_parse_auth_row_rejects_malformed_lines():
    assert parse_auth_row("not,a,valid,row") is None
    assert parse_auth_row("") is None


def test_pth_fires_on_cross_computer_ntlm_network_logon():
    detector = ChemicalMimicryDetector()
    event = _row(100, "U1@DOM1", "U1@DOM1", "C100", "C200", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(event)


def test_pth_does_not_fire_on_same_computer_ntlm_logon():
    detector = ChemicalMimicryDetector()
    event = _row(150, "U1@DOM1", "U1@DOM1", "C100", "C100", "NTLM", "Network")
    assert "PTH_SUSPECTED" not in detector.process_event(event)


def test_pth_does_not_fire_on_non_ntlm_cross_computer_logon():
    detector = ChemicalMimicryDetector()
    event = _row(150, "U1@DOM1", "U1@DOM1", "C100", "C200", "Kerberos", "Network")
    assert "PTH_SUSPECTED" not in detector.process_event(event)


def test_pth_does_not_fire_on_unknown_computers():
    detector = ChemicalMimicryDetector()
    event = _row(150, "U1@DOM1", "U1@DOM1", "?", "C200", "NTLM", "Network")
    assert "PTH_SUSPECTED" not in detector.process_event(event)


def test_ptt_fires_on_first_kerberos_event_for_a_user():
    detector = ChemicalMimicryDetector()
    event = _row(200, "U2@DOM1", "U2@DOM1", "C300", "C400", "Kerberos", "Network")
    assert "PTT_SUSPECTED" in detector.process_event(event)


def test_ptt_does_not_fire_once_user_has_recent_history():
    detector = ChemicalMimicryDetector()
    first = _row(300, "U3@DOM1", "U3@DOM1", "C500", "C600", "Kerberos", "Network")
    second = _row(350, "U3@DOM1", "U3@DOM1", "C500", "C700", "Kerberos", "Network")
    detector.process_event(first)
    assert "PTT_SUSPECTED" not in detector.process_event(second)


def test_ptt_fires_again_after_the_lookback_window_expires():
    detector = ChemicalMimicryDetector()
    first = _row(0, "U6@DOM1", "U6@DOM1", "C1", "C2", "Kerberos", "Network")
    much_later = _row(3600 * 3, "U6@DOM1", "U6@DOM1", "C1", "C3", "Kerberos", "Network")
    detector.process_event(first)
    assert "PTT_SUSPECTED" in detector.process_event(much_later)


def test_failed_logon_never_flags_anything():
    detector = ChemicalMimicryDetector()
    event = _row(400, "U4@DOM1", "U4@DOM1", "C800", "C900", "NTLM", "Network", success="Fail")
    assert detector.process_event(event) == []


def test_logoff_events_never_flag_anything():
    detector = ChemicalMimicryDetector()
    event = _row(450, "U5@DOM1", "U5@DOM1", "C1", "C2", "NTLM", "Network", orientation="LogOff")
    assert detector.process_event(event) == []


def test_unknown_user_never_tracked_or_flagged_for_ptt():
    detector = ChemicalMimicryDetector()
    event = _row(500, "?", "?", "C1", "C2", "Kerberos", "Network")
    assert detector.process_event(event) == []


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


def test_machine_account_does_not_trigger_pth():
    detector = ChemicalMimicryDetector()
    event = _row(100, "C1000$@DOM1", "C1000$@DOM1", "C100", "C200", "NTLM", "Network")
    assert detector.process_event(event) == []


def test_machine_account_does_not_trigger_ptt():
    detector = ChemicalMimicryDetector()
    event = _row(200, "C500$@DOM1", "C500$@DOM1", "C300", "C400", "Kerberos", "Network")
    assert detector.process_event(event) == []


def test_anonymous_logon_does_not_trigger_pth():
    detector = ChemicalMimicryDetector()
    event = _row(300, "ANONYMOUS LOGON@C586", "ANONYMOUS LOGON@C586", "C10", "C586", "NTLM", "Network")
    assert detector.process_event(event) == []


def test_real_human_user_still_triggers_after_exclusion():
    detector = ChemicalMimicryDetector()
    event = _row(400, "U5481@DOM1", "U5481@DOM1", "C1000", "C528", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(event)


def test_pth_not_flagged_for_known_destination_with_baseline():
    baseline = {"U5481@DOM1": {"known_destinations": ["C1065", "C457", "C586"]}}
    detector = ChemicalMimicryDetector(baseline=baseline)
    known = _row(100, "U5481@DOM1", "U5481@DOM1", "C1000", "C1065", "NTLM", "Network")
    assert "PTH_SUSPECTED" not in detector.process_event(known)


def test_pth_still_flagged_for_genuinely_new_destination_with_baseline():
    baseline = {"U5481@DOM1": {"known_destinations": ["C1065", "C457", "C586"]}}
    detector = ChemicalMimicryDetector(baseline=baseline)
    novel = _row(100, "U5481@DOM1", "U5481@DOM1", "C1000", "C999", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(novel)


def test_pth_flags_unconditionally_without_a_baseline():
    detector = ChemicalMimicryDetector()
    event = _row(100, "U1@DOM1", "U1@DOM1", "C100", "C200", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(event)


def test_pth_flags_unknown_user_conservatively_with_baseline():
    baseline = {"U5481@DOM1": {"known_destinations": ["C1065"]}}
    detector = ChemicalMimicryDetector(baseline=baseline)
    event = _row(100, "U_NEVER_SEEN@DOM1", "U_NEVER_SEEN@DOM1", "C1", "C2", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(event)


def test_ptt_not_flagged_for_known_destination_with_baseline():
    baseline = {"U1131@DOM1": {"known_destinations": ["C467", "C1065", "C625"]}}
    detector = ChemicalMimicryDetector(baseline=baseline)
    known = _row(100, "U1131@DOM1", "U1131@DOM1", "C100", "C467", "Kerberos", "Network")
    assert "PTT_SUSPECTED" not in detector.process_event(known)


def test_ptt_still_flagged_for_genuinely_new_destination_with_baseline():
    baseline = {"U1131@DOM1": {"known_destinations": ["C467", "C1065", "C625"]}}
    detector = ChemicalMimicryDetector(baseline=baseline)
    novel = _row(100, "U1131@DOM1", "U1131@DOM1", "C100", "C999", "Kerberos", "Network")
    assert "PTT_SUSPECTED" in detector.process_event(novel)


def test_high_privilege_user_gets_no_exemption():
    baseline = {"U66@DOM1": {"known_destinations": [f"C{i}" for i in range(105)]}}
    detector = ChemicalMimicryDetector(baseline=baseline, high_privilege_threshold=13)
    event = _row(100, "U66@DOM1", "U66@DOM1", "C1000", "C50", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(event)


def test_normal_user_still_gets_exemption_below_privilege_threshold():
    baseline = {"U1@DOM1": {"known_destinations": ["C1", "C2", "C3", "C4", "C5", "C6", "C7"]}}
    detector = ChemicalMimicryDetector(baseline=baseline, high_privilege_threshold=13)
    event = _row(100, "U1@DOM1", "U1@DOM1", "C100", "C3", "NTLM", "Network")
    assert "PTH_SUSPECTED" not in detector.process_event(event)


def test_privilege_threshold_is_configurable():
    baseline = {"U1@DOM1": {"known_destinations": ["C1", "C2", "C3"]}}
    detector = ChemicalMimicryDetector(baseline=baseline, high_privilege_threshold=2)
    event = _row(100, "U1@DOM1", "U1@DOM1", "C100", "C1", "NTLM", "Network")
    assert "PTH_SUSPECTED" in detector.process_event(event)
