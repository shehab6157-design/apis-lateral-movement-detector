"""
test_auth_pipeline_integration.py — real, end-to-end integration tests
proving Layer 7 is genuinely unified onto the SAME shared
infrastructure the flow-side pipeline uses.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_pipeline(work_dir, events_path):
    result = subprocess.run(
        [sys.executable, "auth_pipeline.py", events_path],
        cwd=work_dir, capture_output=True, text=True, timeout=30,
    )
    return result.stdout


@pytest.fixture
def work_dir():
    tmp = tempfile.mkdtemp()
    for fname in os.listdir(PROJECT_DIR):
        if fname.endswith(".py"):
            shutil.copy(os.path.join(PROJECT_DIR, fname), tmp)
    with open(os.path.join(tmp, "auth_baseline.json"), "w") as f:
        json.dump({}, f)
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


def _write_events(path, src_user, src_computer, dst_computer):
    lines = [
        f"{100 + i * 6},{src_user},{src_user},{src_computer},{dst_computer},NTLM,Network,LogOn,Success"
        for i in range(5)
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def test_repeated_pth_confirms_via_shared_quorum(work_dir):
    events_path = os.path.join(work_dir, "events.txt")
    _write_events(events_path, "U1@DOM1", "C100", "C200")

    output = _run_pipeline(work_dir, events_path)
    assert "path: repetition_burst" in output
    assert "ESCALATE FOR REVIEW" in output
    assert "T1550.002" in output
    assert "CEF:0|APIS" in output


def test_suppressed_pth_is_learned_and_self_heals(work_dir):
    events_path = os.path.join(work_dir, "events.txt")
    _write_events(events_path, "U1@DOM1", "C100", "C200")

    run1 = _run_pipeline(work_dir, events_path)
    assert "Learned from 0 events via human-confirmed suppression" in run1

    suppress = subprocess.run(
        [sys.executable, "feedback.py", "suppress", "C100", "C200", "PTH_SUSPECTED", "test_reviewer", "confirmed legitimate"],
        cwd=work_dir, capture_output=True, text=True, timeout=30,
    )
    assert suppress.returncode == 0

    run2 = _run_pipeline(work_dir, events_path)
    assert "SUPPRESSED" in run2
    assert "Learned from 5 events via human-confirmed suppression" in run2

    run3 = _run_pipeline(work_dir, events_path)
    assert "=== 0 raw signal(s)" in run3


def test_unsuppressed_attack_never_learned_across_repeated_runs(work_dir):
    events_path = os.path.join(work_dir, "attack.txt")
    _write_events(events_path, "U2@DOM1", "C100", "C_ATTACKER")

    for run_number in range(3):
        output = _run_pipeline(work_dir, events_path)
        assert "path: repetition_burst" in output, f"run {run_number + 1} failed to confirm"
        assert "ESCALATE FOR REVIEW" in output, f"run {run_number + 1} lost escalation"
        assert "Learned from 0 events via human-confirmed suppression" in output, \
            f"run {run_number + 1} incorrectly learned from an unsuppressed attack"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
