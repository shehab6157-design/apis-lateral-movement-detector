"""
test_adaptive_integration.py — real, end-to-end integration tests for
the adaptive baseline wired into detector.py's actual CLI, run as
subprocesses against real temp files.
"""

import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

BASELINE = {
    "C10": {"known_peers": ["C1"], "active_hours": list(range(9, 18)),
            "avg_bytes": 150, "std_bytes": 50, "avg_fanout_per_hour": 1.0,
            "std_fanout_per_hour": 1.0, "known_ssh_banners": []}
}


def _write_csv(path, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "dst_ip", "dst_port", "bytes", "ssh_banner"])
        writer.writeheader()
        writer.writerows(rows)


def _run_detector(work_dir, traffic_path):
    result = subprocess.run(
        [sys.executable, "detector.py", traffic_path],
        cwd=work_dir, capture_output=True, text=True, timeout=30,
    )
    return result.stdout


@pytest.fixture
def work_dir():
    tmp = tempfile.mkdtemp()
    for fname in os.listdir(PROJECT_DIR):
        if fname.endswith(".py"):
            shutil.copy(os.path.join(PROJECT_DIR, fname), tmp)
    with open(os.path.join(tmp, "baseline.json"), "w") as f:
        json.dump(BASELINE, f)
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


def test_suppressed_repetition_burst_is_learned_and_self_heals(work_dir):
    traffic_path = os.path.join(work_dir, "traffic.csv")
    rows = [
        {"timestamp": f"2026-01-01T09:00:{i * 6:02d}", "src_ip": "C10", "dst_ip": "C1",
         "dst_port": 22, "bytes": 1602, "ssh_banner": ""}
        for i in range(5)
    ]
    _write_csv(traffic_path, rows)

    run1 = _run_detector(work_dir, traffic_path)
    assert "path: repetition_burst" in run1
    assert "Learned from 0 rows via human-confirmed suppression" in run1

    suppress = subprocess.run(
        [sys.executable, "feedback.py", "suppress", "C10", "C1", "VOLUME_OUTLIER", "test_reviewer", "confirmed legitimate"],
        cwd=work_dir, capture_output=True, text=True, timeout=30,
    )
    assert suppress.returncode == 0

    run2 = _run_detector(work_dir, traffic_path)
    assert "SUPPRESSED" in run2
    assert "Learned from 5 rows via human-confirmed suppression" in run2

    run3 = _run_detector(work_dir, traffic_path)
    assert "=== 5 raw alert(s)" not in run3
    assert "0 raw alert(s)" in run3


def test_unsuppressed_attack_is_never_learned_across_repeated_runs(work_dir):
    traffic_path = os.path.join(work_dir, "attack.csv")
    rows = [
        {"timestamp": f"2026-01-01T09:00:{i * 6:02d}", "src_ip": "C10", "dst_ip": "C_ATTACKER",
         "dst_port": 22, "bytes": 50000, "ssh_banner": ""}
        for i in range(5)
    ]
    _write_csv(traffic_path, rows)

    for run_number in range(3):
        output = _run_detector(work_dir, traffic_path)
        assert "path: repetition_burst" in output, f"run {run_number + 1} failed to confirm"
        assert "ESCALATE FOR REVIEW" in output, f"run {run_number + 1} lost escalation"
        assert "Learned from 0 rows via human-confirmed suppression" in output, \
            f"run {run_number + 1} incorrectly learned from an unsuppressed attack"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
