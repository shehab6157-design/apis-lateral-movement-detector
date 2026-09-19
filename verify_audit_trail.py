"""
verify_audit_trail.py — real, standalone CLI check of the audit
trail's tamper-evident hash chain. Run this any time to prove the
recorded history of every autonomous decision has not been altered.

Usage:
    python3 verify_audit_trail.py [path_to_audit_trail.jsonl]
"""

import sys

from audit_trail import verify_chain

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "audit_trail.jsonl"

    intact, broken_at, total = verify_chain(path)

    print(f"Verifying {path} ({total} record(s))...\n")

    if intact:
        print(f"✓ INTACT - all {total} record(s) verified. No alteration, deletion, or reordering detected.")
        sys.exit(0)
    else:
        print(f"✗ TAMPERING DETECTED at record index {broken_at}.")
        print(f"  Everything before index {broken_at} is verified intact.")
        print(f"  Everything from index {broken_at} onward cannot be trusted without further investigation.")
        sys.exit(1)
