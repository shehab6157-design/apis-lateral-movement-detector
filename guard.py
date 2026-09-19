"""
guard.py — Layer 1 of the APIS project (Adaptive Protective Immune System)

Fast, rule-based pre-filter that runs on EVERY row before anything
reaches the Queen's slower, learned-baseline analysis. BLOCKED_PORTS
now comes from config.py instead of being hardcoded.
"""

from config import CONFIG

BLOCKED_PORTS = set(CONFIG["guard"]["blocked_ports"])


def guard_check(row):
    flags = []

    port = int(row.get("dst_port", 0))
    if port in BLOCKED_PORTS:
        flags.append(f"GUARD_BLOCKED_PORT_{port}")

    size = int(row.get("bytes", 0))
    if size <= 0:
        flags.append("GUARD_MALFORMED_SIZE")

    return flags
