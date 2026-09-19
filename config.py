"""
config.py — centralizes every tunable threshold in APIS into one file,
instead of scattered module-level constants across quorum.py, detector.py,
guard.py, overwhelm.py, feedback.py, and hygiene.py.

Real deployments need to tune these against their own traffic - this
project's own testing repeatedly proved that (quorum_ratio, the
SLOW_FANOUT personalization multiplier, the burst window, all needed
real-data-driven adjustment, not guessing). Editing source code for
that is fragile and exactly the kind of thing that caused silent
regressions earlier tonight. One config file, one place to tune.

Falls back to the exact defaults already verified throughout this
project if config.json is missing or a key isn't present, so existing
behavior is completely unchanged unless someone deliberately
customizes it.
"""

import json
import os

DEFAULT_CONFIG = {
    "quorum": {
        "quorum_ratio": 0.5,
        "repetition_threshold": 5,
        "burst_window_seconds": 60,
        "window_seconds": 300,
        "repetition_volume_multiplier": 1.5,
        "excluded_from_confirmation": ["VOLUME_OUTLIER"],
    },
    "detection": {
        "volume_zscore_threshold": 3.0,
        "fanout_zscore_threshold": 2.0,
        "heavy_tail_cv_threshold": 1.0,
        "slow_fanout_window_hours": 24,
        "slow_fanout_base_threshold": 3,
        "slow_fanout_multiplier": 3,
        "active_signal_types": [
            "NEW_PEER", "OFF_HOURS", "VOLUME_OUTLIER",
            "FANOUT_SPIKE", "SLOW_FANOUT", "UNKNOWN_SSH_CLIENT",
        ],
    },
    "guard": {
        "blocked_ports": [23],
    },
    "overwhelm": {
        "pair_threshold": 2,
        "correlation_window_seconds": 120,
    },
    "feedback": {
        "default_expires_days": 90,
    },
    "hygiene": {
        "default_staleness_days": 30,
    },
    "notifications": {
        "webhook_url": None,
    },
    "siem": {
        "syslog_host": None,
        "syslog_port": 514,
        "syslog_tcp": False,
    },
}

CONFIG_PATH = "config.json"


def load_config(path=CONFIG_PATH):
    """
    Loads config.json, falling back to verified defaults for any
    missing file or missing keys. Does a per-section merge (not a full
    replace), so a config.json that only overrides one value doesn't
    wipe out the rest of that section's defaults.
    """
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as f:
            user_config = json.load(f)
        for section, values in user_config.items():
            if section in config and isinstance(values, dict):
                config[section].update(values)
            else:
                config[section] = values
    return config


CONFIG = load_config()


if __name__ == "__main__":
    print(json.dumps(CONFIG, indent=2))
