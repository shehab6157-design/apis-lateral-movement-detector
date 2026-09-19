# config.py — Structure Notes

`config.py` centralizes all tunable thresholds for the lateral-movement-detector
project into a single file, replacing constants that were previously scattered
across `quorum.py`, `detector.py`, `guard.py`, `overwhelm.py`, `feedback.py`, and
`hygiene.py`.

## Layout

- **`DEFAULT_CONFIG`** (dict) — the verified default values for every setting,
  grouped into sections:
  - `quorum` — `quorum_ratio`, `repetition_threshold`, `burst_window_seconds`,
    `window_seconds`, `repetition_volume_multiplier`, `excluded_from_confirmation`
  - `detection` — z-score thresholds (`volume_zscore_threshold`,
    `fanout_zscore_threshold`), `heavy_tail_cv_threshold`, slow-fanout tuning
    (`slow_fanout_window_hours`, `slow_fanout_base_threshold`,
    `slow_fanout_multiplier`), and `active_signal_types` (list of enabled
    detection signals: `NEW_PEER`, `OFF_HOURS`, `VOLUME_OUTLIER`,
    `FANOUT_SPIKE`, `SLOW_FANOUT`, `UNKNOWN_SSH_CLIENT`)
  - `guard` — `blocked_ports` (defaults to `[23]`, i.e. Telnet)
  - `overwhelm` — `pair_threshold`, `correlation_window_seconds`
  - `feedback` — `default_expires_days`
  - `hygiene` — `default_staleness_days`
  - `notifications` — `webhook_url` (defaults to `None`)
  - `siem` — `syslog_host`, `syslog_port`, `syslog_tcp`

- **`CONFIG_PATH`** — constant path to the optional override file, `"config.json"`.

- **`load_config(path=CONFIG_PATH)`** — builds the effective config:
  1. Deep-copies `DEFAULT_CONFIG`.
  2. If `config.json` exists, reads it (UTF-8 with BOM tolerance) and merges it
     in **per-section**, via `dict.update()` on each matching top-level section
     — so overriding one key in a section doesn't wipe out that section's other
     defaults. Unknown top-level keys are added as-is.
  3. Returns the merged dict.

- **`CONFIG`** — module-level singleton produced by calling `load_config()` at
  import time; this is what other modules (`quorum.py`, `detector.py`, etc.)
  are expected to import and read from.

- **`__main__` block** — running `config.py` directly pretty-prints the
  resolved `CONFIG` as JSON, useful for inspecting effective settings.

## Behavior notes

- If `config.json` is absent or a key is missing, behavior falls back exactly
  to `DEFAULT_CONFIG`, so the change is opt-in and non-breaking.
- The merge is shallow per-section (one level of `dict.update`), not a deep
  recursive merge — nested structures within a section value would be replaced
  wholesale rather than merged key-by-key.
