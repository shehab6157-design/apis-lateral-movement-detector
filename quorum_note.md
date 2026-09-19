# What `quorum.py` does

This file is "Layer 4" of a lateral-movement detection system. Its job is to decide
**when enough suspicious evidence has piled up about a source-to-target connection to
raise an alarm**, instead of firing on every single weak signal.

## The core idea

Other parts of the system ("detectors") watch network activity and can flag things
like "this looks like a new peer," "this connection is unusually large," "this is a
slow fan-out," etc. Any *one* of these signals on its own is too weak to be trustworthy
— it could be a false alarm. `QuorumCoordinator` collects these signals per
`(source, target)` pair and only raises an alarm once there's a **quorum** of
evidence, via two independent paths:

1. **Type diversity** — the same source→target pair triggered at least 2
   *different kinds* of detectors (the threshold is fixed at 2, see below). E.g., a
   "new peer" hit plus a "volume outlier" hit on the same pair is more convincing
   than either alone.

2. **Repetition burst** — the *same* detector type fired repeatedly (at least
   `repetition_threshold` times) within a short time window (`burst_window_seconds`).
   This catches a patient/repetitive attacker even if only one detector type ever
   triggers on them.

If either path is satisfied, `on_quorum_reached` (a callback) is invoked and/or an
alarm is raised through an alarm bus, and the accumulated evidence for that pair is
cleared.

## Key mechanics

- **`record()` / `record_batch()`** — the main entry points. Detectors call these to
  report that a signal fired for a given source/target (optionally with multiple
  signal types at once, so simultaneous signals aren't split across separate calls
  and missed by processing order).
- **Time-windowed memory** — old evidence outside `window_seconds` is pruned
  automatically (`_prune_expired`), so evidence has to build up within a reasonable
  timeframe to count.
- **Per-source repetition thresholds** (`repetition_threshold_fn`) — lets the system
  use a higher "chattiness tolerance" for known busy infrastructure (e.g. a domain
  controller) instead of one flat threshold for every device, avoiding false positives
  on legitimately repetitive automated hosts.
- **Excluded types for diversity** (`type_diversity_excluded_types`) — certain signal
  types (like `VOLUME_OUTLIER`) are still shown to humans/SIEM but are not allowed to
  count toward the "2 different types" diversity check by themselves, because in
  practice they caused too many false positives when combined with just one other
  weak signal. They can still trigger an alarm via the repetition-burst path, though,
  since repeated volume-outlier hits are a much stronger, rarer signal than a single
  hit.
- **State persistence (`save_state()` / `load_state()`)** — all not-yet-confirmed
  evidence is saved to a JSON file so a service restart doesn't silently wipe out
  partial progress toward quorum (e.g., an attacker who's already accumulated 2 of
  the 3 needed signals).

## Why it looks the way it does (from the file's own history notes)

The docstring at the top records several rounds of real-world tuning:
- v1 used type-diversity only and missed a repeated-single-signal attack.
- v2 added repetition detection, which then caused false positives on fast bursts of
  legitimate traffic — v3 fixed this by requiring genuine burstiness (a real time
  window, not just a count).
- v4 made `record_batch` atomic so simultaneous signals for the same pair are
  recorded together before quorum is checked.
- v5 fixed the diversity threshold at a constant `2` after discovering that scaling
  it with the total number of detector types broke 3 of 5 real detections when a
  5th detector type (`SLOW_FANOUT`) was added.
- v6 added config-driven defaults and state persistence for production robustness.

In short: `quorum.py` is an evidence-correlation gatekeeper that turns noisy,
individually-weak detection signals into a confident alarm only when there's
sufficient independent corroboration or repeated reinforcement, with thresholds and
exclusions tuned against real attack and false-positive data (including evaluation
against the public LANL dataset).
