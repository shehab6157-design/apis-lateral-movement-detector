"""
quorum.py — Layer 4 of the APIS project (Adaptive Protective Immune System)

Full history: v1 (type-diversity only, missed a real repeated-single-
signal attack) -> v2 (added repetition path, caused false positives on
fast legitimate bursts) -> v3 (repetition path requires genuine burstiness)
-> v4 (record_batch preserves all simultaneous signals atomically) ->
v5 (threshold fixed at 2 regardless of type count, after adding a 5th
type broke 3 of 5 real detections) -> v6 (config-driven defaults +
state persistence, this version).

STATE PERSISTENCE: previously, all partially-accumulated evidence
lived only in memory - a service restart mid-accumulation would
silently lose it, meaning a slow, patient attacker's progress toward
quorum could be wiped out by nothing more than a routine restart.
save_state()/load_state() let that evidence survive a restart.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional
import json

from config import CONFIG

_DEFAULT_QUORUM_RATIO = CONFIG["quorum"]["quorum_ratio"]
_DEFAULT_REPETITION_THRESHOLD = CONFIG["quorum"]["repetition_threshold"]
_DEFAULT_BURST_WINDOW_SECONDS = CONFIG["quorum"]["burst_window_seconds"]
_DEFAULT_WINDOW_SECONDS = CONFIG["quorum"]["window_seconds"]


@dataclass
class QuorumCoordinator:
    active_detector_types: set[str]
    quorum_ratio: float = _DEFAULT_QUORUM_RATIO
    repetition_threshold: int = _DEFAULT_REPETITION_THRESHOLD
    burst_window_seconds: int = _DEFAULT_BURST_WINDOW_SECONDS
    window_seconds: int = _DEFAULT_WINDOW_SECONDS
    on_quorum_reached: Optional[Callable[[str, str, dict[str, int], str], None]] = None
    # Optional per-source override, found necessary after a real evaluation
    # against the public LANL dataset: infrastructure/management hosts
    # making many small, automated, repetitive connections (e.g. a domain
    # controller) were flagged as bursting attackers by one flat
    # repetition_threshold applied to every device regardless of its
    # normal chattiness. When provided, this callable receives the
    # source device and returns the threshold to use for it INSTEAD of
    # self.repetition_threshold. Defaults to None, which preserves the
    # exact prior flat-threshold behavior for every existing caller.
    repetition_threshold_fn: Optional[Callable[[str], int]] = None
    # Signal types that are computed and shown to a human/SIEM, but are
    # NOT trusted to count toward type_diversity confirmation on their
    # own - found necessary after FOUR different statistical approaches
    # to VOLUME_OUTLIER were tried and measured against the real LANL
    # dataset, and every one put VOLUME_OUTLIER at the center of the
    # false-positive problem, specifically via the type_diversity path
    # (a single VOLUME_OUTLIER + a single NEW_PEER was enough to
    # confirm). Deliberately does NOT affect repetition_burst - a real,
    # previously-verified attack in this project's own Docker lab
    # relied on REPEATED VOLUME_OUTLIER hits via repetition_burst,
    # which is a much stronger, rarer signal than type_diversity's
    # "just once each" bar, and stayed reliable throughout every one of
    # the four VOLUME_OUTLIER experiments.
    type_diversity_excluded_types: Optional[set[str]] = None

    _pending: dict[tuple[str, str], dict[str, list[datetime]]] = field(
        default_factory=dict, init=False, repr=False
    )
    _alarm_bus: Optional[object] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self.active_detector_types) < 2:
            raise ValueError(
                "QuorumCoordinator needs at least 2 independent detector "
                "types to function."
            )
        # CORRECTED after a real regression: the threshold used to scale
        # with the TOTAL number of active types. Adding a 5th type (SLOW_FANOUT)
        # mechanically raised it to 3 and caused 3 of 5 previously-confirmed
        # real attack pairs to stop being detected. Fixed at 2, from evidence.
        self._type_threshold = 2

    @property
    def threshold(self) -> int:
        return self._type_threshold

    def record(
        self,
        detector_type: str,
        source: str,
        target: str,
        timestamp: Optional[datetime] = None,
    ) -> bool:
        return self.record_batch([detector_type], source, target, timestamp)

    def record_batch(
        self,
        detector_types: list[str],
        source: str,
        target: str,
        timestamp: Optional[datetime] = None,
    ) -> bool:
        for detector_type in detector_types:
            if detector_type not in self.active_detector_types:
                raise ValueError(
                    f"'{detector_type}' is not in active_detector_types "
                    f"{self.active_detector_types} - register it there first."
                )

        now = timestamp or datetime.now()
        key = (source, target)
        seen = self._pending.setdefault(key, {})

        self._prune_expired(seen, now)

        for detector_type in detector_types:
            ts_list = seen.setdefault(detector_type, [])
            ts_list.append(now)
            ts_list.sort()

        diversity_types = set(seen.keys())
        if self.type_diversity_excluded_types:
            diversity_types = diversity_types - self.type_diversity_excluded_types
        distinct_types = len(diversity_types)
        type_diversity_met = distinct_types >= self._type_threshold

        base_rep_threshold = (
            self.repetition_threshold_fn(source)
            if self.repetition_threshold_fn is not None
            else self.repetition_threshold
        )

        if self._alarm_bus is not None:
            rep_threshold, burst_window = self._alarm_bus.effective_thresholds(
                base_rep_threshold, self.burst_window_seconds, at_time=now
            )
        else:
            rep_threshold, burst_window = base_rep_threshold, self.burst_window_seconds

        repetition_met = False
        for t, ts_list in seen.items():
            if len(ts_list) >= rep_threshold:
                window = ts_list[-rep_threshold:]
                span = (window[-1] - window[0]).total_seconds()
                if span <= burst_window:
                    repetition_met = True
                    break

        if type_diversity_met or repetition_met:
            summary = {t: len(ts_list) for t, ts_list in seen.items()}
            path = "type_diversity" if type_diversity_met else "repetition_burst"
            if self.on_quorum_reached:
                self.on_quorum_reached(source, target, summary, path)
            if self._alarm_bus is not None:
                self._alarm_bus.raise_alarm(source, target, summary, path, timestamp=now)
            del self._pending[key]
            return True

        return False

    def status(self, source: str, target: str) -> dict[str, list[datetime]]:
        key = (source, target)
        seen = self._pending.get(key, {})
        self._prune_expired(seen, datetime.now())
        return dict(seen)

    def _prune_expired(self, seen: dict[str, list[datetime]], now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window_seconds)
        for t in list(seen.keys()):
            seen[t] = [ts for ts in seen[t] if ts >= cutoff]
            if not seen[t]:
                del seen[t]

    def save_state(self, path: str = "quorum_state.json") -> None:
        """Persist all pending (not-yet-confirmed) evidence to disk, so a
        service restart doesn't silently wipe out partial progress toward
        quorum - e.g. a patient attacker's 2-of-3 accumulated NEW_PEER
        events, or a legitimate device's partially-built corroboration."""
        serializable = {
            f"{src}||{dst}": {t: [ts.isoformat() for ts in ts_list] for t, ts_list in seen.items()}
            for (src, dst), seen in self._pending.items()
        }
        with open(path, "w") as f:
            json.dump(serializable, f, indent=2)

    def load_state(self, path: str = "quorum_state.json") -> bool:
        """Restore pending evidence saved by save_state(). Returns True if
        a state file was found and loaded, False if there was nothing to
        load (a fresh start, not an error)."""
        import os
        if not os.path.exists(path):
            return False
        with open(path, encoding="utf-8-sig") as f:
            raw = json.load(f)
        self._pending = {}
        for key, seen in raw.items():
            src, dst = key.split("||", 1)
            self._pending[(src, dst)] = {
                t: [datetime.fromisoformat(ts) for ts in ts_list] for t, ts_list in seen.items()
            }
        return True
