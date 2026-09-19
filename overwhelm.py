"""
overwhelm.py — Layer 8 of the APIS project (Adaptive Protective Immune System)

Biological basis: the Japanese honeybee "hot defensive bee ball."

Asks: "are MULTIPLE INDEPENDENT conversations simultaneously showing
the same weak, ambiguous pattern?" A<->B and B<->A are canonicalized
into one conversation identity before counting (a real bug found via
a live multi-source Docker test).

Defaults now come from config.py instead of being hardcoded.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

from config import CONFIG

_DEFAULT_PAIR_THRESHOLD = CONFIG["overwhelm"]["pair_threshold"]
_DEFAULT_CORRELATION_WINDOW = CONFIG["overwhelm"]["correlation_window_seconds"]


def _conversation_key(src, dst):
    return tuple(sorted((src, dst)))


@dataclass
class OverwhelmMonitor:
    pair_threshold: int = _DEFAULT_PAIR_THRESHOLD
    correlation_window_seconds: int = _DEFAULT_CORRELATION_WINDOW
    on_collective_threat: Optional[Callable[[list], None]] = None

    _recent_events: list = field(default_factory=list, init=False, repr=False)

    def notify_repetition_burst(self, src, dst, summary, timestamp=None):
        now = timestamp or datetime.now()
        self._prune_expired(now)

        self._recent_events.append({"src": src, "dst": dst, "summary": summary, "timestamp": now})

        distinct_conversations = {_conversation_key(e["src"], e["dst"]) for e in self._recent_events}

        if len(distinct_conversations) >= self.pair_threshold:
            if self.on_collective_threat:
                self.on_collective_threat(list(self._recent_events))
            return True
        return False

    def _prune_expired(self, now):
        cutoff = now - timedelta(seconds=self.correlation_window_seconds)
        self._recent_events = [e for e in self._recent_events if e["timestamp"] >= cutoff]
