"""
drift_monitor.py — detects when a device's or user's adaptive baseline
has drifted unusually far, in one consistent direction, over an
extended window - visibility this project's existing adaptive
baselines (rolling_baseline.py, adaptive_auth_baseline.py) do not
otherwise provide.

Real, current, actively-researched grounding, not assumed: "Boiling
Frog" poisoning of adaptive/continual-learning anomaly baselines is a
named, well-documented attack class going back over a decade (Kim,
"The Frog-Boiling Attack," 2009; Rubinstein et al. on PCA poisoning),
with active current research (a 2026 university thesis specifically
titled "Frog-Boiling Poisoning Against Drift-Aware Continual
Learners"). Real, current analysis of this exact problem states the
open tension plainly: "incorrectly updating a model with anomalous
data leads to model poisoning, while failing to update during
legitimate drift leads to a flood of false alarms" - existing drift
detectors are NOT capable of reliably differentiating real drift from
adversarial poisoning; this is stated as an open research problem,
not a solved one.

HONEST SCOPE: this module does not claim to solve that open problem.
It implements a real, standard, currently-recommended MITIGATION -
distinguishing SLOW, SUSTAINED, ONE-DIRECTIONAL drift (the boiling-frog
signature) from ordinary, roughly zero-mean fluctuation - giving a
human visibility into unusually large cumulative shifts for manual
review, the same complementary role hygiene.py already plays for
stale trust relationships: this project's existing poisoning-safety
guarantee (rolling_baseline.py never learns from confirmed,
unsuppressed detections) still holds and is unaffected; this adds a
SEPARATE, longer-horizon check on top of it.
"""

from collections import deque


class DriftMonitor:
    """
    Tracks a rolling history of a numeric baseline value (e.g.
    avg_bytes) for one entity (a device or user) and flags when it has
    drifted UNUSUALLY FAR in ONE CONSISTENT DIRECTION over a long
    window - the real signature of gradual poisoning, as opposed to
    ordinary, roughly zero-mean fluctuation around a stable norm.
    """

    def __init__(self, window_size=50, drift_ratio_threshold=1.5, consistency_threshold=0.7):
        # window_size: how many checkpoints define "the long window" -
        # deliberately much longer than a single EWMA update, since the
        # whole point is catching what a short-horizon view cannot.
        self.window_size = window_size
        # drift_ratio_threshold: the baseline must have moved by at
        # least this MULTIPLE of its value at the start of the window
        # to even be considered for a drift alert.
        self.drift_ratio_threshold = drift_ratio_threshold
        # consistency_threshold: the fraction of individual steps
        # within the window that must move in the SAME direction as
        # the overall trend - ordinary fluctuation is roughly 50/50;
        # sustained poisoning pushes consistently one way.
        self.consistency_threshold = consistency_threshold
        self.history = {}  # entity_id -> deque of recent values

    def observe(self, entity_id, value):
        """
        Records one new checkpoint value for this entity (call this
        alongside each rolling-baseline update - e.g. once per
        observe_safe() call). Returns a dict describing drift status
        for this entity right now.
        """
        history = self.history.setdefault(entity_id, deque(maxlen=self.window_size))
        history.append(value)
        return self._evaluate(history)

    def peek(self, entity_id):
        """Returns the current drift status for an entity WITHOUT
        recording a new observation - useful for reporting after a
        batch of observe() calls elsewhere."""
        history = self.history.get(entity_id)
        if history is None:
            return {"drift_alert": False, "reason": "no history recorded"}
        return self._evaluate(history)

    def _evaluate(self, history):
        if len(history) < self.window_size:
            return {"drift_alert": False, "reason": "insufficient history", "window_fill": f"{len(history)}/{self.window_size}"}

        start_value = history[0]
        end_value = history[-1]

        if start_value == 0:
            return {"drift_alert": False, "reason": "starting value is zero, ratio undefined"}

        ratio = end_value / start_value if start_value > 0 else float("inf")
        direction = 1 if end_value > start_value else -1

        steps_in_trend_direction = 0
        for i in range(1, len(history)):
            step = history[i] - history[i - 1]
            if step != 0 and (step > 0) == (direction > 0):
                steps_in_trend_direction += 1
        consistency = steps_in_trend_direction / (len(history) - 1)

        is_large_drift = ratio >= self.drift_ratio_threshold or ratio <= (1 / self.drift_ratio_threshold)
        is_consistent = consistency >= self.consistency_threshold

        drift_alert = is_large_drift and is_consistent

        return {
            "drift_alert": drift_alert,
            "start_value": start_value,
            "end_value": end_value,
            "ratio": round(ratio, 2),
            "consistency": round(consistency, 2),
            "reason": (
                f"Baseline moved {ratio:.2f}x over the last {self.window_size} observations, "
                f"with {consistency:.0%} of individual steps moving in the same direction - "
                f"the sustained, one-directional signature of gradual (boiling-frog) poisoning, "
                f"not ordinary fluctuation."
                if drift_alert else
                "No sustained one-directional drift detected."
            ),
        }
