"""
flood_detection.py — detects when the detection system itself is
being deliberately flooded with low-confidence noise, and protects
genuine high-confidence signals from being buried in it.

Real, current, MITRE-documented grounding: adversaries deliberately
generating high alert volumes to overwhelm analysts and mask real
intrusion activity is a documented technique - MITRE ATT&CK Defense
Evasion (TA0005), specifically Impair Defenses (T1562). Current 2026
industry research on SOC alert fatigue explicitly names this tactic.
Without a countermeasure, this project's own confidence scoring would
treat a real detection identically whether it arrives during a quiet
period or during a deliberate flood designed to bury it - exactly
backwards from what the real threat model requires.

Design: mirrors rolling_baseline.py's approach - a continuously
updated EWMA baseline of NORMAL raw-alert volume (not confirmed
detections; the raw, uncorroborated signal rate), so "normal" adapts
over time the same way device behavior does. A flood condition is
declared when the real, current raw-alert rate significantly exceeds
this adaptive baseline. Any genuine high-confidence detection
(cross-domain correlated, or type_diversity) that occurs DURING a
flood condition is flagged and boosted, rather than left to compete
for attention against the very noise trying to hide it.
"""

import math

FLOOD_ZSCORE_THRESHOLD = 3.0   # matches this project's own VOLUME_ZSCORE_THRESHOLD convention
FLOOD_CONFIDENCE_BOOST = 20.0  # a real detection during a documented evasion attempt deserves MORE attention, not the same


class FloodDetector:
    """
    Tracks the real, adaptive baseline of raw-alert volume per time
    window and flags when the current window's volume constitutes a
    real flood condition relative to that baseline - the same EWMA
    principle already used for numeric baselines elsewhere in this
    project, applied to alert volume itself.
    """

    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self.avg_rate = None
        self.std_rate = 1.0
        self.history = []

    def observe_window(self, raw_alert_count):
        """
        Call once per time window (e.g. once per minute of processing)
        with the number of RAW alerts seen in that window. Returns
        (is_flood, zscore) for that window BEFORE updating the
        baseline with it - so a genuine flood is judged against what
        was normal before it started, not diluted by itself.
        """
        if self.avg_rate is None:
            self.avg_rate = float(raw_alert_count)
            self.std_rate = max(raw_alert_count * 0.3, 1.0)
            self.history.append(raw_alert_count)
            return False, 0.0

        z = (raw_alert_count - self.avg_rate) / self.std_rate if self.std_rate > 0 else 0.0
        is_flood = z >= FLOOD_ZSCORE_THRESHOLD

        # Only adapt the baseline from non-flood windows - the same
        # poisoning-safety principle as rolling_baseline.py: a real
        # flood must never be allowed to quietly become "the new
        # normal," or the countermeasure defeats itself.
        if not is_flood:
            old_mean = self.avg_rate
            old_var = self.std_rate ** 2
            self.avg_rate = self.alpha * old_mean + (1 - self.alpha) * raw_alert_count
            new_var = (1 - self.alpha) * (old_var + self.alpha * (raw_alert_count - old_mean) ** 2)
            self.std_rate = max(math.sqrt(new_var), 1.0)

        self.history.append(raw_alert_count)
        return is_flood, round(z, 2)


def confirmation_shape(summary, path):
    """A confirmation's 'shape' - its confirmation path plus the SET
    of signal types involved (ignoring exact counts/details). Decoys
    generated en masse to create a flood tend to share the same
    simple shape as each other; a genuine attack tends to be a real
    outlier even within the noise, either in shape or in evidence
    strength."""
    return (path, frozenset(summary.keys()))


def compute_window_rarity(confirmations, rarity_fraction=0.1):
    """
    confirmations: list of (summary, path) tuples, ALL from the SAME
    flood window. Returns a list of booleans (same order/length) -
    True where that confirmation's shape is RARE within this window
    (appears in at most rarity_fraction of the window's confirmations,
    or just once), False where it is COMMON (characteristic of a
    mass-generated decoy wave sharing the same simple shape).
    """
    from collections import Counter

    shapes = [confirmation_shape(s, p) for s, p in confirmations]
    shape_counts = Counter(shapes)
    total = len(confirmations)
    threshold = max(1, total * rarity_fraction)

    return [shape_counts[shape] <= threshold for shape in shapes]


def apply_flood_awareness(confidence_score, breakdown, is_flood_active, flood_zscore=None, is_rare_in_window=True):
    """
    Given a confidence score already computed by confidence_scoring.py,
    boosts it and annotates the breakdown if a confirmed detection is
    BOTH (a) occurring during an active flood condition and (b) a real
    outlier relative to that same flood, rather than one of many
    structurally-identical confirmations making up the flood itself -
    directly countering the documented T1562 evasion pattern.

    Found necessary via two rounds of real, adversarial-scenario
    testing, not assumed: an earlier version boosted every confirmed
    tier uniformly during a flood, which raised the real attack's
    score but ALSO raised the decoys' scores by the same amount (since
    the decoys themselves confirmed via a protected tier too) - the
    relative ranking barely improved, defeating the point. Only
    boosting confirmations whose SHAPE is rare within their own window
    (see compute_window_rarity) correctly separates the genuine
    outlier from the mass-generated noise trying to hide it.
    """
    protected_tiers = {"CROSS_DOMAIN_CORRELATED", "type_diversity", "repetition_burst"}
    if not is_flood_active or breakdown.get("tier") not in protected_tiers or not is_rare_in_window:
        return confidence_score, breakdown

    boosted_score = min(confidence_score + FLOOD_CONFIDENCE_BOOST, 100.0)
    new_breakdown = dict(breakdown)
    new_breakdown["flood_evasion_risk"] = True
    new_breakdown["flood_zscore"] = flood_zscore
    new_breakdown["adjustment"] = breakdown.get("adjustment", 0) + FLOOD_CONFIDENCE_BOOST
    new_breakdown["explanation"] = (
        breakdown.get("explanation", "") +
        f" FLOOD EVASION RISK: this high-confidence signal occurred during an active alert "
        f"flood (a documented MITRE T1562 evasion pattern - deliberately overwhelming analysts "
        f"to mask real intrusion activity). Boosted by +{FLOOD_CONFIDENCE_BOOST} rather than "
        f"left to compete against the noise."
    )
    return round(boosted_score, 1), new_breakdown
