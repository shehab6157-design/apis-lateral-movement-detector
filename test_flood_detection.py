"""
test_flood_detection.py — real tests for flood-aware confidence
protection, grounded in a documented MITRE technique (T1562, Impair
Defenses via alert flooding).
"""

import pytest

from flood_detection import FloodDetector, apply_flood_awareness, compute_window_rarity, confirmation_shape


def test_normal_windows_never_flagged_as_flood():
    fd = FloodDetector()
    for count in [10, 12, 9, 11, 10, 13, 9, 10]:
        is_flood, _ = fd.observe_window(count)
        assert is_flood is False


def test_genuine_spike_is_detected_as_flood():
    fd = FloodDetector()
    for count in [10, 12, 9, 11, 10]:
        fd.observe_window(count)
    is_flood, z = fd.observe_window(200)
    assert is_flood is True
    assert z >= 3.0


def test_flood_never_poisons_the_baseline():
    """Critical safety property, matching rolling_baseline.py's
    principle: the flood itself must never become the new normal, or
    the countermeasure defeats itself."""
    fd = FloodDetector()
    for count in [10, 12, 9, 11, 10]:
        fd.observe_window(count)
    baseline_before = fd.avg_rate

    fd.observe_window(200)

    assert abs(fd.avg_rate - baseline_before) < 2.0


def test_high_confidence_signal_boosted_during_flood():
    score, breakdown = 96.4, {"tier": "CROSS_DOMAIN_CORRELATED", "adjustment": 6.4, "explanation": "x"}
    boosted_score, boosted_breakdown = apply_flood_awareness(score, breakdown, is_flood_active=True, flood_zscore=10.0)
    assert boosted_score > score
    assert boosted_breakdown["flood_evasion_risk"] is True


def test_repetition_burst_also_boosted_during_flood():
    """Real bug found via adversarial-scenario testing: repetition_burst
    has the LOWEST base score of any confirmed tier, making it the
    MOST vulnerable to being buried under a flood of decoys, not the
    least - it must be protected, not excluded."""
    score, breakdown = 50.0, {"tier": "repetition_burst", "adjustment": 0, "explanation": "x"}
    boosted_score, boosted_breakdown = apply_flood_awareness(score, breakdown, is_flood_active=True, flood_zscore=10.0)
    assert boosted_score > score
    assert boosted_breakdown["flood_evasion_risk"] is True


def test_raw_unconfirmed_signal_not_boosted_during_flood():
    """A raw, uncorroborated signal has no real confirmation to
    protect in the first place - only confirmed tiers are protected."""
    score, breakdown = 15.0, {"tier": "raw", "adjustment": 0, "explanation": "x"}
    boosted_score, boosted_breakdown = apply_flood_awareness(score, breakdown, is_flood_active=True, flood_zscore=10.0)
    assert boosted_score == score
    assert "flood_evasion_risk" not in boosted_breakdown


def test_no_boost_when_no_flood_active():
    score, breakdown = 96.4, {"tier": "CROSS_DOMAIN_CORRELATED", "adjustment": 6.4, "explanation": "x"}
    boosted_score, boosted_breakdown = apply_flood_awareness(score, breakdown, is_flood_active=False)
    assert boosted_score == score


def test_boosted_score_never_exceeds_100():
    score, breakdown = 95.0, {"tier": "type_diversity", "adjustment": 0, "explanation": "x"}
    boosted_score, _ = apply_flood_awareness(score, breakdown, is_flood_active=True, flood_zscore=50.0)
    assert boosted_score <= 100.0


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


# ---------------------------------------------------------------------------
# Rarity-based discrimination (found necessary via real adversarial
# testing: uniformly boosting every confirmed tier during a flood also
# boosts the decoys making up the flood itself, since they too confirm
# via a "protected" tier - barely improving the relative ranking)
# ---------------------------------------------------------------------------

def test_common_shape_is_not_rare():
    """50 decoys sharing the exact same shape - none of them should be
    considered rare within their own window."""
    decoy_confirmations = [({"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity") for _ in range(50)]
    rarity = compute_window_rarity(decoy_confirmations)
    assert all(is_rare is False for is_rare in rarity)


def test_unique_shape_is_rare():
    """One real attack with a distinct shape among 50 identical decoys
    must be correctly identified as the outlier."""
    confirmations = [({"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity") for _ in range(50)]
    confirmations.append(({"VOLUME_OUTLIER": 5, "OFF_HOURS": 5}, "repetition_burst"))

    rarity = compute_window_rarity(confirmations)
    assert rarity[-1] is True
    assert all(is_rare is False for is_rare in rarity[:-1])


def test_real_attack_ranked_above_decoys_after_full_flood_awareness():
    """The complete, real fix: the genuine attack must end up scoring
    HIGHER than the decoys once both flood-detection AND rarity are
    correctly applied together - not just individually boosted by the
    same uniform amount as the noise around it."""
    decoy_score, decoy_breakdown = 70.0, {"tier": "type_diversity", "adjustment": 0, "explanation": "x"}
    attack_score, attack_breakdown = 65.0, {"tier": "repetition_burst", "adjustment": 15.0, "explanation": "x"}

    boosted_decoy_score, _ = apply_flood_awareness(
        decoy_score, decoy_breakdown, is_flood_active=True, flood_zscore=50.0, is_rare_in_window=False
    )
    boosted_attack_score, attack_breakdown_out = apply_flood_awareness(
        attack_score, attack_breakdown, is_flood_active=True, flood_zscore=50.0, is_rare_in_window=True
    )

    assert boosted_decoy_score == decoy_score  # decoys NOT boosted - they ARE the flood
    assert boosted_attack_score > attack_score  # the real outlier IS boosted
    assert boosted_attack_score > boosted_decoy_score  # and now correctly outranks the decoys
    assert attack_breakdown_out["flood_evasion_risk"] is True


def test_confirmation_shape_ignores_exact_counts():
    """Shape should match on signal TYPES and path, not exact counts -
    two decoys with slightly different repetition counts but the same
    underlying pattern are still the same shape."""
    shape_a = confirmation_shape({"NEW_PEER": 1, "OFF_HOURS": 1}, "type_diversity")
    shape_b = confirmation_shape({"NEW_PEER": 3, "OFF_HOURS": 2}, "type_diversity")
    assert shape_a == shape_b


def test_empty_window_returns_empty_rarity_list():
    assert compute_window_rarity([]) == []
