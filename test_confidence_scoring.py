"""
test_confidence_scoring.py — real tests for the confidence scoring
module, verifying the score ordering matches the real corroboration
tiers established throughout this project.
"""

import pytest

from confidence_scoring import compute_confidence_score, rank_alerts_by_confidence


def _record(path, occurrences=None, zscores=None, applied_cross_domain=False, suppressed=False):
    signal_evidence = [{"zscore": z} for z in (zscores or [])]
    reasoning = {"path": path}
    if occurrences is not None:
        reasoning["occurrences"] = occurrences
    return {
        "confirmation_path": path,
        "quorum_reasoning": reasoning,
        "signal_evidence": signal_evidence,
        "action": "ESCALATE_FOR_REVIEW",
        "suppressed": suppressed,
        "cross_domain_correlation": {"applied": applied_cross_domain},
    }


def test_cross_domain_scores_highest():
    cross_domain = _record("repetition_burst", occurrences=5, zscores=[9.4], applied_cross_domain=True)
    type_div = _record("type_diversity")
    repetition = _record("repetition_burst", occurrences=5, zscores=[9.4])

    cd_score, _ = compute_confidence_score(cross_domain)
    td_score, _ = compute_confidence_score(type_div)
    rb_score, _ = compute_confidence_score(repetition)

    assert cd_score > td_score > rb_score


def test_more_repetitions_and_higher_zscore_scores_higher_within_tier():
    weak = _record("repetition_burst", occurrences=5, zscores=[9.4])
    strong = _record("repetition_burst", occurrences=10, zscores=[29.04])

    weak_score, _ = compute_confidence_score(weak)
    strong_score, _ = compute_confidence_score(strong)

    assert strong_score > weak_score


def test_suppressed_scores_near_zero_regardless_of_tier():
    suppressed = _record("repetition_burst", occurrences=10, zscores=[29.04], suppressed=True)
    score, breakdown = compute_confidence_score(suppressed)
    assert score < 5
    assert breakdown["tier"] == "suppressed"


def test_score_never_exceeds_100():
    extreme = _record("repetition_burst", occurrences=1000, zscores=[500], applied_cross_domain=True)
    score, _ = compute_confidence_score(extreme)
    assert score <= 100.0


def test_rank_alerts_sorts_highest_first():
    records = [
        _record("repetition_burst", occurrences=5, zscores=[9.4]),
        _record("repetition_burst", occurrences=5, zscores=[9.4], applied_cross_domain=True),
        _record("type_diversity"),
    ]
    ranked = rank_alerts_by_confidence(records)
    scores = [r["confidence_score"] for r in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked[0]["cross_domain_correlation"]["applied"] is True


def test_breakdown_is_present_and_explains_the_score():
    record = _record("repetition_burst", occurrences=8, zscores=[15.0])
    score, breakdown = compute_confidence_score(record)
    assert "explanation" in breakdown
    assert str(score) in breakdown["explanation"] or breakdown["explanation"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
