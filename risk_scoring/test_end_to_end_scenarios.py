"""Path-level integration tests using representative attack-path contexts.

These tests exercise the scoring pipeline from PathScoringInput through the
component scorers and final aggregator. They do not test attack-graph traversal.
"""

import math

import pytest

from risk_scoring.examples.representative_attack_paths import SCENARIOS
from risk_scoring.graph_model.resource_metadata import CriticalityLevel, Environment
from risk_scoring.models.path_scoring_input import PathScoringInput
from risk_scoring.multipliers.reach_multiplier import ReachabilityClass
from risk_scoring.scoring.path_scoring import score_path


def _input(**overrides):
    values = dict(
        path_id="test-path",
        asset_criticality=CriticalityLevel.MEDIUM,
        sensitive_data=False,
        environment=Environment.DEV,
        reachable_downstream_count=2,
        graph_median_reachable=3.0,
        reachability_class=ReachabilityClass.VIA_PATH,
        path_length=2,
        evidence_completeness=0.8,
    )
    values.update(overrides)
    return PathScoringInput(**values)


def test_representative_attack_paths_produce_valid_scores():
    assert len(SCENARIOS) >= 4
    results = [score_path(scenario["input"]) for scenario in SCENARIOS]
    assert len({result.path_id for result in results}) == len(results)
    for result in results:
        assert 0.0 <= result.score <= 100.0
        assert 0.0 <= result.impact <= 100.0
        assert 0.0 <= result.exposure <= 100.0
        assert 0.0 <= result.path_ease <= 100.0
        assert math.isfinite(result.score)


def test_final_score_matches_agreed_weighted_geometric_formula():
    result = score_path(_input())
    i = max(result.impact, 1.0)
    e = max(result.exposure, 1.0)
    a = max(result.path_ease, 1.0)
    expected = 100.0 * (i / 100.0) ** 0.45 * (e / 100.0) ** 0.35 * (a / 100.0) ** 0.20
    assert result.score == pytest.approx(expected)


def test_higher_criticality_increases_impact_and_risk_when_other_factors_match():
    low = score_path(_input(asset_criticality=CriticalityLevel.LOW))
    high = score_path(_input(asset_criticality=CriticalityLevel.HIGH))
    assert high.impact > low.impact
    assert high.exposure == low.exposure
    assert high.path_ease == low.path_ease
    assert high.score > low.score


def test_direct_reachability_scores_higher_exposure_than_via_path_and_post_compromise():
    direct = score_path(_input(reachability_class=ReachabilityClass.DIRECT))
    via_path = score_path(_input(reachability_class=ReachabilityClass.VIA_PATH))
    post = score_path(_input(reachability_class=ReachabilityClass.POST_COMPROMISE))
    assert direct.exposure > via_path.exposure > post.exposure
    assert direct.score > via_path.score > post.score


def test_shorter_path_scores_higher_path_ease_and_risk_when_other_factors_match():
    short = score_path(_input(path_length=1))
    long = score_path(_input(path_length=4))
    assert short.impact == long.impact
    assert short.exposure == long.exposure
    assert short.path_ease > long.path_ease
    assert short.score > long.score


def test_evidence_completeness_is_reported_but_does_not_change_risk_score():
    complete = score_path(_input(evidence_completeness=1.0))
    incomplete = score_path(_input(evidence_completeness=0.25))
    unknown = score_path(_input(evidence_completeness=None))
    assert complete.score == pytest.approx(incomplete.score)
    assert complete.score == pytest.approx(unknown.score)
    assert complete.evidence_completeness == 1.0
    assert incomplete.evidence_completeness == 0.25
    assert unknown.evidence_completeness is None


def test_unknown_resource_metadata_is_accepted_and_kept_distinct_from_evidence():
    result = score_path(
        _input(
            asset_criticality=None,
            sensitive_data=None,
            environment=None,
            reachable_downstream_count=0,
            graph_median_reachable=0.0,
            evidence_completeness=0.25,
        )
    )
    assert result.impact == 50.0
    assert result.evidence_completeness == 0.25


def test_sensitive_production_target_increases_impact_over_equivalent_non_sensitive_dev_target():
    ordinary = score_path(
        _input(
            asset_criticality=CriticalityLevel.MEDIUM,
            sensitive_data=False,
            environment=Environment.DEV,
        )
    )
    sensitive_prod = score_path(
        _input(
            asset_criticality=CriticalityLevel.MEDIUM,
            sensitive_data=True,
            environment=Environment.PROD,
        )
    )
    assert sensitive_prod.impact > ordinary.impact
    assert sensitive_prod.score > ordinary.score
