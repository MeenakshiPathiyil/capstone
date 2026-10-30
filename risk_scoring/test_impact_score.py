import math

import pytest

from risk_scoring.graph_model.resource_metadata import CriticalityLevel, Environment
from risk_scoring.scoring.impact_score import compute_impact_score


BASE = {
    "asset_criticality": CriticalityLevel.MEDIUM,
    "sensitive_data": False,
    "environment": Environment.DEV,
    "reachable_downstream_count": 0,
    "graph_median_reachable": 0,
}


def score(**overrides):
    return compute_impact_score(**(BASE | overrides))


def test_criticality_maps_to_documented_base_scores():
    assert score(asset_criticality=CriticalityLevel.HIGH) == 80.0
    assert score(asset_criticality=CriticalityLevel.MEDIUM) == 60.0
    assert score(asset_criticality=CriticalityLevel.LOW) == 40.0


def test_unknown_criticality_uses_neutral_provisional_base():
    assert score(asset_criticality=None) == 50.0


def test_sensitive_data_adds_ten_points():
    assert score(sensitive_data=True) == 70.0


def test_production_environment_adds_ten_points():
    assert score(environment=Environment.PROD) == 70.0


@pytest.mark.parametrize("environment", [Environment.DEV, Environment.TEST, None])
def test_non_production_or_unknown_environment_has_no_bonus(environment):
    assert score(environment=environment) == 60.0


def test_unknown_sensitive_data_is_not_treated_as_confirmed_false_in_evidence():
    # Score treatment is neutral; evidence completeness is tracked separately.
    assert score(sensitive_data=None) == score(sensitive_data=False)


def test_blast_radius_bonus_increases_with_downstream_reachability():
    low = score(reachable_downstream_count=1, graph_median_reachable=5)
    high = score(reachable_downstream_count=10, graph_median_reachable=5)
    assert high > low


def test_blast_radius_bonus_is_bounded():
    result = score(
        asset_criticality=CriticalityLevel.LOW,
        reachable_downstream_count=10**9,
        graph_median_reachable=0,
    )
    assert result <= 60.0


def test_final_impact_is_capped_at_100():
    assert score(
        asset_criticality=CriticalityLevel.HIGH,
        sensitive_data=True,
        environment=Environment.PROD,
        reachable_downstream_count=10**9,
        graph_median_reachable=0,
    ) == 100.0


def test_negative_downstream_count_is_rejected():
    with pytest.raises(ValueError, match="reachable_downstream_count must be >= 0"):
        score(reachable_downstream_count=-1)


def test_boolean_downstream_count_is_rejected():
    with pytest.raises(TypeError, match="reachable_downstream_count must be an integer"):
        score(reachable_downstream_count=True)


def test_invalid_criticality_is_rejected():
    with pytest.raises(TypeError, match="asset_criticality must be CriticalityLevel or None"):
        score(asset_criticality="high")


def test_invalid_sensitive_data_is_rejected():
    with pytest.raises(TypeError, match="sensitive_data must be bool or None"):
        score(sensitive_data=1)


@pytest.mark.parametrize("value", [-1, math.inf, -math.inf, math.nan])
def test_invalid_graph_median_is_rejected(value):
    with pytest.raises(ValueError):
        score(graph_median_reachable=value)


def test_boolean_graph_median_is_rejected():
    with pytest.raises(TypeError, match="graph_median_reachable must be numeric"):
        score(graph_median_reachable=True)
