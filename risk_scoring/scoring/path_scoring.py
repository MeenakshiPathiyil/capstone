"""Orchestrate context-based scoring for a validated attack path."""

from risk_scoring.models.path_scoring_input import PathScoringInput
from risk_scoring.models.risk_score import RiskScore
from risk_scoring.scoring.exposure_score import compute_exposure_score
from risk_scoring.scoring.impact_score import compute_impact_score
from risk_scoring.scoring.path_ease import compute_path_ease
from risk_scoring.scoring.risk_scorer import RiskScoringEngine


def score_path(
    scoring_input: PathScoringInput,
    engine: RiskScoringEngine | None = None,
) -> RiskScore:
    if not isinstance(scoring_input, PathScoringInput):
        raise TypeError("scoring_input must be PathScoringInput")
    if engine is None:
        engine = RiskScoringEngine()
    if not isinstance(engine, RiskScoringEngine):
        raise TypeError("engine must be RiskScoringEngine or None")

    impact = compute_impact_score(
        asset_criticality=scoring_input.asset_criticality,
        sensitive_data=scoring_input.sensitive_data,
        environment=scoring_input.environment,
        reachable_downstream_count=scoring_input.reachable_downstream_count,
        graph_median_reachable=scoring_input.graph_median_reachable,
    )
    exposure = compute_exposure_score(scoring_input.reachability_class)
    path_ease = compute_path_ease(scoring_input.path_length)

    return engine.score(
        path_id=scoring_input.path_id,
        impact=impact,
        exposure=exposure,
        path_ease=path_ease,
        evidence_completeness=scoring_input.evidence_completeness,
    )
