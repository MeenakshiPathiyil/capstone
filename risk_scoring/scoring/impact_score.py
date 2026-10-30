"""Direct, context-based impact scoring for an attack path's target resource.

The rubric in this module is an initial design choice for the project. Its
weights and point adjustments should be evaluated against representative
infrastructure scenarios before being treated as empirically calibrated.
"""

import math

from graph_model.resource_metadata import (
    CriticalityLevel,
    Environment,
)


_CRITICALITY_BASE = {
    CriticalityLevel.HIGH: 80.0,
    CriticalityLevel.MEDIUM: 60.0,
    CriticalityLevel.LOW: 40.0,
}
_UNKNOWN_CRITICALITY_BASE = 50.0
_SENSITIVE_DATA_BONUS = 10.0
_PRODUCTION_BONUS = 10.0
_MAX_BLAST_RADIUS_BONUS = 20.0


def _require_count(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")


def compute_impact_score(
    *,
    asset_criticality: CriticalityLevel | None,
    sensitive_data: bool | None,
    environment: Environment | None,
    reachable_downstream_count: int,
    graph_median_reachable: float,
) -> float:
    """Return a 1-100 impact score derived directly from target context.

    Rubric:
      * Criticality base: high=80, medium=60, low=40, unknown=50.
      * Confirmed sensitive data: +10.
      * Confirmed production environment: +10.
      * Blast radius: up to +20, relative to the graph median.

    Unknown metadata does not incur a penalty. Callers should preserve missing
    metadata in their evidence-completeness reporting rather than interpreting
    an unknown value as evidence of low impact.
    """
    if asset_criticality is not None and not isinstance(
        asset_criticality, CriticalityLevel
    ):
        raise TypeError("asset_criticality must be CriticalityLevel or None")

    if sensitive_data is not None and not isinstance(sensitive_data, bool):
        raise TypeError("sensitive_data must be bool or None")

    if environment is not None and not isinstance(environment, Environment):
        raise TypeError("environment must be Environment or None")

    _require_count("reachable_downstream_count", reachable_downstream_count)

    if isinstance(graph_median_reachable, bool) or not isinstance(
        graph_median_reachable, (int, float)
    ):
        raise TypeError("graph_median_reachable must be numeric")
    if not math.isfinite(graph_median_reachable):
        raise ValueError("graph_median_reachable must be finite")
    if graph_median_reachable < 0:
        raise ValueError("graph_median_reachable must be >= 0")

    score = _CRITICALITY_BASE.get(
        asset_criticality, _UNKNOWN_CRITICALITY_BASE
    )

    if sensitive_data is True:
        score += _SENSITIVE_DATA_BONUS

    if environment is Environment.PROD:
        score += _PRODUCTION_BONUS

    # Bounded relative contribution. The +1 avoids division by zero and
    # makes the term well-defined for graphs whose median reachability is 0.
    downstream = float(reachable_downstream_count)
    median = float(graph_median_reachable)
    blast_radius_bonus = _MAX_BLAST_RADIUS_BONUS * (
        downstream / (downstream + median + 1.0)
    )
    score += blast_radius_bonus

    return round(min(100.0, max(1.0, score)), 6)
