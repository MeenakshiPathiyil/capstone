"""Validated, immutable input facts for scoring one attack path."""

import math
from dataclasses import dataclass

from graph_model.resource_metadata import CriticalityLevel, Environment
from multipliers.reach_multiplier import ReachabilityClass


def _require_number(name, value, lo=None, hi=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric, got {type(value).__name__}")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value}")
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        lo_txt = "-inf" if lo is None else lo
        hi_txt = "inf" if hi is None else hi
        raise ValueError(f"{name} must be in [{lo_txt}, {hi_txt}], got {value}")


def _require_int(name, value, lo=None):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer, got {type(value).__name__}")
    if lo is not None and value < lo:
        raise ValueError(f"{name} must be >= {lo}, got {value}")


@dataclass(frozen=True)
class PathScoringInput:
    """Contextual facts used to calculate a path's risk score.

    Baseline impact/exposure values and technique scores are deliberately not
    accepted. Impact and exposure are derived directly from context; path
    technique metadata remains part of the attack-path representation, not
    this scoring input.
    """

    path_id: str
    asset_criticality: CriticalityLevel | None
    sensitive_data: bool | None
    environment: Environment | None
    reachable_downstream_count: int
    graph_median_reachable: float
    reachability_class: ReachabilityClass
    path_length: int
    evidence_completeness: float | None = None

    def __post_init__(self):
        if not isinstance(self.path_id, str):
            raise TypeError("path_id must be a string")
        if not self.path_id.strip():
            raise ValueError("path_id must be a non-empty string")

        if self.asset_criticality is not None and not isinstance(
            self.asset_criticality, CriticalityLevel
        ):
            raise TypeError("asset_criticality must be CriticalityLevel or None")
        if self.sensitive_data is not None and not isinstance(self.sensitive_data, bool):
            raise TypeError("sensitive_data must be bool or None")
        if self.environment is not None and not isinstance(self.environment, Environment):
            raise TypeError("environment must be Environment or None")

        _require_int("reachable_downstream_count", self.reachable_downstream_count, lo=0)
        _require_number("graph_median_reachable", self.graph_median_reachable, lo=0.0)

        if not isinstance(self.reachability_class, ReachabilityClass):
            raise TypeError("reachability_class must be ReachabilityClass")
        _require_int("path_length", self.path_length, lo=1)

        if self.evidence_completeness is not None:
            _require_number("evidence_completeness", self.evidence_completeness, 0.0, 1.0)
