"""Weighted geometric aggregation of impact, exposure, and path ease."""

import math

from models.risk_score import RiskScore

_IMPACT_EXPONENT = 0.45
_EXPOSURE_EXPONENT = 0.35
_PATH_EASE_EXPONENT = 0.20
_MIN_AGGREGATION_SCORE = 1.0


def _validate_component(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    if not 0 <= value <= 100:
        raise ValueError(f"{name} must be within [0, 100], got {value}")


class RiskScoringEngine:
    """Combine the three computed component scores into a final path score.

    Component values are floored to 1 for geometric aggregation so a zero or
    unavailable-like component cannot collapse the entire product to zero.
    Unknown input evidence should still be represented separately in metadata.
    """

    def score(
        self,
        path_id: str,
        impact: float,
        exposure: float,
        path_ease: float,
        evidence_completeness: float | None = None,
    ) -> RiskScore:
        _validate_component("impact", impact)
        _validate_component("exposure", exposure)
        _validate_component("path_ease", path_ease)

        if evidence_completeness is not None:
            if isinstance(evidence_completeness, bool) or not isinstance(
                evidence_completeness, (int, float)
            ):
                raise TypeError("evidence_completeness must be numeric or None")
            if not math.isfinite(evidence_completeness):
                raise ValueError("evidence_completeness must be finite")
            if not 0 <= evidence_completeness <= 1:
                raise ValueError("evidence_completeness must be within [0, 1]")

        i = max(float(impact), _MIN_AGGREGATION_SCORE)
        e = max(float(exposure), _MIN_AGGREGATION_SCORE)
        a = max(float(path_ease), _MIN_AGGREGATION_SCORE)
        score = 100.0 * (i / 100.0) ** _IMPACT_EXPONENT * (
            e / 100.0
        ) ** _EXPOSURE_EXPONENT * (a / 100.0) ** _PATH_EASE_EXPONENT
        score = min(100.0, max(0.0, score))

        return RiskScore(
            path_id=path_id,
            score=score,
            impact=float(impact),
            exposure=float(exposure),
            path_ease=float(path_ease),
            evidence_completeness=evidence_completeness,
        )
