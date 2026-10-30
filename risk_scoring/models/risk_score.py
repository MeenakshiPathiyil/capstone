"""Output model for a path-level contextual risk assessment."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RiskScore:
    """Final risk score and its three component scores, all on a 0-100 scale.

    Evidence completeness is metadata and does not affect the numerical score.
    """

    path_id: str
    score: float
    impact: float
    exposure: float
    path_ease: float
    evidence_completeness: Optional[float] = None

    def __post_init__(self):
        if not isinstance(self.path_id, str) or not self.path_id.strip():
            raise ValueError("path_id must be a non-empty string")
        for name, value in (
            ("score", self.score),
            ("impact", self.impact),
            ("exposure", self.exposure),
            ("path_ease", self.path_ease),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if not 0 <= value <= 100:
                raise ValueError(f"{name} must be within [0, 100], got {value}")
        if self.evidence_completeness is not None:
            value = self.evidence_completeness
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError("evidence_completeness must be numeric or None")
            if not 0 <= value <= 1:
                raise ValueError("evidence_completeness must be within [0, 1] or None")
