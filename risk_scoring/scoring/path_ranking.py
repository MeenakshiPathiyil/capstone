"""Dense-rank scored attack paths and keep only the highest-scoring ones."""

from dataclasses import dataclass
from typing import Iterable

from models.path_scoring_input import PathScoringInput
from models.risk_score import RiskScore
from scoring.path_scoring import score_path
from scoring.risk_scorer import RiskScoringEngine

DEFAULT_TOP_N = 5
# Scores are rounded before ranking so floating-point noise does not split
# what are effectively equal scores into different ranks.
_RANK_PRECISION = 4


@dataclass(frozen=True)
class RankedPath:
    """A RiskScore together with its dense rank (1 = highest risk)."""

    rank: int
    risk: RiskScore


def dense_rank(scores: Iterable[RiskScore]) -> list[RankedPath]:
    """Rank by score descending using DENSE_RANK semantics.

    Equal scores share a rank and the next distinct score gets the next
    consecutive rank (e.g. 90, 80, 80, 70 -> ranks 1, 2, 2, 3).
    Ties are ordered by path_id so output is deterministic.
    """
    ordered = sorted(
        scores, key=lambda r: (-round(r.score, _RANK_PRECISION), r.path_id)
    )
    ranked: list[RankedPath] = []
    rank = 0
    previous = None
    for risk in ordered:
        current = round(risk.score, _RANK_PRECISION)
        if current != previous:
            rank += 1
            previous = current
        ranked.append(RankedPath(rank=rank, risk=risk))
    return ranked


def top_ranked_paths(
    scores: Iterable[RiskScore], top_n: int = DEFAULT_TOP_N
) -> list[RankedPath]:
    """Return paths whose dense rank is <= top_n (default: top 5).

    Because ranking is dense, paths tied on a score all stay in the output,
    so more than top_n paths may be returned when there are ties.
    """
    if isinstance(top_n, bool) or not isinstance(top_n, int) or top_n < 1:
        raise ValueError("top_n must be a positive integer")
    return [item for item in dense_rank(scores) if item.rank <= top_n]


def score_and_rank_paths(
    scoring_inputs: Iterable[PathScoringInput],
    top_n: int = DEFAULT_TOP_N,
    engine: RiskScoringEngine | None = None,
) -> list[RankedPath]:
    """Score every path, then return only the top_n dense-ranked ones."""
    scores = [score_path(item, engine) for item in scoring_inputs]
    return top_ranked_paths(scores, top_n)
