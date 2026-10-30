import pytest

from models.risk_score import RiskScore
from scoring.path_ranking import dense_rank, top_ranked_paths


def _rs(pid, score):
    return RiskScore(path_id=pid, score=score, impact=50, exposure=50, path_ease=50)


def test_dense_rank_ties_share_rank_without_gaps():
    ranked = dense_rank([_rs("a", 70), _rs("b", 90), _rs("c", 80), _rs("d", 80)])
    assert [(r.risk.path_id, r.rank) for r in ranked] == [
        ("b", 1), ("c", 2), ("d", 2), ("a", 3)
    ]


def test_top_five_only():
    scores = [_rs(f"p{i}", 10 * i) for i in range(1, 10)]
    top = top_ranked_paths(scores)
    assert [r.rank for r in top] == [1, 2, 3, 4, 5]
    assert top[0].risk.path_id == "p9"


def test_ties_at_cutoff_are_all_kept():
    scores = [_rs("a", 90), _rs("b", 80), _rs("c", 70), _rs("d", 60),
              _rs("e", 50), _rs("f", 50), _rs("g", 40)]
    assert [r.risk.path_id for r in top_ranked_paths(scores)] == list("abcdef")


def test_fewer_than_five_and_invalid_top_n():
    assert len(top_ranked_paths([_rs("a", 10)])) == 1
    with pytest.raises(ValueError):
        top_ranked_paths([], top_n=0)
