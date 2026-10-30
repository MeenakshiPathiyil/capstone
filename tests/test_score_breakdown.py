"""score_breakdown recomposes score_path from a described path alone."""

import pytest

from attack_path.path_finder import find_attack_paths
from attack_path.scoring import (
    CRITICAL_SCORE_THRESHOLD,
    HIGH_SCORE_THRESHOLD,
    LENGTH_DAMPING_PER_HOP,
    PUBLIC_ENTRY_BOOST,
    score_breakdown
)
from security_state_graph.state_graph import build_state_graph


@pytest.fixture(scope="module")
def sample_paths():
    """Every ranked path of the shipped account."""

    return find_attack_paths(build_state_graph())


def test_every_sample_path_score_is_recomposed_exactly(sample_paths):
    """The whole point: a saved path can show how its score was reached."""

    assert len(sample_paths) == 22

    for path in sample_paths:
        assert score_breakdown(path)["score"] == path["score"], path["hops"]


def test_the_terms_are_the_ones_score_path_uses(sample_paths):

    for path in sample_paths:

        breakdown = score_breakdown(path)

        assert breakdown["objective_weight"] == path["objective_weight"]
        assert breakdown["hops"] == max(path["length"], 1)
        assert breakdown["length_factor"] == (
            LENGTH_DAMPING_PER_HOP ** (breakdown["hops"] - 1)
        )
        assert breakdown["public_entry"] == path["public_entry"]
        assert breakdown["boost"] == (
            PUBLIC_ENTRY_BOOST if path["public_entry"] else 1.0
        )
        assert breakdown["threshold_high"] == HIGH_SCORE_THRESHOLD
        assert breakdown["threshold_critical"] == CRITICAL_SCORE_THRESHOLD


def test_a_weakness_on_two_findings_is_counted_once(sample_paths):
    """Same dedupe as path_severity_total: one (resource, state) is one weight."""

    path = dict(sample_paths[0])

    doubled = dict(path, states=path["states"] + path["states"])

    assert score_breakdown(doubled) == score_breakdown(path)


def test_every_objective_carries_its_weight(sample_paths):
    """describe_path writes the base weight score_path added."""

    weights = {
        path["objective"]: path["objective_weight"]
        for path in sample_paths
    }

    assert all(weight > 0 for weight in weights.values())
    assert weights.get("ransomware") == 5.0
    assert weights.get("data_theft") == 4.0
