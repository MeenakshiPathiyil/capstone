"""Tests for the state-transition attack graph.

A node is a security state reached on a resource, not a resource and not a set of
invented facts. The attacker's starting position is its own node, so a path
begins somewhere explicit rather than at a seeded fact.

Node identity is `state@resource`, because a state is only meaningful with the
resource it was raised on: two public buckets are two different things to read.
`state` and `resource_id` are also carried separately so a reader does not have
to split the id.
"""

import pytest

from security_state_graph.attack_graph import ATTACKER_NODE_ID, build_attack_graph
from security_state_graph.state_graph import build_state_graph


@pytest.fixture(scope="module")
def real_graph():
    return build_state_graph()


@pytest.fixture(scope="module")
def attack_graph(real_graph):
    return build_attack_graph(real_graph)


def test_the_graph_has_one_attacker_root(attack_graph):
    """Where every path starts. The old model seeded `internet_reachable` onto
    each entry point instead, which meant the graph had several starting points
    and no way to say "before anything happened"."""

    nodes = attack_graph.to_dict()["nodes"]

    roots = [node for node in nodes if node["type"] == "attacker"]

    assert len(roots) == 1

    assert roots[0]["id"] == ATTACKER_NODE_ID
