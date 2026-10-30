"""GET /api/analyses/{id}/graph, and the exact path matching behind it."""

import pytest

from app.api.graph import attack_view, path_edge_indices, edge_identity
from main import build_infra_model
from runner.graph_runner import analyze
from security_state_graph.attack_graph import AttackGraph


@pytest.fixture(scope="module")
def result():
    """The shipped account, analysed in memory."""

    return analyze(build_infra_model())


def get_graph(client, analysis, view):

    response = client.get("/api/analyses/%s/graph?view=%s" % (analysis["id"], view))

    assert response.status_code == 200, response.text

    return response.json()


# -----------------------------

def test_the_state_view_has_the_verified_counts(shared_client, sample_analysis):

    graph = get_graph(shared_client, sample_analysis, "state")

    assert graph["view"] == "state"
    assert len(graph["nodes"]) == 15
    assert len(graph["edges"]) == 15
    assert sum(edge["reversed"] for edge in graph["edges"]) == 2
    assert graph["dropped_edges"] == 0
    assert graph["warnings"] == []

    # the parallel identity + escalation pair is one edge naming both
    merged = next(
        edge for edge in graph["edges"]
        if edge["key"] == "AppServerRole->DeploymentRole"
    )

    assert sorted(merged["categories"]) == ["escalation", "identity"]

    # every hop of every ranked path is emphasised on its resource edge
    keys = {edge["key"]: edge for edge in graph["edges"]}

    for path in sample_analysis["paths"]:
        for source, target in zip(path["hops"], path["hops"][1:]):
            assert path["source_id"] in keys["%s->%s" % (source, target)]["path_ids"]


def test_the_attack_view_has_the_verified_counts(shared_client, sample_analysis):

    graph = get_graph(shared_client, sample_analysis, "attack")

    assert graph["view"] == "attack"
    assert len(graph["nodes"]) == 22
    assert len(graph["edges"]) == 19
    assert graph["truncated"] is False
    assert graph["warnings"] == []

    keys = [node["key"] for node in graph["nodes"]]

    assert keys == ["s%d" % index for index in range(22)]

    root = [node for node in graph["nodes"] if node["resource"] is None]

    assert len(root) == 1 and root[0]["label_lines"] == ["Attacker"]

    for edge in graph["edges"]:
        assert edge["source"] in keys and edge["target"] in keys

    # every ranked path is highlighted somewhere, by its exact edges
    highlighted = {
        source_id
        for edge in graph["edges"]
        for source_id in edge["path_ids"]
    }

    assert highlighted == {path["source_id"] for path in sample_analysis["paths"]}


def test_every_one_of_the_97_sample_steps_matches_one_exact_edge(result):

    graph = result.attack_graph.to_dict()

    index = {}

    for position, edge in enumerate(graph["edges"]):
        index.setdefault(
            edge_identity(edge["from_state"], edge["to_state"], edge["action_id"],
                          edge["category"], edge.get("relation")),
            []
        ).append(position)

    steps = 0

    for path in result.paths:

        matched = path_edge_indices(result.state_graph, path, index)

        assert matched is not None, path["hops"]
        assert len(matched) == len(path["steps"])

        for position, step in zip(matched, path["steps"]):

            edge = graph["edges"][position]

            assert (edge["source"], edge["target"]) == (step["source"], step["target"])
            assert edge["action_id"] == step["action_id"]

        steps = steps + len(path["steps"])

    assert steps == 97


def test_one_resource_pair_under_distinct_facts_or_actions_is_not_conflated(result):
    """Two edges between the same two resources are different transitions.

    OverPermissiveRole -> InsecureS3Bucket is reached holding different facts on
    the PublicEC2Instance and AppServerInstance routes, and AppServerRole ->
    DeploymentRole has both an identity and an escalation action. A match by
    resource pair would light up both of each; the exact match must not.
    """

    view = attack_view(result.state_graph, result.attack_graph, result.paths)

    graph = result.attack_graph.to_dict()

    by_pair = {}

    for position, edge in enumerate(graph["edges"]):
        by_pair.setdefault((edge["source"], edge["target"]), []).append(position)

    for pair in [
        ("OverPermissiveRole", "InsecureS3Bucket"),
        ("OverPermissiveRole", "PublicRDS"),
        ("AppServerRole", "DeploymentRole")
    ]:

        positions = by_pair[pair]

        assert len(positions) >= 2, pair

        assigned = [set(view["edges"][position]["path_ids"]) for position in positions]

        for first in range(len(assigned)):
            for second in range(first + 1, len(assigned)):
                assert not assigned[first] & assigned[second], pair

    # the identity and escalation hops between the two roles are distinct
    actions = {
        graph["edges"][position]["action_id"]
        for position in by_pair[("AppServerRole", "DeploymentRole")]
    }

    assert actions == {"ACT_USE_ATTACHED_IDENTITY", "ACT_PASS_ROLE_TO_SERVICE"}


def test_a_truncated_graph_warns_and_never_guesses(result):

    truncated = AttackGraph(result.state_graph, max_states=6)

    assert truncated.truncated

    view = attack_view(result.state_graph, truncated, result.paths)

    kinds = [warning["kind"] for warning in view["warnings"]]

    assert view["truncated"] is True
    assert "graph_truncated" in kinds
    assert "graph_mapping" in kinds

    unmatched = {
        warning["message"].split()[0]
        for warning in view["warnings"]
        if warning["kind"] == "graph_mapping"
    }

    # an unmatched path is highlighted nowhere, not partially
    for edge in view["edges"]:
        assert not unmatched & set(edge["path_ids"])


def test_an_unknown_view_is_422(shared_client, sample_analysis):

    response = shared_client.get(
        "/api/analyses/%s/graph?view=resources" % sample_analysis["id"]
    )

    assert response.status_code == 422
