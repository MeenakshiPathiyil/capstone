"""Tests for security_state_graph/attack_graph.py — the attack graph layer's artifact.

What makes this a different graph from the security state graph, and what these
tests are here to hold:

  security state graph      attack graph
  node = a resource         node = (resource, the facts the attacker holds)
  edge = "A references B"   edge = an action instance

The property the whole layer exists for is Task 6's: "A valid path is one where
every step's precondition is satisfied by the postcondition of the previous
step." Built this way it holds by construction, and the tests below are what stop
it quietly ceasing to.
"""

import json

import pytest

from security_state_graph.attack_graph import (
    ATTACK_GRAPH_FILES,
    MAX_DEPTH,
    AttackGraph,
    build_attack_graph,
    state_id,
    write_attack_graph
)
from security_state_graph.state_graph import build_state_graph


@pytest.fixture(scope="module")
def real_graph():
    return build_state_graph()


@pytest.fixture(scope="module")
def attack_graph(real_graph):
    return build_attack_graph(real_graph)


# -- The state identity ------------------------------------------------------

def test_a_state_is_a_resource_plus_the_facts_held():
    """The name has to be stable across runs, because the golden files depend on
    it and because two routes arriving with the same facts must land on the same
    node rather than forking."""

    one = state_id("Role", {"credential(Role)", "internet_reachable"})
    two = state_id("Role", {"internet_reachable", "credential(Role)"})

    assert one == two
    assert one == "Role|credential(Role),internet_reachable"


def test_one_resource_can_be_several_attacker_states(attack_graph):
    """THE ASSERTION THAT MAKES THIS AN ATTACK GRAPH.

    A resource reached holding different facts is a different situation with
    different actions available. Collapsed onto one node per resource, the search
    either allows steps that are not available or forbids steps that are.
    """

    counts = {}

    for node in attack_graph.nodes.values():
        counts[node["resource"]] = counts.get(node["resource"], 0) + 1

    assert max(counts.values()) > 1, counts

    # And the states of one resource really do differ in their facts, rather than
    # being duplicates under different names.
    for resource, count in counts.items():

        if count < 2:
            continue

        states = attack_graph.states_of(resource)

        fact_sets = [tuple(node["facts"]) for node in states]

        assert len(set(fact_sets)) == len(fact_sets), resource


def test_the_attack_graph_agrees_with_the_search_on_depth():
    """A graph built to a different depth than the search walks either wastes
    work or hides paths. MAX_DEPTH is restated in attack_graph to avoid a
    circular import, so it has to be checked rather than assumed."""

    from attack_path.path_finder import MAX_DEPTH as SEARCH_MAX_DEPTH

    assert MAX_DEPTH == SEARCH_MAX_DEPTH


def test_no_state_is_deeper_than_the_bound(attack_graph):
    for node in attack_graph.nodes.values():
        assert node["depth"] <= MAX_DEPTH


def test_entry_states_are_the_state_graph_entry_points(attack_graph, real_graph):
    from security_state_graph.semantics import entry_points

    entries = {
        node["resource"]
        for node in attack_graph.nodes.values()
        if node["is_entry"]
    }

    assert entries == set(entry_points(real_graph))


def test_every_entry_state_is_at_depth_zero(attack_graph):
    for node in attack_graph.nodes.values():

        if node["is_entry"]:
            assert node["depth"] == 0


# -- The chaining property ---------------------------------------------------

def test_every_action_chains_from_its_own_source_state(attack_graph):
    """TASK 6'S VALIDITY CONDITION, over the whole graph.

    An edge exists only where the action's precondition is in the facts of the
    state it leaves. Asserted against the recorded states rather than recomputed,
    so a builder that wrote the wrong from_state is caught.
    """

    nodes = attack_graph.nodes

    assert attack_graph.edges

    for edge in attack_graph.edges:

        held = set(nodes[edge["from_state"]]["facts"])

        assert edge["precondition"] or not edge["precondition_options"], edge

        for item in edge["precondition"]:
            assert item in held, (edge, sorted(held))


def test_every_action_lands_on_a_state_holding_its_postcondition(attack_graph):
    """The other half. The target state's facts have to be the source state's
    plus whatever the action grants, or the chain is broken on arrival."""

    nodes = attack_graph.nodes

    for edge in attack_graph.edges:

        before = set(nodes[edge["from_state"]]["facts"])
        after = set(nodes[edge["to_state"]]["facts"])

        assert after == before | set(edge["postcondition"]), edge


def test_every_edge_names_states_that_exist(attack_graph):
    for edge in attack_graph.edges:
        assert edge["from_state"] in attack_graph.nodes
        assert edge["to_state"] in attack_graph.nodes


def test_an_action_moves_between_the_resources_its_edge_joins(attack_graph):
    nodes = attack_graph.nodes

    for edge in attack_graph.edges:

        assert nodes[edge["from_state"]]["resource"] == edge["source"]
        assert nodes[edge["to_state"]]["resource"] == edge["target"]


# -- The four fields ---------------------------------------------------------

def test_every_action_carries_all_four_fields(attack_graph):
    """Task 5 names four, not two. precondition and postcondition say the step is
    legal; input and output say what it was done to and what came out, which is
    what a generated scenario needs to be specific."""

    for edge in attack_graph.edges:

        for field in ("precondition", "postcondition", "input", "output"):
            assert field in edge, (edge["action_id"], field)

        assert isinstance(edge["input"], dict)
        assert isinstance(edge["output"], dict)


def test_an_action_that_grants_something_records_what_came_out(attack_graph):
    """A postcondition with an empty output is a step that changed the attacker's
    position and cannot say what it produced, which is exactly the vagueness this
    layer exists to remove."""

    for edge in attack_graph.edges:

        if not edge["postcondition"]:
            continue

        assert edge["output"], edge["action_id"]


def test_the_inputs_carry_evidence_from_the_findings(attack_graph):
    """The link back to Module 2. At least some actions have to name the finding
    that justifies them, or the attack graph is asserting steps with nothing
    underneath them."""

    with_evidence = [
        edge
        for edge in attack_graph.edges
        if edge["input"].get("evidence")
    ]

    assert with_evidence

    for edge in with_evidence:
        assert isinstance(edge["input"]["evidence"], list)
        assert edge["input"]["evidence"]


# -- The artifact ------------------------------------------------------------

def test_every_edge_list_names_an_edge_the_same_way(real_graph, attack_graph):
    """THE VOCABULARY GUARD.

    Four lists in this project describe an edge: the declared edges, the
    traversal edges, the attack graph's actions, and a path's steps. They carry
    different extra fields, which is fine, but the fields they share have to be
    spelled the same or the lists cannot be joined against each other.

    This is not hypothetical. The attack graph's edges said `edge_category`
    instead of `category` and omitted `relation` entirely, which made it the one
    edge list a reader could not line up with the others.
    """

    from attack_path.path_finder import find_attack_paths

    shared = {"source", "target", "category", "relation"}

    lists = {
        "declared": real_graph.to_dict()["edges"],
        "traversal": real_graph.to_dict()["traversal_edges"],
        "attack graph": attack_graph.to_dict()["edges"],
        "path steps": [
            step
            for path in find_attack_paths(real_graph)
            for step in path["steps"]
        ]
    }

    for name, edges in lists.items():

        assert edges, name

        for edge in edges:

            missing = sorted(shared - set(edge))

            assert missing == [], (name, missing)


def test_the_summary_counts_what_it_says(attack_graph):
    artifact = attack_graph.to_dict()

    summary = artifact["summary"]

    assert summary["attacker_states"] == len(artifact["nodes"])
    assert summary["actions"] == len(artifact["edges"])

    assert summary["distinct_techniques"] == len(summary["techniques"])

    assert summary["entry_states"] == len([
        node for node in artifact["nodes"] if node["is_entry"]
    ])

    assert summary["edges_from_the_fallback_table"] == len(
        attack_graph.fallback_edges()
    )


def test_the_summary_reports_the_fallback_count(attack_graph):
    """Not decoration. A non-zero count is the number of hops the transition
    ruleset does not name yet, and the layer is only as grounded as it is small.
    On the shipped account it is zero."""

    summary = attack_graph.to_dict()["summary"]

    assert summary["edges_from_the_fallback_table"] == 0


def test_writing_produces_one_file_per_block(tmp_path):
    graph = build_attack_graph()

    files = {
        name: tmp_path / path.name
        for name, path in ATTACK_GRAPH_FILES.items()
    }

    written = write_attack_graph(graph, files)

    assert sorted(written) == sorted(ATTACK_GRAPH_FILES)

    for name, path in written.items():

        loaded = json.loads(path.read_text(encoding="utf-8"))

        assert loaded == graph.to_dict()[name]


def test_a_block_missing_from_the_file_table_is_an_error(tmp_path):
    """Same guard the state graph has: a block added to to_dict and left out of
    the table would be silently unwritten."""

    graph = build_attack_graph()

    with pytest.raises(KeyError):
        write_attack_graph(graph, {"summary": tmp_path / "summary.json"})

    with pytest.raises(KeyError):
        write_attack_graph(
            graph,
            dict(
                {name: tmp_path / path.name
                 for name, path in ATTACK_GRAPH_FILES.items()},
                not_a_block=tmp_path / "nope.json"
            )
        )


def test_the_build_is_deterministic(real_graph):
    """Two builds over the same state graph produce the same bytes. A set
    iterating in a different order would break the golden files and, worse, make
    two runs of the pipeline disagree about what the account permits."""

    one = AttackGraph(real_graph).to_dict()
    two = AttackGraph(real_graph).to_dict()

    assert json.dumps(one, indent=2) == json.dumps(two, indent=2)


def test_the_state_bound_truncates_rather_than_running_away(real_graph):
    """MAX_STATES is a stop, not a tuning knob. Reaching it has to be reported,
    because a truncated graph missing paths and a graph with no paths look the
    same from the outside."""

    graph = AttackGraph(real_graph, max_states=3)

    assert graph.truncated is True
    assert graph.to_dict()["summary"]["truncated"] is True
    assert len(graph.nodes) <= 3

    assert build_attack_graph(real_graph).truncated is False


# -- Agreement with the path layer -------------------------------------------

def test_every_reported_path_is_a_walk_of_the_attack_graph(
    real_graph,
    attack_graph
):
    """THE CONSISTENCY ASSERTION.

    The two layers read the same ruleset, so a step a path reports must be an
    action the attack graph holds. Before both went through
    security_state_graph.transitions.actions_for they came from different places and could
    disagree without anything noticing.
    """

    from attack_path.path_finder import find_attack_paths

    available = {
        (edge["source"], edge["target"], edge["action_id"])
        for edge in attack_graph.edges
    }

    paths = find_attack_paths(real_graph)

    assert paths

    for path in paths:

        for step in path["steps"]:

            key = (step["source"], step["target"], step["action_id"])

            assert key in available, (path["hops"], step)
