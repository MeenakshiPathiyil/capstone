"""Tests for the join — nodes, states, and the direction the edges are read in."""

import json
from pathlib import Path

import pytest

from attack_path.path_finder import (
    ENTRY_SEMANTICS,
    data_targets,
    entry_points,
    finding_severity,
    finding_weight,
    severity_weight
)
from security_state_graph.state_graph import (
    BIDIRECTIONAL_CATEGORIES,
    ENTRY_REASON_FINDING,
    ENTRY_REASON_NONE,
    ENTRY_REASON_TEMPLATE,
    GRAPH_FILES,
    INBOUND_REACHABLE_TYPES,
    REVERSED_CATEGORIES,
    STATE_KEYS,
    SecurityStateGraph,
    build_state_graph,
    edge_sort_key,
    entry_reason,
    evaluate_findings,
    highest_severity,
    sorted_edges,
    write_state_graph
)


# One golden per block, matching the four files write_state_graph produces.
GOLDEN_DIR = Path(__file__).resolve().parent

GOLDEN_FILES = {
    "summary": GOLDEN_DIR / "golden_graph_summary.json",
    "nodes": GOLDEN_DIR / "golden_graph_nodes.json",
    "edges": GOLDEN_DIR / "golden_graph_edges.json",
    "traversal_edges": GOLDEN_DIR / "golden_graph_traversal_edges.json"
}


# -----------------------------

def pairs(edges, category=None):
    """Edges as (source, target) tuples, optionally narrowed to one category."""

    return [
        (edge["source"], edge["target"])
        for edge in edges
        if category is None or edge["category"] == category
    ]


def state_ids(state_graph, resource_id):
    """The state ids attached to one resource."""

    return [
        finding["state"]
        for finding in state_graph.states_of(resource_id)
    ]


def reachable(state_graph, start):
    """Every node reachable from `start` in the traversal view."""

    adjacency = state_graph.traversal_adjacency()

    seen = set()
    queue = [start]

    while queue:

        current = queue.pop(0)

        for target in adjacency.get(current, []):

            if target in seen:
                continue

            seen.add(target)
            queue.append(target)

    return seen


# -----------------------------

# Findings written by hand, so a test can assert on exactly one resource
HAND_WRITTEN_FINDINGS = [
    {
        "resource": "SampleSecurityGroup",
        "rule_id": "RESTRICTED_COMMON_PORTS",
        "state": "unrestricted_common_port_access",
        "semantic": "exposure",
        "severity": "high"
    }
]

# The stale-data problem, reproduced. "DeletedBucket" was in the dataset when
# these findings were generated and is not in it now.
STALE_FINDINGS = [
    {
        "resource": "DeletedBucket",
        "rule_id": "S3_PUBLIC_ACL",
        "state": "public_bucket_acl",
        "semantic": "exposure",
        "severity": "high"
    },
    {
        "resource": "SampleBucket",
        "rule_id": "S3_PUBLIC_ACL",
        "state": "public_bucket_acl",
        "semantic": "exposure",
        "severity": "high"
    }
]


@pytest.fixture
def real_graph(real_infra, rules_path):
    """The shipped dataset joined to the findings the shipped rules produce."""

    return SecurityStateGraph(
        real_infra,
        evaluate_findings(real_infra, rules_path)
    )


@pytest.fixture
def sample_graph(sample_infra):
    """The hand-built infra joined to one hand-written finding."""

    return SecurityStateGraph(sample_infra, HAND_WRITTEN_FINDINGS)


# -----------------------------

def test_state_lands_on_the_correct_node(real_graph):
    """THE JOIN."""

    assert "unrestricted_common_port_access" in state_ids(
        real_graph,
        "OpenSecurityGroup"
    )

    # Two groups leave a blocked port open now, so the state is not unique to
    # one node. What still has to hold is that it lands only on security groups:
    # a finding on the wrong *kind* of resource is the join going wrong.
    for resource_id, node in real_graph.nodes.items():

        if "unrestricted_common_port_access" in state_ids(real_graph, resource_id):
            assert node["type"] == "AWS::EC2::SecurityGroup"


def test_every_state_carries_the_fields_later_phases_read(real_graph):
    """The whole finding is attached, not just its id: entry points are selected by"""

    for node in real_graph.nodes.values():

        for finding in node["states"]:

            assert finding["resource"] == node["id"]
            assert finding["rule_id"]
            assert finding["source_id"]
            assert finding["state"]
            assert finding["semantic"]

            # Not finding["severity"]: the canonical rules declare none, so the
            # stored finding carries None and the severity is derived from the
            # semantic. What later phases read is the derived value.
            assert finding_severity(finding)


def test_every_node_carries_its_own_connections(real_graph):
    """A node record answers "what does this resource name" on its own.

    Same shape as data/infra_output.json: {"target", "type", "relation"}.
    """

    nodes = {node["id"]: node for node in real_graph.to_dict()["nodes"]}

    instance = nodes["PublicEC2Instance"]

    assert instance["connections"] == [
        {
            "target": "OpenSecurityGroup",
            "type": "network_control",
            "relation": "association"
        },
        {
            "target": "OverPermissiveInstanceProfile",
            "type": "identity",
            "relation": "dependency"
        }
    ]

    # A resource that names nothing says so with an empty list, not a missing key.
    assert nodes["InsecureS3Bucket"]["connections"] == []


def test_the_node_connections_are_exactly_the_stored_edges(real_graph):
    """THE TWO-PLACES GUARD.

    The same facts are now written twice — once per node as `connections`, once
    for the whole graph as `edges`. Two copies of a fact drift, so this pins them
    to each other: every connection has a matching stored edge and every stored
    edge has a matching connection, with nothing left over on either side.
    """

    artifact = real_graph.to_dict()

    from_nodes = sorted(
        (node["id"], connection["target"], connection["type"])
        for node in artifact["nodes"]
        for connection in node["connections"]
    )

    from_edges = sorted(
        (edge["source"], edge["target"], edge["category"])
        for edge in artifact["edges"]
    )

    assert from_nodes == from_edges

    # And the relation travels with them, so a node cannot describe an edge as a
    # dependency while the edge list calls it an association.
    relations = {
        (edge["source"], edge["target"], edge["category"]): edge["relation"]
        for edge in artifact["edges"]
    }

    for node in artifact["nodes"]:
        for connection in node["connections"]:

            key = (node["id"], connection["target"], connection["type"])

            assert relations[key] == connection["relation"]


def test_node_with_no_findings_has_an_empty_state_list(sample_graph):
    """Not None, not a KeyError, not a missing node. A resource with nothing wrong"""

    assert sample_graph.states_of("SampleSecurityGroup") == [
        HAND_WRITTEN_FINDINGS[0]
    ]

    for resource_id in ["SampleEC2Instance", "SampleRole", "SampleBucket"]:

        node = sample_graph.node(resource_id)

        assert node is not None
        assert node["states"] == []
        assert sample_graph.states_of(resource_id) == []


def test_states_of_an_unknown_resource_is_empty_not_a_crash(sample_graph):
    assert sample_graph.states_of("NeverDeclared") == []
    assert sample_graph.node("NeverDeclared") is None


def test_every_resource_becomes_a_node(real_graph, real_resource_dicts):
    assert sorted(real_graph.nodes) == sorted(
        resource["id"] for resource in real_resource_dicts
    )


def test_no_finding_from_the_real_dataset_is_orphaned(real_graph):
    """The join key already agreed before this phase; this is the assertion that"""

    assert real_graph.orphan_findings == []


# -----------------------------

def test_finding_for_an_unknown_resource_warns_and_is_skipped(
    sample_infra,
    capsys
):
    """THE FAILURE THIS REPOSITORY ALREADY HAD."""

    state_graph = SecurityStateGraph(sample_infra, STALE_FINDINGS)

    output = capsys.readouterr().out

    assert "Warning" in output
    assert "DeletedBucket" in output

    # the stale row is dropped, the live one still lands
    assert "DeletedBucket" not in state_graph.nodes
    assert state_ids(state_graph, "SampleBucket") == ["public_bucket_acl"]

    # and it is retrievable, so a runner can report how much of the file missed
    assert state_graph.orphan_findings == [STALE_FINDINGS[0]]


def test_an_empty_findings_list_still_builds_a_graph(sample_infra):
    """Rules and topology are separate inputs; one of them being empty is a graph"""

    state_graph = SecurityStateGraph(sample_infra, [])

    assert len(state_graph.nodes) == 4
    assert state_graph.edges
    assert all(
        node["states"] == []
        for node in state_graph.nodes.values()
    )


# -----------------------------

def test_raw_properties_survive_onto_every_node(real_graph, real_resource_dicts):
    """WHY THE GRAPH IS BUILT IN MEMORY."""

    for resource in real_resource_dicts:

        node = real_graph.node(resource["id"])

        assert node["raw_properties"] == resource["raw_properties"]
        assert node["semantic_properties"] == resource["semantic_properties"]

    assert all(
        node["raw_properties"]
        for node in real_graph.nodes.values()
    )


def test_build_state_graph_joins_both_inputs_from_disk_in_one_pass():
    """The end-to-end entry point. raw_properties is asserted again here because it"""

    state_graph = build_state_graph()

    assert state_graph.node("PublicEC2Instance")["raw_properties"]
    assert state_ids(state_graph, "OpenSecurityGroup")
    assert state_graph.orphan_findings == []


def test_build_state_graph_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    build_state_graph()

    assert list(tmp_path.iterdir()) == []


# -----------------------------

def test_stored_edges_keep_the_declared_direction(real_graph):
    """The graph stores what the template says: the instance declares its group."""

    edges = pairs(real_graph.edges)

    assert ("PublicEC2Instance", "OpenSecurityGroup") in edges
    assert ("OpenSecurityGroup", "PublicEC2Instance") not in edges


def test_stored_edge_carries_its_category_and_relation(real_graph):
    edges = real_graph.edges_from("PublicEC2Instance")

    assert {
        "source": "PublicEC2Instance",
        "target": "OpenSecurityGroup",
        "category": "network_control",
        "relation": "association"
    } in edges

    assert {
        "source": "PublicEC2Instance",
        "target": "OverPermissiveInstanceProfile",
        "category": "identity",
        "relation": "dependency"
    } in edges


# -----------------------------

def test_network_control_edge_is_reversed_for_traversal(real_graph):
    """THE DESIGN DECISION."""

    traversal = pairs(real_graph.traversal_edges(), "network_control")

    assert ("OpenSecurityGroup", "PublicEC2Instance") in traversal
    assert ("PublicEC2Instance", "OpenSecurityGroup") not in traversal


def test_only_reversed_categories_are_flagged_reversed(real_graph):
    """A `reversed` flag means the edge is not in its declared direction, which is
    true of a REVERSED_CATEGORIES edge and of the back-copy of a bidirectional
    one. A forward edge of any category must never carry it."""

    for edge in real_graph.traversal_edges():

        if edge["category"] in REVERSED_CATEGORIES:
            assert edge["reversed"] is True

        elif edge["category"] not in BIDIRECTIONAL_CATEGORIES:
            assert edge["reversed"] is False

    assert REVERSED_CATEGORIES == ["network_control"]
    assert BIDIRECTIONAL_CATEGORIES == ["traffic_path"]


def test_a_bidirectional_edge_is_emitted_both_ways_and_flagged_once(real_graph):
    """One stored traffic_path edge becomes two traversal edges: the declared
    direction unflagged, and the back-copy flagged reversed."""

    for edge in real_graph.edges:

        if edge["category"] not in BIDIRECTIONAL_CATEGORIES:
            continue

        pair = (edge["source"], edge["target"])
        back = (edge["target"], edge["source"])

        seen = {
            (item["source"], item["target"]): item["reversed"]
            for item in real_graph.traversal_edges()
            if item["category"] in BIDIRECTIONAL_CATEGORIES
        }

        assert seen.get(pair) is False
        assert seen.get(back) is True


def test_the_view_neither_duplicates_nor_drops_an_edge(real_graph):
    """Reversal replaces the stored edge; it does not add a second copy. Keeping"""

    traversal = real_graph.traversal_edges()

    assert len(traversal) == len(real_graph.edges)

    categories = sorted(edge["category"] for edge in traversal)

    assert categories == sorted(
        edge["category"]
        for edge in real_graph.edges
    )


def test_building_the_view_does_not_mutate_the_stored_edges(real_graph):
    before = [dict(edge) for edge in real_graph.edges]

    real_graph.traversal_edges()
    real_graph.traversal_adjacency()

    assert real_graph.edges == before


# -----------------------------

def test_adjacency_de_duplicates_parallel_edges(parallel_edge_infra):
    """ParallelRole reaches ParallelBucket twice, through a "connection" edge and a"""

    state_graph = SecurityStateGraph(parallel_edge_infra, [])

    assert pairs(state_graph.traversal_edges()).count(
        ("ParallelRole", "ParallelBucket")
    ) == 2

    assert state_graph.traversal_adjacency()[
        "ParallelRole"
    ].count("ParallelBucket") == 1


def test_adjacency_has_an_entry_for_every_node(real_graph):
    adjacency = real_graph.traversal_adjacency()

    assert sorted(adjacency) == sorted(real_graph.nodes)

    # a resource that reaches nothing answers with an empty list
    assert adjacency["PublicRDS"] == []


# -----------------------------

def test_the_artifact_carries_exactly_the_four_documented_blocks(real_graph):
    """summary / nodes / edges / traversal_edges, and nothing else. An extra block"""

    artifact = real_graph.to_dict()

    assert sorted(artifact) == [
        "edges",
        "nodes",
        "summary",
        "traversal_edges"
    ]


def test_every_node_reaches_the_artifact_with_its_states(real_graph):
    """THE COMPLETENESS ASSERTION."""

    artifact = real_graph.to_dict()

    nodes = {node["id"]: node for node in artifact["nodes"]}

    assert sorted(nodes) == sorted(real_graph.nodes)

    for node_id, node in real_graph.nodes.items():

        serialized = nodes[node_id]

        assert serialized["type"] == node["type"]
        assert len(serialized["states"]) == len(node["states"])

        for state, finding in zip(serialized["states"], node["states"]):

            assert sorted(state) == sorted(STATE_KEYS)

            for key in STATE_KEYS:

                # The artifact resolves severity rather than copying it, so a
                # canonical finding is not written out with a null severity next
                # to findings that have one.
                if key == "severity":
                    assert state[key] == finding_severity(finding)
                    continue

                assert state[key] == finding[key]


def test_the_artifact_does_not_carry_raw_properties(real_graph):
    """Deliberately dropped even though it is on the node. It is already on disk"""

    artifact = real_graph.to_dict()

    for node in artifact["nodes"]:
        assert "raw_properties" not in node
        assert "semantic_properties" not in node

    text = json.dumps(artifact)

    assert "raw_properties" not in text
    assert "semantic_properties" not in text

    # and the properties really were on the graph, or the assertion above is
    # about a graph that never had them
    assert real_graph.node("PublicEC2Instance")["raw_properties"]


def test_the_summary_block_is_the_counts_the_runner_prints(real_graph):
    summary = real_graph.to_dict()["summary"]

    assert summary["resources"] == len(real_graph.nodes)
    assert summary["edges"] == len(real_graph.edges)
    assert summary["findings"] == real_graph.finding_count()
    assert summary["entry_points"] == len(entry_points(real_graph))
    assert summary["targets"] == len(data_targets(real_graph))
    assert summary["orphan_findings"] == len(real_graph.orphan_findings)


def test_the_summary_counts_orphan_findings_rather_than_hiding_them(
    sample_infra,
    capsys
):
    """The distinction the count exists to make: "the rules found nothing" and "the"""

    state_graph = SecurityStateGraph(sample_infra, STALE_FINDINGS)

    capsys.readouterr()

    summary = state_graph.to_dict()["summary"]

    assert summary["orphan_findings"] == 1
    assert summary["findings"] == 1


# -----------------------------

def test_is_entry_agrees_with_the_module_that_searches_entries(real_graph):
    """THE FLAG THAT MUST NOT DIVERGE."""

    artifact = real_graph.to_dict()

    entries = entry_points(real_graph)

    assert sorted(
        node["id"] for node in artifact["nodes"] if node["is_entry"]
    ) == sorted(entries)

    # and the dataset really has some, or this passes on two empty lists
    assert entries


def test_a_node_does_not_claim_to_be_a_target(real_graph):
    """Deliberately absent, and asserted so it is not re-added by reflex.

    Whether a resource is worth reaching depends on which objective is being
    pursued, and five objectives claim overlapping type sets. A single boolean on
    the node had to pick one answer and then read as a fact about the resource.
    The question is answered per objective, in output/attack_paths.json.
    """

    for node in real_graph.to_dict()["nodes"]:
        assert "is_target" not in node
        assert "target_reason" not in node


def test_targets_are_still_selectable_from_the_graph(real_graph):
    """Dropping the field must not mean dropping the capability: path finding
    still has to be able to ask which nodes are worth reaching."""

    targets = data_targets(real_graph)

    assert targets
    assert "PublicRDS" in targets
    assert "InsecureS3Bucket" in targets


def test_the_entry_reason_names_the_rule_that_made_it_one(real_graph):
    """The reason is the evidence. Entry points are derived from rule metadata, so"""

    nodes = {
        node["id"]: node
        for node in real_graph.to_dict()["nodes"]
    }

    group = nodes["OpenSecurityGroup"]

    assert group["is_entry"]

    # The rule, the state it raised, and its severity — enough to judge the entry
    # point without opening the rule file.
    # Both network_control findings, each with the state it raised and its
    # severity — enough to judge the entry point without opening the rule file.
    assert group["entry_reason"] == ENTRY_REASON_TEMPLATE.format(
        ", ".join([
            ENTRY_REASON_FINDING.format(
                "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroup",
                "unrestricted_common_port_access",
                "high"
            ),
            ENTRY_REASON_FINDING.format(
                "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup",
                "unrestricted_ssh_access",
                "high"
            )
        ])
    )

    # a node no entry rule fired on says so, rather than saying nothing
    profile = nodes["OverPermissiveInstanceProfile"]

    assert not profile["is_entry"]
    assert profile["entry_reason"] == ENTRY_REASON_NONE.format(
        ", ".join(ENTRY_SEMANTICS)
    )


def test_the_entry_reason_names_every_exposure_finding(real_graph):
    """Two ways in are two facts. Collapsing them loses which one to fix."""

    nodes = {node["id"]: node for node in real_graph.to_dict()["nodes"]}

    instance = nodes["PublicEC2Instance"]

    assert instance["is_entry"]

    # EC2_PUBLIC_IP is the exposure finding; EC2_IMDSV1_ENABLED is privilege and
    # must NOT appear, or the reason stops meaning "why you can reach this".
    assert "EC2_PUBLIC_IP" in instance["entry_reason"]
    assert "EC2_IMDSV1_ENABLED" not in instance["entry_reason"]


# -----------------------------

def test_max_severity_is_the_worst_and_not_the_alphabetically_last(real_graph):
    """THE COMPARISON THAT WOULD HAVE BEEN WRONG."""

    nodes = {
        node["id"]: node
        for node in real_graph.to_dict()["nodes"]
    }

    assert nodes["OverPermissiveRole"]["max_severity"] == "critical"

    # a node with nothing wrong with it answers None, not "clean": "clean" is
    assert nodes["OverPermissiveInstanceProfile"]["max_severity"] is None

    for node_id, node in nodes.items():

        severities = [
            finding_severity(finding)
            for finding in real_graph.states_of(node_id)
        ]

        if not severities:
            assert node["max_severity"] is None
            continue

        assert node["max_severity"] in severities

        assert severity_weight(node["max_severity"]) == max(
            severity_weight(severity)
            for severity in severities
        )


# -----------------------------

def test_both_edge_lists_reach_the_artifact_complete(real_graph):
    artifact = real_graph.to_dict()

    assert len(artifact["edges"]) == len(real_graph.edges)
    assert len(artifact["traversal_edges"]) == len(real_graph.traversal_edges())

    assert sorted(pairs(artifact["edges"])) == sorted(
        pairs(real_graph.edges)
    )

    assert sorted(pairs(artifact["traversal_edges"])) == sorted(
        pairs(real_graph.traversal_edges())
    )


def test_the_gate_dropped_edge_is_stored_and_not_traversed(gate_dropped_infra):
    """THE ARM THE SHIPPED DATASET NEVER EXERCISES."""

    artifact = SecurityStateGraph(gate_dropped_infra, []).to_dict()

    assert "AWS::Lambda::Function" not in INBOUND_REACHABLE_TYPES

    assert ("GateLambda", "GateSecurityGroup") in pairs(artifact["edges"])

    traversal = pairs(artifact["traversal_edges"])

    assert ("GateLambda", "GateSecurityGroup") not in traversal
    assert ("GateSecurityGroup", "GateLambda") not in traversal

    # the categories the gate leaves alone come through untouched, so this is a
    # gate and not a general loss of edges
    assert ("GateLambda", "GateRole") in traversal
    assert ("GateRole", "GateBucket") in traversal

    # and the artifact's own counts report the asymmetry rather than papering
    # over it: the summary counts stored edges, the traversal list is shorter
    assert artifact["summary"]["edges"] == 3
    assert len(artifact["traversal_edges"]) == 2


def test_both_edge_lists_are_sorted_on_all_four_fields(real_graph):
    """The graph is a multigraph — a role that both names a bucket and grants "*"""

    artifact = real_graph.to_dict()

    for key in ["edges", "traversal_edges"]:

        keys = [edge_sort_key(edge) for edge in artifact[key]]

        assert keys == sorted(keys)


def test_edge_sort_key_separates_parallel_edges(parallel_edge_infra):
    """ParallelRole reaches ParallelBucket through a "connection" edge and a"""

    state_graph = SecurityStateGraph(parallel_edge_infra, [])

    artifact = state_graph.to_dict()

    parallel = [
        edge
        for edge in artifact["edges"]
        if (edge["source"], edge["target"]) == ("ParallelRole", "ParallelBucket")
    ]

    assert len(parallel) == 2
    assert len({edge_sort_key(edge) for edge in parallel}) == 2

    keys = [edge_sort_key(edge) for edge in parallel]

    assert keys == sorted(keys)


# -----------------------------

def test_write_state_graph_writes_one_file_per_block(tmp_path, real_graph):
    files = {
        name: tmp_path / "output" / path.name
        for name, path in GRAPH_FILES.items()
    }

    written = write_state_graph(real_graph, files)

    artifact = real_graph.to_dict()

    assert set(written) == set(GRAPH_FILES)

    for name, path in written.items():
        assert path.exists()
        assert json.loads(path.read_text(encoding="utf-8")) == artifact[name]


def test_writing_overwrites_rather_than_appends(tmp_path, real_graph):
    files = {name: tmp_path / path.name for name, path in GRAPH_FILES.items()}

    write_state_graph(real_graph, files)

    files["summary"].write_text("{}\n", encoding="utf-8")

    write_state_graph(real_graph, files)

    assert json.loads(files["summary"].read_text(encoding="utf-8")) == (
        real_graph.to_dict()["summary"]
    )


def test_every_block_has_a_file_and_every_file_has_a_block(real_graph):
    """The table drives the writing, so a block added to to_dict() and left out of
    GRAPH_FILES is a block nobody writes. Asserted both ways, because either
    direction failing is a file quietly missing or a KeyError at write time."""

    assert set(GRAPH_FILES) == set(real_graph.to_dict())


def test_a_block_missing_from_the_table_is_an_error(tmp_path, real_graph):
    """Loudly, rather than a file silently not appearing."""

    with pytest.raises(KeyError):
        write_state_graph(real_graph, {"summary": tmp_path / "summary.json"})


def test_the_default_artifacts_land_in_output_and_never_in_the_cwd():
    """The constants, not a run. Writing relative to the working directory is a
    bug this repository already had once."""

    for path in GRAPH_FILES.values():
        assert path.parent.name == "output"
        assert path.is_absolute()
        assert path.name.startswith("graph_")

    # four distinct files, not one path repeated
    assert len({path.name for path in GRAPH_FILES.values()}) == len(GRAPH_FILES)


def test_the_serialized_graph_is_deterministic(tmp_path):
    """THE CLAIM THE SORTING EXISTS FOR."""

    def write_into(folder):
        folder.mkdir()

        return write_state_graph(
            build_state_graph(),
            {name: folder / path.name for name, path in GRAPH_FILES.items()}
        )

    first = write_into(tmp_path / "first")
    second = write_into(tmp_path / "second")

    for name in GRAPH_FILES:
        assert (
            first[name].read_text(encoding="utf-8")
            == second[name].read_text(encoding="utf-8")
        )


def test_each_block_matches_its_golden_file(tmp_path):
    """Every block, byte for byte. Every other test here asserts one property of
    the artifact; this one asserts the whole thing did not move."""

    written = write_state_graph(
        build_state_graph(),
        {name: tmp_path / path.name for name, path in GRAPH_FILES.items()}
    )

    for name, golden in GOLDEN_FILES.items():
        assert written[name].read_text(encoding="utf-8") == golden.read_text(
            encoding="utf-8"
        ), (
            "the %s block changed - read the diff, then regenerate the golden "
            "files (see the docstring at the top of this module)" % name
        )
