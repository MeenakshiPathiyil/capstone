"""Tests for the two renders, which are the only artifacts nothing can validate."""

import json
import re
from pathlib import Path

import pytest

from attack_path.exporter import HOP_ARROW, source_id_for
from attack_path.path_finder import find_attack_paths
from attack_path.renderer import (
    DOT_PATH,
    DOT_SHAPES,
    EMPHASIS_COLOR,
    EMPHASIS_WIDTH,
    MERMAID_HEADER,
    MERMAID_PATH,
    MERMAID_SHAPES,
    SEVERITY_STYLES,
    edge_label,
    emphasis_index,
    node_tokens,
    render_dot,
    render_mermaid,
    safe_token,
    style_key,
    write_dot,
    write_mermaid,
    write_renders
)
from security_state_graph.state_graph import SecurityStateGraph, build_state_graph


GOLDEN_MERMAID = Path(__file__).resolve().parent / "golden_security_state_graph.mmd"
GOLDEN_DOT = Path(__file__).resolve().parent / "golden_security_state_graph.dot"


# -----------------------------

# Written against the *format*, not against graph/renderer.py's constants. The
MERMAID_NODE = re.compile(
    r"^ {4}(n_\w+)(\(\[|\[\(|\{\{|\[)\"(.*)\"(\]\)|\)\]|\}\}|\])$"
)

MERMAID_EDGE = re.compile(
    r"^ {4}(n_\w+) (-->|==>)\|\"(.*)\"\| (n_\w+)$"
)

MERMAID_CLASSDEF = re.compile(r"^ {4}classDef sev_\w+ [\w\-:#,]+;$")
MERMAID_CLASS = re.compile(r"^ {4}class (n_\w+) (sev_\w+);$")
MERMAID_LINKSTYLE = re.compile(r"^ {4}linkStyle ([\d,]+) [\w\-:#,]+;$")
MERMAID_COMMENT = re.compile(r"^%%( .*)?$")

DOT_NODE = re.compile(
    r"^ {4}\"(n_\w+)\" \[label=\"(.*)\", shape=\"(\w+)\", "
    r"fillcolor=\"(#[0-9a-fA-F]{6})\", color=\"(#[0-9a-fA-F]{6})\"\];$"
)

DOT_EDGE = re.compile(
    r"^ {4}\"(n_\w+)\" -> \"(n_\w+)\" \[label=\"(.*)\", "
    r"color=\"(#[0-9a-fA-F]{6})\", penwidth=\"(\d+)\"\];$"
)

DOT_ATTRIBUTE = re.compile(r"^ {4}(rankdir=\"LR\";|(graph|node|edge) \[.*\];)$")
DOT_COMMENT = re.compile(r"^ {4}//( .*)?$")


# -----------------------------

def mermaid_problems(text):
    """Everything structurally wrong with a Mermaid render, as a list of strings."""

    problems = []

    lines = text.split("\n")

    # -----------------------------

    if not lines or lines[0] != MERMAID_HEADER:
        problems.append(
            "line 1 is not the flowchart declaration: "
            + repr(lines[0] if lines else None)
        )

    # -----------------------------

    declared = []
    edges = []

    for number, line in enumerate(lines[1:], 2):

        if not line.strip():
            continue

        node = MERMAID_NODE.match(line)

        if node:

            if node.group(1) in declared:
                problems.append(f"line {number}: duplicate node {node.group(1)}")

            declared.append(node.group(1))
            continue

        edge = MERMAID_EDGE.match(line)

        if edge:
            edges.append((number, edge.group(1), edge.group(4)))
            continue

        if (
            MERMAID_COMMENT.match(line)
            or MERMAID_CLASSDEF.match(line)
            or MERMAID_CLASS.match(line)
            or MERMAID_LINKSTYLE.match(line)
        ):
            continue

        problems.append(f"line {number}: unrecognised syntax: {line!r}")

    # -----------------------------

    for number, source, target in edges:

        for endpoint in [source, target]:

            if endpoint not in declared:
                problems.append(
                    f"line {number}: edge endpoint {endpoint} was never declared"
                )

    return problems


def unquoted(text):
    """A DOT source with every quoted string removed, escapes honoured."""

    return re.sub(r"\"(?:\\.|[^\"\\])*\"", "", text)


def dot_problems(text):
    """Everything structurally wrong with a DOT render, as a list of strings."""

    problems = []

    lines = text.split("\n")

    # -----------------------------

    if not lines or not lines[0].startswith("digraph "):
        problems.append(
            "line 1 is not a digraph declaration: "
            + repr(lines[0] if lines else None)
        )

    stripped = [line for line in lines if line.strip()]

    if not stripped or stripped[-1] != "}":
        problems.append("the file does not end with a closing brace")

    # -----------------------------

    skeleton = unquoted(text)

    opened = skeleton.count("{")
    closed = skeleton.count("}")

    if opened != closed:
        problems.append(f"unbalanced braces: {opened} open, {closed} closed")

    if opened != 1:
        problems.append(f"expected exactly one graph block, found {opened}")

    # -----------------------------

    declared = []
    edges = []

    for number, line in enumerate(lines[1:], 2):

        if not line.strip() or line.strip() == "}":
            continue

        # Quotes first: an odd count is the corruption that makes every later
        # check on this line meaningless.
        if unquoted(line).count("\"") % 2 != 0:
            problems.append(f"line {number}: unbalanced quotes: {line!r}")
            continue

        node = DOT_NODE.match(line)

        if node:

            if node.group(1) in declared:
                problems.append(f"line {number}: duplicate node {node.group(1)}")

            declared.append(node.group(1))
            continue

        edge = DOT_EDGE.match(line)

        if edge:
            edges.append((number, edge.group(1), edge.group(2)))
            continue

        if DOT_COMMENT.match(line) or DOT_ATTRIBUTE.match(line):
            continue

        problems.append(f"line {number}: unrecognised syntax: {line!r}")

    # -----------------------------

    for number, source, target in edges:

        for endpoint in [source, target]:

            if endpoint not in declared:
                problems.append(
                    f"line {number}: edge endpoint {endpoint} was never declared"
                )

    return problems


def mermaid_nodes(text):
    """token -> (opening bracket, label, closing bracket) for every declared node."""

    found = {}

    for line in text.split("\n"):

        match = MERMAID_NODE.match(line)

        if match:
            found[match.group(1)] = (
                match.group(2),
                match.group(3),
                match.group(4)
            )

    return found


def mermaid_edges(text):
    """(source token, target token) -> (arrow, label) for every declared edge."""

    found = {}

    for line in text.split("\n"):

        match = MERMAID_EDGE.match(line)

        if match:
            found[(match.group(1), match.group(4))] = (
                match.group(2),
                match.group(3)
            )

    return found


def dot_nodes(text):
    """token -> (label, shape, fill, stroke) for every declared node."""

    found = {}

    for line in text.split("\n"):

        match = DOT_NODE.match(line)

        if match:
            found[match.group(1)] = (
                match.group(2),
                match.group(3),
                match.group(4),
                match.group(5)
            )

    return found


def dot_edges(text):
    """(source token, target token) -> (label, color, penwidth) for every edge."""

    found = {}

    for line in text.split("\n"):

        match = DOT_EDGE.match(line)

        if match:
            found[(match.group(1), match.group(2))] = (
                match.group(3),
                match.group(4),
                int(match.group(5))
            )

    return found


def mermaid_classes(text):
    """token -> the severity class assigned to it."""

    found = {}

    for line in text.split("\n"):

        match = MERMAID_CLASS.match(line)

        if match:
            found[match.group(1)] = match.group(2)

    return found


def linkstyle_indices(text):
    """The edge indices the linkStyle line addresses, or [] when there is none."""

    for line in text.split("\n"):

        match = MERMAID_LINKSTYLE.match(line)

        if match:
            return [int(index) for index in match.group(1).split(",")]

    return []


# -----------------------------

# Hand-built as a to_dict() dictionary, because the point is label content the
HOSTILE_GRAPH = {
    "summary": {
        "resources": 4,
        "edges": 1,
        "findings": 0,
        "entry_points": 1,
        "targets": 1,
        "orphan_findings": 0
    },
    "nodes": [
        {
            "id": "A -> B",
            "type": "AWS::Custom::Type#1",
            "states": [],
            "max_severity": "high",
            "is_entry": True,
            "entry_reason": "exposure finding: HOSTILE_RULE",
            "is_target": False,
            "target_reason": "resource type AWS::Custom::Type#1 is not a data resource"
        },
        {
            "id": "A-B",
            "type": "AWS::S3::Bucket",
            "states": [],
            "max_severity": None,
            "is_entry": False,
            "entry_reason": "no state declares semantic: exposure",
            "is_target": True,
            "target_reason": "resource type AWS::S3::Bucket is a data resource"
        },
        {
            "id": "A.B",
            "type": "AWS::S3::Bucket",
            "states": [],
            "max_severity": "catastrophic",
            "is_entry": False,
            "entry_reason": "no state declares semantic: exposure",
            "is_target": False,
            "target_reason": "resource type AWS::S3::Bucket is a data resource"
        },
        {
            "id": "Odd \"Quoted\" Name",
            "type": "AWS::EC2::Instance",
            "states": [],
            "max_severity": "critical",
            "is_entry": False,
            "entry_reason": "no state declares semantic: exposure",
            "is_target": False,
            "target_reason": "resource type AWS::EC2::Instance is not a data resource"
        }
    ],
    "edges": [],
    "traversal_edges": [
        {
            "source": "A -> B",
            "target": "A-B",
            "category": "identity",
            "relation": "dependency",
            "reversed": False
        }
    ]
}

# One ranked path over the hostile graph, in the shape find_attack_paths()
# returns: the hops are node ids, which is what the emphasis is read off.
HOSTILE_PATHS = [
    {
        "hops": ["A -> B", "A-B"],
        "attack_level": "CRITICAL"
    }
]


# -----------------------------

@pytest.fixture
def real_graph(real_resources_path, rules_path):
    """The shipped dataset, joined to the findings the shipped rules produce."""

    return build_state_graph(real_resources_path, rules_path)


@pytest.fixture
def real_paths(real_graph):
    return find_attack_paths(real_graph)


@pytest.fixture
def mermaid(real_graph, real_paths):
    return render_mermaid(real_graph.to_dict(), real_paths)


@pytest.fixture
def dot(real_graph, real_paths):
    return render_dot(real_graph.to_dict(), real_paths)


# -----------------------------

def test_the_mermaid_render_is_structurally_sound(mermaid):
    assert mermaid_problems(mermaid) == []


def test_the_dot_render_is_structurally_sound(dot):
    assert dot_problems(dot) == []


def test_the_mermaid_header_is_the_first_line(mermaid):
    """A comment block would be legal ahead of it — Mermaid's %%{init}%% directive"""

    assert mermaid.split("\n")[0] == "flowchart LR"


def test_the_dot_header_and_footer_bracket_the_whole_file(dot):
    lines = [line for line in dot.split("\n") if line.strip()]

    assert lines[0] == "digraph security_state_graph {"
    assert lines[-1] == "}"

    assert unquoted(dot).count("{") == 1
    assert unquoted(dot).count("}") == 1


def test_both_renders_end_with_exactly_one_newline(mermaid, dot):
    for text in [mermaid, dot]:
        assert text.endswith("\n")
        assert not text.endswith("\n\n")


# -----------------------------

CORRUPTIONS = [
    ("mermaid", "undeclared endpoint",
     lambda m, d: m.replace("n_PublicEC2Instance ==>", "n_Ghost ==>", 1)),
    ("mermaid", "duplicate declaration",
     lambda m, d: "\n".join(
         line for pair in ((l, l) if MERMAID_NODE.match(l) else (l,)
                           for l in m.split("\n")) for line in pair)),
    ("mermaid", "broken header",
     lambda m, d: m.replace("flowchart LR", "flowchart", 1)),
    ("mermaid", "truncated label",
     lambda m, d: m.replace('n_OverPermissiveRole["OverPermissiveRole',
                            "n_OverPermissiveRole[OverPermissiveRole", 1)),
    ("dot", "missing brace", lambda m, d: d.rstrip()[:-1]),
    ("dot", "unbalanced quote",
     lambda m, d: d.replace('[label="OverPermissiveRole',
                            "[label=OverPermissiveRole", 1)),
    ("dot", "undeclared endpoint",
     lambda m, d: d.replace('"n_PublicEC2Instance" ->', '"n_Ghost" ->', 1)),
    ("dot", "second graph block", lambda m, d: d + "digraph second {\n}\n"),
]


@pytest.mark.parametrize(
    "fmt,label,corrupt",
    CORRUPTIONS,
    ids=[f"{f}-{l}" for f, l, _ in CORRUPTIONS]
)
def test_the_structural_checkers_are_not_vacuous(mermaid, dot, fmt, label, corrupt):
    """Each checker must reject a corruption the diagram tool would accept silently."""

    checker = mermaid_problems if fmt == "mermaid" else dot_problems

    assert checker(corrupt(mermaid, dot)), label



# -----------------------------

def test_both_formats_declare_the_same_nodes(mermaid, dot, real_graph):
    """THE ASSERTION THAT MAKES ONE MODULE WORTH IT."""

    tokens = node_tokens(real_graph.to_dict())

    assert set(mermaid_nodes(mermaid)) == set(dot_nodes(dot))
    assert set(mermaid_nodes(mermaid)) == set(tokens.values())

    assert len(tokens) == len(real_graph.nodes)


def test_both_formats_declare_the_same_edges(mermaid, dot):
    assert set(mermaid_edges(mermaid)) == set(dot_edges(dot))


def test_every_drawn_node_is_a_resource_of_the_account(mermaid, dot, real_graph):
    """The other direction: nothing in either file is a node the graph does not"""

    tokens = node_tokens(real_graph.to_dict())

    reverse = {token: node_id for node_id, token in tokens.items()}

    for drawn in [mermaid_nodes(mermaid), dot_nodes(dot)]:

        for token in drawn:

            assert token in reverse
            assert reverse[token] in real_graph.nodes


def test_the_drawn_edges_are_the_traversal_view(mermaid, dot, real_graph):
    """The attacker's direction, not the declared one. Drawn over the stored edges"""

    artifact = real_graph.to_dict()
    tokens = node_tokens(artifact)

    expected = {
        (tokens[edge["source"]], tokens[edge["target"]])
        for edge in artifact["traversal_edges"]
    }

    assert set(mermaid_edges(mermaid)) == expected
    assert set(dot_edges(dot)) == expected

    # and specifically: the reversed network_control edge, in the attacker's
    # direction, with the declared direction absent
    assert (
        tokens["OpenSecurityGroup"],
        tokens["PublicEC2Instance"]
    ) in expected

    assert (
        tokens["PublicEC2Instance"],
        tokens["OpenSecurityGroup"]
    ) not in expected


def test_the_reversed_edge_says_so_in_its_label(mermaid, dot, real_graph):
    """The decision graph/state_graph.py exists to make, visible in the picture"""

    tokens = node_tokens(real_graph.to_dict())

    pair = (tokens["OpenSecurityGroup"], tokens["PublicEC2Instance"])

    assert "reversed" in mermaid_edges(mermaid)[pair][1]
    assert "reversed" in dot_edges(dot)[pair][0]

    # and an edge that was not reversed does not claim to have been
    identity = (
        tokens["PublicEC2Instance"],
        tokens["OverPermissiveInstanceProfile"]
    )

    assert "reversed" not in mermaid_edges(mermaid)[identity][1]
    assert "reversed" not in dot_edges(dot)[identity][0]


# -----------------------------

def test_exactly_the_ranked_path_hops_are_emphasised(
    mermaid,
    dot,
    real_graph,
    real_paths
):
    """THE REQUIREMENT THE DIAGRAM EXISTS FOR."""

    tokens = node_tokens(real_graph.to_dict())

    expected = set()

    for path in real_paths:

        hops = path["hops"]

        for source, target in zip(hops, hops[1:]):
            expected.add((tokens[source], tokens[target]))

    assert expected, "the shipped dataset produced no paths to emphasise"

    thick = {
        pair
        for pair, (arrow, _) in mermaid_edges(mermaid).items()
        if arrow == "==>"
    }

    assert thick == expected

    coloured = {
        pair
        for pair, (_, color, width) in dot_edges(dot).items()
        if color == EMPHASIS_COLOR and width == EMPHASIS_WIDTH
    }

    assert coloured == expected

    # the edge that is not on any path is drawn plainly in both
    plain = (tokens["PublicBucketPolicy"], tokens["InsecureS3Bucket"])

    assert plain not in expected
    assert mermaid_edges(mermaid)[plain][0] == "-->"
    assert dot_edges(dot)[plain][1] != EMPHASIS_COLOR


def test_an_emphasised_edge_names_the_paths_that_use_it(
    mermaid,
    dot,
    real_graph,
    real_paths
):
    """A hop two paths share is labelled with both AP ids, in rank order, or a"""

    tokens = node_tokens(real_graph.to_dict())

    shared = (
        tokens["PublicEC2Instance"],
        tokens["OverPermissiveInstanceProfile"]
    )

    # Whichever paths use this hop, the label names them all and in rank order.
    from attack_path.renderer import emphasis_index

    expected = ", ".join(
        emphasis_index(real_paths)[
            ("PublicEC2Instance", "OverPermissiveInstanceProfile")
        ]
    )

    assert expected
    assert expected in mermaid_edges(mermaid)[shared][1]
    assert expected in dot_edges(dot)[shared][0]

    # and a hop's label names exactly the paths that use it — no more. A hop
    # off every ranked path carries no AP id at all.
    for (source, target), ids in emphasis_index(real_paths).items():

        pair = (tokens[source], tokens[target])
        label = mermaid_edges(mermaid)[pair][1]

        assert ", ".join(ids) in label

    unused = (tokens["DeploymentRole"], tokens["AppServerRole"])

    assert "AP-" not in mermaid_edges(mermaid)[unused][1]


def test_the_linkstyle_addresses_exactly_the_thick_edges(mermaid):
    """linkStyle addresses edges by their position in the file, so an index off by"""

    order = [
        (match.group(1), match.group(4))
        for match in (
            MERMAID_EDGE.match(line)
            for line in mermaid.split("\n")
        )
        if match
    ]

    thick = [
        index
        for index, line in enumerate(
            line for line in mermaid.split("\n") if MERMAID_EDGE.match(line)
        )
        if MERMAID_EDGE.match(line).group(2) == "==>"
    ]

    assert order
    assert linkstyle_indices(mermaid) == thick


def test_emphasis_index_reads_the_hops_and_not_the_exported_name():
    """WHY THE SHORTCUT IS REFUSED."""

    index = emphasis_index(HOSTILE_PATHS)

    assert index == {("A -> B", "A-B"): ["AP-001"]}

    assert HOP_ARROW.join(HOSTILE_PATHS[0]["hops"]) == "A -> B -> A-B"

    # what a splitter would have produced from that display string
    assert ("A", "B") not in index

    # rank order, and one id per path even where two paths share a hop
    two_paths = emphasis_index([
        {"hops": ["X", "Y", "Z"]},
        {"hops": ["X", "Y", "W"]}
    ])

    assert two_paths[("X", "Y")] == [source_id_for(1), source_id_for(2)]
    assert two_paths[("Y", "Z")] == [source_id_for(1)]
    assert two_paths[("Y", "W")] == [source_id_for(2)]


def test_no_paths_means_no_emphasis_and_a_file_that_still_renders(real_graph):
    """A zero-path account is a legitimate result, and the diagram of it has to"""

    artifact = real_graph.to_dict()

    mermaid = render_mermaid(artifact, [])
    dot = render_dot(artifact, [])

    assert mermaid_problems(mermaid) == []
    assert dot_problems(dot) == []

    assert "linkStyle" not in mermaid

    assert all(
        arrow == "-->"
        for arrow, _ in mermaid_edges(mermaid).values()
    )

    assert all(
        color != EMPHASIS_COLOR
        for _, color, _ in dot_edges(dot).values()
    )

    # the nodes and edges are all still there — no paths is not no graph
    assert len(mermaid_nodes(mermaid)) == len(real_graph.nodes)
    assert len(mermaid_edges(mermaid)) == len({
        (edge["source"], edge["target"])
        for edge in artifact["traversal_edges"]
    })

    # and the legend says so in words rather than leaving a blank
    assert "none - no route survived" in mermaid
    assert "none - no route survived" in dot


# -----------------------------

def test_a_label_containing_the_hop_arrow_survives_both_formats():
    """THE TRAP THE FORMATS INVITE, AND IT IS LIVE IN THE REAL DATA."""

    mermaid = render_mermaid(HOSTILE_GRAPH, HOSTILE_PATHS)
    dot = render_dot(HOSTILE_GRAPH, HOSTILE_PATHS)

    assert mermaid_problems(mermaid) == []
    assert dot_problems(dot) == []

    assert len(mermaid_nodes(mermaid)) == 4
    assert len(mermaid_edges(mermaid)) == 1

    assert len(dot_nodes(dot)) == 4
    assert len(dot_edges(dot)) == 1

    tokens = node_tokens(HOSTILE_GRAPH)

    # The id is in a label and nowhere else. In Mermaid the ">" is additionally
    assert "A -#gt; B" in mermaid_nodes(mermaid)[tokens["A -> B"]][1]
    assert "A -> B" in dot_nodes(dot)[tokens["A -> B"]][0]

    # and the arrow never appears outside a label in the Mermaid source, which
    for line in mermaid.split("\n"):

        if MERMAID_NODE.match(line):
            assert "->" not in line


def test_a_label_containing_a_double_quote_is_escaped_in_both_formats():
    """The escape the two grammars spell differently: Mermaid takes an HTML entity,"""

    mermaid = render_mermaid(HOSTILE_GRAPH, HOSTILE_PATHS)
    dot = render_dot(HOSTILE_GRAPH, HOSTILE_PATHS)

    tokens = node_tokens(HOSTILE_GRAPH)

    mermaid_label = mermaid_nodes(mermaid)[tokens["Odd \"Quoted\" Name"]][1]

    assert "#quot;" in mermaid_label
    assert "\"" not in mermaid_label

    dot_label = dot_nodes(dot)[tokens["Odd \"Quoted\" Name"]][0]

    assert "\\\"" in dot_label

    # every quote in the DOT label is an escaped one
    assert dot_label.count("\"") == dot_label.count("\\\"")


def test_a_hash_in_a_label_cannot_forge_a_mermaid_entity():
    """"#" is what introduces Mermaid's entity escapes, so it is escaped first and"""

    mermaid = render_mermaid(HOSTILE_GRAPH, HOSTILE_PATHS)

    tokens = node_tokens(HOSTILE_GRAPH)

    label = mermaid_nodes(mermaid)[tokens["A -> B"]][1]

    assert "AWS::Custom::Type#35;1" in label
    assert "#35;quot;" not in mermaid


def test_every_label_in_the_real_renders_is_quoted(mermaid, dot):
    """Not "the ones that needed it". Every resource type in the shipped dataset"""

    assert mermaid_nodes(mermaid)
    assert dot_nodes(dot)

    for line in mermaid.split("\n"):

        match = MERMAID_NODE.match(line)

        if match:
            assert "::" in line or "InstanceProfile" in line
            assert line.count("\"") == 2

    for label, _, _, _ in dot_nodes(dot).values():
        assert "::" in label


def test_two_ids_deriving_one_identifier_do_not_collide():
    """"A-B" and "A.B" both reduce to n_A_B. The collision is resolved by appending"""

    tokens = node_tokens(HOSTILE_GRAPH)

    assert len(set(tokens.values())) == len(tokens)

    assert safe_token("A-B") == safe_token("A.B")

    assert tokens["A-B"] == "n_A_B"
    assert tokens["A.B"] == "n_A_B_2"

    # and the diagram declares both, once each
    mermaid = render_mermaid(HOSTILE_GRAPH, HOSTILE_PATHS)

    assert mermaid_problems(mermaid) == []
    assert set(mermaid_nodes(mermaid)) == set(tokens.values())


def test_an_identifier_can_never_be_a_bare_mermaid_keyword():
    """"end" and "graph" are Mermaid keywords, and a node called either would"""

    for hostile in ["end", "graph", "subgraph", "class", "flowchart"]:
        assert safe_token(hostile) == "n_" + hostile
        assert safe_token(hostile) != hostile


# -----------------------------

def test_the_way_in_is_encoded_as_a_shape(mermaid, dot, real_graph):
    """Two cases, and the shipped account contains both: a way in, and everything
    else. There used to be four, keyed on (is_entry, is_target) — the node no
    longer claims to be a target, because that depends on which objective is
    being pursued and five objectives claim overlapping type sets."""

    artifact = real_graph.to_dict()
    tokens = node_tokens(artifact)

    seen = set()

    for node in artifact["nodes"]:

        is_entry = bool(node["is_entry"])

        seen.add(is_entry)

        token = tokens[node["id"]]

        opening, closing = MERMAID_SHAPES[is_entry]

        assert mermaid_nodes(mermaid)[token][0] == opening
        assert mermaid_nodes(mermaid)[token][2] == closing

        assert dot_nodes(dot)[token][1] == DOT_SHAPES[is_entry]

    # both cases really occur, or this passes without distinguishing anything
    assert seen == {True, False}

    # and the two shapes are two distinct shapes
    assert len(set(DOT_SHAPES.values())) == 2
    assert len(set(MERMAID_SHAPES.values())) == 2


def test_the_role_is_also_written_in_words(mermaid, dot, real_graph):
    """Shape and colour both fail on a monochrome print and on a projector with poor"""

    artifact = real_graph.to_dict()
    tokens = node_tokens(artifact)

    entry = tokens["OpenSecurityGroup"]
    not_entry = tokens["OverPermissiveRole"]

    assert "[entry]" in mermaid_nodes(mermaid)[entry][1]
    assert "[entry" not in mermaid_nodes(mermaid)[not_entry][1]

    assert "[entry]" in dot_nodes(dot)[entry][0]
    assert "[entry" not in dot_nodes(dot)[not_entry][0]

    # "target" is not a word the diagram uses any more, anywhere
    assert "target]" not in mermaid
    assert "target]" not in dot


def test_the_fill_is_the_worst_severity_on_the_resource(mermaid, dot, real_graph):
    """Driven by max_severity, which the JSON artifact carries because a renderer"""

    artifact = real_graph.to_dict()
    tokens = node_tokens(artifact)

    for node in artifact["nodes"]:

        key = style_key(node["max_severity"])

        token = tokens[node["id"]]

        assert mermaid_classes(mermaid)[token] == "sev_" + key

        assert dot_nodes(dot)[token][2] == SEVERITY_STYLES[key]["fill"]
        assert dot_nodes(dot)[token][3] == SEVERITY_STYLES[key]["stroke"]

    # the account exercises more than one of them, or the encoding is a constant
    assert len(set(mermaid_classes(mermaid).values())) > 1


def test_every_node_gets_exactly_one_severity_class(mermaid, real_graph):
    """No node may fall through to a renderer default, because a default is a colour"""

    tokens = node_tokens(real_graph.to_dict())

    classes = mermaid_classes(mermaid)

    assert sorted(classes) == sorted(tokens.values())

    for name in classes.values():
        assert name[len("sev_"):] in SEVERITY_STYLES


def test_a_clean_node_and_an_unknown_severity_are_not_the_same_colour():
    """"nothing is wrong with this resource" and "something is wrong and nobody has"""

    assert style_key(None) == "clean"
    assert style_key("catastrophic") == "unknown"

    # and a rule cannot claim either by writing it as a severity
    assert style_key("clean") == "unknown"
    assert style_key("unknown") == "unknown"

    assert style_key("CRITICAL") == "critical"
    assert style_key("Critical") == "critical"

    fills = {
        SEVERITY_STYLES[key]["fill"]
        for key in SEVERITY_STYLES
    }

    assert len(fills) == len(SEVERITY_STYLES)


def test_the_severity_table_is_keyed_lowercase():
    """THE CONTRACT. data/security_rules.yaml writes `severity: high`, and an"""

    for key in SEVERITY_STYLES:
        assert key == key.lower()


def test_a_clean_node_says_so_rather_than_leaving_a_gap(mermaid, real_graph):
    """An empty line where the severity goes reads as a rendering bug, so the label"""

    tokens = node_tokens(real_graph.to_dict())

    label = mermaid_nodes(mermaid)[tokens["OverPermissiveInstanceProfile"]][1]

    assert "no findings" in label
    assert real_graph.states_of("OverPermissiveInstanceProfile") == []


# -----------------------------

def test_the_gate_dropped_edge_is_not_drawn(gate_dropped_infra):
    """The arm the shipped dataset never exercises. GateLambda names"""

    state_graph = SecurityStateGraph(gate_dropped_infra, [])

    artifact = state_graph.to_dict()
    tokens = node_tokens(artifact)

    mermaid = render_mermaid(artifact, [])
    dot = render_dot(artifact, [])

    assert mermaid_problems(mermaid) == []
    assert dot_problems(dot) == []

    forward = (tokens["GateLambda"], tokens["GateSecurityGroup"])
    backward = (tokens["GateSecurityGroup"], tokens["GateLambda"])

    for drawn in [mermaid_edges(mermaid), dot_edges(dot)]:

        assert forward not in drawn
        assert backward not in drawn

        # the categories the gate leaves alone are drawn
        assert (tokens["GateLambda"], tokens["GateRole"]) in drawn
        assert (tokens["GateRole"], tokens["GateBucket"]) in drawn

    # the group is still declared, with no edge touching it
    assert tokens["GateSecurityGroup"] in mermaid_nodes(mermaid)
    assert tokens["GateSecurityGroup"] in dot_nodes(dot)


# -----------------------------

def test_the_edge_label_names_the_category_and_its_notes():
    """The label builder on its own: category alone when there is nothing to add,"""

    plain = {"category": "identity", "reversed": False}

    assert edge_label(plain, []) == "identity"

    assert edge_label(plain, ["AP-001"]) == "identity (AP-001)"

    flipped = {"category": "network_control", "reversed": True}

    assert edge_label(flipped, []) == "network_control (reversed)"

    assert edge_label(flipped, ["AP-001", "AP-002"]) == (
        "network_control (reversed; AP-001, AP-002)"
    )


def test_every_drawn_edge_is_labelled_with_its_category(
    mermaid,
    dot,
    real_graph
):
    artifact = real_graph.to_dict()
    tokens = node_tokens(artifact)

    for edge in artifact["traversal_edges"]:

        pair = (tokens[edge["source"]], tokens[edge["target"]])

        assert edge["category"] in mermaid_edges(mermaid)[pair][1]
        assert edge["category"] in dot_edges(dot)[pair][0]


# -----------------------------

def test_both_renders_are_deterministic(real_graph, real_paths):
    """Otherwise the golden files below are flakes rather than assertions. Nothing"""

    artifact = real_graph.to_dict()

    assert render_mermaid(artifact, real_paths) == render_mermaid(
        artifact,
        real_paths
    )

    assert render_dot(artifact, real_paths) == render_dot(artifact, real_paths)

    # and rebuilt from disk, not just re-rendered from one dictionary
    rebuilt = build_state_graph()

    assert render_mermaid(
        rebuilt.to_dict(),
        find_attack_paths(rebuilt)
    ) == render_mermaid(artifact, real_paths)


def test_reordering_the_input_does_not_change_the_renders(
    tmp_path,
    real_resource_dicts,
    real_graph,
    real_paths
):
    """The renders inherit their ordering from to_dict(), which is sorted precisely"""

    reordered = tmp_path / "reversed.json"
    reordered.write_text(
        json.dumps(list(reversed(real_resource_dicts)), indent=2),
        encoding="utf-8"
    )

    other = build_state_graph(reordered)

    assert render_mermaid(
        other.to_dict(),
        find_attack_paths(other)
    ) == render_mermaid(real_graph.to_dict(), real_paths)

    assert render_dot(
        other.to_dict(),
        find_attack_paths(other)
    ) == render_dot(real_graph.to_dict(), real_paths)


def test_the_mermaid_render_matches_the_golden_file(mermaid):
    """The whole file, byte for byte. Every other test here asserts one property;"""

    assert mermaid == GOLDEN_MERMAID.read_text(encoding="utf-8"), (
        "the Mermaid render changed — read the diff, then regenerate the golden "
        "file (see the docstring at the top of this module)"
    )


def test_the_dot_render_matches_the_golden_file(dot):
    assert dot == GOLDEN_DOT.read_text(encoding="utf-8"), (
        "the DOT render changed — read the diff, then regenerate the golden "
        "file (see the docstring at the top of this module)"
    )


def test_the_golden_files_are_themselves_well_formed():
    """The goldens are checked in, so a bad regeneration would be committed and then"""

    assert mermaid_problems(GOLDEN_MERMAID.read_text(encoding="utf-8")) == []
    assert dot_problems(GOLDEN_DOT.read_text(encoding="utf-8")) == []


# -----------------------------

def test_write_mermaid_and_write_dot_write_what_they_rendered(
    tmp_path,
    real_graph,
    real_paths,
    mermaid,
    dot
):
    """The file is re-read rather than trusted: the artifact is the file, not the"""

    mermaid_target = tmp_path / "renders" / "graph.mmd"
    dot_target = tmp_path / "renders" / "graph.dot"

    assert write_mermaid(real_graph, real_paths, mermaid_target) == mermaid_target
    assert write_dot(real_graph, real_paths, dot_target) == dot_target

    assert mermaid_target.read_text(encoding="utf-8") == mermaid
    assert dot_target.read_text(encoding="utf-8") == dot


def test_write_renders_writes_both_and_overwrites(tmp_path, real_graph, real_paths):
    mermaid_target = tmp_path / "graph.mmd"
    dot_target = tmp_path / "graph.dot"

    written = write_renders(
        real_graph,
        real_paths,
        mermaid_target,
        dot_target
    )

    assert written == [mermaid_target, dot_target]

    mermaid_target.write_text("clobbered\n", encoding="utf-8")

    write_renders(real_graph, real_paths, mermaid_target, dot_target)

    assert mermaid_problems(
        mermaid_target.read_text(encoding="utf-8")
    ) == []


def test_the_default_render_paths_land_in_output():
    """The constants, not a run. Writing relative to the working directory is the"""

    for path in [MERMAID_PATH, DOT_PATH]:

        assert path.parent.name == "output"
        assert path.is_absolute()

    assert MERMAID_PATH.name == "security_state_graph.mmd"
    assert DOT_PATH.name == "security_state_graph.dot"

    # the three artifacts share a stem, so a reader who found one found all three
    assert MERMAID_PATH.stem == DOT_PATH.stem
