"""Draw the security state graph as text a diagram tool can render."""

import re
from pathlib import Path

from attack_path.exporter import HOP_ARROW, source_id_for


BASE_DIR = Path(__file__).resolve().parent.parent

# Where the two renders land. Siblings of output/security_state_graph.json on
MERMAID_PATH = BASE_DIR / "output" / "security_state_graph.mmd"
DOT_PATH = BASE_DIR / "output" / "security_state_graph.dot"

# The first line of each file, and nothing is emitted before them.
MERMAID_HEADER = "flowchart LR"
DOT_HEADER = "digraph security_state_graph {"
DOT_FOOTER = "}"

MERMAID_COMMENT = "%% "
DOT_COMMENT = "// "

INDENT = "    "

# The identifier prefix. Fixed, and not empty: "end" is a Mermaid keyword and
NODE_TOKEN_PREFIX = "n_"

# Anything that is not a bare identifier character becomes one underscore.
NODE_TOKEN_UNSAFE = re.compile(r"[^A-Za-z0-9_]")

# Appended to a derived identifier that is already taken, counting from 2.
NODE_TOKEN_COLLISION_START = 2

# How the lines of one node label are separated in each format. Mermaid labels
MERMAID_LINE_BREAK = "<br/>"
DOT_LINE_BREAK = "\\n"

# Mermaid's entity escapes, applied in this order. "#" is first because it is
# what introduces the other three, so escaping it last would double-escape them.
MERMAID_ESCAPES = [
    ("#", "#35;"),
    ("\"", "#quot;"),
    ("<", "#lt;"),
    (">", "#gt;")
]

# DOT's escapes, in this order for the same reason: the backslash introduces the
# quote escape.
DOT_ESCAPES = [
    ("\\", "\\\\"),
    ("\"", "\\\"")
]

# Node shape by is_entry.
#
# THEORY (why there is no target shape any more):
# The shape used to be keyed on (is_entry, is_target), which needed `is_target` on
# the node. It is no longer written there, because whether a resource is worth
# reaching depends on which objective is being pursued and five objectives claim
# overlapping type sets — a single boolean had to pick one answer and then read as
# if it were a fact about the resource. The diagram consequently distinguishes
# only "a way in" from "everything else"; which nodes are objectives is answered
# by output/attack_paths.json, where it is stated per objective rather than once.
MERMAID_SHAPES = {
    False: ("[", "]"),
    True: ("([", "])")
}

DOT_SHAPES = {
    False: "box",
    True: "house"
}

# Fill and stroke per severity.
SEVERITY_STYLES = {
    "critical": {"fill": "#f8b4b4", "stroke": "#7f1d1d"},
    "high": {"fill": "#fbcfa4", "stroke": "#7c2d12"},
    "medium": {"fill": "#fde68a", "stroke": "#78350f"},
    "low": {"fill": "#bfdbfe", "stroke": "#1e3a8a"},
    "clean": {"fill": "#e5e7eb", "stroke": "#374151"},
    "unknown": {"fill": "#ede9fe", "stroke": "#4c1d95"}
}

# The two keys in SEVERITY_STYLES that no rule may claim. A rule writing
PSEUDO_SEVERITIES = ["clean", "unknown"]

CLEAN_SEVERITY = "clean"
UNKNOWN_SEVERITY = "unknown"

# What a node with no findings says where the severity would go. Spelled out
# rather than left blank: an empty line in a label reads as a rendering bug.
CLEAN_SEVERITY_LABEL = "no findings"

# The Mermaid class name for a severity, and the prefix that keeps it from
# colliding with a node identifier.
SEVERITY_CLASS_PREFIX = "sev_"

# One text colour for every node. Near-black on all six fills, so contrast does
# not depend on which severity a resource happens to carry.
LABEL_TEXT_COLOR = "#111827"

# Ordinary edges and the ones on a ranked path.
EDGE_COLOR = "#374151"
EDGE_WIDTH = 2
EMPHASIS_COLOR = "#b3261e"
EMPHASIS_WIDTH = 4

MERMAID_EDGE = "-->"
MERMAID_EMPHASIS_EDGE = "==>"

# How an edge's label is assembled: the category, then the notes about it in
EDGE_NOTE_JOINER = "; "
EDGE_PATH_JOINER = ", "
REVERSED_NOTE = "reversed"

# How the categories of a merged parallel edge are joined in its label.
EDGE_CATEGORY_JOINER = " + "

# The role written into a node's label alongside its shape. Only one now — see
# the THEORY note on MERMAID_SHAPES for why there is no target role.
ROLE_ENTRY = "entry"
ROLE_JOINER = ", "

# Font sizes. Node text is deliberately larger than edge text: a reader follows
# the chain by its boxes and consults the edge labels afterwards.
NODE_FONT_SIZE = 14
EDGE_FONT_SIZE = 11
GRAPH_FONT_SIZE = 12
DOT_FONT = "Helvetica"


def safe_token(resource_id):
    """A resource id as a bare identifier both grammars accept."""

    return NODE_TOKEN_PREFIX + NODE_TOKEN_UNSAFE.sub(
        "_",
        str(resource_id)
    )


def node_tokens(graph):
    """resource id -> identifier, for every node in the serialized graph."""

    tokens = {}
    taken = []

    for node in graph.get("nodes") or []:

        # -----------------------------

        derived = safe_token(node["id"])

        candidate = derived
        suffix = NODE_TOKEN_COLLISION_START

        while candidate in taken:
            candidate = f"{derived}_{suffix}"
            suffix = suffix + 1

        taken.append(candidate)
        tokens[node["id"]] = candidate

    return tokens


def escape_mermaid(text):
    """One line of label text, safe inside a Mermaid quoted label."""

    escaped = str(text)

    for character, replacement in MERMAID_ESCAPES:
        escaped = escaped.replace(character, replacement)

    return escaped


def escape_dot(text):
    """One line of label text, safe inside a DOT quoted string."""

    escaped = str(text)

    for character, replacement in DOT_ESCAPES:
        escaped = escaped.replace(character, replacement)

    return escaped


def style_key(max_severity):
    """The SEVERITY_STYLES key for a node's worst severity."""

    if max_severity is None:
        return CLEAN_SEVERITY

    key = str(max_severity).lower()

    if key in PSEUDO_SEVERITIES:
        return UNKNOWN_SEVERITY

    if key in SEVERITY_STYLES:
        return key

    return UNKNOWN_SEVERITY


def role_note(node):
    """"[entry]" for a way in, or "" for anything else."""

    roles = []

    if node.get("is_entry"):
        roles.append(ROLE_ENTRY)

    if not roles:
        return ""

    return "[" + ROLE_JOINER.join(roles) + "]"


def node_label_lines(node):
    """The lines of one node's label: id, type, severity, and its roles if any."""

    severity = node.get("max_severity")

    lines = [
        node["id"],
        node["type"],
        severity if severity is not None else CLEAN_SEVERITY_LABEL
    ]

    role = role_note(node)

    if role:
        lines.append(role)

    return lines


def emphasis_index(paths):
    """(source, target) -> the AP ids of the ranked paths using that hop."""

    index = {}

    for rank, path in enumerate(paths or [], 1):

        source_id = source_id_for(rank)

        hops = path.get("hops") or []

        for source, target in zip(hops, hops[1:]):

            names = index.setdefault((source, target), [])

            if source_id not in names:
                names.append(source_id)

    return index


def edge_label(edge, path_ids):
    """An edge's label: its categories, then the notes about it in parentheses."""

    notes = []

    if edge.get("reversed"):
        notes.append(REVERSED_NOTE)

    if path_ids:
        notes.append(EDGE_PATH_JOINER.join(path_ids))

    # Every category of the pair, so a merged edge does not hide one of them.
    categories = edge.get("categories")

    if categories:
        label = EDGE_CATEGORY_JOINER.join(str(item) for item in categories)

    else:
        label = str(edge.get("category"))

    if not notes:
        return label

    return label + " (" + EDGE_NOTE_JOINER.join(notes) + ")"


def drawable_edges(graph, tokens):
    """One drawable edge per (source, target), and the count of dropped ones.

    THEORY (why parallel edges are merged rather than one of them winning):
    A pair of resources can be joined by more than one category at once — since
    the privilege escalation catalogue landed, AppServerRole -> DeploymentRole is
    both the `identity` reference the template declares and the `escalation` the
    catalogue detects. Drawing two arrows between one pair of boxes is noise, and
    drawing only the first silently threw away the more informative half: the
    diagram said "identity" about the hop that is the whole attack. So the
    categories of a pair are merged into one edge, and its label names all of
    them. `reversed` carries if any of them was reversed.
    """

    merged = {}
    order = []
    dropped = 0

    for edge in graph.get("traversal_edges") or []:

        source = edge.get("source")
        target = edge.get("target")

        if source not in tokens or target not in tokens:
            dropped = dropped + 1
            continue

        # -----------------------------

        key = (source, target)

        if key not in merged:

            merged[key] = {
                "source": source,
                "target": target,
                "categories": [],
                "reversed": False
            }

            order.append(key)

        category = edge.get("category")

        if category not in merged[key]["categories"]:
            merged[key]["categories"].append(category)

        if edge.get("reversed"):
            merged[key]["reversed"] = True

    return [merged[key] for key in order], dropped


def path_summary_lines(paths):
    """One line per ranked path: its AP id, its band, and its hop chain."""

    if not paths:
        return ["none - no route survived the exploitability policy."]

    lines = []

    for rank, path in enumerate(paths, 1):

        lines.append(
            "{}  {}  {}".format(
                source_id_for(rank),
                path.get("attack_level"),
                HOP_ARROW.join(path.get("hops") or [])
            )
        )

    return lines


def legend_lines(graph, paths, dropped_edges, render_command):
    """The comment block both formats carry, as unprefixed text lines."""

    summary = graph.get("summary") or {}

    lines = [
        "Security state graph: "
        "{} resources, {} edges, {} findings, "
        "{} entry points, {} targets.".format(
            summary.get("resources"),
            summary.get("edges"),
            summary.get("findings"),
            summary.get("entry_points"),
            summary.get("targets")
        ),
        "Render it with: " + render_command,
        "Diagram key in README.md. Arrows are the attacker's direction, so a "
        "network_control edge is labelled 'reversed'.",
        "",
        "Ranked attack paths, worst first (see output/attack_paths.json):"
    ]

    for line in path_summary_lines(paths):
        lines.append("  " + line)

    # -----------------------------

    if dropped_edges:

        lines.append("")
        lines.append(
            "Warning: {} edge(s) named a resource outside the node list and "
            "were not drawn.".format(dropped_edges)
        )

    return lines


def commented(lines, marker):
    """Label-free text as comment lines, with no trailing space on a blank one."""

    return [
        (marker + line) if line else marker.rstrip()
        for line in lines
    ]


def joined_blocks(blocks):
    """Blocks of lines as one string: blank line between blocks, newline at the end."""

    return "\n\n".join(
        "\n".join(block)
        for block in blocks
        if block
    ) + "\n"


def render_mermaid(graph, paths):
    """The graph as Mermaid flowchart source."""

    tokens = node_tokens(graph)
    emphasis = emphasis_index(paths)

    edges, dropped = drawable_edges(graph, tokens)

    # -----------------------------

    header = [MERMAID_HEADER]

    header.extend(
        commented(
            legend_lines(
                graph,
                paths,
                dropped,
                "mmdc -i output/security_state_graph.mmd "
                "-o security_state_graph.svg"
            ),
            MERMAID_COMMENT
        )
    )

    # -----------------------------

    node_lines = []

    for node in graph.get("nodes") or []:

        opening, closing = MERMAID_SHAPES[bool(node.get("is_entry"))]

        label = MERMAID_LINE_BREAK.join(
            escape_mermaid(line)
            for line in node_label_lines(node)
        )

        node_lines.append(
            "{}{}{}\"{}\"{}".format(
                INDENT,
                tokens[node["id"]],
                opening,
                label,
                closing
            )
        )

    # -----------------------------

    # linkStyle addresses edges by their position in this block, so the indices
    edge_lines = []
    emphasised_indices = []

    for index, edge in enumerate(edges):

        path_ids = emphasis.get((edge["source"], edge["target"]), [])

        arrow = MERMAID_EDGE

        if path_ids:
            arrow = MERMAID_EMPHASIS_EDGE
            emphasised_indices.append(index)

        edge_lines.append(
            "{}{} {}|\"{}\"| {}".format(
                INDENT,
                tokens[edge["source"]],
                arrow,
                escape_mermaid(edge_label(edge, path_ids)),
                tokens[edge["target"]]
            )
        )

    # -----------------------------

    style_lines = [
        "{}classDef {}{} fill:{},stroke:{},stroke-width:{}px,"
        "color:{},font-size:{}px;".format(
            INDENT,
            SEVERITY_CLASS_PREFIX,
            key,
            style["fill"],
            style["stroke"],
            EDGE_WIDTH,
            LABEL_TEXT_COLOR,
            NODE_FONT_SIZE
        )
        for key, style in SEVERITY_STYLES.items()
    ]

    class_lines = [
        "{}class {} {}{};".format(
            INDENT,
            tokens[node["id"]],
            SEVERITY_CLASS_PREFIX,
            style_key(node.get("max_severity"))
        )
        for node in graph.get("nodes") or []
    ]

    # -----------------------------

    # Omitted entirely when nothing is emphasised: `linkStyle` with an empty
    link_style_lines = []

    if emphasised_indices:

        link_style_lines.append(
            "{}linkStyle {} stroke:{},stroke-width:{}px;".format(
                INDENT,
                ",".join(str(index) for index in emphasised_indices),
                EMPHASIS_COLOR,
                EMPHASIS_WIDTH
            )
        )

    return joined_blocks([
        header,
        node_lines,
        edge_lines,
        style_lines,
        class_lines,
        link_style_lines
    ])


def render_dot(graph, paths):
    """The graph as Graphviz DOT source."""

    tokens = node_tokens(graph)
    emphasis = emphasis_index(paths)

    edges, dropped = drawable_edges(graph, tokens)

    # -----------------------------

    header = [DOT_HEADER]

    header.extend(
        commented(
            legend_lines(
                graph,
                paths,
                dropped,
                "dot -Tsvg output/security_state_graph.dot "
                "-o security_state_graph.svg"
            ),
            INDENT + DOT_COMMENT
        )
    )

    defaults = [
        "{}rankdir=\"LR\";".format(INDENT),

        "{}graph [fontname=\"{}\", fontsize=\"{}\"];".format(
            INDENT,
            DOT_FONT,
            GRAPH_FONT_SIZE
        ),

        # style="filled" here rather than per node, so a node line carries only
        # what is specific to that resource.
        "{}node [style=\"filled\", fontname=\"{}\", fontsize=\"{}\", "
        "fontcolor=\"{}\", penwidth=\"{}\"];".format(
            INDENT,
            DOT_FONT,
            NODE_FONT_SIZE,
            LABEL_TEXT_COLOR,
            EDGE_WIDTH
        ),

        "{}edge [fontname=\"{}\", fontsize=\"{}\", fontcolor=\"{}\"];".format(
            INDENT,
            DOT_FONT,
            EDGE_FONT_SIZE,
            LABEL_TEXT_COLOR
        )
    ]

    # -----------------------------

    node_lines = []

    for node in graph.get("nodes") or []:

        style = SEVERITY_STYLES[style_key(node.get("max_severity"))]

        label = DOT_LINE_BREAK.join(
            escape_dot(line)
            for line in node_label_lines(node)
        )

        node_lines.append(
            "{}\"{}\" [label=\"{}\", shape=\"{}\", fillcolor=\"{}\", "
            "color=\"{}\"];".format(
                INDENT,
                tokens[node["id"]],
                label,
                DOT_SHAPES[bool(node.get("is_entry"))],
                style["fill"],
                style["stroke"]
            )
        )

    # -----------------------------

    edge_lines = []

    for edge in edges:

        path_ids = emphasis.get((edge["source"], edge["target"]), [])

        if path_ids:
            color = EMPHASIS_COLOR
            width = EMPHASIS_WIDTH

        else:
            color = EDGE_COLOR
            width = EDGE_WIDTH

        edge_lines.append(
            "{}\"{}\" -> \"{}\" [label=\"{}\", color=\"{}\", "
            "penwidth=\"{}\"];".format(
                INDENT,
                tokens[edge["source"]],
                tokens[edge["target"]],
                escape_dot(edge_label(edge, path_ids)),
                color,
                width
            )
        )

    # The closing brace is appended rather than joined in as a block of its own,
    # so it sits flush against the last statement instead of behind a blank line.
    return joined_blocks([
        header,
        defaults,
        node_lines,
        edge_lines
    ]) + DOT_FOOTER + "\n"


def write_text(text, output_path):
    """Write one render to `output_path`, and return the path."""

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)

    return output_path


def write_mermaid(state_graph, paths, output_path=MERMAID_PATH):
    """Render `state_graph` as Mermaid and write it, returning the path."""

    return write_text(
        render_mermaid(state_graph.to_dict(), paths),
        output_path
    )


def write_dot(state_graph, paths, output_path=DOT_PATH):
    """Render `state_graph` as Graphviz DOT and write it, returning the path."""

    return write_text(
        render_dot(state_graph.to_dict(), paths),
        output_path
    )


def write_renders(
    state_graph,
    paths,
    mermaid_path=MERMAID_PATH,
    dot_path=DOT_PATH
):
    """Write both renders, and return their paths in that order."""

    return [
        write_mermaid(state_graph, paths, mermaid_path),
        write_dot(state_graph, paths, dot_path)
    ]
