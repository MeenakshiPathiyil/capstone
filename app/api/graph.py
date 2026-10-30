"""The two drawable graph payloads: resources (state view) and attacker states.

Both carry, on every edge, the AP ids of the ranked paths that use it, so the web
app can highlight a path without re-deriving it.

The attack view matches a path to its edges exactly. Each step is replayed from
the entry's initial facts, giving the (state before, state after, action,
category, relation) the attack graph recorded for it. A step with no such edge
is reported and that path is not highlighted at all: a partial highlight drawn
along resource pairs would show transitions the attacker never made.
"""

from attack_path.exporter import source_id_for
from attack_path.renderer import (
    drawable_edges,
    edge_label,
    emphasis_index,
    node_label_lines,
    node_tokens,
    style_key
)
from security_state_graph.attack_graph import ATTACKER_NODE_ID, state_id
from security_state_graph.facts import facts_after


ATTACKER_LABEL = "Attacker"

# The attacker root has no resource and so no severity; it is drawn neutral.
ATTACKER_STYLE = "clean"


def state_view(state_graph, paths):
    """Resources and the traversal edges between them, in the attacker's direction."""

    graph = state_graph.to_dict()

    tokens = node_tokens(graph)
    edges, dropped = drawable_edges(graph, tokens)

    # Every ranked path, not only the selected ones: the graph shows them all.
    emphasis = emphasis_index(paths)

    nodes = [
        {
            "key": node["id"],
            "label_lines": node_label_lines(node),
            "style": style_key(node["max_severity"]),
            "is_entry": node["is_entry"],
            "resource": node["id"],
            "facts": None
        }
        for node in graph["nodes"]
    ]

    warnings = []

    if dropped:
        warnings.append({
            "kind": "graph_mapping",
            "message": "%d edge(s) named a resource outside the template and "
                       "are not drawn." % dropped
        })

    return {
        "view": "state",
        "nodes": nodes,
        "edges": [
            {
                "key": "%s->%s" % (edge["source"], edge["target"]),
                "source": edge["source"],
                "target": edge["target"],

                # The categories and the reversed note; the path ids are a field
                # of their own, so they are left out of the label.
                "label": edge_label(edge, []),
                "categories": [str(item) for item in edge["categories"]],
                "reversed": edge["reversed"],
                "path_ids": list(
                    emphasis.get((edge["source"], edge["target"]), [])
                ),
                "action_id": None,
                "tactic": None,
                "technique": None
            }
            for edge in edges
        ],
        "dropped_edges": dropped,
        "truncated": False,
        "warnings": warnings
    }


def edge_identity(from_state, to_state, action_id, category, relation):
    """What makes two attack graph edges the same transition."""

    return (from_state, to_state, action_id, category, relation)


def path_edge_indices(state_graph, path, index):
    """The attack graph edge indices one path walks, or None if a step is absent."""

    facts = set(state_graph.initial_facts(path["entry_id"]))

    matched = []

    for step in path["steps"]:

        after = facts_after(step, facts)

        key = edge_identity(
            state_id(step["source"], facts),
            state_id(step["target"], after),
            step["action_id"],
            step["category"],
            step.get("relation")
        )

        if key not in index:
            return None

        matched.extend(index[key])

        facts = after

    return matched


def attack_view(state_graph, attack_graph, paths):
    """Attacker states and the actions between them, with exact path matching."""

    graph = attack_graph.to_dict()

    severities = {
        node["id"]: node["max_severity"]
        for node in state_graph.to_dict()["nodes"]
    }

    # Whether the resource hop an action was taken on runs against the
    # template's declared direction.
    reversed_hops = {
        (edge["source"], edge["target"], edge["category"], edge["relation"]):
            edge["reversed"]
        for edge in state_graph.traversal_edges()
    }

    # -----------------------------

    keys = {}
    nodes = []

    for position, node in enumerate(graph["nodes"]):

        key = "s%d" % position
        keys[node["id"]] = key

        if node["id"] == ATTACKER_NODE_ID:

            nodes.append({
                "key": key,
                "label_lines": [ATTACKER_LABEL],
                "style": ATTACKER_STYLE,
                "is_entry": False,
                "resource": None,
                "facts": []
            })

            continue

        nodes.append({
            "key": key,
            "label_lines": [node["resource"], str(node["type"])],
            "style": style_key(severities.get(node["resource"])),
            "is_entry": node["is_entry"],
            "resource": node["resource"],
            "facts": list(node["facts"])
        })

    # -----------------------------

    # Identical duplicates share a key, so a path walking one marks all of them.
    index = {}

    for position, edge in enumerate(graph["edges"]):

        index.setdefault(
            edge_identity(
                edge["from_state"],
                edge["to_state"],
                edge["action_id"],
                edge["category"],
                edge.get("relation")
            ),
            []
        ).append(position)

    path_ids = [[] for _ in graph["edges"]]
    warnings = []

    for rank, path in enumerate(paths, 1):

        source_id = source_id_for(rank)

        matched = path_edge_indices(state_graph, path, index)

        if matched is None:

            warnings.append({
                "kind": "graph_mapping",
                "message": "%s could not be matched to attack graph edges and "
                           "is not highlighted in the attack view." % source_id
            })

            continue

        for position in matched:
            if source_id not in path_ids[position]:
                path_ids[position].append(source_id)

    if graph["summary"]["truncated"]:
        warnings.append({
            "kind": "graph_truncated",
            "message": "The attack graph reached its state limit and is "
                       "incomplete. States beyond it are not shown."
        })

    # -----------------------------

    edges = []

    for position, edge in enumerate(graph["edges"]):

        edges.append({
            "key": "e%d" % position,
            "source": keys[edge["from_state"]],
            "target": keys[edge["to_state"]],
            "label": edge["action"],
            "categories": [str(edge["category"])],
            "reversed": reversed_hops.get(
                (edge["source"], edge["target"], edge["category"],
                 edge.get("relation")),
                False
            ),
            "path_ids": path_ids[position],
            "action_id": edge["action_id"],
            "tactic": edge["tactic"],
            "technique": edge["technique"]
        })

    return {
        "view": "attack",
        "nodes": nodes,
        "edges": edges,
        "dropped_edges": 0,
        "truncated": bool(graph["summary"]["truncated"]),
        "warnings": warnings
    }
