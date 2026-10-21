"""Build the attack graph from the security state graph.

    security state graph          attack graph
    node = a resource             node = (resource, the facts the attacker holds)
    edge = "A references B"       edge = an action instance

A resource reached holding different facts is a different node, because different
actions are available from it. Collapsed onto one node per resource the search
either allows steps that are not available or forbids steps that are.

Task 6's validity condition holds by construction: an edge exists only where the
action's precondition is in the source state's facts and its postcondition is in
the target's.

Node count is in principle exponential in the fact set. The fact set is
canonicalised to a frozenset so equivalent states merge, the depth bound caps how
many facts one route accumulates, and a visited state is not expanded twice.
MAX_STATES is a stop, not a tuning knob: reaching it reports the graph truncated
rather than leaving it quietly partial.
"""

from pathlib import Path

from security_state_graph.facts import (
    facts_after,
    precondition_met
)
from security_state_graph.semantics import entry_points
from security_state_graph.state_graph import build_state_graph
from security_state_graph.transitions import actions_for, load_transitions
from utils.helpers import write_json


BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "output"

ATTACK_GRAPH_SUMMARY_PATH = OUTPUT_DIR / "attack_graph_summary.json"
ATTACK_GRAPH_NODES_PATH = OUTPUT_DIR / "attack_graph_nodes.json"
ATTACK_GRAPH_EDGES_PATH = OUTPUT_DIR / "attack_graph_edges.json"

# block name -> file, iterated on write so a block added to to_dict and left out
# of the table fails a test rather than going unwritten. Same arrangement as
# security_state_graph/state_graph.py's GRAPH_FILES.
ATTACK_GRAPH_FILES = {
    "summary": ATTACK_GRAPH_SUMMARY_PATH,
    "nodes": ATTACK_GRAPH_NODES_PATH,
    "edges": ATTACK_GRAPH_EDGES_PATH
}

# The attacker's position before anything has happened. Every path starts here,
# so a reader can see where the search began instead of inferring it from which
# nodes have no inbound edge.
ATTACKER_NODE_ID = "attacker"

ATTACKER_NODE_TYPE = "attacker"

STATE_NODE_TYPE = "state"

# Hops from an entry, matching attack_path/path_finder.MAX_DEPTH. Restated rather than
# imported to avoid a circular import; tests/test_attack_graph.py asserts they
# agree, because a graph built to a different depth than the search walks is a
# graph that either wastes work or hides paths.
MAX_DEPTH = 6

# The stop, not a tuning knob. See the note at the top of the module.
MAX_STATES = 20000

# How a state is named in the artifact. The facts are sorted so the name is
# stable across runs, which the golden files depend on.
STATE_NAME = "{}|{}"

FACT_JOINER = ","


def state_id(resource_id, facts):
    """The stable name of one attacker state.

    Sorted, because a set has no order and a golden file needs one. The resource
    comes first so the states of one resource sort together, which is how a
    reader scans the file.
    """

    return STATE_NAME.format(
        resource_id,
        FACT_JOINER.join(sorted(facts))
    )


class AttackGraph:
    """Attacker states, and the actions that move between them."""

    def __init__(self, state_graph, transitions=None, max_depth=MAX_DEPTH,
                 max_states=MAX_STATES):

        self.state_graph = state_graph
        self.transitions = (
            load_transitions() if transitions is None else transitions
        )

        self.max_depth = max_depth
        self.max_states = max_states

        # state id -> the state record. Insertion-ordered, so the artifact is
        # written in discovery order: entry states first, then what they reach.
        self.nodes = {}

        self.edges = []

        self.truncated = False

        self._build()

    # -----------------------------

    def _build(self):

        adjacency = self.state_graph.traversal_edge_adjacency()

        self._add_attacker_node()

        pending = []

        for entry_id in entry_points(self.state_graph):

            facts = frozenset(self.state_graph.initial_facts(entry_id))

            identifier, is_new = self._add_node(
                entry_id, facts, depth=0, entry=True
            )

            if is_new:
                pending.append(self.nodes[identifier])

        # Breadth-first, so `depth` on a state is the fewest hops that reach it
        # and the truncation bound cuts the deepest states rather than an
        # arbitrary branch.
        while pending:

            current = pending.pop(0)

            if current["depth"] >= self.max_depth:
                continue

            for edge in adjacency.get(current["resource"], []):

                for action in actions_for(
                    edge,
                    self.state_graph,
                    self.transitions
                ):

                    if not precondition_met(action, current["facts"]):
                        continue

                    gained = frozenset(
                        facts_after(action, set(current["facts"]))
                    )

                    target, is_new = self._add_node(
                        edge["target"],
                        gained,
                        depth=current["depth"] + 1,
                        entry=False
                    )

                    # Refused by the state bound, so the node does not exist and
                    # an edge to it would dangle. A truncated graph is useful; a
                    # graph with edges to missing nodes is corrupt.
                    if target is None:
                        continue

                    self.edges.append({
                        "from_state": current["id"],
                        "to_state": target,
                        "source": edge["source"],
                        "target": edge["target"],

                        # `category` and `relation`, spelled the way every other
                        # edge list in the project spells them. This block used
                        # to say `edge_category` and to drop `relation`
                        # altogether, which made the attack graph the one edge
                        # list a reader could not join against the others.
                        "category": edge["category"],
                        "relation": edge.get("relation"),

                        "action_id": action["action_id"],
                        "action": action["action"],
                        "tactic": action["tactic"],
                        "technique": action["technique"],
                        "precondition": [
                            item
                            for item in action["precondition"]
                            if item in current["facts"]
                        ],
                        "precondition_options": action["precondition"],

                        # The other two sources of a precondition: what the
                        # security state graph found, and Rhino's own
                        # `Required Permission(s)` for the method detected.
                        "required_capabilities": action["required_capabilities"],
                        "required_permissions": action["required_permissions"],

                        "postcondition": action["postcondition"],
                        "input": action["input"],
                        "output": action["output"],
                        "fallback": action["fallback"]
                    })

                    if is_new:
                        pending.append(self.nodes[target])

    def _add_attacker_node(self):
        """Record the attacker's starting position.

        Carries the same keys a state node does, so anything iterating the node
        list can read it without a special case.
        """

        self.nodes[ATTACKER_NODE_ID] = {
            "id": ATTACKER_NODE_ID,
            "type": ATTACKER_NODE_TYPE,
            "resource": None,
            "facts": [],
            "depth": 0,
            "is_entry": False
        }

    def _add_node(self, resource_id, facts, depth, entry):
        """Record a state. Returns (id, is_new).

        (id, False) when the state already exists — the caller may still draw an
        edge to it. (None, False) only when the state bound refused it, which is
        the case where an edge would dangle.
        """

        identifier = state_id(resource_id, facts)

        if identifier in self.nodes:
            return identifier, False

        if len(self.nodes) >= self.max_states:
            self.truncated = True
            return None, False

        node = self.state_graph.node(resource_id)

        record = {
            "id": identifier,
            "resource": resource_id,
            "type": (node or {}).get("type"),
            "facts": sorted(facts),
            "depth": depth,
            "is_entry": entry
        }

        self.nodes[identifier] = record

        return identifier, True

    # -----------------------------

    def states_of(self, resource_id):
        """Every attacker state that stands at one resource."""

        return [
            node
            for node in self.nodes.values()
            if node["resource"] == resource_id
        ]

    def fallback_edges(self):
        """The edges whose action came from the category table, not the ruleset.

        The gap list: every one of these is a hop the transition ruleset does not
        yet name, carrying no technique and no tactic.
        """

        return [edge for edge in self.edges if edge["fallback"]]

    def to_dict(self):
        """The whole attack graph as one JSON-ready dictionary."""

        techniques = sorted({
            edge["technique"]
            for edge in self.edges
            if edge["technique"]
        })

        tactics = sorted({
            edge["tactic"]
            for edge in self.edges
            if edge["tactic"]
        })

        return {
            "summary": {
                "attacker_states": len(self.nodes),
                "actions": len(self.edges),
                "entry_states": len([
                    node for node in self.nodes.values() if node["is_entry"]
                ]),
                "distinct_techniques": len(techniques),
                "techniques": techniques,
                "tactics": tactics,

                # Not decoration. A non-zero count is the number of hops the
                # transition ruleset does not name yet, and the whole layer is
                # only as grounded as this number is small.
                "edges_from_the_fallback_table": len(self.fallback_edges()),

                "truncated": self.truncated,
                "max_depth": self.max_depth
            },

            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }


def build_attack_graph(state_graph=None, transitions=None, max_depth=MAX_DEPTH):
    """Build the attack graph, building the state graph first if needed."""

    if state_graph is None:
        state_graph = build_state_graph()

    return AttackGraph(state_graph, transitions, max_depth)




def write_attack_graph(attack_graph, files=None):
    """Write each block to its own file. Returns {block name: path}."""

    files = files or ATTACK_GRAPH_FILES

    artifact = attack_graph.to_dict()

    missing = [name for name in files if name not in artifact]

    if missing:
        raise KeyError(
            "ATTACK_GRAPH_FILES names blocks to_dict() does not produce: %s"
            % missing
        )

    unwritten = [name for name in artifact if name not in files]

    if unwritten:
        raise KeyError(
            "to_dict() produces blocks ATTACK_GRAPH_FILES does not write: %s"
            % unwritten
        )

    return {
        name: write_json(artifact[name], path)
        for name, path in files.items()
    }
