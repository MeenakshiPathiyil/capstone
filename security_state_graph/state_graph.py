"""Join the infrastructure model to the security findings."""

from pathlib import Path

from engine.connection_builder import DATA_TYPES, IAM_PRINCIPAL_TYPES
from engine.rule_engine import RuleEngine
from main import build_infra_model
from processing.attribute_extractor import process_resources
from security_state_graph.facts import (
    CREDENTIAL,
    DATA_ACCESS,
    FOOTHOLD,
    INTERNET_REACHABLE,
    fact
)
from security_state_graph.semantics import (
    ENTRY_SEMANTICS,
    data_targets,
    entry_points,
    finding_severity,
    finding_weight
)
from utils.helpers import write_json


BASE_DIR = Path(__file__).resolve().parent.parent

INFRA_PATH = BASE_DIR / "data" / "normalized_resources.json"
RULES_PATH = BASE_DIR / "data" / "security_rules.yaml"

# Where the serialized graph lands. The headline deliverable of this module, and
# the only file on disk that carries the join rather than one half of it.
# THEORY (why four files and not one):
# The graph is four different things a reader wants separately: how big it is,
# what the resources are, what the template declared, and what an attacker can
# walk. One combined file meant a reviewer diffing an edge change also diffed
# every node, and a reader after the summary loaded the whole thing. Each block
# now stands alone, and `write_state_graph` writes all four so they cannot drift.
OUTPUT_DIR = BASE_DIR / "output"

GRAPH_SUMMARY_PATH = OUTPUT_DIR / "graph_summary.json"
GRAPH_NODES_PATH = OUTPUT_DIR / "graph_nodes.json"
GRAPH_EDGES_PATH = OUTPUT_DIR / "graph_edges.json"
GRAPH_TRAVERSAL_EDGES_PATH = OUTPUT_DIR / "graph_traversal_edges.json"

# block name -> the file it is written to. Iterated by write_state_graph, so
# adding a block to to_dict() and forgetting to write it is not possible.
GRAPH_FILES = {
    "summary": GRAPH_SUMMARY_PATH,
    "nodes": GRAPH_NODES_PATH,
    "edges": GRAPH_EDGES_PATH,
    "traversal_edges": GRAPH_TRAVERSAL_EDGES_PATH
}

# The reason written next to is_entry.
#
# THEORY (why it is a sentence and not a boolean):
# `is_entry: true` tells a reader the search may start here and nothing about
# why, so the first question is always "which finding did that?". The reason
# answers it in the artifact instead of sending them back to the rule file. It
# names the rule, the state it raised, and the severity, because those are the
# three things needed to judge whether an entry point is worth worrying about.
ENTRY_REASON_TEMPLATE = "reachable from outside: {}"
ENTRY_REASON_NONE = (
    "not an entry point: no finding on this resource declares one of the "
    "semantics that mean reachable from outside ({})"
)

# One exposure finding inside that sentence: "SG_OPEN (unrestricted_ssh, high)".
ENTRY_REASON_FINDING = "{} ({}, {})"

RULE_ID_JOINER = ", "

# The finding fields the serialized node carries: everything the rule engine
STATE_KEYS = [
    "rule_id",

    # The check without the origin and resource type its composite id wraps it
    # in. Carried so a reader can tell three per-type copies of one canonical
    # check apart from three unrelated checks.
    "source_id",

    "state",
    "semantic",
    "severity"
]

# The only edge category whose stored direction is the reverse of the direction
# an attacker travels along it. Everything else is left forward.
# Declared child -> parent, travelled parent -> child: an instance names its
# security group, so the attacker arrives through the group.
REVERSED_CATEGORIES = ["network_control"]

# Traversable both ways.
#
# Load balancer plumbing declares its references in inconsistent directions: a
# Listener names its LoadBalancer (child to parent) and its TargetGroup (parent to
# child). No single reversal rule is right for both. These edges are membership in
# a traffic path, and for reachability that is symmetric, so both directions are
# emitted and the search decides.
#
# The cost: such an edge can be walked outward to a resource an attacker had no
# reason to visit. The depth bound absorbs it.
BIDIRECTIONAL_CATEGORIES = ["traffic_path"]

# The resource types an inbound network connection can actually arrive at, and
INBOUND_REACHABLE_TYPES = [
    "AWS::EC2::Instance",
    # Load balancer plumbing. These do receive forwarded traffic — that is their
    # only purpose — so they are legitimate inbound hops. Listed explicitly
    # rather than exempted, so the gate still applies to every category.
    "AWS::ElasticLoadBalancingV2::Listener",
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::EC2::LaunchTemplate",
    "AWS::AutoScaling::LaunchConfiguration",
    "AWS::RDS::DBInstance",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::ECS::Service",
    "AWS::ElasticSearch::Domain",
    "AWS::Elasticache::CacheCluster"
]


class SecurityStateGraph:
    """Resources, their security states, and the edges between them."""

    def __init__(self, infra, findings):

        # -----------------------------

        # raw_properties and semantic_properties are carried through, not

        self.nodes = {}

        for resource in infra.all_resources():

            self.nodes[resource.id] = {
                "id": resource.id,
                "type": resource.type,
                "raw_properties": resource.raw_properties,
                "semantic_properties": resource.semantic_properties,

                # The resource's own outgoing references, in the infra model's
                # shape: {"target", "type", "relation"}. Carried so a node
                # record answers "what does this resource name" without the
                # reader joining it against the edge list themselves.
                "connections": list(resource.connections),

                # The projected abstract attributes. Not serialized by to_dict:
                # they are already in the infra model and in the rule findings,
                # and repeating a template's whole ingress list on every node
                # would triple the size of graph_nodes.json. Kept in memory
                # because the attack graph layer binds action inputs from them —
                # `exposed_cidr: source.attr:ingress.cidr` reads this.
                "attributes": resource.attributes,

                "states": []
            }

        # -----------------------------

        self.edges = []

        for resource in infra.all_resources():

            for connection in resource.connections:

                self.edges.append({
                    "source": resource.id,
                    "target": connection["target"],

                    # A connection's "type" is its semantic category, while a
                    "category": connection["type"],

                    "relation": connection["relation"]
                })

        # -----------------------------

        self.orphan_findings = []

        for finding in findings or []:

            resource_id = finding.get("resource")

            node = self.nodes.get(resource_id)

            if node is None:

                # Stale findings are expected, not exceptional. Kept as a list
                self.orphan_findings.append(finding)

                print(
                    f"Warning: skipping finding "
                    f"{finding.get('rule_id', 'unknown')} for unknown "
                    f"resource {resource_id}"
                )

                continue

            node["states"].append(finding)

    def node(self, resource_id):
        """The node record for one resource, or None."""

        return self.nodes.get(resource_id)

    def states_of(self, resource_id):
        """The findings attached to one resource, in the order they were joined."""

        node = self.nodes.get(resource_id)

        if node is None:
            return []

        return node["states"]

    def edges_from(self, resource_id):
        """The stored edges leaving one resource, in declared direction."""

        return [
            edge
            for edge in self.edges
            if edge["source"] == resource_id
        ]

    def admits_inbound(self, resource_id):
        """True when a resource is a type an inbound connection can arrive at."""

        node = self.nodes.get(resource_id)

        if node is None:
            return False

        return node["type"] in INBOUND_REACHABLE_TYPES

    def traversal_edges(self):
        """Every edge in the direction an attacker moves.

        Structural only: which resources, which category, which way round. What
        an attacker needs to walk an edge and what they gain by it belong to the
        action taken on it, which the attack graph records. This method used to
        attach a precondition pair derived from the edge category, and it
        disagreed with the one the search enforced.
        """

        view = []

        for edge in self.edges:

            # -----------------------------

            if edge["category"] in BIDIRECTIONAL_CATEGORIES:

                view.append({
                    "source": edge["source"],
                    "target": edge["target"],
                    "category": edge["category"],
                    "relation": edge["relation"],
                    "reversed": False
                })

                # The back-copy is an inbound hop, so it answers to the same gate
                # a reversed edge does. It did not, and that quietly made the
                # "no inbound hop into a resource that does not receive traffic"
                # invariant inapplicable to a whole category.
                if self.admits_inbound(edge["source"]):

                    view.append({
                        "source": edge["target"],
                        "target": edge["source"],
                        "category": edge["category"],
                        "relation": edge["relation"],
                        "reversed": True
                    })

                continue

            # -----------------------------

            if edge["category"] in REVERSED_CATEGORIES:

                # The declaring resource becomes the target of the reversed
                # edge, so it is the one that has to be able to listen.
                if not self.admits_inbound(edge["source"]):
                    continue

                view.append({
                    "source": edge["target"],
                    "target": edge["source"],
                    "category": edge["category"],
                    "relation": edge["relation"],
                    "reversed": True
                })

                continue

            # -----------------------------

            view.append({
                "source": edge["source"],
                "target": edge["target"],
                "category": edge["category"],
                "relation": edge["relation"],
                "reversed": False
            })

        return view

    def traversal_adjacency(self):
        """source id -> the ids reachable from it in one hop, de-duplicated."""

        adjacency = {
            node_id: []
            for node_id in self.nodes
        }

        for edge in self.traversal_edges():

            targets = adjacency.setdefault(edge["source"], [])

            if edge["target"] not in targets:
                targets.append(edge["target"])

        return adjacency

    def traversal_edge_adjacency(self):
        """source id -> the traversal edges leaving it.

        The edge-level companion to traversal_adjacency. The search needs the
        edges and not just the neighbour ids, because whether a hop can be taken
        depends on that edge's precondition. Two edges can join the same pair of
        resources in different categories, and they are not interchangeable.
        """

        adjacency = {
            node_id: []
            for node_id in self.nodes
        }

        for edge in self.traversal_edges():
            adjacency.setdefault(edge["source"], []).append(edge)

        return adjacency

    def neighbors(self, resource_id):
        """One hop from a resource in the attacker's direction."""

        return self.traversal_adjacency().get(resource_id, [])


    def initial_facts(self, entry_id):
        """What the attacker holds on arriving at an entry point.

        `internet_reachable` always; then whatever reaching that kind of resource
        gets them — code execution on something that accepts connections, the
        identity of an IAM principal, the contents of a data store.

        A security group gets only `internet_reachable`: it is the door, not the
        room, so a path through one must take its edge to reach what is behind it.
        """

        facts = {INTERNET_REACHABLE}

        if self.admits_inbound(entry_id):
            facts.add(fact(FOOTHOLD, entry_id))

        node = self.node(entry_id)

        if node is None:
            return facts

        if node["type"] in IAM_PRINCIPAL_TYPES:
            facts.add(fact(CREDENTIAL, entry_id))

        if node["type"] in DATA_TYPES:
            facts.add(fact(DATA_ACCESS, entry_id))

        return facts

    def finding_count(self):
        """How many findings landed on a node, across the whole graph."""

        return sum(
            len(node["states"])
            for node in self.nodes.values()
        )

    def to_dict(self):
        """The whole graph as one JSON-ready dictionary."""

        # -----------------------------

        entries = entry_points(self)

        # Counted for the summary only. `is_target` is deliberately NOT written
        # onto a node: whether a resource is worth reaching is a property of the
        # objective being pursued, not of the resource, and five objectives claim
        # overlapping type sets. A single boolean on the node had to pick one
        # answer, so it silently meant "some objective claims this type" — which
        # is not a fact about the resource and read as if it were.
        targets = data_targets(self)

        # -----------------------------

        nodes = []

        for node_id in sorted(self.nodes):

            node = self.nodes[node_id]

            # `severity` is resolved rather than copied: the canonical rules
            # declare none and path_finder derives it from the semantic, so
            # writing the raw value would put `null` in the artifact next to a
            # finding that does have a severity everywhere else.
            states = [
                dict(
                    {
                        key: finding.get(key)
                        for key in STATE_KEYS
                    },
                    severity=finding_severity(finding)
                )
                for finding in node["states"]
            ]

            nodes.append({
                "id": node["id"],
                "type": node["type"],

                # THEORY (why this is here as well as in graph_edges.json):
                # the edge list is the graph, and it is the right place to ask
                # "what reaches this resource". But a reader looking at one node
                # nearly always wants the other question first — what does this
                # resource itself name — and answering it from a 16-row edge list
                # means filtering by source by hand. Same facts, written the way
                # they are read. `data/infra_output.json` carries the same block,
                # so the two artifacts can be diffed against each other.
                "connections": [
                    dict(connection)
                    for connection in node.get("connections") or []
                ],

                "states": states,

                # The one field a renderer needs and cannot derive without
                # knowing the severity scale, which path_finder owns.
                "max_severity": highest_severity(states, finding_weight),

                "is_entry": node_id in entries,
                "entry_reason": entry_reason(states, ENTRY_SEMANTICS)
            })

        # -----------------------------

        # The pair is the point. Stored edges are what the template declares and
        return {
            "summary": {
                "resources": len(self.nodes),
                "edges": len(self.edges),
                "findings": self.finding_count(),
                "entry_points": len(entries),
                "targets": len(targets),

                # Not one of the counts asked for, and kept anyway: it is the
                "orphan_findings": len(self.orphan_findings)
            },

            "nodes": nodes,
            "edges": sorted_edges(self.edges),
            "traversal_edges": sorted_edges(self.traversal_edges())
        }


def edge_sort_key(edge):
    """The total order both edge lists are written in."""

    return (
        edge["source"],
        edge["target"],
        edge["category"],
        edge["relation"]
    )


def sorted_edges(edges):
    """An edge list in deterministic order, as plain dictionaries."""

    return [
        dict(edge)
        for edge in sorted(edges, key=edge_sort_key)
    ]


def highest_severity(states, weight_of):
    """The worst severity label among `states`, or None when there are none.

    `weight_of` takes a whole finding, not a severity label, because a finding
    whose rule declared no severity has one derived from its semantic and the
    label alone is not enough to weigh it.
    """

    best = None
    best_weight = None

    for finding in states:

        weight = weight_of(finding)

        if best_weight is None or weight > best_weight:
            best = finding.get("severity")
            best_weight = weight

    return best


def entry_reason(states, entry_semantics):
    """Why a node is — or is not — an entry point, as a sentence.

    Names every finding that makes this resource a way in, with the state it
    raised, its severity and the semantic that qualified it. A node with two such
    findings names both: "public IP" and "open SSH" are different ways in and
    collapsing them to one loses which.

    The semantic is named because there are two that qualify and they mean
    different things. `network_control` is an open door on this resource;
    `exposure` is the resource itself being readable or addressable from outside.
    A reader deciding whether an entry point is real needs to know which.
    """

    described = [
        ENTRY_REASON_FINDING.format(
            finding.get("rule_id"),
            finding.get("state"),
            finding.get("severity")
        )
        for finding in states
        if finding.get("semantic") in entry_semantics
    ]

    if not described:
        return ENTRY_REASON_NONE.format(
            RULE_ID_JOINER.join(entry_semantics)
        )

    return ENTRY_REASON_TEMPLATE.format(RULE_ID_JOINER.join(described))




def write_state_graph(state_graph, files=None):
    """Write each block of the serialized graph to its own file.

    Returns {block name: path}. Driven by the GRAPH_FILES table rather than four
    hand-written calls, so a block added to to_dict() and left out of the table
    fails a test instead of being silently unwritten.
    """

    files = files or GRAPH_FILES

    artifact = state_graph.to_dict()

    missing = [name for name in files if name not in artifact]

    if missing:
        raise KeyError(
            "GRAPH_FILES names blocks to_dict() does not produce: %s" % missing
        )

    unwritten = [name for name in artifact if name not in files]

    if unwritten:
        raise KeyError(
            "to_dict() produces blocks GRAPH_FILES does not write: %s" % unwritten
        )

    return {
        name: write_json(artifact[name], path)
        for name, path in files.items()
    }


def evaluate_findings(infra, rules_path=RULES_PATH):
    """Every finding on `infra`: the rule engine's, plus privilege escalation.

    THEORY (why escalation findings do not come from the rule engine):
    engine/condition_evaluator.py compares a field to a value. A privilege
    escalation method asks whether the set of actions a principal holds *covers*
    the set a method needs, with wildcards on both sides — set covering, not
    comparison. It cannot be written as a condition tree, which is why
    engine/privesc_detector.py exists and why its findings are appended here
    rather than expressed as YAML rules. They are the same shape as a rule
    engine finding, so everything downstream is unaffected.
    """

    engine = RuleEngine(rules_path)

    # `attributes` is what the canonical ruleset is written against. It was left
    # out of this projection for one commit and every canonical rule silently
    # matched nothing, because process_resources fills `_attributes` from this
    # key and an absent key reads as an empty vocabulary.
    resources = [
        {
            "id": resource.id,
            "type": resource.type,
            "raw_properties": resource.raw_properties,
            "semantic_properties": resource.semantic_properties,
            "attributes": resource.attributes
        }
        for resource in infra.all_resources()
    ]

    findings = engine.evaluate_all(
        process_resources(resources)
    )

    findings.extend(privesc_findings(infra))

    return findings


def privesc_findings(infra):
    """One finding per privilege escalation method an IAM principal holds."""

    from engine.connection_builder import IAM_PRINCIPAL_TYPES
    from engine.privesc_detector import (
        attached_statements,
        broad_grant_findings,
        detect_from_patterns,
        granted_actions_for,
        load_methods
    )

    methods = load_methods()

    # A principal's permissions are its own statements plus those of every
    # `AWS::IAM::Policy` resource naming it. Real templates put them there far
    # more often than inline, so reading only the resource's own properties
    # missed most of the escalation in the corpus.
    attached = attached_statements(infra)

    findings = []

    for resource in infra.all_resources():

        if resource.type not in IAM_PRINCIPAL_TYPES:
            continue

        patterns = granted_actions_for(resource, attached)

        for method in detect_from_patterns(patterns, methods):

            findings.append({
                "resource": resource.id,
                "rule_id": method["id"],

                # An escalation method has no composite id to strip, so the
                # check and the rule are the same name. Carried anyway, because
                # everything downstream reads source_id and a finding missing it
                # would be a KeyError rather than a fallback.
                "source_id": method["id"],

                "state": method["id"].lower(),
                # Always `privilege`: every catalogue entry is an escalation, and
                # path_finder's exploitability policy reads exactly this field.
                "semantic": "privilege",
                "severity": method["severity"]
            })

        # A wildcard grant the catalogue does not name is still an escalation.
        # Without this a role holding `s3:*` on `*` through an attached policy got
        # capability edges and no privilege finding, so the exploitability policy
        # rejected every path through the very role those edges came from.
        for broad in broad_grant_findings(resource, attached):

            findings.append({
                "resource": resource.id,
                "rule_id": broad["rule_id"],
                "source_id": broad["rule_id"],
                "state": broad["state"],
                "semantic": "privilege",
                "severity": broad["severity"]
            })

    return findings


def build_state_graph(infra_path=INFRA_PATH, rules_path=RULES_PATH, infra=None):
    """Build the joined graph end to end, in memory.

    `infra` accepts an already-built model. graph_runner builds one so it can save
    the infrastructure model as its own artifact, and passing it here means the
    same file is not parsed and connected twice — and, more importantly, that the
    saved model and the graph are guaranteed to be the same object rather than two
    builds that could differ.
    """

    if infra is None:
        infra = build_infra_model(infra_path)

    return SecurityStateGraph(
        infra,
        evaluate_findings(infra, rules_path)
    )
