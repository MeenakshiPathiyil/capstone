"""Turn the joined graph into ranked attack paths."""

import yaml
from pathlib import Path

from security_state_graph.semantics import (
    AUTHORITY_SEMANTICS,
    entry_points,
    finding_severity,
    has_any_semantic,
    has_semantic
)
from security_state_graph.facts import facts_after, precondition_met
from attack_path.scoring import (
    attack_level_for,
    is_public_entry,
    score_path
)
from security_state_graph.state_graph import INFRA_PATH, RULES_PATH, build_state_graph


BASE_DIR = Path(__file__).resolve().parent.parent

# What an attacker is trying to achieve. See the THEORY note in the file itself
# for why the endpoint is a set of objectives rather than one hardcoded list.
OBJECTIVES_PATH = BASE_DIR / "data" / "objectives.yaml"


# Hops, not nodes: a path of MAX_DEPTH hops visits MAX_DEPTH + 1 resources.
MAX_DEPTH = 6


def load_objectives(path=OBJECTIVES_PATH):
    """The attack objectives, validated on the way in."""

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    objectives = data.get("objectives") or []

    for objective in objectives:

        if not objective.get("resource_types"):
            raise ValueError(
                "objective {} qualifies no resource types"
                .format(objective.get("id"))
            )

        if "requires_privilege" not in objective:
            raise ValueError(
                "objective {} does not say whether it requires privilege"
                .format(objective.get("id"))
            )

    return objectives


def objectives_of(state_graph, node_id, objectives=None):
    """Every objective a node can serve as the endpoint of."""

    if objectives is None:
        objectives = load_objectives()

    node = state_graph.node(node_id)

    if node is None:
        return []

    qualifying = []

    for objective in objectives:

        if node["type"] not in objective["resource_types"]:
            continue

        # An objective may demand that the endpoint itself carries a finding of a
        # given semantic — see identity_takeover in data/objectives.yaml, and why.
        required = objective.get("target_requires_semantic")

        if required and not has_semantic(node["states"], required):
            continue

        qualifying.append(objective)

    return qualifying


def objective_targets(state_graph, objectives=None):
    """Every id that is the endpoint of at least one objective, in graph order."""

    if objectives is None:
        objectives = load_objectives()

    return [
        node_id
        for node_id in state_graph.nodes
        if objectives_of(state_graph, node_id, objectives)
    ]


def walk_paths(state_graph, max_depth=MAX_DEPTH, objectives=None):
    """Every entry -> target route in the traversal view, as lists of node ids.

    `objectives` pins which endpoints count. Left None it is the whole set from
    data/objectives.yaml; passed explicitly it lets a caller ask "what routes
    exist for data theft alone", which is also how the fixture tests state which
    objective they are about.
    """


    # traversal_edges() rebuilds the reversed view from the stored edges on every
    # call, so it is indexed here rather than consulted per hop. Indexed by edge
    # and not by neighbour id, because whether a hop can be taken depends on that
    # edge's precondition.
    adjacency = state_graph.traversal_edge_adjacency()

    # Every objective's endpoints, not just the data stores: an attack that ends
    # by encrypting a database walks the same route as one that reads it.
    targets = objective_targets(state_graph, objectives)


    routes = []

    for entry_id in entry_points(state_graph):

        search = Search(
            adjacency=adjacency,
            targets=targets,
            max_depth=max_depth,
            state_graph=state_graph,
            transitions=None,
            routes=routes
        )

        extend_path(search, [entry_id], state_graph.initial_facts(entry_id))

    # Two edges can join one pair of resources — AppServerRole to DeploymentRole
    # is both `identity` and `escalation` — and the search walks each. That is one
    # route, and reporting it twice put 11 duplicate records in the export.
    return [
        list(route)
        for route in dict.fromkeys(tuple(route) for route in routes)
    ]


def available_actions(edge, state_graph, facts, transitions=None):
    """Every action this hop could be taken by, given what the attacker holds.

    The search branches on all of them, because two actions on one edge can grant
    different postconditions and so open different routes downstream. Taking only
    the first made path existence depend on the order of the ruleset: with a
    generic rule listed before a specific one, a reachable target could disappear.
    """

    from security_state_graph.transitions import actions_for

    return [
        action
        for action in actions_for(edge, state_graph, transitions)
        if precondition_met(action, facts)
    ]


def step_action(edge, state_graph, facts, transitions=None):
    """The action this hop is reported as, or None when it cannot be taken.

    The most specific available one, which ruleset order puts first. The search
    branches on all of them (see available_actions); the report names one,
    because enumerating a route once per way of walking each hop multiplies the
    output without adding a route.
    """

    available = available_actions(edge, state_graph, facts, transitions)

    return available[0] if available else None


class Search:
    """What does not change while the search runs.

    Five of these were re-threaded through every recursive call, which made the
    signature eight parameters wide and hid the two that actually vary — the path
    so far and the facts held at the end of it.
    """

    __slots__ = ("adjacency", "targets", "max_depth", "state_graph",
                 "transitions", "routes")

    def __init__(self, adjacency, targets, max_depth, state_graph, transitions,
                 routes):

        self.adjacency = adjacency
        self.targets = targets
        self.max_depth = max_depth
        self.state_graph = state_graph
        self.transitions = transitions

        # The accumulator, mutated in place by every level of the recursion.
        self.routes = routes


def extend_path(search, path, facts):
    """Depth-first step: append every route that extends `path` to search.routes.

    `facts` is what the attacker holds at the end of `path`. A hop whose
    precondition is not in that set is skipped, which is what makes a route a
    derivation rather than a drawing: the postcondition of each step has to
    satisfy the precondition of the next.

    The conditions come from the action the hop is taken by, which comes from
    data/attack_transitions.yaml — see step_action. An edge the ruleset does not
    name still yields an action, synthesised from its category, so an unwritten
    rule costs detail and never a path.
    """

    current = path[-1]

    for edge in search.adjacency.get(current, []):

        neighbor = edge["target"]


        # This is also what terminates a cycle: A -> B -> C -> A stops here
        # instead of running to the depth bound.
        if neighbor in path:
            continue


        # The one call that turns reachability into derivation.
        action = step_action(
            edge, search.state_graph, facts, search.transitions
        )

        if action is None:
            continue

        extended = path + [neighbor]
        extended_facts = facts_after(action, facts)


        # Recorded on arrival, and the search continues past it: a target can
        # also be a hop on the way to a further one.
        if neighbor in search.targets:
            search.routes.append(extended)


        # A route of N ids is N - 1 hops.
        if len(extended) - 1 < search.max_depth:

            extend_path(search, extended, extended_facts)


def is_exploitable(state_graph, path, objective=None):
    """True when a route is an attack path under `objective`'s policy.

    THEORY (why the privilege requirement is per objective):
    Reading a database needs credentials you were not given, so a data-theft
    path must gain authority somewhere. Flooding a public load balancer needs
    nothing of the sort — you reach it and you are done. A single global rule
    therefore *rejects* denial of service, which is a real attack. So the
    requirement is read off the objective, and `objective=None` keeps the
    original behaviour of demanding it.
    """


    if len(path) < 2:
        return False


    if not state_graph.states_of(path[0]):
        return False


    if objective is not None and not objective.get("requires_privilege"):
        return True

    # path[1:-1] and not path: authority the attacker already holds at the entry
    # is not an escalation, and neither is authority on the target itself.
    return any(
        has_any_semantic(state_graph.states_of(node_id), AUTHORITY_SEMANTICS)
        for node_id in path[1:-1]
    )


def path_steps(state_graph, path):
    """The hops of `path` as edges, each with its action and conditions.

    The search knows which edge it took; the path it returns is a list of
    resource ids. Rather than thread edges through the recursion, the fact chain
    is replayed here, which also means the exported steps are the steps the
    search actually accepted: the same precondition test, in the same edge order.

    THEORY (why the export carries them at all):
    A reader looking at `A -> B -> C` has to take on faith that B follows from A.
    With `action`, `precondition` and `postcondition` per hop they can check it,
    and the scenario generator gets the reason for each step instead of an arrow.
    """

    adjacency = state_graph.traversal_edge_adjacency()

    facts = state_graph.initial_facts(path[0])

    steps = []

    for source, target in zip(path, path[1:]):

        chosen = None
        chosen_edge = None

        for edge in adjacency.get(source, []):

            if edge["target"] != target:
                continue

            action = step_action(edge, state_graph, facts)

            if action is None:
                continue

            chosen = action
            chosen_edge = edge
            break

        # None when the caller built a path this module did not walk. Recorded
        # rather than raised, because a half-described path is more use to a
        # reader than an exception, and find_attack_paths cannot produce one.
        if chosen is None:

            steps.append({
                "source": source,
                "target": target,
                "category": None,
                "action_id": None,
                "action": "unverified_step",
                "tactic": None,
                "technique": None,
                "precondition": [],
                "precondition_options": [],
                "required_capabilities": [],
                "required_permissions": [],
                "postcondition": [],
                "input": {},
                "output": {}
            })

            continue

        steps.append({
            "source": chosen_edge["source"],
            "target": chosen_edge["target"],
            "category": chosen_edge["category"],
            "relation": chosen_edge.get("relation"),

            # The action, from data/attack_transitions.yaml. `tactic` is what
            # gives the exported scenario its STAGE labels, and `technique` is
            # the ATT&CK citation for the step rather than for the whole path.
            "action_id": chosen["action_id"],
            "action": chosen["action"],
            "tactic": chosen["tactic"],
            "technique": chosen["technique"],

            # The facts that actually held, not the list of alternatives the
            # action accepts. Written this way so the chain reads as a chain:
            # a step's `precondition` appears verbatim in the previous step's
            # `postcondition`, which is the property a reader checks. The
            # alternatives are kept beside it because "this hop would also have
            # been available with a credential" is worth being able to see.
            "precondition": [
                item
                for item in chosen["precondition"]
                if item in facts
            ],

            "precondition_options": chosen["precondition"],

            "required_capabilities": chosen["required_capabilities"],
            "required_permissions": chosen["required_permissions"],

            "postcondition": chosen["postcondition"],

            # The other half of Task 5's four fields. Preconditions say the step
            # is legal; these say what it was done to and what came out, which is
            # the detail a generated scenario needs to name a port and a finding
            # instead of saying "the attacker gained access".
            "input": chosen["input"],
            "output": chosen["output"],

            "fallback": chosen["fallback"]
        })

        facts = facts_after(chosen, facts)

    return steps


def states_with_severity(state_graph, path):
    """Every finding on `path`, with a severity filled in.

    Copies rather than the stored findings, because the severity of a canonical
    finding is derived and does not belong on the object the rule engine
    produced. Everything downstream reads severity, so it is resolved once here.
    """

    return [
        dict(finding, severity=finding_severity(finding))
        for node_id in path
        for finding in state_graph.states_of(node_id)
    ]


def describe_path(state_graph, path, objective=None):
    """One scored attack path as a dictionary."""

    score = score_path(state_graph, path, objective)

    states = states_with_severity(state_graph, path)

    return {
        "entry_id": path[0],
        "target_id": path[-1],

        # One entry per hop, carrying what the attacker does and what has to be
        # true before and after. See path_steps.
        "steps": path_steps(state_graph, path),

        # The resources in order, entry first. Named "hops" because that is what
        # a reader of the report calls them.
        "hops": list(path),

        "length": len(path) - 1,
        "public_entry": is_public_entry(state_graph, path[0]),
        "states": states,
        "rule_ids": [finding.get("rule_id") for finding in states],
        "score": score,
        "attack_level": attack_level_for(score),

        # What the attacker achieves at the end. The scenario generator reads
        # this to decide whether it is writing a theft, a ransomware or a
        # denial-of-service narrative.
        "objective": (objective or {}).get("id"),
        "objective_name": (objective or {}).get("name"),
        "objective_techniques": (objective or {}).get("techniques") or [],

        # The weight score_path added for the objective, so the score can be
        # recomposed from this record alone. See scoring.score_breakdown.
        "objective_weight": float((objective or {}).get("base_weight") or 0.0)
    }


def is_subsumed(route, routes):
    """True when `route` is a strict tail of another route in `routes`.

    Task 6 asks for "all valid attack paths", and a tail whose first hop is
    itself an entry point is arguably a second way in rather than a fragment.
    Enumerating those was tried and reverted: on the shipped account it turned 22
    paths into 40, and the 18 extra were the same attack starting one hop later,
    because a public instance and the open security group in front of it are one
    door described from two resources. The tail is kept only when it reaches
    something the longer route does not.
    """

    length = len(route)

    return any(
        len(other) > length and other[-length:] == route
        for other in routes
    )


def find_attack_paths(state_graph, max_depth=MAX_DEPTH, objectives=None):
    """Every exploitable path in the graph, worst first, tails collapsed.

    THEORY (one path per route AND objective):
    A route ending at a database is a data-theft path and, walked by an attacker
    with different intent, a ransomware path. They share every hop and are not
    the same attack: different techniques, different impact, different narrative
    for the scenario generator to write. So a route that serves several
    objectives yields one path per objective rather than being collapsed to its
    worst. The alternative — keep only the highest-weighted objective — would
    have hidden data theft behind ransomware on every database in the account,
    which is the reporting gap this layer exists to close.
    """

    if objectives is None:
        objectives = load_objectives()


    routes = walk_paths(state_graph, max_depth, objectives)

    # Exploitable under *at least one* objective. Subsumption is judged against
    # this set, matching the original behaviour of comparing tails only against
    # routes that were themselves worth reporting.
    live = [
        route
        for route in routes
        if any(
            is_exploitable(state_graph, route, objective)
            for objective in objectives_of(state_graph, route[-1], objectives)
        )
    ]


    paths = []

    for route in live:

        if is_subsumed(route, live):
            continue

        for objective in objectives_of(state_graph, route[-1], objectives):

            if not is_exploitable(state_graph, route, objective):
                continue

            paths.append(
                describe_path(state_graph, route, objective)
            )

    paths.sort(
        key=lambda path: (
            -path["score"],
            path["length"],
            path["hops"],
            path["objective"] or ""
        )
    )

    return paths


def build_attack_paths(
    infra_path=INFRA_PATH,
    rules_path=RULES_PATH,
    max_depth=MAX_DEPTH,
    objectives=None
):
    """Build the graph and rank its paths in one call."""

    return find_attack_paths(
        build_state_graph(infra_path, rules_path),
        max_depth,
        objectives
    )
