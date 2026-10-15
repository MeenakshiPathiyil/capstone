"""Turn one security state graph edge into the attacker actions it permits.

data/attack_transitions.yaml is the knowledge; this applies it. An edge plus the
nodes at its ends are matched against each rule's `applies_to` and the capability
half of its precondition, and every rule that matches becomes an action.

Several actions can match one edge, and each becomes its own attack graph edge:
an `escalation` edge is not one generic step, it is whichever named method the
role's findings support. `stop_after_match` lets a specific action shadow its
generic sibling.

An edge no rule matches gets a fallback action that claims nothing, so it stays
walkable and cannot be why a path exists.
"""

import re
from functools import lru_cache
from pathlib import Path

import yaml

from security_state_graph.facts import SOURCE, TARGET, fact, resolve


BASE_DIR = Path(__file__).resolve().parent.parent

TRANSITIONS_PATH = BASE_DIR / "data" / "attack_transitions.yaml"

# The id given to a step that fell back to the edge-category table. Not a real
# action id, and deliberately obvious in the output.
FALLBACK_ID = "ACT_UNCLASSIFIED"

ENDS = [SOURCE, TARGET]

# "foothold(target)" -> ("foothold", "target"); "internet_reachable" -> (name, None).
#
# The facts are written as strings in the YAML because that is how a person reads
# them, and because it makes a rule's precondition line up visually with the
# postcondition of the rule before it.
FACT_PATTERN = re.compile(r"^([a-z_]+)(?:\(([a-z]+)\))?$")


@lru_cache(maxsize=None)
def load_transitions(path=TRANSITIONS_PATH):
    """The action ruleset, in file order. Order decides `stop_after_match`.

    Cached: actions_for() runs once per edge per step of the search, and parsing
    the YAML on each call took the suite from 12 seconds to not finishing. Use
    `load_transitions.cache_clear()` after editing the file in place.
    """

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if isinstance(data, list):
        return data

    return data.get("transitions") or []


def parse_fact(text):
    """One written fact as the (name, end) pair security_state_graph.facts.resolve wants.

    Raises on anything unparseable rather than skipping it: a typo in a
    precondition is a step that can never be taken, and silently dropping it
    would turn that into a step that is always available.
    """

    if not isinstance(text, str):
        raise ValueError("a fact must be written as a string, got %r" % (text,))

    match = FACT_PATTERN.match(text.strip())

    if match is None:
        raise ValueError(
            "cannot read %r as a fact. Expected `internet_reachable` or "
            "`foothold(target)`." % (text,)
        )

    name, end = match.groups()

    if end is not None and end not in ENDS:
        raise ValueError(
            "%r names %r, which is not an end of an edge (%s)"
            % (text, end, " or ".join(ENDS))
        )

    return (name, end)


def parse_facts(items):
    """A written precondition or postcondition list as (name, end) pairs."""

    return [parse_fact(item) for item in items or []]


def precondition_parts(rule):
    """A rule's precondition, split into where each half comes from.

    A precondition has two sources and only one of them used to be visible:

      facts         from the PREVIOUS step's postcondition — what the attacker
                    already holds
      capabilities  from the SECURITY STATE GRAPH — what the rule engine found on
                    the resource. These lived in `applies_to`, which read as a
                    matching detail rather than as half the precondition, and is
                    why Task 5 looked half-implemented
      permissions   Rhino Security Labs' own `Required Permission(s)` field, for
                    the IAM escalation actions

    Written as a mapping, or as a bare list for facts alone.
    """

    declared = rule.get("precondition")

    if isinstance(declared, dict):
        return (
            declared.get("facts") or [],
            declared.get("capabilities") or [],
            declared.get("permissions")
        )

    return (declared or [], [], None)


# -- Matching ----------------------------------------------------------------

def evidence_source_ids(node, semantics=None):
    """The source_id of every finding on `node`, optionally filtered."""

    if node is None:
        return []

    found = []

    for finding in node.get("states") or []:

        if semantics and finding.get("semantic") not in semantics:
            continue

        source_id = finding.get("source_id") or finding.get("rule_id")

        if source_id and source_id not in found:
            found.append(source_id)

    return found


def capability_holds(requirement, source_node, target_node):
    """True when the security state graph found what a precondition demands.

    One entry of `precondition.capabilities`: which end of the edge, and either a
    set of `state` ids, a set of `source_id` checks, a set of `semantic` values, or
    `source_id_prefix` for the escalation families.

    The key is `end` and not `on`, because YAML 1.1 reads a bare `on` as the
    boolean true — `on: source` parsed as `{True: "source"}` and every rule using
    it silently stopped matching.
    """

    node = {SOURCE: source_node, TARGET: target_node}.get(
        requirement.get("end")
    )

    states = (node or {}).get("states") or []

    wanted = requirement.get("state")

    if wanted and not any(f.get("state") in wanted for f in states):
        return False

    wanted = requirement.get("source_id")

    if wanted and not any(
        (f.get("source_id") or f.get("rule_id")) in wanted for f in states
    ):
        return False

    wanted = requirement.get("source_id_prefix")

    if wanted and not any(
        str(f.get("source_id") or f.get("rule_id")).startswith(prefix)
        for f in states
        for prefix in wanted
    ):
        return False

    wanted = requirement.get("semantic")

    if wanted and not any(f.get("semantic") in wanted for f in states):
        return False

    return True


def matches(rule, edge, source_node, target_node, admits_inbound):
    """True when the edge is the right shape AND carries the capabilities the
    rule's precondition demands.

    Absent keys do not constrain. An `applies_to` with nothing in it matches
    every edge, which is a mistake rather than a wildcard, so it is refused.
    """

    applies = rule.get("applies_to")

    if not isinstance(applies, dict) or not applies:
        raise ValueError(
            "%s has no applies_to, so it would match every edge in the graph"
            % rule.get("id")
        )

    _, capabilities, _ = precondition_parts(rule)

    for requirement in capabilities:

        if not capability_holds(requirement, source_node, target_node):
            return False

    category = applies.get("edge_category")

    if category and edge.get("category") != category:
        return False

    for end, node in ((SOURCE, source_node), (TARGET, target_node)):

        wanted_types = applies.get("%s_type" % end)

        if wanted_types and (node or {}).get("type") not in wanted_types:
            return False

        wanted_ids = applies.get("%s_evidence_source_id" % end)

        if wanted_ids:

            held = evidence_source_ids(node)

            if not any(item in held for item in wanted_ids):
                return False

        prefixes = applies.get("%s_evidence_source_id_prefix" % end)

        if prefixes:

            held = evidence_source_ids(node)

            if not any(
                item.startswith(prefix)
                for item in held
                for prefix in prefixes
            ):
                return False

        wanted_semantics = applies.get("%s_evidence_semantic" % end)

        if wanted_semantics and not evidence_source_ids(node, wanted_semantics):
            return False

    if "target_admits_inbound" in applies:

        # Compared, not tested for truthiness: `false` is a constraint too, and
        # `if applies.get(...) and ...` silently ignored it.
        if bool(applies["target_admits_inbound"]) != bool(admits_inbound):
            return False

    return True


# -- Binding -----------------------------------------------------------------

def flatten_values(values):
    """A list of resolved values, with lists spliced in and duplicates dropped."""

    flat = []

    for value in values:

        items = value if isinstance(value, list) else [value]

        for item in items:

            if item is None:
                continue

            if item not in flat:
                flat.append(item)

    return flat


def attribute_values(node, path):
    """Every value a projected attribute path names on `node`.

    Reads the same `attributes` block the rule engine resolves against, so an
    input naming `ingress.cidr` yields what the rules saw rather than a second
    reading of the raw template.
    """

    from engine.condition_evaluator import get_field_values

    attributes = (node or {}).get("attributes") or {}

    if path in attributes:
        return flatten_values([attributes[path]])

    return flatten_values(get_field_values(attributes, path))


def bind_value(spec, edge, source_node, target_node):
    """One input or output value, per the mini-syntax documented in the ruleset.

    Anything that is not a recognised reference is a literal, which is how
    `access: interactive shell` and `credential_type: temporary session
    credentials` work. A reference that resolves to nothing returns None and the
    caller drops the key, so an input block only states what is known.
    """

    if not isinstance(spec, str):
        return spec

    nodes = {SOURCE: source_node, TARGET: target_node}

    for end in ENDS:

        if spec == "%s.id" % end:
            return edge.get(end)

        if spec == "%s.type" % end:
            return (nodes[end] or {}).get("type")

        prefix = "%s.attr:" % end

        if spec.startswith(prefix):

            values = attribute_values(nodes[end], spec[len(prefix):])

            return values or None

        prefix = "%s.evidence:" % end

        if spec.startswith(prefix):

            semantics = [
                item.strip()
                for item in spec[len(prefix):].split(",")
                if item.strip()
            ]

            values = evidence_source_ids(nodes[end], semantics or None)

            return values or None

        # A typo in a reference used to ship as the literal string, so
        # `targt.id` reached the output as "targt.id". Anything that names an end
        # of the edge has to name a form that exists.
        if spec.startswith("%s." % end):

            known = ("id", "type", "attr:", "evidence:", "states:")

            if not spec[len(end) + 1:].startswith(known):
                raise ValueError(
                    "%r is not a binding reference. Expected one of %s."
                    % (spec, ", ".join("%s.%s" % (end, form) for form in known))
                )

        prefix = "%s.states:" % end

        if spec.startswith(prefix):

            semantics = [
                item.strip()
                for item in spec[len(prefix):].split(",")
                if item.strip()
            ]

            findings = [
                dict(finding)
                for finding in (nodes[end] or {}).get("states") or []
                if not semantics or finding.get("semantic") in semantics
            ]

            return findings or None

    return spec


def bind_block(block, edge, source_node, target_node):
    """An `input` or `output` mapping with every value resolved."""

    bound = {}

    for key, spec in (block or {}).items():

        value = bind_value(spec, edge, source_node, target_node)

        if value is None:
            continue

        bound[key] = value

    return bound


def required_permissions(spec, source_node, target_node):
    """Rhino Security Labs' `Required Permission(s)` for the methods detected.

    Not a static list: which permission the escalation needs depends on which
    method the role's findings actually support, so it is looked up per finding in
    data/privesc_methods.yaml. That file's `requires` field IS Rhino's field.
    """

    if not spec:
        return []

    from engine.privesc_detector import load_methods

    end = spec.split(".", 1)[0]

    node = {SOURCE: source_node, TARGET: target_node}.get(end)

    held = {
        f.get("source_id") or f.get("rule_id")
        for f in (node or {}).get("states") or []
    }

    permissions = []

    for method in load_methods():

        if method.get("id") not in held:
            continue

        for action in method.get("requires") or []:

            if action not in permissions:
                permissions.append(action)

    return permissions


def build_action(rule, edge, source_node, target_node):
    """One matched rule as a concrete action on this edge."""

    facts, capabilities, permissions = precondition_parts(rule)

    return {
        "action_id": rule["id"],
        "action": rule.get("name") or rule["id"],
        "tactic": rule.get("tactic"),
        "technique": rule.get("technique"),
        "summary": (rule.get("summary") or "").strip(),

        # The facts, which chain. `precondition` stays a flat list of these so a
        # step's precondition still appears verbatim in the previous step's
        # postcondition, which is the property a reader checks.
        "precondition": resolve(parse_facts(facts), edge),
        "postcondition": resolve(parse_facts(rule.get("postcondition")), edge),

        # The other two halves, stated rather than implied.
        "required_capabilities": [
            dict(requirement) for requirement in capabilities
        ],
        "required_permissions": required_permissions(
            permissions, source_node, target_node
        ),

        "input": bind_block(rule.get("input"), edge, source_node, target_node),
        "output": bind_block(rule.get("output"), edge, source_node, target_node),

        "fallback": False
    }


def fallback_action(edge):
    """The action for an edge no rule matched. It claims nothing.

    No precondition and no postcondition, so it stays walkable and cannot be why
    a path exists. `technique` and `tactic` are null: a category says what a hop
    is structurally, not which attacker behaviour it is. Every category the graph
    emits has a named rule, so reaching this means a new one arrived without.
    """

    return {
        "action_id": FALLBACK_ID,
        "action": "unclassified_step",
        "tactic": None,
        "technique": None,
        "summary": (
            "No transition rule matched this %s edge, so nothing is claimed "
            "about what it requires or grants."
            % edge.get("category")
        ),

        "precondition": [],
        "postcondition": [],
        "required_capabilities": [],
        "required_permissions": [],

        "input": {"from": edge.get(SOURCE), "to": edge.get(TARGET)},
        "output": {},

        "fallback": True
    }


def actions_for(edge, state_graph, rules=None):
    """Every action `edge` permits, in ruleset order. Never empty.

    Falls back to the edge-category table when no rule matches, so the caller
    always has a step and the search cannot lose a path to an unwritten rule.
    """

    if rules is None:
        rules = load_transitions()

    source_node = state_graph.node(edge.get(SOURCE))
    target_node = state_graph.node(edge.get(TARGET))

    admits_inbound = state_graph.admits_inbound(edge.get(TARGET))

    found = []

    for rule in rules:

        if not matches(rule, edge, source_node, target_node, admits_inbound):
            continue

        found.append(build_action(rule, edge, source_node, target_node))

        if rule.get("stop_after_match"):
            break

    if not found:
        return [fallback_action(edge)]

    return found


def describe_edge(edge, state_graph, rules=None):
    """`edge` with its actions attached, as one dictionary.

    The edge keeps the precondition and postcondition of its FIRST action, so
    anything reading an edge rather than an action still sees a usable pair. The
    first action is the most specific one that matched, because
    `stop_after_match` puts it there.
    """

    found = actions_for(edge, state_graph, rules)

    first = found[0]

    return dict(
        edge,
        actions=found,
        action=first["action"],
        action_id=first["action_id"],
        tactic=first["tactic"],
        technique=first["technique"],
        precondition=first["precondition"],
        postcondition=first["postcondition"],
        input=first["input"],
        output=first["output"],
        fallback=first["fallback"]
    )
