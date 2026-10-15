"""Tests for data/attack_transitions.yaml and graph/transitions.py.

The attack graph layer's ruleset, and the engine that applies it. What these
tests defend is the same thing test_security_rules.py defends for the other
ruleset: a rule that matches nothing, cites a technique that does not exist, or
claims a fact nothing produces, all fail quietly rather than loudly.
"""

import re

import pytest

from security_state_graph.attack_graph import build_attack_graph
from security_state_graph.facts import (
    CREDENTIAL,
    DATA_ACCESS,
    FOOTHOLD,
    INTERNET_REACHABLE,
    fact
)
from security_state_graph.state_graph import build_state_graph
from security_state_graph.transitions import (
    FALLBACK_ID,
    precondition_parts,
    actions_for,
    bind_value,
    describe_edge,
    load_transitions,
    matches,
    parse_fact,
    parse_facts
)


FACT_NAMES = [INTERNET_REACHABLE, FOOTHOLD, CREDENTIAL, DATA_ACCESS]

ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# The keys `applies_to` is allowed to carry. A typo in one of these would be a
# constraint that silently does not constrain, so the rule matches far more edges
# than its author meant.
APPLIES_TO_KEYS = {
    "edge_category",
    "source_type",
    "target_type",
    "source_evidence_source_id",
    "target_evidence_source_id",
    "source_evidence_source_id_prefix",
    "target_evidence_source_id_prefix",
    "source_evidence_semantic",
    "target_evidence_semantic",
    "target_admits_inbound"
}

RULE_KEYS = {
    "id",
    "name",
    "tactic",
    "technique",
    "summary",
    "applies_to",
    "precondition",
    "postcondition",
    "input",
    "output",
    "stop_after_match"
}


@pytest.fixture(scope="module")
def rules():
    return load_transitions()


@pytest.fixture(scope="module")
def real_graph():
    return build_state_graph()


@pytest.fixture(scope="module")
def real_attack_graph(real_graph):
    return build_attack_graph(real_graph)


# -- The ruleset -------------------------------------------------------------

def test_the_ruleset_is_not_empty(rules):
    assert rules
    assert len(rules) >= 10


def test_every_rule_declares_the_required_fields(rules):
    for rule in rules:

        assert rule.get("id")
        assert rule.get("name")
        assert rule.get("tactic")
        assert rule.get("summary")
        assert rule.get("applies_to")

        # precondition and postcondition may be empty — a configuration
        # reference legitimately claims nothing — but the keys have to be there,
        # so "claims nothing" is a decision and not an omission.
        assert "precondition" in rule, rule["id"]
        assert "postcondition" in rule, rule["id"]

        assert isinstance(rule["postcondition"], list)

        # A bare list is facts alone; a mapping names where each half comes from.
        assert isinstance(rule["precondition"], (list, dict)), rule["id"]


def test_rule_ids_are_unique(rules):
    ids = [rule["id"] for rule in rules]

    assert len(ids) == len(set(ids))


def test_no_rule_uses_the_fallback_id(rules):
    """FALLBACK_ID marks a step no rule matched. A rule claiming it would make a
    covered hop indistinguishable from an uncovered one."""

    assert FALLBACK_ID not in {rule["id"] for rule in rules}


def test_no_rule_carries_an_unknown_key(rules):
    for rule in rules:

        unknown = set(rule) - RULE_KEYS

        assert unknown == set(), (rule["id"], sorted(unknown))


def test_every_applies_to_key_is_recognised(rules):
    """THE SILENT-WILDCARD GUARD.

    graph/transitions.matches ignores keys it does not know, so a misspelled
    constraint does not narrow anything and the rule fires on every edge of its
    category. That is the failure mode most likely to go unnoticed, because the
    output grows rather than shrinks.
    """

    for rule in rules:

        unknown = set(rule["applies_to"]) - APPLIES_TO_KEYS

        assert unknown == set(), (rule["id"], sorted(unknown))


def test_every_category_the_graph_can_emit_has_a_rule(rules):
    """THE COVERAGE GUARD.

    An edge no rule matches falls back to an action that claims nothing, so paths
    through it stop being derivable and the only symptom is a lower path count.
    The categories are read off models/cloud_resource.py's relation map, which is
    the one place that decides what a category is.
    """

    import inspect

    from models.cloud_resource import CloudResource
    from security_state_graph.state_graph import BIDIRECTIONAL_CATEGORIES, REVERSED_CATEGORIES

    body = inspect.getsource(CloudResource.add_connection)
    body = body.split("relation_map = {", 1)[1].split("}", 1)[0]

    declared = {
        line.split('"')[1]
        for line in body.splitlines()
        if line.strip().startswith('"') and '":' in line
    }

    assert declared, "could not read the relation map — has add_connection moved?"

    categories = (
        declared | set(REVERSED_CATEGORIES) | set(BIDIRECTIONAL_CATEGORIES)
    )

    covered = {
        rule["applies_to"].get("edge_category")
        for rule in rules
    }

    assert sorted(categories - covered) == []


def test_no_rule_matches_every_edge(rules):
    """An empty applies_to is refused rather than treated as a wildcard."""

    for rule in rules:
        assert rule["applies_to"], rule["id"]


def test_every_technique_is_in_the_iaas_matrix(rules):
    """THE CITATION GUARD, same as the security ruleset has."""

    from engine.attack_catalog import is_known

    for rule in rules:

        technique = rule.get("technique")

        if technique is None:
            continue

        assert ATTACK_ID_PATTERN.match(technique), rule["id"]
        assert is_known(technique), (rule["id"], technique)


def test_every_tactic_is_one_the_matrix_names(rules):
    """`tactic` orders the STAGE labels in the generated attack graph, so a tactic
    outside the matrix is a stage that cannot be placed in the kill chain."""

    import yaml

    from pathlib import Path

    catalog = yaml.safe_load(
        open(
            Path(__file__).resolve().parent.parent / "data" / "attack_techniques.yaml",
            encoding="utf-8"
        )
    )

    known = set(catalog["tactics"])

    for rule in rules:
        assert rule["tactic"] in known, (rule["id"], rule["tactic"])


def test_the_tactic_agrees_with_the_technique_it_cites(rules):
    """A tactic that contradicts the matrix's own filing for that technique is a
    stage label a reader will query.

    ATT&CK lists several techniques under more than one tactic, so the rule's
    tactic has to be the primary one or one of the `also` entries.
    """

    from engine.attack_catalog import load_catalog

    # load_catalog returns techniques already keyed by id.
    by_id = load_catalog()["techniques"]

    for rule in rules:

        technique = rule.get("technique")

        if technique is None:
            continue

        entry = by_id[technique]

        allowed = {entry.get("tactic")} | set(entry.get("also") or [])

        assert rule["tactic"] in allowed, (
            rule["id"],
            technique,
            rule["tactic"],
            sorted(allowed)
        )


def test_every_declared_fact_is_parseable_and_known(rules):
    """A typo in a precondition is a step that can never be taken; a typo in a
    postcondition is a fact nothing downstream can consume."""

    for rule in rules:

        facts, _, _ = precondition_parts(rule)

        for text in facts + rule["postcondition"]:

            name, end = parse_fact(text)

            assert name in FACT_NAMES, (rule["id"], text)
            assert end in (None, "source", "target"), (rule["id"], text)


def test_a_rule_that_grants_nothing_also_requires_nothing(rules):
    """Same invariant the edge-category table has. A rule that requires a fact
    and grants none consumes a hop of the depth budget for nothing; one that
    grants a fact and requires none is a free win the attacker did not earn."""

    for rule in rules:

        if not rule["postcondition"]:
            assert rule["precondition"] == [], rule["id"]


def test_a_misspelled_fact_raises_rather_than_being_skipped():
    with pytest.raises(ValueError):
        parse_fact("foothold[target]")

    with pytest.raises(ValueError):
        parse_fact("foothold(neither)")

    with pytest.raises(ValueError):
        parse_fact(42)


def test_parse_facts_reads_the_written_form():
    assert parse_facts(["internet_reachable", "foothold(target)"]) == [
        ("internet_reachable", None),
        ("foothold", "target")
    ]

    assert parse_facts(None) == []


# -- Binding -----------------------------------------------------------------

def test_the_binding_syntax_resolves_each_reference(real_graph):
    edge = {
        "source": "OpenSecurityGroup",
        "target": "PublicEC2Instance",
        "category": "network_control"
    }

    source = real_graph.node("OpenSecurityGroup")
    target = real_graph.node("PublicEC2Instance")

    assert bind_value("target.id", edge, source, target) == "PublicEC2Instance"
    assert bind_value("source.id", edge, source, target) == "OpenSecurityGroup"

    assert bind_value("target.type", edge, source, target) == "AWS::EC2::Instance"

    # A projected attribute, read from the same block the rules resolve against.
    assert bind_value("source.attr:ingress.cidr", edge, source, target) == [
        "0.0.0.0/0"
    ]

    assert sorted(
        bind_value("source.attr:ingress.from_port", edge, source, target)
    ) == [22, 3389]

    # Findings, by semantic.
    assert bind_value(
        "source.evidence:network_control", edge, source, target
    ) == ["RESTRICTED_INCOMING_TRAFFIC", "INCOMING_SSH_DISABLED"]

    # Anything unrecognised is a literal, which is how `access: interactive
    # shell` works.
    assert bind_value("interactive shell", edge, source, target) == (
        "interactive shell"
    )


def test_a_reference_that_resolves_to_nothing_is_dropped(real_graph):
    """An input block should only ever state what is actually known. A key
    written as null reads as "we looked and there is none", which is a different
    claim from "this action does not record that"."""

    edge = {
        "source": "OverPermissiveInstanceProfile",
        "target": "OverPermissiveRole",
        "category": "identity"
    }

    actions = actions_for(edge, real_graph)

    for action in actions:
        assert None not in action["input"].values()
        assert None not in action["output"].values()


# -- Matching ----------------------------------------------------------------

def test_the_most_specific_action_shadows_its_generic_sibling(real_graph):
    """PublicEC2Instance carries EC2_IMDSV1_ENABLED, so the hop to its profile is
    "read role credentials from the metadata service" and not the vague "use an
    attached identity". `stop_after_match` is what arranges that."""

    edge = next(
        edge
        for edge in real_graph.traversal_edges()
        if edge["source"] == "PublicEC2Instance"
        and edge["target"] == "OverPermissiveInstanceProfile"
    )

    actions = actions_for(edge, real_graph)

    assert [action["action_id"] for action in actions] == [
        "ACT_READ_INSTANCE_METADATA"
    ]


def test_an_identity_hop_with_no_imdsv1_finding_gets_the_generic_action(real_graph):
    """The discriminating half. A profile does not carry an IMDSv1 finding, so the
    specific rule must not match and the generic one must."""

    edge = next(
        edge
        for edge in real_graph.traversal_edges()
        if edge["source"] == "OverPermissiveInstanceProfile"
    )

    actions = actions_for(edge, real_graph)

    assert [action["action_id"] for action in actions] == [
        "ACT_USE_ATTACHED_IDENTITY"
    ]


def test_an_unmatched_edge_falls_back_rather_than_disappearing(real_graph):
    """THE WRAPPING CONTRACT.

    An edge category the ruleset does not name still yields an action, so an
    unwritten rule costs detail and never a path. The fallback carries no
    technique and no tactic, because the category says what the hop is
    structurally and nothing about which attacker behaviour it is — filling that
    in from the category would be inventing a citation.
    """

    edge = {
        "source": "OpenSecurityGroup",
        "target": "PublicEC2Instance",
        "category": "a_category_no_rule_names"
    }

    actions = actions_for(edge, real_graph)

    assert len(actions) == 1

    action = actions[0]

    assert action["action_id"] == FALLBACK_ID
    assert action["fallback"] is True
    assert action["technique"] is None
    assert action["tactic"] is None


def test_matches_refuses_a_rule_with_an_empty_applies_to(real_graph):
    with pytest.raises(ValueError):
        matches({"id": "X", "applies_to": {}}, {}, None, None, False)


def test_describe_edge_keeps_the_first_action_on_the_edge(real_graph):
    """Anything reading an edge rather than an action still sees a usable
    precondition/postcondition pair, and it is the most specific one."""

    edge = next(
        edge
        for edge in real_graph.traversal_edges()
        if edge["category"] == "network_control"
    )

    described = describe_edge(edge, real_graph)

    assert described["actions"]
    assert described["action_id"] == described["actions"][0]["action_id"]
    assert described["precondition"] == described["actions"][0]["precondition"]
    assert described["input"] == described["actions"][0]["input"]


# -- On the shipped account --------------------------------------------------

def test_the_shipped_account_needs_no_fallback(real_attack_graph):
    """THE COVERAGE ASSERTION.

    Every edge in the shipped dataset is named by a transition rule. If this
    fails, the ruleset has stopped covering an edge category the graph emits and
    those hops carry no ATT&CK technique.
    """

    fallbacks = real_attack_graph.fallback_edges()

    assert fallbacks == [], sorted(
        {(edge["category"], edge["source"], edge["target"])
         for edge in fallbacks}
    )


def test_every_action_on_the_shipped_account_cites_a_technique(real_attack_graph):
    for edge in real_attack_graph.edges:

        assert edge["technique"], edge["action_id"]
        assert edge["tactic"], edge["action_id"]


def test_the_shipped_account_exercises_a_real_kill_chain(real_attack_graph):
    """Not one tactic repeated. A path that is initial access four times over is
    not an attack narrative, and it would mean the actions are not discriminating
    between the kinds of hop."""

    summary = real_attack_graph.to_dict()["summary"]

    assert "initial access" in summary["tactics"]
    assert "credential access" in summary["tactics"]
    assert "privilege escalation" in summary["tactics"]
    assert "collection" in summary["tactics"]

    assert summary["distinct_techniques"] >= 5


def test_every_input_names_the_resources_the_edge_joins(real_attack_graph):
    """An input block that does not mention either end of its own edge is
    describing something else."""

    for edge in real_attack_graph.edges:

        if not edge["input"]:
            continue

        mentioned = set()

        for value in edge["input"].values():

            items = value if isinstance(value, list) else [value]

            mentioned.update(item for item in items if isinstance(item, str))

        assert {edge["source"], edge["target"]} & mentioned, edge


def test_every_usable_action_is_offered_regardless_of_order(real_graph):
    """THE ORDER-INDEPENDENCE GUARD.

    Two rules can match one edge with the same precondition and different
    postconditions. The search takes all of them, so listing the generic one first
    cannot strand a route behind it. Taking only the first made path existence
    depend on the order of a YAML file.
    """

    from attack_path.path_finder import available_actions

    specific = {
        "id": "AR_TEST_SPECIFIC",
        "name": "specific",
        "tactic": "collection",
        "technique": "T1530",
        "summary": "grants data access",
        "applies_to": {"edge_category": "capability"},
        "precondition": ["credential(source)"],
        "postcondition": ["data_access(target)"],
        "input": {},
        "output": {"data_access": "target.id"}
    }

    generic = dict(
        specific,
        id="AR_TEST_GENERIC",
        name="generic",
        tactic="discovery",
        technique="T1580",
        summary="grants nothing",
        postcondition=[]
    )

    edge = next(
        edge
        for edge in real_graph.traversal_edges()
        if edge["category"] == "capability"
    )

    held = {fact(CREDENTIAL, edge["source"])}

    def offered(rules):
        return {
            action["action_id"]
            for action in available_actions(edge, real_graph, held, rules)
        }

    assert offered([specific, generic]) == {"AR_TEST_SPECIFIC", "AR_TEST_GENERIC"}
    assert offered([generic, specific]) == {"AR_TEST_SPECIFIC", "AR_TEST_GENERIC"}


# -- The precondition's two sources ------------------------------------------

def test_a_capability_requirement_names_an_end_of_the_edge(rules):
    """THE YAML-BOOLEAN GUARD.

    This key was `on` until YAML 1.1 turned `on: source` into `{True: "source"}`
    and every rule using it silently stopped matching. Any key that is not a
    string is that class of bug — `off`, `yes`, `no`, `y`, `n` are all booleans
    too.
    """

    for rule in rules:

        _, capabilities, _ = precondition_parts(rule)

        for requirement in capabilities:

            for key in requirement:
                assert isinstance(key, str), (rule["id"], key)

            assert requirement.get("end") in ("source", "target"), rule["id"]

            # It has to demand something, or it constrains nothing.
            assert set(requirement) - {"end"}, rule["id"]


def test_the_capability_half_of_a_precondition_comes_from_the_state_graph(rules):
    """Task 5's precondition has two sources: the previous step's postcondition,
    and what the security state graph found. The second half used to live in
    `applies_to`, which read as a matching detail rather than as a precondition —
    which is why Task 5 looked half-implemented."""

    with_capabilities = [
        rule["id"]
        for rule in rules
        if precondition_parts(rule)[1]
    ]

    assert with_capabilities

    # And no rule still hides them in applies_to.
    for rule in rules:

        hidden = {
            key
            for key in rule["applies_to"]
            if "evidence" in key
        }

        assert hidden == set(), (rule["id"], sorted(hidden))


def test_escalation_preconditions_cite_rhino_permissions(real_attack_graph):
    """Rhino Security Labs publishes `Required Permission(s)` per method. That is
    a precondition in the source's own words, so an escalation action states it
    rather than only asserting `credential(source)`."""

    escalations = [
        edge
        for edge in real_attack_graph.edges
        if edge["category"] in ("escalation", "hijack")
    ]

    assert escalations

    for edge in escalations:
        assert edge["required_permissions"], edge["action_id"]

        for permission in edge["required_permissions"]:
            assert ":" in permission, permission
