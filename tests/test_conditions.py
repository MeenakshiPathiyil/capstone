"""Tests for graph/conditions.py — the fact vocabulary.

The conditions themselves live in data/attack_transitions.yaml; this module only
holds the four fact names and the helpers for testing and accumulating them. It
used to hold a second precondition table keyed by edge category, and the two
disagreed. See docs/adr/0002-one-home-for-conditions.md.
"""


from security_state_graph.facts import (
    CREDENTIAL,
    DATA_ACCESS,
    FOOTHOLD,
    INTERNET_REACHABLE,
    SOURCE,
    TARGET,
    fact,
    facts_after,
    precondition_met,
    resolve
)


def edge(**fields):
    return dict({"source": "A", "target": "B"}, **fields)


def test_a_fact_about_the_whole_environment_carries_no_resource():
    """`internet_reachable` is a claim about the account, not one resource. Scoped
    to a resource it would never match the precondition of an edge leaving a
    different one."""

    assert fact(INTERNET_REACHABLE) == "internet_reachable"


def test_a_fact_about_a_resource_names_it():
    """The opposite half: "the attacker has a foothold" is not a fact."""

    assert fact(FOOTHOLD, "WebServer") == "foothold(WebServer)"
    assert fact(CREDENTIAL, "WebRole") == "credential(WebRole)"
    assert fact(DATA_ACCESS, "Bucket") == "data_access(Bucket)"


def test_resolve_puts_each_fact_on_the_end_it_names():
    """A postcondition naming SOURCE instead of TARGET would grant the attacker
    something they already had, and the chain would go nowhere."""

    hop = edge(source="Instance", target="Profile")

    assert resolve([(FOOTHOLD, SOURCE)], hop) == ["foothold(Instance)"]
    assert resolve([(CREDENTIAL, TARGET)], hop) == ["credential(Profile)"]
    assert resolve([(INTERNET_REACHABLE, None)], hop) == ["internet_reachable"]


def test_a_precondition_is_any_of_not_all_of():
    """An `identity` hop is taken either from code running on the source or from
    already holding its identity. Requiring both would break the
    instance -> profile -> role chain every IAM finding depends on."""

    hop = edge(precondition=["foothold(A)", "credential(A)"])

    assert precondition_met(hop, {"foothold(A)"}) is True
    assert precondition_met(hop, {"credential(A)"}) is True
    assert precondition_met(hop, {"credential(Elsewhere)"}) is False
    assert precondition_met(hop, set()) is False


def test_a_hop_with_no_precondition_is_always_available():
    """And such a hop grants nothing, so it cannot be why a path exists."""

    assert precondition_met(edge(precondition=[]), set()) is True
    assert precondition_met(edge(), set()) is True


def test_taking_a_hop_adds_its_postcondition_and_keeps_the_rest():
    hop = edge(postcondition=["data_access(Bucket)"])

    held = {"internet_reachable", "credential(Role)"}

    assert facts_after(hop, held) == held | {"data_access(Bucket)"}

    # The original set is not mutated: the search explores a sibling branch with
    # the facts it held before this hop.
    assert held == {"internet_reachable", "credential(Role)"}


def test_a_hop_that_grants_nothing_leaves_the_facts_alone():
    assert facts_after(edge(), {"x"}) == {"x"}
    assert facts_after(edge(postcondition=[]), {"x"}) == {"x"}
