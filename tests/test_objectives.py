"""The objectives layer: what an attacker is trying to achieve.

Grounded in the Impact, Collection and Exfiltration tactics of the ATT&CK IaaS
matrix. The endpoint used to be a hardcoded list of data stores, which defined
every non-theft attack out of existence — an attacker who encrypts the same
database walks an identical route and was reported as nothing.
"""

import pytest

from engine.attack_catalog import is_known
from attack_path.path_finder import (
    is_exploitable,
    load_objectives,
    objective_targets,
    objectives_of
)
from attack_path.scoring import score_path
from security_state_graph.state_graph import SecurityStateGraph, evaluate_findings
from tests.conftest import data_theft_only


@pytest.fixture
def real_graph(real_infra, rules_path):
    """The shipped dataset joined to the findings the shipped rules produce."""

    return SecurityStateGraph(
        real_infra,
        evaluate_findings(real_infra, rules_path)
    )


def objective(objective_id):
    return next(
        item
        for item in load_objectives()
        if item["id"] == objective_id
    )


# -----------------------------
# The file itself.

def test_the_objectives_load_and_every_entry_is_complete():
    objectives = load_objectives()

    assert objectives

    for item in objectives:
        assert item["id"]
        assert item["name"]
        assert item["resource_types"]
        assert isinstance(item["requires_privilege"], bool)
        assert item["base_weight"] > 0
        assert item["techniques"]


def test_objective_ids_are_unique():
    ids = [item["id"] for item in load_objectives()]

    assert len(ids) == len(set(ids))


def test_every_cited_technique_is_in_the_iaas_matrix():
    for item in load_objectives():
        for technique_id in item["techniques"]:
            assert is_known(technique_id), (item["id"], technique_id)


def test_an_objective_with_no_resource_types_is_a_load_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "objectives:\n"
        "  - id: nothing\n"
        "    resource_types: []\n"
        "    requires_privilege: true\n",
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_objectives(bad)


def test_an_objective_that_does_not_say_whether_it_needs_privilege_is_an_error(
    tmp_path
):
    """The field decides whether a whole class of attack is reportable."""

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "objectives:\n"
        "  - id: vague\n"
        "    resource_types: [AWS::S3::Bucket]\n",
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_objectives(bad)


def test_the_ransomware_and_theft_objectives_share_their_targets():
    """The same database is both, which is the point: one route, two attacks."""

    theft = set(objective("data_theft")["resource_types"])
    ransom = set(objective("ransomware")["resource_types"])

    assert "AWS::RDS::DBInstance" in theft & ransom
    assert "AWS::S3::Bucket" in theft & ransom


def test_exactly_one_objective_needs_no_escalation():
    """Denial of service is the case a single global policy would have rejected."""

    without = [
        item["id"]
        for item in load_objectives()
        if not item["requires_privilege"]
    ]

    assert without == ["denial_of_service"]


# -----------------------------
# Which nodes qualify.

def test_a_node_qualifies_for_every_objective_its_type_serves(real_graph):
    """A database is a theft target, a ransomware target and a DoS target."""

    ids = {
        item["id"]
        for item in objectives_of(real_graph, "PublicRDS")
    }

    assert {"data_theft", "ransomware", "denial_of_service"} <= ids


def test_an_unknown_node_qualifies_for_nothing(real_graph):
    assert objectives_of(real_graph, "NoSuchResource") == []


def test_target_requires_semantic_gates_identity_takeover(real_graph):
    """THE NOISE THIS FIELD EXISTS TO STOP.

    Every IAM role is a role, so listing the type alone made every hop of every
    escalation chain an endpoint. Seizing an identity is only an objective when
    the identity is worth having, so the target must carry a privilege finding.
    """

    def ids_for(resource_id):
        return {item["id"] for item in objectives_of(real_graph, resource_id)}

    # carries IAM_WILDCARD_PERMISSIONS, so it is worth taking over
    assert "identity_takeover" in ids_for("OverPermissiveRole")

    # a role with no finding of its own is not an objective, even though the
    # type is listed
    assert real_graph.states_of("AppInstanceProfile") == []
    assert "identity_takeover" not in ids_for("AppInstanceProfile")


def test_objective_targets_agrees_with_objectives_of(real_graph):
    """Otherwise the search walks to endpoints that are then rejected."""

    targets = objective_targets(real_graph)

    for node_id in real_graph.nodes:

        if objectives_of(real_graph, node_id):
            assert node_id in targets

        else:
            assert node_id not in targets


def test_narrowing_the_objective_set_narrows_the_targets(real_graph):
    theft_only = objective_targets(real_graph, data_theft_only())

    assert "ReportsTable" in theft_only

    # a Lambda is a hijacking target, never a data-theft one
    assert "IngestFunction" not in theft_only


# -----------------------------
# The per-objective policy.

def test_denial_of_service_does_not_need_an_escalation(real_graph):
    """THE ATTACK A SINGLE GLOBAL POLICY WOULD HAVE THROWN AWAY."""

    route = ["OpenSecurityGroup", "PublicEC2Instance"]

    assert is_exploitable(real_graph, route, objective("denial_of_service"))

    # the same route, judged as data theft, is not exploitable: nothing on it
    # hands over authority
    assert not is_exploitable(real_graph, route, objective("data_theft"))


def test_an_objective_of_none_still_demands_an_escalation(real_graph):
    """The pre-objectives behaviour, kept so old callers are unchanged."""

    route = ["OpenSecurityGroup", "PublicEC2Instance"]

    assert not is_exploitable(real_graph, route)


def test_a_route_of_one_node_is_never_exploitable(real_graph):
    for item in load_objectives():
        assert not is_exploitable(real_graph, ["PublicRDS"], item)


def test_an_entry_with_no_finding_is_rejected_for_every_objective(real_graph):
    """Including the objective that needs no escalation."""

    route = ["AppInstanceProfile", "AppServerRole"]

    assert real_graph.states_of("AppInstanceProfile") == []

    for item in load_objectives():
        assert not is_exploitable(real_graph, route, item)


# -----------------------------
# Scoring.

def test_the_objective_weight_is_added_to_the_score(real_graph):
    route = [
        "OpenSecurityGroup",
        "PublicEC2Instance",
        "OverPermissiveInstanceProfile",
        "OverPermissiveRole",
        "PublicRDS"
    ]

    plain = score_path(real_graph, route)
    theft = score_path(real_graph, route, objective("data_theft"))
    ransom = score_path(real_graph, route, objective("ransomware"))

    assert theft > plain
    assert ransom > theft

    # and the gap is the difference in base weight, before damping and the boost
    assert ransom - theft == pytest.approx(
        (objective("ransomware")["base_weight"]
         - objective("data_theft")["base_weight"])
        * (0.85 ** (len(route) - 2))
        * 1.25,
        abs=0.02
    )


def test_destroying_data_outranks_copying_it(real_graph):
    """The one judgement the base weights encode, asserted rather than implied."""

    assert (
        objective("ransomware")["base_weight"]
        > objective("data_theft")["base_weight"]
        > objective("resource_hijacking")["base_weight"]
        > objective("denial_of_service")["base_weight"]
    )
