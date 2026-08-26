"""The resource-type lists in different modules have to agree.

THEORY (why this file exists):
Three of the nine findings in the review that prompted it were the same mistake:
a resource type added to one module's list and not to the other module that has
to know about it. Each was invisible because nothing failed — the pipeline ran,
the tests passed, and the feature simply did not work.

  * AWS::RDS::DBCluster went into connection_builder.DATA_TYPES to fix Aurora,
    and into no objective's resource_types, so a capability edge was drawn to it
    and no route could ever end there. The fix was a no-op for the stack it was
    written for.
  * LaunchTemplate and AutoScalingGroup went into COMPUTE_TYPES, so `hijack`
    edges pointed at them, and resource_hijacking still listed only three types.
  * TRAFFIC_PATH_TYPES and RELATION_BY_TARGET_TYPE were maintained separately and
    disagreed about the classic load balancer immediately.

A type list is a contract between modules, and these are the assertions that make
breaking it fail loudly. Adding a type to one place and running the suite now
tells you the other places to add it to.
"""

import re

import pytest
import yaml

from engine.connection_builder import (
    COMPUTE_TYPES,
    DATA_TYPES,
    IAM_PRINCIPAL_TYPES,
    RELATION_BY_TARGET_TYPE,
    SERVICE_BY_TYPE,
    TRAFFIC_PATH_CATEGORY,
    TRAFFIC_PATH_TYPES
)
from security_state_graph.state_graph import (
    BIDIRECTIONAL_CATEGORIES,
    INBOUND_REACHABLE_TYPES,
    REVERSED_CATEGORIES
)


# AWS::Service::Resource. Anything else is a typo, and a typo in a type list is
# an entry that silently never matches.
TYPE_PATTERN = re.compile(r"^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$")

REGISTRIES = {
    "DATA_TYPES": DATA_TYPES,
    "COMPUTE_TYPES": COMPUTE_TYPES,
    "IAM_PRINCIPAL_TYPES": IAM_PRINCIPAL_TYPES,
    "TRAFFIC_PATH_TYPES": TRAFFIC_PATH_TYPES
}


@pytest.fixture
def objectives(objectives_path):
    return yaml.safe_load(objectives_path.read_text())["objectives"]


@pytest.fixture
def objective_types(objectives):
    """Every resource type at least one objective accepts as an endpoint."""

    claimed = set()

    for objective in objectives:
        claimed.update(objective["resource_types"])

    return claimed


# -----------------------------

@pytest.mark.parametrize("name", sorted(REGISTRIES))
def test_every_registered_type_is_well_formed(name):
    for resource_type in REGISTRIES[name]:
        assert TYPE_PATTERN.match(resource_type), (name, resource_type)


@pytest.mark.parametrize("name", sorted(REGISTRIES))
def test_no_registry_repeats_a_type(name):
    types = REGISTRIES[name]

    assert len(types) == len(set(types)), name


# -----------------------------

def test_every_data_type_can_end_a_path(objective_types):
    """THE ASSERTION THAT WOULD HAVE CAUGHT THE AURORA BUG.

    build_capability_edges draws an edge to every DATA_TYPES resource a wildcard
    grant covers. walk_paths only terminates a route at a node some objective
    claims. A type in the first list and not the second is therefore an edge that
    leads nowhere, which is exactly how Aurora stayed unreachable after being
    "added".
    """

    unclaimed = [
        resource_type
        for resource_type in DATA_TYPES
        if resource_type not in objective_types
    ]

    assert unclaimed == [], (
        "in DATA_TYPES but no objective accepts it as an endpoint: %s"
        % unclaimed
    )


def test_every_compute_type_can_end_a_path(objective_types):
    """The same contract for `hijack` edges: build_escalation_edges points them at
    COMPUTE_TYPES, so resource_hijacking has to accept those types."""

    unclaimed = [
        resource_type
        for resource_type in COMPUTE_TYPES
        if resource_type not in objective_types
    ]

    assert unclaimed == [], (
        "in COMPUTE_TYPES but no objective accepts it as an endpoint: %s"
        % unclaimed
    )


def test_every_data_type_maps_to_an_iam_service(objective_types):
    """A wildcard grant is scoped by Action, and SERVICE_BY_TYPE is what turns a
    resource type into the prefix to look for. A data type missing from it cannot
    be scoped, so the grant is either dropped or over-claimed."""

    unmapped = [
        resource_type
        for resource_type in DATA_TYPES
        if resource_type not in SERVICE_BY_TYPE
    ]

    assert unmapped == []


# -----------------------------

def test_traffic_path_types_all_classify_as_traffic_path():
    """RELATION_BY_TARGET_TYPE is derived from TRAFFIC_PATH_TYPES rather than
    hand-copied, because the hand-copied version disagreed with it about the
    classic load balancer, and nothing read the list at all."""

    for resource_type in TRAFFIC_PATH_TYPES:
        assert RELATION_BY_TARGET_TYPE.get(resource_type) == TRAFFIC_PATH_CATEGORY


def test_the_classic_load_balancer_is_classified():
    """It was in the unused list and absent from the live table, so classic-ELB
    references fell through to the default relation and the front door stayed
    disconnected while looking handled."""

    assert RELATION_BY_TARGET_TYPE.get(
        "AWS::ElasticLoadBalancing::LoadBalancer"
    ) == TRAFFIC_PATH_CATEGORY


def test_traffic_path_is_bidirectional_and_not_also_reversed():
    """The two lists are alternatives. A category in both would take the
    bidirectional branch and never reach the reversal one, so the second entry
    would be a silent no-op."""

    assert TRAFFIC_PATH_CATEGORY in BIDIRECTIONAL_CATEGORIES
    assert TRAFFIC_PATH_CATEGORY not in REVERSED_CATEGORIES

    assert set(BIDIRECTIONAL_CATEGORIES).isdisjoint(REVERSED_CATEGORIES)


def test_every_traffic_path_type_may_receive_traffic():
    """A bidirectional edge's back-copy is an inbound hop, and inbound hops answer
    to admits_inbound(). A traffic type missing from INBOUND_REACHABLE_TYPES
    would have its back-edge dropped, disconnecting the path this category exists
    to build."""

    missing = [
        resource_type
        for resource_type in TRAFFIC_PATH_TYPES
        if resource_type not in INBOUND_REACHABLE_TYPES
    ]

    assert missing == [], (
        "traffic_path types whose inbound hop would be dropped: %s" % missing
    )


# -----------------------------

def test_an_iam_policy_is_not_a_principal():
    """A policy document is not an actor.

    While AWS::IAM::Policy was in this list, build_escalation_edges drew
    "AttachedPolicy -> VictimRole" — a hop no attacker can walk, since a policy
    cannot call AttachRolePolicy; whoever holds the policy can. It also produced
    an escalation edge from a policy to the very role it was attached to. The
    permissions belong to the principals the policy names, which
    privesc_detector.attached_statements resolves.
    """

    assert "AWS::IAM::Policy" not in IAM_PRINCIPAL_TYPES
    assert "AWS::IAM::ManagedPolicy" not in IAM_PRINCIPAL_TYPES


def test_the_registries_that_must_not_overlap_do_not():
    """A type that is both a principal and a data store would be handed a
    capability edge to itself, and one that is both compute and a principal would
    be hijacked and be the hijacker."""

    assert set(IAM_PRINCIPAL_TYPES).isdisjoint(DATA_TYPES)
    assert set(IAM_PRINCIPAL_TYPES).isdisjoint(COMPUTE_TYPES)
