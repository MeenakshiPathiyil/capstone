"""What a finding means.

A security rule gives every finding a `semantic`. This decides three things: is
the finding a way into the account, is it the attacker gaining authority, or is it
neither; and how severe it is when the rule did not say.

Module 2's business, not the path layer's. It lives here so the security state
graph can label its own nodes without importing the search that reads them.
"""

from engine.connection_builder import DATA_TYPES


EXPOSURE_SEMANTIC = "exposure"
PRIVILEGE_SEMANTIC = "privilege"

# A way in from outside the account.
ENTRY_SEMANTICS = [
    "network_control",
    EXPOSURE_SEMANTIC
]

# The attacker gaining rights they did not have. A path that needs privilege
# requires one of these on an interior hop.
AUTHORITY_SEMANTICS = [
    PRIVILEGE_SEMANTIC,
    "identity",
    "trust",
    "capability"
]

# Reported, and never moves the search. `impact` is damage done once inside;
# `connection` is one resource naming another.
NON_PATH_SEMANTICS = [
    "impact",
    "connection"
]

# The parser emits seven semantics. `privilege` is ours: it is the only one that
# marks the attacker gaining authority, without which every path is rejected, and
# Rhino Security Labs is the one primary source using "privilege" as state an
# attacker holds. See docs/research/precondition-sources.md.

# Checks whose findings are real but are not attack steps.
#
# REQUIRED_TAGS is canonical `capability`, which counts as authority, so without
# this a missing cost-centre tag would satisfy the privilege requirement and the
# tool would report attack paths built on a billing problem.
NON_PATH_SOURCE_IDS = [
    "REQUIRED_TAGS"
]

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0
}

# Severity when the rule did not declare one, which the canonical rules never do.
# One table to defend rather than a number per rule. Not calibrated against
# incident data.
SEVERITY_BY_SEMANTIC = {
    PRIVILEGE_SEMANTIC: "critical",

    "network_control": "high",
    EXPOSURE_SEMANTIC: "high",
    "identity": "high",
    "trust": "high",

    "capability": "low",
    "connection": "low",

    "impact": "medium"
}

# An unrecognised label still counts: the finding is real even when the label is
# not one this table knows.
DEFAULT_SEVERITY_WEIGHT = 0.5


def is_path_relevant(finding):
    """False for a finding that is reported but must not move the search."""

    source_id = finding.get("source_id") or finding.get("rule_id")

    return source_id not in NON_PATH_SOURCE_IDS


def has_semantic(states, semantic):
    """True when any path-relevant finding carries `semantic`."""

    return any(
        finding.get("semantic") == semantic
        for finding in states
        if is_path_relevant(finding)
    )


def has_any_semantic(states, semantics):
    """True when any path-relevant finding carries one of `semantics`."""

    return any(
        finding.get("semantic") in semantics
        for finding in states
        if is_path_relevant(finding)
    )


def finding_severity(finding):
    """A finding's severity, derived from its semantic when the rule gave none.

    A finding that carries its own keeps it, which is how the privilege
    escalation detector keeps the values it takes from privesc_methods.yaml.
    """

    declared = finding.get("severity")

    if isinstance(declared, str) and declared:
        return declared

    return SEVERITY_BY_SEMANTIC.get(finding.get("semantic"))


def severity_weight(severity):
    """The weight of one severity label, case-insensitively."""

    if not isinstance(severity, str):
        return DEFAULT_SEVERITY_WEIGHT

    return SEVERITY_WEIGHTS.get(severity.lower(), DEFAULT_SEVERITY_WEIGHT)


def finding_weight(finding):
    """The weight of one finding, whether or not its rule declared a severity."""

    return severity_weight(finding_severity(finding))


def entry_points(state_graph):
    """The ids an attacker can start from, in graph order."""

    return [
        node_id
        for node_id, node in state_graph.nodes.items()
        if has_any_semantic(node["states"], ENTRY_SEMANTICS)
    ]


def data_targets(state_graph):
    """The ids that hold data, in graph order.

    A type fact, not an objective one — attack_path/path_finder decides which
    resources a given objective counts as its endpoint.
    """

    return [
        node_id
        for node_id, node in state_graph.nodes.items()
        if node["type"] in DATA_TYPES
    ]
