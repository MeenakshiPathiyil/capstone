"""Score an attack path, and band the score.

Split out of graph/path_finder.py, which had grown to own objectives, entry
points, the search itself, per-hop narration, export shaping AND this. Re-tuning a
threshold and fixing the cycle check are unrelated reasons to open a file.

FOR WHOEVER BUILDS THE RISK SCORING MODEL: everything here is the thing to
replace. `path_severity_total` sums every finding on every resource in the path,
so the score grows with how thoroughly the ruleset covers those resource types
rather than with how bad the path is. That is why the thresholds have moved each
time the ruleset grew.
"""

from security_state_graph.semantics import (
    EXPOSURE_SEMANTIC,
    finding_weight
)
from utils.helpers import flatten_dict


# Surviving fraction per hop beyond the first.
LENGTH_DAMPING_PER_HOP = 0.85

# Multiplier when the entry is reachable from the internet.
PUBLIC_ENTRY_BOOST = 1.25

# Property values, on a property the extractor tagged `exposure`, that mean the
# resource is addressable from outside.
PUBLIC_EXPOSURE_VALUES = [
    "0.0.0.0/0",
    "::/0",
    "internet-facing",
    "publicread",
    "publicreadwrite"
]

# The score bands.
#
# FOR WHOEVER BUILDS THE RISK SCORING MODEL:
# these two numbers are fitted to the current scale rather than derived from a
# statement about findings, because the sum they band moves whenever the ruleset
# grows. See the module docstring.
CRITICAL_SCORE_THRESHOLD = 40.0

HIGH_SCORE_THRESHOLD = 30.0

ATTACK_LEVEL_CRITICAL = "CRITICAL"
ATTACK_LEVEL_HIGH = "HIGH"
ATTACK_LEVEL_MEDIUM = "MEDIUM"

# Worst first, so "at least HIGH" is a slice of this list.
ATTACK_LEVELS = [
    ATTACK_LEVEL_CRITICAL,
    ATTACK_LEVEL_HIGH,
    ATTACK_LEVEL_MEDIUM
]


def path_severity_total(state_graph, path):
    """The summed severity weight of the path, counting each weakness once."""


    # A list rather than a set, walked in path order, so the total is summed in
    # a fixed order and two runs agree to the last decimal place.
    counted = []
    total = 0.0

    for node_id in path:

        for finding in state_graph.states_of(node_id):

            weakness = (node_id, finding.get("state"))

            if weakness in counted:
                continue

            counted.append(weakness)

            total = total + finding_weight(finding)

    return total


def is_public_entry(state_graph, node_id):
    """True when a node's own configuration puts it on the internet."""

    node = state_graph.node(node_id)

    if node is None:
        return False

    semantics = node["semantic_properties"]

    # The tags are written against flat, "Ingress[0].CidrIp" style keys, so the
    # properties have to be flattened to the same shape before lookup.
    flat_properties = flatten_dict(node["raw_properties"])

    for key, category in semantics.items():

        if category != EXPOSURE_SEMANTIC:
            continue

        value = flat_properties.get(key)

        # Checked before the string branch: bool is a subclass of int and
        # str(True) is not a value anybody writes in a template.
        if isinstance(value, bool):

            if value:
                return True

            continue

        if isinstance(value, str) and value.lower() in PUBLIC_EXPOSURE_VALUES:
            return True

    return False


def score_path(state_graph, path, objective=None):
    """The risk score of one path: summed severity, damped by length, boosted
    when the entry is publicly reachable, plus the objective's base weight."""


    score = path_severity_total(state_graph, path)

    # The objective's own weight, so destroying data outranks copying it and
    # both outrank making a service briefly unavailable.
    if objective is not None:
        score = score + float(objective.get("base_weight") or 0.0)


    # A route of N ids is N - 1 hops, and the first hop is free: the penalty is
    # for the hops an attacker has to chain *after* getting in.
    hops = max(len(path) - 1, 1)

    score = score * (LENGTH_DAMPING_PER_HOP ** (hops - 1))


    if is_public_entry(state_graph, path[0]):
        score = score * PUBLIC_ENTRY_BOOST

    return round(score, 2)


def select_high_risk(paths, min_level=ATTACK_LEVEL_HIGH):
    """The paths at or above `min_level`. Task 8's selection step.

    A parameter rather than a constant: the spec says "above a defined threshold"
    without naming one, and the band a path lands in depends on score constants
    that are still provisional.
    """

    if min_level not in ATTACK_LEVELS:
        raise ValueError(
            "%r is not an attack level (%s)"
            % (min_level, ", ".join(ATTACK_LEVELS))
        )

    keep = ATTACK_LEVELS[:ATTACK_LEVELS.index(min_level) + 1]

    return [path for path in paths if path.get("attack_level") in keep]


def attack_level_for(score):
    """The band a score falls in."""

    if score >= CRITICAL_SCORE_THRESHOLD:
        return ATTACK_LEVEL_CRITICAL

    if score >= HIGH_SCORE_THRESHOLD:
        return ATTACK_LEVEL_HIGH

    return ATTACK_LEVEL_MEDIUM
