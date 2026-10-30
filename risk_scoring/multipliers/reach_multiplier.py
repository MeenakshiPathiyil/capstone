# One ReachabilityClass, defined with the graph model. This module used to
# import it and then define a second enum of the same name, so the two were
# different types and an isinstance check against one rejected the other.
from risk_scoring.graph_model.graph_node import ReachabilityClass


# Frozen V1 values. Authored modeling choices, not empirically
# derived -- see the "Provenance of baselines and weights" decision:
# these express an ordering (Direct > Network-mediated >
# Post-compromise), not a claim of objectively correct magnitudes.
_REACH_MULTIPLIERS = {
    ReachabilityClass.DIRECT: 1.2,
    ReachabilityClass.VIA_PATH: 1.0,
    ReachabilityClass.POST_COMPROMISE: 0.7,
}


def compute_reach_multiplier(
    reachability_class: ReachabilityClass,
) -> float:
    """
    Pure function: a table lookup.

    Deliberately takes only a ReachabilityClass -- no graph, no
    node, no path length. The separation between M_reach (how
    directly reachable is the entry resource) and A (how complex is
    the attack path) is enforced by this signature, not just by
    convention: this function has no way to see path length even if
    a caller wanted it to.
    """

    if not isinstance(reachability_class, ReachabilityClass):
        raise TypeError(
            "compute_reach_multiplier expected ReachabilityClass, "
            f"got {type(reachability_class).__name__}."
        )

    return _REACH_MULTIPLIERS[reachability_class]