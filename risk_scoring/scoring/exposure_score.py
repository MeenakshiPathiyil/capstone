"""Direct exposure scoring for an attack path.

The values in this module are provisional, authored design choices. They
encode an ordinal relationship between reachability classes and should be
evaluated against representative infrastructure scenarios before being
considered empirically calibrated.
"""

from multipliers.reach_multiplier import ReachabilityClass


_EXPOSURE_SCORE_BY_REACHABILITY = {
    ReachabilityClass.DIRECT: 90.0,
    ReachabilityClass.VIA_PATH: 65.0,
    ReachabilityClass.POST_COMPROMISE: 40.0,
}


def compute_exposure_score(
    reachability_class: ReachabilityClass,
) -> float:
    """Return a direct 1-100 exposure score from reachability context.

    Provisional rubric:
      * DIRECT: 90 -- the target is directly reachable from the path's
        attacker-facing entry context.
      * VIA_PATH: 65 -- reaching the target requires one or more
        intermediate transitions.
      * POST_COMPROMISE: 40 -- access depends on an already-compromised
        resource or attacker foothold.

    Reachability class represents exposure context only. Path length is
    scored separately by ``compute_path_ease`` and is deliberately not an
    input to this function.
    """
    if not isinstance(reachability_class, ReachabilityClass):
        raise TypeError(
            "reachability_class must be ReachabilityClass, got "
            f"{type(reachability_class).__name__}"
        )

    return _EXPOSURE_SCORE_BY_REACHABILITY[reachability_class]
