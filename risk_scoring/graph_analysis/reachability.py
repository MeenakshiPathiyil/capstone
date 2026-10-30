"""Classify path-target reachability for the path-level risk model."""
from __future__ import annotations

from risk_scoring.multipliers.reach_multiplier import ReachabilityClass


def classify_path_reachability(path, entry_resource_ids: set[str]) -> ReachabilityClass:
    """Classify how the target resource is reached along an enriched path.

    DIRECT: target resource is itself represented by an entry state.
    POST_COMPROMISE: a state before the target indicates an established
    foothold/compromise.
    VIA_PATH: otherwise, the target is reached through graph transitions.

    The classifier uses the enriched state facts and entry flags; it does not
    infer reachability from path length (path ease is scored separately).
    """
    details = list(getattr(path, "node_details", ()) or ())
    if not details:
        raise ValueError(f"Path {getattr(path, 'path_id', '<unknown>')} has no node details")

    target_resource = None
    for node in reversed(details):
        if node.get("resource"):
            target_resource = node["resource"]
            break
    if not target_resource:
        raise ValueError(f"Could not resolve target resource for path {path.path_id}")

    if target_resource in entry_resource_ids:
        return ReachabilityClass.DIRECT

    # Exclude the target node: a foothold created at the target is the result
    # of this path, not evidence that the path started after compromise.
    for node in details[:-1]:
        facts = node.get("facts", []) or []
        for fact in facts:
            normalized = str(fact).lower()
            if "foothold(" in normalized or "compromised" in normalized:
                return ReachabilityClass.POST_COMPROMISE

    return ReachabilityClass.VIA_PATH
