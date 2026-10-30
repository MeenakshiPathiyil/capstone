"""Score the pipeline's ranked attack paths with the contextual risk model.

risk_input_adapter.py reads enriched path objects (path_id, edge_ids,
path_length, node_details) and a JSON metadata file. The pipeline produces
something else: attack_path.path_finder describes each path as a dict with
``hops`` (resources, entry first), ``length`` (edges) and ``steps`` (the facts
required and granted at each hop), and the template itself carries the tags.
This module bridges the two and reuses the same classifier, blast-radius and
scoring code, so there is one risk model, not two.

How each input is taken from the pipeline:

- node_details: one entry per hop, holding the facts the attacker has on
  arriving there. The entry hop holds the first step's preconditions (for
  example internet_reachable); every later hop holds the postconditions of the
  step that reached it (for example foothold(PublicEC2Instance)).
- entry resources: the state graph's entry points (is_entry).
- downstream counts: over the state graph's traversal edges. Those are
  resource-to-resource edges in attacker direction, the resource graph that
  blast_radius.py asks production callers to supply.
- metadata: read from each resource's CloudFormation Tags, see
  metadata_from_tags. A resource without matching tags stays unknown, which the
  impact rubric scores without a penalty.
"""

from __future__ import annotations

from types import SimpleNamespace

from risk_scoring.graph_analysis.blast_radius import (
    compute_downstream_counts,
    compute_graph_median_reachable,
)
from risk_scoring.graph_analysis.reachability import classify_path_reachability
from risk_scoring.graph_model.resource_metadata import (
    CriticalityLevel,
    Environment,
    ResourceMetadata,
)
from risk_scoring.models.path_scoring_input import PathScoringInput
from risk_scoring.scoring.path_ranking import dense_rank
from risk_scoring.scoring.path_scoring import score_path


# Tag keys and values read as metadata, compared case-insensitively. This is a
# convention of this adapter, not an AWS standard: change it here if the team
# settles on other tag names.
ENVIRONMENT_TAGS = ("environment", "env", "stage")
ENVIRONMENT_VALUES = {
    "prod": Environment.PROD,
    "production": Environment.PROD,
    "dev": Environment.DEV,
    "development": Environment.DEV,
    "test": Environment.TEST,
    "testing": Environment.TEST,
    "qa": Environment.TEST,
}

CRITICALITY_TAGS = ("criticality", "assetcriticality", "asset_criticality", "businesscriticality")
CRITICALITY_VALUES = {
    "high": CriticalityLevel.HIGH,
    "critical": CriticalityLevel.HIGH,
    "medium": CriticalityLevel.MEDIUM,
    "moderate": CriticalityLevel.MEDIUM,
    "low": CriticalityLevel.LOW,
}

SENSITIVE_DATA_TAGS = ("sensitivedata", "sensitive_data", "containspii", "pii")
CLASSIFICATION_TAGS = ("dataclassification", "classification", "data_classification")
SENSITIVE_CLASSIFICATIONS = {"confidential", "restricted", "sensitive", "secret", "pii"}
NON_SENSITIVE_CLASSIFICATIONS = {"public", "internal"}
TRUE_VALUES = {"true", "yes", "1"}
FALSE_VALUES = {"false", "no", "0"}


def _tag_map(raw_properties) -> dict[str, str]:
    """{lower-case key: lower-case value} for the string tags of a resource."""
    tags = (raw_properties or {}).get("Tags")
    if not isinstance(tags, list):
        return {}
    result = {}
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        key, value = tag.get("Key"), tag.get("Value")
        # A tag whose value is an intrinsic (Ref, Sub) is not known statically.
        if isinstance(key, str) and isinstance(value, str):
            result[key.strip().lower()] = value.strip().lower()
    return result


def _first(tags: dict[str, str], keys) -> str | None:
    return next((tags[key] for key in keys if key in tags), None)


def metadata_from_tags(raw_properties) -> ResourceMetadata:
    """The ResourceMetadata the resource's tags state; unknown fields stay None."""
    tags = _tag_map(raw_properties)

    environment = ENVIRONMENT_VALUES.get(_first(tags, ENVIRONMENT_TAGS))
    criticality = CRITICALITY_VALUES.get(_first(tags, CRITICALITY_TAGS))

    sensitive = None
    flag = _first(tags, SENSITIVE_DATA_TAGS)
    classification = _first(tags, CLASSIFICATION_TAGS)
    if flag in TRUE_VALUES or classification in SENSITIVE_CLASSIFICATIONS:
        sensitive = True
    elif flag in FALSE_VALUES or classification in NON_SENSITIVE_CLASSIFICATIONS:
        sensitive = False

    return ResourceMetadata(
        sensitive_data=sensitive,
        environment=environment,
        asset_criticality=criticality,
    )


def infra_metadata(infra) -> dict[str, ResourceMetadata]:
    """Tag-derived metadata for every resource of an InfraModel."""
    return {
        resource.id: metadata_from_tags(resource.raw_properties)
        for resource in infra.all_resources()
    }


def node_details(path: dict) -> list[dict]:
    """One {resource, facts} per hop: the facts held on arriving there."""
    steps = path.get("steps") or []
    hops = path.get("hops") or []
    if not steps or len(hops) != len(steps) + 1:
        raise ValueError(f"Path {path.get('entry_id')} -> {path.get('target_id')} has no usable steps")

    details = [{"resource": hops[0], "facts": list(steps[0].get("precondition") or [])}]
    for hop, step in zip(hops[1:], steps):
        details.append({"resource": hop, "facts": list(step.get("postcondition") or [])})
    return details


def scoring_input(path_id: str, path: dict, metadata, downstream_counts, graph_median,
                  entry_resources) -> tuple[PathScoringInput, ResourceMetadata]:
    """The PathScoringInput for one pipeline path, and its target's metadata."""
    details = node_details(path)
    target = path["target_id"]
    target_metadata = metadata.get(target, ResourceMetadata())

    reachability = classify_path_reachability(
        SimpleNamespace(path_id=path_id, node_details=details),
        entry_resources,
    )

    return PathScoringInput(
        path_id=path_id,
        asset_criticality=target_metadata.asset_criticality,
        sensitive_data=target_metadata.sensitive_data,
        environment=target_metadata.environment,
        reachable_downstream_count=downstream_counts.get(target, 0),
        graph_median_reachable=graph_median,
        reachability_class=reachability,
        path_length=path["length"],
        evidence_completeness=None,
    ), target_metadata


def score_pipeline_paths(state_graph, paths: list[dict], infra, path_ids: list[str]) -> list[dict]:
    """A contextual risk assessment for every path, in the order given.

    Each item: path_id, score, impact, exposure, path_ease (0-100), rank (dense,
    1 = highest), reachability, target, downstream_count, graph_median and the
    target's tag-derived metadata (None where no tag says).
    """
    if len(paths) != len(path_ids):
        raise ValueError("paths and path_ids must have the same length")

    graph = state_graph.to_dict()
    resources = [node["id"] for node in graph["nodes"]]
    downstream_counts = compute_downstream_counts(graph["traversal_edges"], resources)
    graph_median = compute_graph_median_reachable(downstream_counts)
    entry_resources = {node["id"] for node in graph["nodes"] if node.get("is_entry")}
    metadata = infra_metadata(infra)

    scored = []
    for path_id, path in zip(path_ids, paths):
        item, target_metadata = scoring_input(
            path_id, path, metadata, downstream_counts, graph_median, entry_resources
        )
        scored.append((item, target_metadata, score_path(item)))

    ranks = {ranked.risk.path_id: ranked.rank for ranked in dense_rank(risk for _, _, risk in scored)}

    return [
        {
            "path_id": risk.path_id,
            "score": round(risk.score, 2),
            "impact": round(risk.impact, 2),
            "exposure": round(risk.exposure, 2),
            "path_ease": round(risk.path_ease, 2),
            "rank": ranks[risk.path_id],
            "reachability": item.reachability_class.value,
            "target": path["target_id"],
            "downstream_count": item.reachable_downstream_count,
            "graph_median": item.graph_median_reachable,
            "asset_criticality": _value(target_metadata.asset_criticality),
            "sensitive_data": target_metadata.sensitive_data,
            "environment": _value(target_metadata.environment),
        }
        for (item, target_metadata, risk), path in zip(scored, paths)
    ]


def _value(member):
    return None if member is None else member.value
