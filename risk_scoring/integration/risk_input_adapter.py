"""Adapt enriched attack paths and graph context to PathScoringInput."""
from __future__ import annotations

import json
from pathlib import Path

from graph_analysis.blast_radius import (
    compute_downstream_counts,
    compute_graph_median_reachable,
)
from graph_analysis.reachability import classify_path_reachability
from graph_model.resource_metadata import (
    CriticalityLevel,
    Environment,
    ResourceMetadata,
)
from models.path_scoring_input import PathScoringInput


def _parse_enum(enum_type, value, field_name):
    if value is None:
        return None
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string or null")
    normalized = value.strip().lower()
    for member in enum_type:
        if member.value.lower() == normalized or member.name.lower() == normalized:
            return member
    allowed = ", ".join(member.value for member in enum_type)
    raise ValueError(f"Invalid {field_name}={value!r}; expected one of: {allowed}")


def _parse_optional_bool(value, field_name):
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
    raise ValueError(f"{field_name} must be true, false, or null")


def load_resource_metadata(path: str | Path | None) -> dict[str, ResourceMetadata]:
    """Load optional normalized metadata from a JSON resource-to-fields map.

    Expected shape:
      {"LogicalResourceId": {"asset_criticality": "high",
                              "sensitive_data": true,
                              "environment": "prod"}}

    Missing file means no metadata was supplied; missing fields remain None.
    """
    if path is None or not Path(path).exists():
        return {}
    with Path(path).open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("Resource metadata JSON must be an object keyed by resource ID")

    result: dict[str, ResourceMetadata] = {}
    for resource_id, values in raw.items():
        if not isinstance(resource_id, str) or not resource_id.strip():
            raise ValueError("Resource metadata keys must be non-empty resource IDs")
        if not isinstance(values, dict):
            raise ValueError(f"Metadata for {resource_id} must be a JSON object")
        result[resource_id] = ResourceMetadata(
            asset_criticality=_parse_enum(
                CriticalityLevel, values.get("asset_criticality"), "asset_criticality"
            ),
            sensitive_data=_parse_optional_bool(
                values.get("sensitive_data"), "sensitive_data"
            ),
            environment=_parse_enum(
                Environment, values.get("environment"), "environment"
            ),
        )
    return result


def _resource_ids(nodes: list[dict], edges: list[dict]) -> set[str]:
    resources = {
        node.get("resource")
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("resource"), str)
        and node.get("resource")
    }
    for edge in edges:
        if isinstance(edge, dict):
            for field in ("source", "target"):
                value = edge.get(field)
                if isinstance(value, str) and value:
                    resources.add(value)
    return resources


def build_scoring_context(nodes: list[dict], edges: list[dict]):
    resources = _resource_ids(nodes, edges)
    downstream_counts = compute_downstream_counts(edges, resources)
    graph_median = compute_graph_median_reachable(downstream_counts)
    entry_resources = {
        node.get("resource")
        for node in nodes
        if isinstance(node, dict) and node.get("is_entry") and node.get("resource")
    }
    return downstream_counts, graph_median, entry_resources


def build_path_scoring_input(path, metadata, downstream_counts, graph_median, entry_resources):
    if not getattr(path, "edge_ids", None):
        raise ValueError(f"Path {path.path_id} contains no transitions")
    if path.path_length != len(path.edge_ids):
        raise ValueError(
            f"Path length mismatch for {path.path_id}: path_length={path.path_length}, "
            f"edge_count={len(path.edge_ids)}"
        )

    target_resource = next(
        (node.get("resource") for node in reversed(path.node_details) if node.get("resource")),
        None,
    )
    if not target_resource:
        raise ValueError(f"Could not resolve target resource for path {path.path_id}")

    target_metadata = metadata.get(target_resource, ResourceMetadata())
    if target_resource not in metadata:
        # Unknown metadata is supported by the scoring model. It is kept as
        # None rather than incorrectly treated as explicit LOW/False/DEV.
        pass

    downstream_count = downstream_counts.get(target_resource)
    if downstream_count is None:
        raise ValueError(f"No downstream-count metric for target resource {target_resource}")

    return PathScoringInput(
        path_id=path.path_id,
        asset_criticality=target_metadata.asset_criticality,
        sensitive_data=target_metadata.sensitive_data,
        environment=target_metadata.environment,
        reachable_downstream_count=downstream_count,
        graph_median_reachable=graph_median,
        reachability_class=classify_path_reachability(path, entry_resources),
        path_length=path.path_length,
        # Completeness is intentionally None until the project defines a
        # documented metric; the path evidence is still preserved separately.
        evidence_completeness=None,
    )
