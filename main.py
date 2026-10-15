"""Build the infrastructure model from normalized resources."""

import json
from pathlib import Path

from utils.loader import load_json
from models.cloud_resource import CloudResource
from models.infra_model import InfraModel
from processing.attributes import project_all
from engine.connection_builder import (
    build_capability_edges,
    build_connections,
    build_escalation_edges
)


# main.py sits at the repo root, so BASE_DIR is one .parent up, not two
BASE_DIR = Path(__file__).resolve().parent

INFRA_PATH = BASE_DIR / "data" / "normalized_resources.json"

# Named for what it holds, not for being this module's output. runner/graph_runner
# has its own OUTPUT_PATH (the attack-path export), and two modules calling
# different files OUTPUT_PATH is one import away from a confusing bug.
INFRA_OUTPUT_PATH = BASE_DIR / "data" / "infra_output.json"


def build_infra_from_resources(resource_dicts):
    """Build a connected InfraModel from already-loaded resource dictionaries."""

    infra = InfraModel()

    # The abstract vocabulary the ruleset is written against. Projected here and
    # not left to the caller, because the parser emits raw properties only and
    # every canonical rule resolves nothing without it.
    resource_dicts = project_all(resource_dicts)

    # Step 1: Create resources
    for r in resource_dicts:
        resource = CloudResource(
            id=r["id"],
            type=r["type"],
            raw_properties=r["raw_properties"],
            semantic_properties=r["semantic_properties"],
            attributes=r.get("attributes")
        )
        infra.add_resource(resource)

    # Step 2: Build connections
    build_connections(infra)
    build_capability_edges(infra)

    # Step 3: Privilege escalation edges, from data/privesc_methods.yaml
    build_escalation_edges(infra)

    return infra


def build_infra_model(path=INFRA_PATH):
    """Load normalized resources from `path` and return a connected InfraModel."""

    data = load_json(path)

    if isinstance(data, dict):
        data = [data]

    return build_infra_from_resources(data)


def save_infra_model(path, infra):
    """Write the model to `path`, overwriting whatever the previous run left there."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            infra.to_dict(),
            f,
            indent=2
        )


def main():

    infra = build_infra_model(INFRA_PATH)

    # Step 3: Print (optional)
    for r in infra.all_resources():
        targets = [c["target"] for c in r.connections]
        print(f"{r.id} -> {targets}")

    # Step 4: Save to file
    save_infra_model(INFRA_OUTPUT_PATH, infra)

    print(f"Infra model saved to {INFRA_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
