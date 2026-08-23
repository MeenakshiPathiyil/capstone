import json

from utils.loader import load_json
from models.cloud_resource import CloudResource
from models.infra_model import InfraModel
from engine.connection_builder import build_connections


def main():
    data = load_json("normalized_resources.json")

    if isinstance(data, dict):
        data = [data]

    infra = InfraModel()

    # Step 1: Create resources
    for r in data:
        resource = CloudResource(
            id=r["id"],
            type=r["type"],
            raw_properties=r["raw_properties"],
            semantic_properties=r["semantic_properties"]
        )
        infra.add_resource(resource)

    # Step 2: Build connections
    build_connections(infra)

    # Step 3: Print (optional)
    for r in infra.all_resources():
        targets = [c["target"] for c in r.connections]
        print(f"{r.id} -> {targets}")

    # Step 4: Save to file
    # output_path = r"infra_output.json"
    # with open(output_path, "a") as f:
    #     json.dump(infra.to_dict(), f, indent=2)

    # print(f"Infra model saved to {output_path}")
    output_path = r"infra_output.json"

    try:
        with open(output_path, "r") as f:
            existing = json.load(f)
    except:
        existing = []

    existing.append(infra.to_dict())

    with open(output_path, "w") as f:
        json.dump(existing, f, indent=2)


if __name__ == "__main__":
    main()