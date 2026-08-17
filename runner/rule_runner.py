import json
from pathlib import Path

from engine.rule_engine import RuleEngine
from processing.attribute_extractor import process_resources


BASE_DIR = Path(__file__).resolve().parent.parent

RULES_PATH = BASE_DIR / "data" / "security_rules.yaml"
INFRA_PATH = BASE_DIR / "data" / "normalized_resources.json"
OUTPUT_PATH = BASE_DIR / "output" / "output_states.json"


def load_infra(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_output(path, data):

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2
        )


if __name__ == "__main__":

    # 1. Load security rules
    engine = RuleEngine(RULES_PATH)

    # 2. Load normalized infrastructure
    resources = load_infra(INFRA_PATH)

    # 3. Prepare attributes
    processed_resources = process_resources(resources)

    # 4. Evaluate rules
    results = engine.evaluate_all(
        processed_resources
    )

    # 5. Save security states
    save_output(
        OUTPUT_PATH,
        results
    )

    print(
        f"Done. "
        f"{len(results)} security findings generated."
    )