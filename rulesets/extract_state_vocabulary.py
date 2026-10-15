import csv
import json
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent

INPUT_YAML = HERE / "canonical_rules.yaml"
OUTPUT_CSV = HERE / "state_vocabulary.csv"
OUTPUT_JSON = HERE / "state_vocabulary.json"


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, list):
        raise ValueError(
            "Expected top-level YAML structure to be a list of rules."
        )

    return data


def extract_state_vocabulary(rules):
    rows = []
    warnings = []

    for idx, rule in enumerate(rules, start=1):

        if not isinstance(rule, dict):
            warnings.append(
                f"Rule #{idx}: expected dict, found {type(rule).__name__}"
            )
            continue

        rule_id = rule.get("id", f"<missing_id_{idx}>")
        resource_type = rule.get("resource_type", "")

        state = rule.get("state")

        if state is None:
            warnings.append(
                f"{rule_id}: missing state block"
            )
            continue

        if not isinstance(state, dict):
            warnings.append(
                f"{rule_id}: state must be a mapping"
            )
            continue

        state_id = state.get("id")

        if not state_id:
            warnings.append(
                f"{rule_id}: missing state.id"
            )
            continue

        rows.append({
            "state_id": state_id,
            "display_name": state.get("display_name", ""),
            "resource_type": resource_type,
            "source_rule_id": rule_id
        })

    return rows, warnings


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "state_id",
                "display_name",
                "resource_type",
                "source_rule_id"
            ],
            lineterminator="\n"
        )

        writer.writeheader()
        writer.writerows(rows)


def write_json(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)


def generate_statistics(rows):
    unique_states = {}

    for row in rows:
        state_id = row["state_id"]

        if state_id not in unique_states:
            unique_states[state_id] = {
                "display_name": row["display_name"],
                "resource_types": set(),
                "source_rules": set()
            }

        unique_states[state_id]["resource_types"].add(
            row["resource_type"]
        )

        unique_states[state_id]["source_rules"].add(
            row["source_rule_id"]
        )

    return unique_states


def print_summary(rows, warnings, unique_states):
    print("\n========== TASK 1 SUMMARY ==========\n")

    print(f"State occurrences : {len(rows)}")
    print(f"Unique state IDs  : {len(unique_states)}")

    print("\nUnique States:\n")

    for state_id in sorted(unique_states):
        info = unique_states[state_id]

        print(
            f"{state_id}"
            f" | resources={len(info['resource_types'])}"
            f" | rules={len(info['source_rules'])}"
        )

    if warnings:
        print("\nWarnings:\n")

        for warning in warnings:
            print(f" - {warning}")

    print("\nCSV  ->", OUTPUT_CSV)
    print("JSON ->", OUTPUT_JSON)
    print("\n====================================")


def main():
    if not Path(INPUT_YAML).exists():
        raise FileNotFoundError(
            f"Cannot find {INPUT_YAML}"
        )

    rules = load_yaml(INPUT_YAML)

    rows, warnings = extract_state_vocabulary(rules)

    rows.sort(
        key=lambda r: (
            r["state_id"],
            r["resource_type"],
            r["source_rule_id"]
        )
    )

    write_csv(rows, OUTPUT_CSV)
    write_json(rows, OUTPUT_JSON)

    unique_states = generate_statistics(rows)

    print_summary(
        rows,
        warnings,
        unique_states
    )


if __name__ == "__main__":
    main()
