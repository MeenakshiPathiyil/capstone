"""One command from normalized resources to ranked attack paths."""

import json
from pathlib import Path

from attack_path.exporter import (
    DEFAULT_INDUSTRY,
    STEPS_PATH,
    build_export,
    technique_index,
    write_export,
    write_steps
)
from security_state_graph.attack_graph import (
    build_attack_graph,
    write_attack_graph
)
from attack_path.path_finder import find_attack_paths
from attack_path.scoring import (
    ATTACK_LEVEL_HIGH,
    select_high_risk
)
from main import INFRA_OUTPUT_PATH, build_infra_model, save_infra_model
from attack_path.renderer import DOT_PATH, MERMAID_PATH, write_dot, write_mermaid
from security_state_graph.state_graph import (
    build_state_graph,
    write_state_graph
)


BASE_DIR = Path(__file__).resolve().parent.parent

INFRA_PATH = BASE_DIR / "data" / "normalized_resources.json"
RULES_PATH = BASE_DIR / "data" / "security_rules.yaml"
OUTPUT_PATH = BASE_DIR / "output" / "attack_paths.json"

# GRAPH_JSON_PATH, MERMAID_PATH and DOT_PATH are not restated here the way


def count_findings(state_graph):
    """How many findings landed on a node, across the whole graph."""

    return sum(
        len(node["states"])
        for node in state_graph.nodes.values()
    )


def existing_export_records(output_path):
    """How many records the file at `output_path` already holds."""

    output_path = Path(output_path)

    if not output_path.exists():
        return 0

    try:
        with open(output_path, "r", encoding="utf-8") as f:
            existing = json.load(f)

    except (ValueError, OSError):
        return 0

    if not isinstance(existing, list):
        return 0

    return len(existing)


def summarize(state_graph, paths, records, output_path, wrote, artifacts=(),
              attack_graph=None):
    """Print what each stage produced, and where every artifact went."""

    print(
        f"Done. "
        f"{len(state_graph.nodes)} resources, "
        f"{len(state_graph.edges)} edges, "
        f"{count_findings(state_graph)} security findings, "
        f"{len(paths)} attack paths."
    )

    # -----------------------------

    if attack_graph is not None:

        summary = attack_graph.to_dict()["summary"]

        print(
            f"Attack graph: "
            f"{summary['attacker_states']} attacker states, "
            f"{summary['actions']} actions, "
            f"{summary['distinct_techniques']} distinct ATT&CK techniques."
        )

        # THE GAP LINE. Every one of these is a hop data/attack_transitions.yaml
        # does not name yet, so it carries no technique and no tactic and the
        # generated scenario has nothing specific to say about it. Printed every
        # run because a silently growing number here is the layer decaying.
        if summary["edges_from_the_fallback_table"]:
            print(
                f"Warning: "
                f"{summary['edges_from_the_fallback_table']} actions fell back "
                f"to the edge-category table — no transition rule matched. "
                f"They carry no ATT&CK technique."
            )

        if summary["truncated"]:
            print(
                "Warning: the attack graph hit MAX_STATES and is truncated. "
                "Paths through the states beyond it are missing."
            )

    # -----------------------------

    if not paths:
        print(
            "No attack paths were found. Either this account has none, or a "
            "stage collapsed — check the resource, edge and finding counts "
            "above before believing the first."
        )

    # Stale findings are not an error, but they are the difference between "the
    if state_graph.orphan_findings:
        print(
            f"Warning: "
            f"{len(state_graph.orphan_findings)} findings named resources "
            f"outside the model and were not used."
        )

    for record in records:
        print(
            f"  {record['source_id']}  "
            f"{record['attack_level']:<8}  "
            f"{record['source_name']}"
        )

    if wrote:
        print(f"Ranked attack paths saved to {output_path}")

    else:
        print(
            f"Refused to overwrite the existing export at {output_path} with an "
            f"empty one. Nothing was written; the previous run's paths are still "
            f"there."
        )

    # -----------------------------

    # Printed after the export because the export is the deliverable the other
    # repository reads; these three are for the examiner reading this one.
    for description, path in artifacts:
        print(f"{description} saved to {path}")


def run_pipeline(
    infra_path=INFRA_PATH,
    rules_path=RULES_PATH,
    output_path=OUTPUT_PATH,
    industry=DEFAULT_INDUSTRY,
    graph_files=None,
    attack_graph_files=None,
    mermaid_path=MERMAID_PATH,
    dot_path=DOT_PATH,
    steps_path=STEPS_PATH,
    min_level=ATTACK_LEVEL_HIGH
):
    """Run every stage and write all four artifacts. Returns"""

    # 1. Build the joined graph. The infra model is built on the way, and saved,
    #    so the connection graph is an artifact of the pipeline rather than
    #    something only `python3 main.py` ever produces.
    infra = build_infra_model(infra_path)
    save_infra_model(INFRA_OUTPUT_PATH, infra)
    infra_written = INFRA_OUTPUT_PATH

    state_graph = build_state_graph(
        infra_path,
        rules_path,
        infra=infra
    )

    # 2. Write the graph itself — one file per block
    graph_written = write_state_graph(state_graph, graph_files)

    # 3. The attack graph layer: apply data/attack_transitions.yaml to the state
    #    graph. Its nodes are attacker states, not resources, so a resource
    #    reached holding different facts is a different node with different
    #    actions available. Written as its own artifact because it is a stage of
    #    the architecture and not an implementation detail of path finding.
    attack_graph = build_attack_graph(state_graph)
    attack_graph_written = write_attack_graph(attack_graph, attack_graph_files)

    # 4. Rank the attack paths. Same ruleset, so the conditions the search
    #    enforces are the conditions the attack graph states.
    paths = find_attack_paths(state_graph)

    # 5. Draw the graph, twice
    mermaid_written = write_mermaid(state_graph, paths, mermaid_path)
    dot_written = write_dot(state_graph, paths, dot_path)

    # 6. Select the high-risk paths, then translate into the export vocabulary.
    #    The export is what the scenario generator reads, so the filter belongs
    #    here. attack_path_steps.json below keeps every path, because that is the
    #    record of what the search actually found.
    selected = select_high_risk(paths, min_level)

    records = build_export(
        state_graph,
        selected,
        technique_index(rules_path),
        industry
    )

    # 7. Write the cross-repository contract
    wrote = bool(records) or existing_export_records(output_path) == 0

    if wrote:
        write_export(records, output_path)

    # 7b. And the per-hop conditions, which the seven-key contract has no room
    #     for. Written unconditionally: unlike the export, nothing downstream
    #     depends on it, so an empty file is a true statement rather than a
    #     regression that overwrote a good one.
    steps_written = write_steps(paths, steps_path)

    # 8. Report every stage, and every file, on one screen
    summarize(
        state_graph,
        paths,
        records,
        output_path,
        wrote,
        [("Infrastructure model", infra_written)]
        + [("Attack path steps", steps_written)]
        + [
            ("Attack graph (%s)" % name, path)
            for name, path in sorted(attack_graph_written.items())
        ]
        + [
            ("Security state graph (%s)" % name, path)
            for name, path in sorted(graph_written.items())
        ]
        + [
            ("Mermaid render", mermaid_written),
            ("Graphviz DOT render", dot_written)
        ],
        attack_graph
    )

    return state_graph, paths, records


if __name__ == "__main__":

    # A run that found nothing exits non-zero. The command line is where this
    _, produced, _ = run_pipeline()

    if not produced:
        raise SystemExit(1)
