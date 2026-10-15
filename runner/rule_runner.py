"""Stage 2 alone: every security finding, written to output/output_states.json.

Uses the same evaluate_findings as the full pipeline, so the count matches its
"security findings": the declarative rules over the projected attributes, plus
privilege escalation. Severity is left as each rule declares it; the canonical
rules declare none, and the path search derives one from `semantic`.
"""

from pathlib import Path

from main import build_infra_model
from security_state_graph.state_graph import INFRA_PATH, RULES_PATH, evaluate_findings
from utils.helpers import write_json


BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_PATH = BASE_DIR / "output" / "output_states.json"


def main():

    findings = evaluate_findings(build_infra_model(INFRA_PATH), RULES_PATH)

    write_json(findings, OUTPUT_PATH)

    print(f"Done. {len(findings)} security findings written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
