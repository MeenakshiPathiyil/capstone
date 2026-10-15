"""runner/rule_runner.py reports the same findings as the full pipeline."""

import json

from main import build_infra_model
from runner import rule_runner
from security_state_graph.state_graph import INFRA_PATH, RULES_PATH, evaluate_findings


def test_stage_two_alone_writes_the_pipelines_findings(tmp_path, monkeypatch):
    """It used to evaluate the rules on unprojected records, so every rule written
    against the abstract attributes matched nothing: 13 findings instead of 21."""

    out = tmp_path / "output_states.json"
    monkeypatch.setattr(rule_runner, "OUTPUT_PATH", out)

    rule_runner.main()

    expected = evaluate_findings(build_infra_model(INFRA_PATH), RULES_PATH)
    assert json.loads(out.read_text(encoding="utf-8")) == expected
    assert len(expected) == 21
