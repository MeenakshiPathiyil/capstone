"""runner.graph_runner.analyze: the pipeline in memory, agreeing with the CLI."""

import builtins
import json
from pathlib import Path

import pytest

from main import build_infra_model
from runner import graph_runner
from runner.graph_runner import analyze
from security_state_graph.attack_graph import ATTACK_GRAPH_FILES
from security_state_graph.state_graph import (
    GRAPH_FILES,
    INFRA_PATH,
    RULES_PATH,
    build_state_graph,
    evaluate_findings,
    evaluate_findings_with_errors
)


# A rule whose comparison the evaluator does not know. It raises on every
# instance that has the field, which is what a typo in a real rule does.
BROKEN_RULE = """
- id: BROKEN_RULE
  origin: capstone
  source_id: BROKEN_RULE
  service: ec2
  resource_type: AWS::EC2::Instance
  semantic: exposure
  state:
    id: broken_state
    display_name: Broken
  summary: A rule that cannot be evaluated.
  conditions:
    operator: AND
    operands:
      - field: AssociatePublicIpAddress
        comparison: frobnicates
        value: true
"""


def redirected(tmp_path):
    """Every artifact run_pipeline writes, under tmp_path."""

    return {
        "output_path": tmp_path / "attack_paths.json",
        "graph_files": {
            name: tmp_path / path.name
            for name, path in GRAPH_FILES.items()
        },
        "attack_graph_files": {
            name: tmp_path / path.name
            for name, path in ATTACK_GRAPH_FILES.items()
        },
        "mermaid_path": tmp_path / "security_state_graph.mmd",
        "dot_path": tmp_path / "security_state_graph.dot",
        "steps_path": tmp_path / "attack_path_steps.json"
    }


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def roundtrip(value):
    """`value` as it reads back from a written JSON file."""

    return json.loads(json.dumps(value))


@pytest.fixture
def broken_rules(tmp_path):
    """The shipped ruleset plus BROKEN_RULE."""

    path = tmp_path / "rules_with_a_broken_one.yaml"

    path.write_text(
        Path(RULES_PATH).read_text(encoding="utf-8") + BROKEN_RULE,
        encoding="utf-8"
    )

    return path


# -----------------------------

def test_analyze_agrees_with_every_artifact_the_cli_writes(tmp_path):

    keywords = redirected(tmp_path)

    graph_runner.run_pipeline(**keywords)

    result = analyze(build_infra_model(INFRA_PATH))

    assert read(keywords["output_path"]) == roundtrip(result.records)
    assert read(keywords["steps_path"]) == roundtrip(result.steps)

    state_dict = roundtrip(result.state_graph.to_dict())

    for name, path in keywords["graph_files"].items():
        assert read(path) == state_dict[name], name

    attack_dict = roundtrip(result.attack_graph.to_dict())

    for name, path in keywords["attack_graph_files"].items():
        assert read(path) == attack_dict[name], name


def test_analyze_counts_on_the_shipped_account():

    result = analyze(build_infra_model(INFRA_PATH))

    summary = result.state_graph.to_dict()["summary"]

    assert summary["resources"] == 15
    assert summary["edges"] == 16
    assert summary["findings"] == 22
    assert len(result.paths) == 22
    assert len(result.selected) == 19
    assert len(result.records) == 19
    assert result.evaluation_errors == []

    # selected is the ranked prefix, so AP ids agree between records and steps
    assert result.selected == result.paths[:len(result.selected)]
    assert [record["source_id"] for record in result.records] == [
        step["source_id"] for step in result.steps[:len(result.records)]
    ]


def test_analyze_writes_no_file(monkeypatch):
    """The app calls analyze per request, so it must not touch output/."""

    infra = build_infra_model(INFRA_PATH)

    real_open = builtins.open

    def read_only_open(file, mode="r", *args, **kwargs):

        if any(flag in mode for flag in "wax+"):
            raise AssertionError("analyze opened %s for writing" % file)

        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", read_only_open)

    result = analyze(infra)

    assert result.paths


def test_analyze_honours_industry_and_min_level():

    infra = build_infra_model(INFRA_PATH)

    result = analyze(infra, industry="Education (ISIC P)", min_level="MEDIUM")

    assert len(result.selected) == len(result.paths)
    assert {record["industry"] for record in result.records} == {
        "Education (ISIC P)"
    }


# -----------------------------

def test_a_failing_rule_is_reported_as_data_and_still_printed(
    broken_rules, capsys
):

    infra = build_infra_model(INFRA_PATH)

    findings, errors = evaluate_findings_with_errors(infra, broken_rules)

    assert errors
    assert {error["rule_id"] for error in errors} == {"BROKEN_RULE"}
    assert all(error["resource"] and error["error"] for error in errors)
    assert "Unsupported comparison operator" in errors[0]["error"]

    # the existing print is kept for the command line
    assert "Warning: failed to evaluate BROKEN_RULE" in capsys.readouterr().out

    # the broken rule costs nothing else: same findings as the clean ruleset,
    # privilege escalation included
    assert findings == evaluate_findings(infra, RULES_PATH)
    assert any(f["rule_id"].startswith("PRIVESC_") for f in findings)


def test_errors_and_privesc_findings_are_identical_in_both_callers(broken_rules):
    """analyze and the CLI's build_state_graph see the same findings."""

    infra = build_infra_model(INFRA_PATH)

    result = analyze(infra, rules_path=broken_rules)

    _, errors = evaluate_findings_with_errors(infra, broken_rules)

    assert result.evaluation_errors == errors
    assert result.evaluation_errors

    cli_graph = build_state_graph(rules_path=broken_rules, infra=infra)

    assert result.state_graph.to_dict() == cli_graph.to_dict()

    privesc = [
        finding
        for finding in result.findings
        if finding["rule_id"].startswith("PRIVESC_")
    ]

    assert {finding["rule_id"] for finding in privesc} == {
        "PRIVESC_ATTACH_ROLE_POLICY",
        "PRIVESC_PASSROLE_LAMBDA_INVOKE"
    }


def test_evaluate_findings_is_the_findings_half():

    infra = build_infra_model(INFRA_PATH)

    findings, errors = evaluate_findings_with_errors(infra)

    assert evaluate_findings(infra) == findings
    assert errors == []
