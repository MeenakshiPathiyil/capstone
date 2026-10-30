"""POST /api/analyses and /api/analyses/sample: real analyses, and every refusal."""

import json
import re
import time
import uuid
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.api import analysis, schemas, worker
from app.api.analysis import jsonable, project_step, validated
from app.api.config import REPO_ROOT
from app.api.main import create_app
from app.api.tests import stalled_job
from app.api.tests.conftest import INDUSTRY, SAMPLE_PATH, make_settings, upload


GOLDEN_RECORDS = REPO_ROOT / "tests" / "golden_attack_paths.json"
GOLDEN_STEPS = REPO_ROOT / "tests" / "golden_attack_path_steps.json"


def resources_yaml(count):
    """A template of `count` buckets."""

    return "Resources:\n" + "".join(
        "  Bucket%d:\n    Type: AWS::S3::Bucket\n" % index
        for index in range(count)
    )


# -- The sample, uploaded ---------------------------------------------------------

def test_the_sample_upload_has_the_verified_counts(sample_analysis):

    summary = sample_analysis["summary"]

    assert summary["resources"] == 15
    assert summary["edges"] == 16
    assert summary["findings"] == 22
    assert summary["paths"] == 22
    assert summary["paths_exported"] == 19

    assert len(sample_analysis["resources"]) == 15
    assert len(sample_analysis["findings"]) == 22
    assert len(sample_analysis["paths"]) == 22
    assert sum(path["exported"] for path in sample_analysis["paths"]) == 19

    assert sum(summary["findings_by_severity"].values()) == 22
    assert sum(summary["paths_by_level"].values()) == 22
    assert summary["top_score"] == sample_analysis["paths"][0]["score"]

    assert sample_analysis["warnings"] == []
    assert sample_analysis["nested_report"] is None
    assert sample_analysis["input_name"] == "cloudformation5.yml"
    assert sample_analysis["schema_version"] == 1


def test_the_upload_agrees_with_the_cli_golden_artifacts(sample_analysis):
    """Uploaded bytes, parsed in the worker, give what the CLI wrote."""

    records = json.loads(GOLDEN_RECORDS.read_text(encoding="utf-8"))
    steps = json.loads(GOLDEN_STEPS.read_text(encoding="utf-8"))

    exported = [path for path in sample_analysis["paths"] if path["exported"]]

    assert [path["export"] for path in exported] == records

    assert len(steps) == len(sample_analysis["paths"])

    for path, golden in zip(sample_analysis["paths"], steps):

        assert path["source_id"] == golden["source_id"]
        assert path["entry_id"] == golden["entry_id"]
        assert path["target_id"] == golden["target_id"]
        assert path["objective"] == golden["objective"]
        assert path["score"] == golden["risk_score"]
        assert path["attack_level"] == golden["attack_level"]
        assert path["steps"] == [
            validated(schemas.Step, project_step(step)) for step in golden["steps"]
        ]


def test_paths_are_ranked_and_carry_their_breakdown(sample_analysis):

    paths = sample_analysis["paths"]

    assert [path["rank"] for path in paths] == list(range(1, 23))
    assert paths[0]["source_id"] == "AP-001"

    for path in paths:
        assert path["breakdown"]["score"] == path["score"]
        assert (path["export"] is not None) == path["exported"]

    # identical hop chains share a group; the sample has seven chains that more
    # than one objective's path runs along
    groups = {}

    for path in paths:
        groups.setdefault(path["chain_group"], set()).add(tuple(path["hops"]))

    assert all(len(chains) == 1 for chains in groups.values())

    shared = [
        path
        for path in paths
        if sum(other["chain_group"] == path["chain_group"] for other in paths) > 1
    ]

    assert len({path["chain_group"] for path in shared}) == 7
    assert len(groups) == 13


def test_paths_carry_the_contextual_risk_of_analyze(sample_analysis):

    records, _ = analysis.records_from_text(SAMPLE_PATH.read_text(), 500)

    result = analysis.run_pipeline_on(records, INDUSTRY, "HIGH")

    paths = sample_analysis["paths"]

    assert len(result.risk) == len(paths)

    for path, risk in zip(paths, result.risk):

        # path_id and target repeat the path's own ids, so they are not sent
        assert (risk["path_id"], risk["target"]) == (path["source_id"], path["target_id"])

        assert path["risk"] == {
            key: value for key, value in risk.items() if key not in ("path_id", "target")
        }

    by_id = {path["source_id"]: path["risk"] for path in paths}

    assert by_id["AP-019"] == {
        "score": 77.03,
        "impact": 60.77,
        "exposure": 90.0,
        "path_ease": 100.0,
        "rank": 1,
        "reachability": "direct",
        "downstream_count": 7,
        "graph_median": 5.0,
        "asset_criticality": None,
        "sensitive_data": None,
        "environment": None
    }

    assert by_id["AP-015"]["rank"] == 2
    assert by_id["AP-006"]["reachability"] == "post_compromise"

    # five paths tie for third
    assert [path["source_id"] for path in paths if path["risk"]["rank"] == 3] == [
        "AP-001", "AP-002", "AP-003", "AP-004", "AP-005"
    ]
    assert {path["risk"]["score"] for path in paths if path["risk"]["rank"] == 3} == {55.5}

    # a second opinion: the pipeline's own order is untouched
    assert [path["rank"] for path in paths] == list(range(1, 23))
    assert [path["score"] for path in paths] == sorted(
        (path["score"] for path in paths), reverse=True
    )


def test_findings_join_rules_resources_and_paths(sample_analysis):

    findings = {finding["id"]: finding for finding in sample_analysis["findings"]}
    resources = {resource["id"]: resource for resource in sample_analysis["resources"]}

    for finding in findings.values():

        assert finding["id"] == "%s::%s" % (finding["resource"], finding["rule_id"])
        assert finding["id"] in resources[finding["resource"]]["findings"]
        assert finding["rule"]["display_name"]

        for source_id in finding["on_paths"]:
            path = next(
                path for path in sample_analysis["paths"]
                if path["source_id"] == source_id
            )
            assert finding["id"] in path["finding_ids"]

    privesc = findings["DeploymentRole::PRIVESC_ATTACH_ROLE_POLICY"]

    assert privesc["severity"] == "critical"
    assert privesc["semantic"] == "privilege"
    assert privesc["rule"]["references"][0]["url"].startswith("https://")

    canonical = findings[
        "OpenSecurityGroup::aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup"
    ]

    assert canonical["source_id"] == "INCOMING_SSH_DISABLED"
    assert canonical["severity"] == "high"
    assert canonical["rule"]["attack_techniques"]


def test_steps_carry_evidence_without_target_and_source(sample_analysis):

    first = sample_analysis["paths"][0]["steps"][0]

    keys = [item["key"] for item in first["evidence"]]

    assert "target" not in keys and "source" not in keys
    assert {"key": "exposed_ports", "value": [22, 3389]} in first["evidence"]


PYTHON_REPR = re.compile(r"^[A-Z][A-Za-z]+\(.*\)$")


def leaves(value):
    """Every scalar inside nested dicts and lists."""

    if isinstance(value, dict):
        for item in value.values():
            yield from leaves(item)

    elif isinstance(value, list):
        for item in value:
            yield from leaves(item)

    else:
        yield value


def test_no_attribute_value_is_a_python_repr(sample_analysis):

    values = []

    for resource in sample_analysis["resources"]:
        values.extend(leaves(resource["attributes"]))
        values.extend(leaves(resource["raw_properties"]))

    for path in sample_analysis["paths"]:
        for step in path["steps"]:
            values.extend(leaves([item["value"] for item in step["evidence"]]))
            values.extend(leaves(step["output"]))

    assert values
    assert [v for v in values if isinstance(v, str) and PYTHON_REPR.match(v)] == []


def test_a_security_group_port_is_its_number(sample_analysis):

    group = next(r for r in sample_analysis["resources"] if r["id"] == "OpenSecurityGroup")

    assert [rule["port"] for rule in group["attributes"]["ingress"]] == [22, 3389]


def test_a_port_range_is_a_number_or_from_and_to():
    from processing.attributes import PortRange

    assert jsonable({"port": PortRange(22, 22)}) == {"port": 22}
    assert jsonable([PortRange(0, 65535)]) == [{"from": 0, "to": 65535}]


def test_every_step_technique_has_a_matrix_name(sample_analysis):

    steps = [step for path in sample_analysis["paths"] for step in path["steps"]]
    with_technique = [step for step in steps if step["technique"]]

    assert with_technique
    assert [s["technique"] for s in with_technique if not s["technique_name"]] == []
    assert next(
        s["technique_name"] for s in with_technique if s["technique"] == "T1550"
    ) == "Use Alternate Authentication Material"
    assert all(step["technique_name"] is None for step in steps if not step["technique"])


def test_created_analyses_have_a_location(client):

    response = upload(client, "sample.yml", SAMPLE_PATH.read_bytes())

    assert response.status_code == 201
    assert response.headers["location"] == "/api/analyses/%s" % response.json()["id"]


# -- Samples ----------------------------------------------------------------------

def test_the_single_sample_matches_the_upload(shared_client, sample_analysis):

    response = shared_client.post(
        "/api/analyses/sample",
        json={"sample_id": "cloudformation5", "industry": INDUSTRY}
    )

    assert response.status_code == 201

    analysis = response.json()

    assert analysis["id"] != sample_analysis["id"]
    assert analysis["summary"] == sample_analysis["summary"]
    assert analysis["input_sha256"] == sample_analysis["input_sha256"]


def test_the_nested_sample_merges_three_children(shared_client):

    response = shared_client.post(
        "/api/analyses/sample",
        json={"sample_id": "nested", "industry": INDUSTRY}
    )

    assert response.status_code == 201

    analysis = response.json()

    assert analysis["summary"]["resources"] == 8
    assert len(analysis["nested_report"]["merged"]) == 3
    assert analysis["nested_report"]["skipped"] == []

    # repo-relative, never an absolute local path
    for merged in analysis["nested_report"]["merged"]:
        assert merged["template"].startswith("tests/fixtures/nested/")


def test_an_unknown_sample_is_404(client):

    response = client.post(
        "/api/analyses/sample", json={"sample_id": "nope", "industry": INDUSTRY}
    )

    assert response.status_code == 404


def test_min_level_and_industry_are_applied(client):

    response = client.post(
        "/api/analyses/sample",
        json={"sample_id": "cloudformation5", "industry": "  Education (ISIC P) ",
              "min_level": "MEDIUM"}
    )

    analysis = response.json()

    assert analysis["industry"] == "Education (ISIC P)"
    assert analysis["min_level"] == "MEDIUM"
    assert analysis["summary"]["paths_exported"] == 22
    assert analysis["paths"][0]["export"]["industry"] == "Education (ISIC P)"


# -- Refusals ---------------------------------------------------------------------

def test_over_two_mib_is_413(client):

    response = upload(client, "big.yaml", b"#" * (2 * 1024 * 1024 + 1))

    assert response.status_code == 413
    assert set(response.json()) == {"detail"}


def test_a_body_past_the_limit_without_content_length_is_413(client):
    """Streamed with no Content-Length: refused as it arrives, not trusted."""

    boundary = "capstoneboundary"

    def body():
        yield (
            "--%s\r\nContent-Disposition: form-data; name=\"industry\"\r\n\r\nx\r\n"
            "--%s\r\nContent-Disposition: form-data; name=\"file\"; "
            "filename=\"big.yaml\"\r\n\r\n" % (boundary, boundary)
        ).encode()

        for _ in range(40):
            yield b"#" * (64 * 1024)

        yield ("\r\n--%s--\r\n" % boundary).encode()

    response = client.post(
        "/api/analyses",
        content=body(),
        headers={"content-type": "multipart/form-data; boundary=%s" % boundary}
    )

    assert response.status_code == 413


def test_a_file_just_past_the_limit_inside_the_overhead_is_413(client):
    """The middleware allows framing overhead; the file itself is checked exactly."""

    response = upload(client, "edge.yaml", b"#" * (2 * 1024 * 1024 + 10))

    assert response.status_code == 413


def test_a_wrong_extension_is_415(client):

    response = upload(client, "template.txt", SAMPLE_PATH.read_bytes())

    assert response.status_code == 415


def test_invalid_utf8_is_422(client):

    response = upload(client, "bad.yaml", b"Resources:\n  X: \xff\xfe\n")

    assert response.status_code == 422
    assert "UTF-8" in response.json()["detail"]


def test_a_byte_order_mark_is_accepted(client):

    response = upload(client, "bom.yaml", b"\xef\xbb\xbf" + SAMPLE_PATH.read_bytes())

    assert response.status_code == 201


def test_invalid_yaml_is_422_with_a_line(client):

    response = upload(client, "bad.yaml", b"Resources:\n  X: [unclosed\n")

    assert response.status_code == 422
    assert "line" in response.json()["detail"]


def test_a_recursive_alias_is_422(client):

    data = (
        b"Resources:\n"
        b"  Loop:\n"
        b"    Type: AWS::S3::Bucket\n"
        b"    Properties: &props\n"
        b"      Self: *props\n"
    )

    response = upload(client, "loop.yaml", data)

    assert response.status_code == 422
    assert "recursive aliases" in response.json()["detail"]


def test_excessive_nesting_is_422(client):

    data = (
        "Resources:\n  Deep:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      Tags: " + "[" * 5000 + "]" * 5000 + "\n"
    ).encode()

    response = upload(client, "deep.yaml", data)

    assert response.status_code == 422
    assert "nests too deeply" in response.json()["detail"]


def test_ordinary_repeated_aliases_are_fine(client):

    data = (
        b"Resources:\n"
        b"  A:\n    Type: AWS::S3::Bucket\n    Properties: &shared\n"
        b"      Tags: [{Key: team, Value: x}]\n"
        b"  B:\n    Type: AWS::S3::Bucket\n    Properties: *shared\n"
        b"  C:\n    Type: AWS::S3::Bucket\n    Properties: *shared\n"
    )

    response = upload(client, "aliases.yaml", data)

    assert response.status_code == 201
    assert response.json()["summary"]["resources"] == 3


def test_more_than_500_resources_is_422(client):

    response = upload(client, "many.yaml", resources_yaml(501).encode())

    assert response.status_code == 422
    assert "limit is 500" in response.json()["detail"]


def test_exactly_500_resources_is_accepted(client):

    response = upload(client, "many.yaml", resources_yaml(500).encode())

    assert response.status_code == 201
    assert response.json()["summary"]["resources"] == 500


def test_malformed_shapes_are_422(client):

    cases = {
        b"- just\n- a list\n": "top level must be a mapping",
        b"AWSTemplateFormatVersion: '2010-09-09'\n": "no Resources",
        b"Resources: [a, b]\n": "Resources must be a mapping",
        b"Resources:\n  X: 3\n": "X must be a mapping",
        b"Resources:\n  X:\n    Properties: {}\n": "nonempty Type",
        b"Resources:\n  X:\n    Type: ''\n": "nonempty Type",
        b"Resources:\n  X:\n    Type: AWS::S3::Bucket\n    Properties: [1]\n":
            "Properties of X must be a mapping",
        b"": "top level must be a mapping"
    }

    for data, message in cases.items():

        response = upload(client, "shape.yaml", data)

        assert response.status_code == 422, data
        assert message in response.json()["detail"], (data, response.json())


def test_empty_resources_is_an_honest_zero_result(client):

    response = upload(client, "empty.yaml", b"Resources: {}\n")

    assert response.status_code == 201

    analysis = response.json()

    assert analysis["summary"]["resources"] == 0
    assert analysis["summary"]["paths"] == 0
    assert analysis["summary"]["top_score"] is None
    assert analysis["paths"] == [] and analysis["findings"] == []

    graph = client.get("/api/analyses/%s/graph?view=attack" % analysis["id"]).json()

    assert [node["resource"] for node in graph["nodes"]] == [None]


def test_json_templates_are_accepted(client):

    data = json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}).encode()

    response = upload(client, "template.json", data)

    assert response.status_code == 201
    assert response.json()["summary"]["resources"] == 1


def test_an_uploaded_nested_stack_is_not_fetched_and_says_so(client):

    data = (
        b"Resources:\n  Child:\n    Type: AWS::CloudFormation::Stack\n"
        b"    Properties:\n      TemplateURL: https://example.com/child.yaml\n"
    )

    analysis = upload(client, "parent.yaml", data).json()

    assert [warning["kind"] for warning in analysis["warnings"]] == ["nested_skipped"]
    assert analysis["summary"]["resources"] == 1


TRANSFORMS = Path(__file__).parent / "fixtures" / "transforms"

UNEXPANDED = (
    "This template uses the transform %s. Transforms and macros are not "
    "expanded, so resources they generate are not analysed."
)


@pytest.mark.parametrize("name, transform", [
    ("sam_transform.yaml", "AWS::Serverless-2016-10-31"),
    ("language_extensions.yaml", "AWS::LanguageExtensions"),
    ("macro_in_properties.yaml", "MyMacro"),
    # SAM resource types without the Transform line are just as unexpanded
    ("sam_without_transform_line.yaml", "AWS::Serverless-2016-10-31")
])
def test_a_transform_or_macro_is_warned_about_not_expanded(client, name, transform):

    response = upload(client, name, (TRANSFORMS / name).read_bytes())

    assert response.status_code == 201, response.text
    assert response.json()["warnings"] == [
        {"kind": "transform_unexpanded", "message": UNEXPANDED % transform}
    ]


def test_a_list_of_transforms_is_one_warning_each(client):

    data = (
        b"Transform:\n  - AWS::LanguageExtensions\n  - Name: AWS::Include\n"
        b"    Parameters: {Location: s3://b/k}\n  - AWS::LanguageExtensions\n"
        b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
    )

    warnings = upload(client, "t.yaml", data).json()["warnings"]

    assert [warning["message"] for warning in warnings] == [
        UNEXPANDED % "AWS::LanguageExtensions", UNEXPANDED % "AWS::Include"
    ]


def test_a_template_without_transforms_has_no_such_warning(client):

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    assert "transform_unexpanded" not in [warning["kind"] for warning in analysis["warnings"]]


@pytest.mark.parametrize("name, message", [
    (
        "foreach_tables.yaml",
        "Fn::ForEach (AWS::LanguageExtensions) is not supported yet; "
        "expand the loop before uploading."
    ),
    (
        "fn_transform_under_resources.yaml",
        "Fn::Transform directly under Resources (a macro or AWS::Include) is "
        "not supported; expand it before uploading."
    )
])
def test_a_loop_or_macro_in_place_of_a_resource_is_a_clear_422(client, name, message):

    response = upload(client, name, (TRANSFORMS / name).read_bytes())

    assert response.status_code == 422
    assert response.json() == {"detail": message}


def test_industry_is_required_and_capped(client):

    data = SAMPLE_PATH.read_bytes()

    assert upload(client, "a.yml", data, industry="   ").status_code == 422
    assert upload(client, "a.yml", data, industry="x" * 201).status_code == 422

    missing = client.post(
        "/api/analyses", files={"file": ("a.yml", data, "application/x-yaml")}
    )

    assert missing.status_code == 422
    assert isinstance(missing.json()["detail"], str)


def test_min_level_must_be_a_level(client):

    response = upload(client, "a.yml", SAMPLE_PATH.read_bytes(), min_level="LOW")

    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)


def test_the_filename_is_display_text_only(client):

    response = upload(client, "../../etc/passwd.yaml", SAMPLE_PATH.read_bytes())

    assert response.status_code == 201
    assert response.json()["input_name"] == "passwd.yaml"


# -- Nesting and size limits --------------------------------------------------------

def nested(shape, depth):
    """A flow-style value `depth` containers deep."""

    if shape == "mapping":
        return "{a: " * depth + "x" + "}" * depth

    return "[" * depth + "x" + "]" * depth


def template_with(value):

    return (
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      Deep: %s\n"
        % value
    ).encode()


@pytest.mark.parametrize("shape", ["mapping", "list"])
@pytest.mark.parametrize("depth", [50, 150, 300, 400, 5000])
def test_nesting_is_judged_by_depth_and_always_answers_in_json(client, shape, depth):
    """Up to 100 levels is analysed. Past it, whether the YAML parser or the
    explicit depth check notices, the answer is the same JSON 422."""

    response = upload(client, "deep.yaml", template_with(nested(shape, depth)))

    assert response.headers["content-type"] == "application/json"

    if depth == 50:
        assert response.status_code == 201, response.text
        return

    assert response.status_code == 422, response.text[:200]
    assert response.json() == {"detail": analysis.RECURSION_MESSAGE}


def test_the_depth_limit_is_exactly_100_levels():

    def check(depth):
        analysis.check_template(
            yaml.safe_load(template_with(nested("mapping", depth)).decode()), 500
        )

    # Resources, B, Properties and Deep take four of the hundred levels.
    check(96)

    with pytest.raises(analysis.InputError):
        check(97)


def test_an_unexpected_failure_while_assembling_is_a_json_500_without_details(
    client, monkeypatch
):

    def broken(self, manifest, body):
        raise RuntimeError("secret internal detail /Users/someone/app")

    monkeypatch.setattr(analysis.AnalysisService, "_assembled", broken)

    response = upload(client, "a.yml", SAMPLE_PATH.read_bytes())

    assert response.status_code == 500
    assert response.json() == {"detail": analysis.UNEXPECTED_MESSAGE}


def test_any_unhandled_error_is_a_json_500_with_a_fixed_message(settings, monkeypatch):

    def broken(self, analysis_id):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(analysis.AnalysisService, "get", broken)

    with TestClient(create_app(settings), raise_server_exceptions=False) as quiet:

        response = quiet.get("/api/analyses/%s" % uuid.uuid4())

    assert response.status_code == 500
    assert response.json() == {"detail": analysis.UNEXPECTED_MESSAGE}


@pytest.mark.parametrize("key", ["1", "null", "true", "2.5", "2024-01-01"])
def test_a_key_under_properties_that_is_not_text_is_422(client, key):

    data = (
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      %s: one\n" % key
    ).encode()

    response = upload(client, "key.yaml", data)

    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/json"

    detail = response.json()["detail"]

    assert "Properties of B has the key" in detail
    assert "not text" in detail
    assert "AttributeError" not in detail


def test_quoted_and_deeper_keys_are_fine(client):

    data = (
        b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        b"      '1': one\n      Tags:\n        - {80: http}\n"
    )

    assert upload(client, "key.yaml", data).status_code == 201


def fan_out(levels, width=10):
    """A template whose Properties hold `levels` layers of aliases, each layer
    listing the one below `width` times: width ** levels leaves when expanded."""

    lines = ["  L0: &a0 [%s]" % ", ".join(["x"] * width)]

    for level in range(1, levels):
        lines.append(
            "  L%d: &a%d [%s]" % (level, level, ", ".join(["*a%d" % (level - 1)] * width))
        )

    return (
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        + "\n".join("  " + line for line in lines) + "\n"
    ).encode()


def test_ordinary_fan_out_aliases_are_analysed(client):

    response = upload(client, "fan3.yaml", fan_out(3))

    assert response.status_code == 201, response.text

    # the saved copy is the expanded data, which at this size is small
    stored = client.get("/api/analyses/%s" % response.json()["id"])

    assert stored.status_code == 200


@pytest.mark.parametrize("levels", [7, 8])
def test_a_fan_out_alias_bomb_is_refused_cheaply(client, settings, levels):

    data = fan_out(levels)

    assert len(data) < 1000

    started = time.monotonic()

    response = upload(client, "bomb.yaml", data)

    assert response.status_code == 422, response.text[:200]
    assert response.json() == {"detail": analysis.EXPANSION_MESSAGE}

    # measured, not expanded: well inside a second of work, nothing written
    assert time.monotonic() - started < 10
    assert not settings.analyses_dir.exists() or not list(settings.analyses_dir.iterdir())


def test_the_expanded_size_is_counted_once_per_shared_node():

    template = yaml.safe_load(fan_out(8).decode())

    started = time.monotonic()

    with pytest.raises(analysis.InputError, match="expands to too much data"):
        analysis.check_structure(template)

    assert time.monotonic() - started < 1.0


def test_an_oversized_worker_reply_is_a_clean_json_error(tmp_path):

    app = create_app(make_settings(tmp_path / "cache"))

    with TestClient(app) as client:

        app.state.worker.target = stalled_job.big_reply
        app.state.worker.max_reply_bytes = 1000

        response = client.post(
            "/api/analyses/sample",
            json={"sample_id": "cloudformation5", "industry": INDUSTRY}
        )

        assert response.status_code == 413
        assert response.json()["detail"] == worker.too_large_message()
        assert "smaller template" in response.json()["detail"]
        assert not app.state.worker.busy


def test_a_result_past_the_reply_limit_says_how_many_paths_it_had(monkeypatch):

    sent = []

    class Connection:
        def send_bytes(self, data):
            sent.append(json.loads(data))

        def close(self):
            pass

    monkeypatch.setattr(worker, "MAX_REPLY_BYTES", 1000)

    worker.run_job(Connection(), "analysis", json.dumps({
        "source": {"kind": "upload", "text": SAMPLE_PATH.read_text()},
        "industry": INDUSTRY,
        "min_level": "HIGH",
        "max_resources": 500
    }))

    [reply] = sent

    assert reply["ok"] is False
    assert reply["status"] == 413
    assert re.fullmatch(
        r"The analysis produced more data than the app can handle \(\d+ paths\)\. "
        r"Try a smaller template or a higher minimum level\.",
        reply["detail"]
    )


# -- Unreadable values, and text that is printed -----------------------------------

def test_a_number_with_thousands_of_digits_is_422(client):

    data = b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      N: " + b"9" * 100000 + b"\n"

    response = upload(client, "big.yaml", data)

    assert response.status_code == 422
    assert "cannot be read" in response.json()["detail"]


def test_a_date_that_does_not_exist_is_422(client):

    data = b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      D: 2024-13-45\n"

    assert upload(client, "date.yaml", data).status_code == 422


def test_control_and_bidi_characters_are_removed_from_the_industry(client):

    dirty = "Fin\x00ance\x1b[31m \u202eevil\u2069\x7f\n(ISIC K)"

    response = upload(client, "a.yml", SAMPLE_PATH.read_bytes(), industry=dirty)

    assert response.status_code == 201
    assert response.json()["industry"] == "Finance[31m evil(ISIC K)"


def test_control_and_bidi_characters_are_removed_from_the_filename(client):

    # A multipart client percent-encodes controls, so the bidi characters are
    # what reaches the server raw; display_name handles the rest.
    response = upload(client, "re\u202eport.y\u2066aml", SAMPLE_PATH.read_bytes())

    assert response.status_code == 201
    assert response.json()["input_name"] == "report.yaml"

    assert analysis.display_name("a\x00b\x1b\x7fc\n.yml\u202e") == "abc.yml"
    assert analysis.display_name("dir\\x\u2067y\u2069.yml") == "xy.yml"
    assert analysis.display_name("keep\ttab.yml") == "keep\ttab.yml"


def test_an_industry_of_only_control_characters_is_required(client):

    response = upload(client, "a.yml", SAMPLE_PATH.read_bytes(), industry="\x00\u202e \n")

    assert response.status_code == 422
    assert response.json()["detail"] == "Industry is required."
