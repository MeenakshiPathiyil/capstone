"""The contextual risk model (risk_scoring/) run over the pipeline's paths."""

from pathlib import Path

import pytest

from main import build_infra_from_resources
from parser.infra_parser import normalize, parse
from risk_scoring.graph_model.resource_metadata import CriticalityLevel, Environment
from risk_scoring.integration.pipeline_adapter import metadata_from_tags, node_details
from runner.graph_runner import analyze


SAMPLE = Path(__file__).resolve().parent.parent / "sample_yamls" / "cloudformation5.yml"


@pytest.fixture(scope="module")
def sample():
    return analyze(build_infra_from_resources(parse(SAMPLE)))


def test_every_path_gets_one_assessment_in_path_order(sample):
    assert [item["path_id"] for item in sample.risk] == [
        "AP-%03d" % rank for rank in range(1, len(sample.paths) + 1)
    ]
    for item, path in zip(sample.risk, sample.paths):
        assert item["target"] == path["target_id"]
        for component in ("score", "impact", "exposure", "path_ease"):
            assert 0 <= item[component] <= 100


def test_the_risk_model_does_not_change_the_pipeline_ranking(sample):
    scores = [path["score"] for path in sample.paths]
    assert scores == sorted(scores, reverse=True)
    assert len(sample.records) == len(sample.selected)


def test_sample_assessment(sample):
    by_id = {item["path_id"]: item for item in sample.risk}

    # The two one-hop denial-of-service paths are the most direct and easiest.
    assert [by_id["AP-019"]["rank"], by_id["AP-015"]["rank"]] == [1, 2]
    assert by_id["AP-019"]["reachability"] == "direct"
    assert by_id["AP-019"]["path_ease"] == 100.0

    # A public bucket is an entry point itself, so a path ending there is direct.
    assert by_id["AP-001"]["reachability"] == "direct"
    # Past a foothold, the rest of the path is post-compromise.
    assert by_id["AP-006"]["reachability"] == "post_compromise"

    # The template has no tags, so no metadata is known.
    assert {item["environment"] for item in sample.risk} == {None}
    assert {item["asset_criticality"] for item in sample.risk} == {None}
    assert {item["sensitive_data"] for item in sample.risk} == {None}


def test_node_details_carry_the_facts_held_on_arrival(sample):
    path = sample.paths[0]
    details = node_details(path)
    assert [node["resource"] for node in details] == path["hops"]
    assert details[0]["facts"] == ["internet_reachable"]
    assert details[1]["facts"] == ["foothold(PublicEC2Instance)"]


@pytest.mark.parametrize("tags, expected", [
    ([], (None, None, None)),
    ([{"Key": "Environment", "Value": "Production"}], (None, None, Environment.PROD)),
    ([{"Key": "env", "Value": "dev"}], (None, None, Environment.DEV)),
    ([{"Key": "Criticality", "Value": "High"}], (CriticalityLevel.HIGH, None, None)),
    ([{"Key": "DataClassification", "Value": "Confidential"}], (None, True, None)),
    ([{"Key": "DataClassification", "Value": "Public"}], (None, False, None)),
    ([{"Key": "SensitiveData", "Value": "false"}], (None, False, None)),
    ([{"Key": "Environment", "Value": "staging"}], (None, None, None)),
    ([{"Key": "Environment", "Value": {"Ref": "Stage"}}], (None, None, None)),
])
def test_metadata_from_tags(tags, expected):
    metadata = metadata_from_tags({"Tags": tags})
    assert (metadata.asset_criticality, metadata.sensitive_data, metadata.environment) == expected


def test_tags_on_the_target_raise_its_impact():
    template = {
        "Resources": {
            "OpenGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "open",
                    "SecurityGroupIngress": [
                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}
                    ],
                },
            },
            "Web": {
                "Type": "AWS::EC2::Instance",
                "Properties": {"SecurityGroups": [{"Ref": "OpenGroup"}], "ImageId": "ami-1"},
            },
        }
    }

    def assess(tags):
        template["Resources"]["Web"]["Properties"]["Tags"] = tags
        result = analyze(build_infra_from_resources(normalize(template)))
        assert result.risk, "the template should give at least one path"
        return max(item["impact"] for item in result.risk if item["target"] == "Web")

    untagged = assess([])
    tagged = assess([
        {"Key": "Environment", "Value": "prod"},
        {"Key": "Criticality", "Value": "high"},
        {"Key": "DataClassification", "Value": "confidential"},
    ])
    assert tagged > untagged
