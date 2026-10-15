"""Tests for parser/infra_parser.py, stage 0 of the pipeline."""

import json

import pytest

from parser.infra_parser import (
    DEFAULT_INPUT,
    DEFAULT_OUTPUT,
    load_cloudformation_template,
    main,
    parse,
    validate_template
)


def test_the_committed_pipeline_input_is_what_the_parser_produces():
    """data/normalized_resources.json is the parser's output for the sample
    template. Edited by hand, or left stale after a parser change, it would feed
    the graph pipeline records the parser can no longer produce."""

    committed = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))

    assert parse(DEFAULT_INPUT) == committed


def test_the_cli_writes_the_committed_file_byte_for_byte(tmp_path):

    out = tmp_path / "normalized_resources.json"

    assert main(["--out", str(out)]) == 0
    assert out.read_bytes() == DEFAULT_OUTPUT.read_bytes()


def test_records_carry_no_projected_attributes():
    """Projection belongs to processing/attributes.py. A second copy in the
    parser drifted once and silently dropped findings."""

    assert all("attributes" not in record for record in parse(DEFAULT_INPUT))


def test_intrinsic_function_tags_load_as_plain_values(tmp_path):

    template = tmp_path / "t.yml"
    template.write_text(
        "Resources:\n"
        "  Group:\n"
        "    Type: AWS::EC2::SecurityGroup\n"
        "    Properties:\n"
        "      VpcId: !Ref Vpc\n"
        "      GroupName: !Sub '${AWS::StackName}-web'\n",
        encoding="utf-8"
    )

    properties = load_cloudformation_template(template)["Resources"]["Group"]["Properties"]

    assert properties["VpcId"] == "Vpc"
    assert properties["GroupName"] == "${AWS::StackName}-web"


@pytest.mark.parametrize("template, message", [
    ({}, "Missing Resources section"),
    ({"Resources": {"Bucket": None}}, "Bucket is malformed or empty"),
    ({"Resources": {"Bucket": {"Properties": {}}}}, "Bucket missing Type")
])
def test_a_malformed_template_is_rejected(template, message):

    with pytest.raises(ValueError, match=message):
        validate_template(template)
