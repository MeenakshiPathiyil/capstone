"""Tests for how parser/infra_parser resolves CloudFormation intrinsic functions.

Each case started as a template from aws-cloudformation-templates that the
analyser read wrongly: an open SSH default that was missed, a `!GetAtt` that drew
no edge, and YAML and JSON copies of one template that disagreed. The templates
here are minimal copies of those cases.
"""

from pathlib import Path

import pytest

from attack_path.path_finder import find_attack_paths
from main import build_infra_from_resources
from parser.infra_parser import load_cloudformation_template, parse
from parser.nested import parse_merged
from security_state_graph.state_graph import SecurityStateGraph, evaluate_findings


TWINS_DIR = Path(__file__).resolve().parent / "fixtures" / "twins"

OPEN_SSH = "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup"
INTERNET_FACING = "ELB_INTERNET_FACING"


def write(tmp_path, text, name="t.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def analyse(path):
    """(records, findings, edges, paths) for one template, through the pipeline."""

    records = parse(path)

    infra = build_infra_from_resources(records)
    findings = evaluate_findings(infra)

    edges = sorted(
        (resource.id, connection["target"], connection["type"])
        for resource in infra.all_resources()
        for connection in resource.connections
    )

    paths = find_attack_paths(SecurityStateGraph(infra, findings))

    return (
        records,
        sorted((finding["resource"], finding["rule_id"]) for finding in findings),
        edges,
        paths
    )


def properties(path, resource_id):
    return load_cloudformation_template(path)["Resources"][resource_id]["Properties"]


# -- Ref to a parameter --------------------------------------------------------

SSH_FROM_PARAMETER = """
Parameters:
  SSHLocation:
    Type: String
    Default: 0.0.0.0/0
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: ssh
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: !Ref SSHLocation}
"""


def test_a_ref_to_a_parameter_resolves_to_its_default(tmp_path):
    """EC2InstanceWithSecurityGroupSample and friends: SSH open by default was
    read as the CIDR "SSHLocation" and never reported."""

    path = write(tmp_path, SSH_FROM_PARAMETER)

    ingress = properties(path, "SG")["SecurityGroupIngress"][0]

    assert ingress["CidrIp"] == "0.0.0.0/0"
    assert ("SG", OPEN_SSH) in analyse(path)[1]


def test_the_json_spelling_resolves_the_same_default(tmp_path):

    path = write(tmp_path, """{
      "Parameters": {"SSHLocation": {"Type": "String", "Default": "0.0.0.0/0"}},
      "Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "ssh",
        "SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 22,
          "ToPort": 22, "CidrIp": {"Ref": "SSHLocation"}}]}}}}""", "t.json")

    assert ("SG", OPEN_SSH) in analyse(path)[1]


def test_a_default_scheme_makes_a_load_balancer_internet_facing(tmp_path):
    """CloudFrontCustomOriginLambda@Edge: `Scheme: !Ref ALBScheme`."""

    path = write(tmp_path, """
Parameters:
  ALBScheme: {Type: String, Default: internet-facing}
Resources:
  ALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties: {Scheme: !Ref ALBScheme}
""")

    assert ("ALB", INTERNET_FACING) in analyse(path)[1]


def test_a_parameter_without_a_default_keeps_its_name(tmp_path):
    """Nothing to assume, so the existing representation stays."""

    path = write(tmp_path, """
Parameters:
  KeyName: {Type: 'AWS::EC2::KeyPair::KeyName'}
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: {KeyName: !Ref KeyName}
""")

    assert properties(path, "Web")["KeyName"] == "KeyName"


def test_an_ssm_parameter_default_is_not_the_value(tmp_path):
    """The Default of an SSM parameter type is the name of a stored value, not
    the value, so `ImageId` must not become "/aws/service/..."."""

    path = write(tmp_path, """
Parameters:
  LatestAmiId:
    Type: 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>'
    Default: /aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: {ImageId: !Ref LatestAmiId}
""")

    assert properties(path, "Web")["ImageId"] == "LatestAmiId"


def test_defaults_resolve_to_the_strings_cloudformation_passes(tmp_path):
    """A Ref to a parameter is a string, or a list of strings for a list type,
    however YAML typed the Default."""

    path = write(tmp_path, """
Parameters:
  Port: {Type: Number, Default: 22}
  Public: {Type: String, Default: true}
  Subnets: {Type: 'List<AWS::EC2::Subnet::Id>', Default: 'subnet-1, subnet-2'}
Resources:
  Group:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: {FromPort: !Ref Port, Description: !Ref Public}
  Balancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties: {Subnets: !Ref Subnets}
""")

    assert properties(path, "Group") == {"FromPort": "22", "Description": "true"}
    assert properties(path, "Balancer")["Subnets"] == ["subnet-1", "subnet-2"]


def test_pseudo_parameters_stay_unresolved_in_both_spellings(tmp_path):

    yaml_path = write(tmp_path, """
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties: {BucketName: !Ref AWS::Region, Tags: [{Key: a, Value: !Ref 'AWS::AccountId'}]}
""")

    json_path = write(tmp_path, """{"Resources": {"B": {"Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": {"Ref": "AWS::Region"},
        "Tags": [{"Key": "a", "Value": {"Ref": "AWS::AccountId"}}]}}}}""", "t.json")

    for path in (yaml_path, json_path):
        assert properties(path, "B") == {
            "BucketName": "AWS::Region",
            "Tags": [{"Key": "a", "Value": "AWS::AccountId"}]
        }


def test_a_parameter_a_parent_stack_passes_is_not_defaulted(tmp_path):
    """The value passed wins over the Default, and parser/nested substitutes it
    by the parameter's name. Defaulting it first would cut the cross-stack edge."""

    write(tmp_path, """
Resources:
  Group:
    Type: AWS::EC2::SecurityGroup
    Properties: {GroupDescription: g}
  Child:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: https://s3.amazonaws.com/bucket/child.yaml
      Parameters: {SecurityGroup: !Ref Group}
""", "parent.yaml")

    write(tmp_path, """
Parameters:
  SecurityGroup: {Type: String, Default: sg-default}
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: {SecurityGroupIds: [!Ref SecurityGroup]}
""", "child.yaml")

    records, _ = parse_merged(tmp_path / "parent.yaml", root=tmp_path)

    web = next(record for record in records if record["id"] == "Child.Web")

    assert web["raw_properties"]["SecurityGroupIds"] == ["Group"]


# -- Fn::GetAtt ----------------------------------------------------------------

GET_ATT_FORMS = [
    "!GetAtt SG.GroupId",
    "!GetAtt [SG, GroupId]",
    "{'Fn::GetAtt': [SG, GroupId]}",
    "!Ref SG"
]


@pytest.mark.parametrize("reference", GET_ATT_FORMS)
def test_every_spelling_of_get_att_draws_the_edge_ref_draws(tmp_path, reference):
    """Synthetic cases s13 and s15: `!GetAtt SG.GroupId` was the string
    "SG.GroupId", named no resource and drew no edge, so the instance behind an
    open security group was unreachable. `!Ref SG` was fine."""

    path = write(tmp_path, """
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties: {GroupDescription: x}
  Ing:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: {GroupId: %s, IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}
  Web:
    Type: AWS::EC2::Instance
    Properties: {ImageId: ami-1, SecurityGroupIds: [%s]}
""" % (reference, reference))

    records, _, edges, _ = analyse(path)

    web = next(record for record in records if record["id"] == "Web")

    assert web["raw_properties"]["SecurityGroupIds"] == ["SG"]
    assert ("Web", "SG", "network_control") in edges
    assert ("Ing", "SG", "connection") in edges


def test_get_att_keeps_the_part_of_a_dotted_attribute_after_the_first_dot(tmp_path):
    """`Endpoint.Address` is one attribute. The logical id is before the first
    dot, so the record names the database."""

    path = write(tmp_path, """
Resources:
  DB:
    Type: AWS::RDS::DBInstance
  App:
    Type: AWS::Lambda::Function
    Properties: {Environment: {Variables: {HOST: !GetAtt DB.Endpoint.Address}}}
""")

    assert properties(path, "App")["Environment"]["Variables"]["HOST"] == "DB"


def test_a_nested_stack_output_stays_dotted_for_the_merge(tmp_path):
    """parser/nested resolves `Child.Outputs.Name` through the child's Outputs."""

    path = write(tmp_path, """
Resources:
  Child:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: child.yaml
      Parameters:
        A: !GetAtt Network.Outputs.OpenGroup
        B: {'Fn::GetAtt': [Network, Outputs.OpenGroup]}
""")

    assert properties(path, "Child")["Parameters"] == {
        "A": "Network.Outputs.OpenGroup",
        "B": "Network.Outputs.OpenGroup"
    }


# -- YAML and JSON twins ---------------------------------------------------------

def twin_pairs():
    return sorted(
        (path, path.with_suffix(".json"))
        for path in TWINS_DIR.glob("*.yaml")
    )


def test_there_are_twins_to_compare():
    assert twin_pairs()


@pytest.mark.parametrize(
    "yaml_path, json_path", twin_pairs(), ids=lambda path: path.name
)
def test_yaml_and_json_spellings_of_one_template_analyse_identically(
    yaml_path, json_path
):
    """The same template, short form and long form. Before, the YAML copy of
    CloudFrontCustomOriginLambda@Edge gave 4 findings and the JSON copy 3,
    because `{"Ref": "LoggingBucket"}` never matched its bucket."""

    assert analyse(yaml_path)[:3] == analyse(json_path)[:3]
    assert len(analyse(yaml_path)[3]) == len(analyse(json_path)[3])


def test_the_twin_fixture_resolves_every_function_it_uses():
    """What the twins agree on, spelled out, so they cannot agree on the
    unresolved form."""

    path = TWINS_DIR / "intrinsics.json"

    template = load_cloudformation_template(path)
    instance = template["Resources"]["Instance"]["Properties"]

    assert instance["SecurityGroupIds"] == ["InstanceSecurityGroup"] * 2
    assert instance["SubnetId"] == [0, ["subnet-1", "subnet-2"]]
    assert instance["AvailabilityZone"] == [0, ""]
    assert instance["UserData"] == ["", ["#!/bin/bash", "AWS::Region"]]
    assert [tag["Value"] for tag in instance["Tags"]] == [
        "AWS::Region",
        ["RegionMap", "AWS::Region", "AMI"],
        "SharedStackOutput",
        [",", ["|", "a|b"]],
        [0, ["10.0.0.0/16", 2, 8]],
        ["IsProd", "prod", "AWS::NoValue"]
    ]

    assert template["Conditions"]["Both"] == ["IsProd", ["IsNotDev", "IsProd"]]

    findings = analyse(path)[1]

    assert ("InstanceSecurityGroup", OPEN_SSH) in findings
    assert ("OriginALB", INTERNET_FACING) in findings
