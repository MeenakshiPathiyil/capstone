"""Tests for processing/attributes.py, the projection the ruleset reads."""

import pytest

from processing.attributes import (
    PortRange,
    as_port,
    project,
    project_all
)


def record(resource_id, resource_type, properties):
    return {
        "id": resource_id,
        "type": resource_type,
        "raw_properties": properties
    }


# -- PortRange ---------------------------------------------------------------

def test_a_range_equals_any_port_inside_it():
    """Why the class exists. `FromPort: 0, ToPort: 65535` opens 3389 without ever
    naming it, and that wide-open group is the case the ruleset most needs."""

    assert PortRange(0, 65535) == 3389
    assert PortRange(22, 22) == 22
    assert PortRange(22, 22) != 3389


def test_a_range_does_not_coerce_strings():
    """engine.condition_evaluator.compare documents that `equals` must not
    coerce. This field must not be the exception."""

    assert (PortRange(22, 22) == "22") is False


def test_a_range_is_not_hashable():
    """PortRange(22) == 22 but their hashes differ, so a set holding both would
    keep two entries. Failing loudly beats a silent duplicate."""

    with pytest.raises(TypeError):
        {PortRange(22, 22)}


def test_a_boolean_is_not_a_port():
    """True is 1 in Python. A rule comparing a port to a flag has a bug in it and
    should not be given a plausible answer."""

    assert as_port(True) is None
    assert as_port("22") == 22
    assert as_port("not a port") is None


# -- Ingress -----------------------------------------------------------------

def test_both_spellings_of_an_inbound_rule_project_the_same():
    """The whole argument for the abstract vocabulary: a rule nested in a group
    and a standalone AWS::EC2::SecurityGroupIngress are one fact in two shapes."""

    nested = project(record("Group", "AWS::EC2::SecurityGroup", {
        "SecurityGroupIngress": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "CidrIp": "0.0.0.0/0"}
        ]
    }))

    standalone = project(record("Rule", "AWS::EC2::SecurityGroupIngress", {
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"
    }))

    assert nested["ingress"] == standalone["ingress"]

    assert nested["ingress"][0]["port"] == 22
    assert nested["ingress"][0]["cidr"] == "0.0.0.0/0"


def test_protocol_minus_one_opens_every_port():
    """A protocol of -1 carries no port fields, so a range test on the entry
    cannot fire and the widest possible rule reads as the narrowest."""

    entries = project(record("Group", "AWS::EC2::SecurityGroup", {
        "SecurityGroupIngress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}]
    }))["ingress"]

    assert entries[0]["port"] == 3389
    assert entries[0]["from_port"] == 0
    assert entries[0]["to_port"] == 65535


def test_an_entry_with_no_source_is_still_an_entry():
    """The ports it opens are a fact. Dropping it would hide a rule that names no
    CIDR."""

    entries = project(record("Group", "AWS::EC2::SecurityGroup", {
        "SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 22,
                                  "ToPort": 22}]
    }))["ingress"]

    assert len(entries) == 1
    assert entries[0]["cidr"] is None


# -- Buckets -----------------------------------------------------------------

def test_a_missing_public_access_block_reads_as_not_blocked():
    """AWS does not block public access unless told to, so a template that never
    mentions the block has all four flags off. Leaving them unset would mean a
    rule only ever caught people who explicitly opted in to being insecure."""

    attributes = project(record("Bucket", "AWS::S3::Bucket", {
        "BucketName": "b"
    }))

    for flag in ("BlockPublicAcls", "BlockPublicPolicy",
                 "IgnorePublicAcls", "RestrictPublicBuckets"):
        assert attributes[
            "PublicAccessBlockConfiguration.%s" % flag
        ] is False


def test_only_the_canned_acls_that_mean_public_count():
    """AuthenticatedRead means every AWS account, which is very bad and is not
    the same claim as public."""

    def acl(value):
        return project(record("Bucket", "AWS::S3::Bucket", {
            "AccessControl": value
        }))["BucketAcl.AllowsPublicRead"]

    assert acl("PublicRead") is True
    assert acl("PublicReadWrite") is True
    assert acl("AuthenticatedRead") is False
    assert acl("Private") is False


def test_a_policy_on_another_resource_is_attributed_to_its_bucket():
    """An AWS::S3::BucketPolicy names its bucket; the bucket never names the
    policy. So the policy's conclusions have to be carried across."""

    records = [
        record("Bucket", "AWS::S3::Bucket", {"BucketName": "b"}),
        record("Policy", "AWS::S3::BucketPolicy", {
            "Bucket": "Bucket",
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Principal": "*",
                               "Action": "s3:GetObject"}]
            }
        })
    ]

    projected = {
        item["id"]: item["attributes"]
        for item in project_all(records)
    }

    assert projected["Bucket"]["BucketPolicy.AllowsPublicRead"] is True
    assert projected["Bucket"]["BucketPolicy.Grantee"] == ["*"]


def test_a_wildcard_principal_on_a_write_action_is_not_public_read():
    """All three have to hold: Allow, a wildcard principal, and a read action.
    Reporting a write-only grant under a rule named for public read would be a
    finding that says the wrong thing."""

    records = [
        record("Bucket", "AWS::S3::Bucket", {"BucketName": "b"}),
        record("Policy", "AWS::S3::BucketPolicy", {
            "Bucket": "Bucket",
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Principal": "*",
                               "Action": "s3:PutObject"}]
            }
        })
    ]

    projected = {
        item["id"]: item["attributes"]
        for item in project_all(records)
    }

    assert projected["Bucket"]["BucketPolicy.AllowsPublicRead"] is False
