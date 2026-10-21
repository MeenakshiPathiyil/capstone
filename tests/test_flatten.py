"""Tests for the consolidated flattener."""

from engine.flatten import flatten_dict as engine_flatten_dict
from utils.helpers import flatten_dict as helpers_flatten_dict


# -----------------------------

def test_flatten_nested_dict():
    flat = helpers_flatten_dict(
        {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow"
                }
            }
        }
    )

    assert flat == {"PolicyDocument.Statement.Effect": "Allow"}


def test_flatten_leaves_top_level_scalars_alone():
    flat = helpers_flatten_dict({"BucketName": "insecure-public-bucket-demo"})

    assert flat == {"BucketName": "insecure-public-bucket-demo"}


# -----------------------------

def test_flatten_list_keeps_whole_list_and_indexed_keys():
    flat = helpers_flatten_dict({"Subnets": ["subnet-12345678", "subnet-87654321"]})

    # the whole-list key is what ANY matching reads
    assert flat["Subnets"] == ["subnet-12345678", "subnet-87654321"]

    # the indexed keys are what semantic_properties tags and edges read
    assert flat["Subnets[0]"] == "subnet-12345678"
    assert flat["Subnets[1]"] == "subnet-87654321"


def test_flatten_list_of_dicts_expands_every_element():
    flat = helpers_flatten_dict(
        {
            "SecurityGroupIngress": [
                {"FromPort": 22, "CidrIp": "0.0.0.0/0"},
                {"FromPort": 3389, "CidrIp": "0.0.0.0/0"}
            ]
        }
    )

    assert len(flat["SecurityGroupIngress"]) == 2
    assert flat["SecurityGroupIngress[0].FromPort"] == 22
    assert flat["SecurityGroupIngress[1].FromPort"] == 3389
    assert flat["SecurityGroupIngress[1].CidrIp"] == "0.0.0.0/0"


# -----------------------------

def test_flatten_normalizes_numeric_strings():
    flat = helpers_flatten_dict({"FromPort": "22"})

    assert flat["FromPort"] == 22
    assert isinstance(flat["FromPort"], int)


def test_flatten_normalizes_boolean_strings():
    flat = helpers_flatten_dict(
        {
            "PubliclyAccessible": "true",
            "StorageEncrypted": "False"
        }
    )

    assert flat["PubliclyAccessible"] is True
    assert flat["StorageEncrypted"] is False


def test_flatten_normalizes_scalars_inside_lists():
    flat = helpers_flatten_dict({"Ports": ["22", "true"]})

    assert flat["Ports[0]"] == 22
    assert flat["Ports[1]"] is True

    # the whole-list key deliberately keeps the values as written, so a rule
    # matching on the raw list still sees the original document
    assert flat["Ports"] == ["22", "true"]


def test_flatten_leaves_non_string_scalars_untouched():
    flat = helpers_flatten_dict(
        {
            "AllocatedStorage": 20,
            "AssociatePublicIpAddress": True,
            "KmsKeyId": None
        }
    )

    assert flat["AllocatedStorage"] == 20
    assert flat["AssociatePublicIpAddress"] is True
    assert flat["KmsKeyId"] is None


# -----------------------------

def test_both_flatten_names_resolve_to_one_function():
    assert engine_flatten_dict is helpers_flatten_dict


def test_working_edge_survives_the_consolidation(real_infra):
    """The one edge that worked before the flatteners were merged."""

    instance = real_infra.get_resource("PublicEC2Instance")
    targets = [c["target"] for c in instance.connections]

    assert "OpenSecurityGroup" in targets

    # the utils flattener also emits the whole-list key "SecurityGroupIds";
    # that must not produce a second, duplicate edge
    assert targets.count("OpenSecurityGroup") == 1
