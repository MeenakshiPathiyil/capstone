"""Shared fixtures for the infrastructure model test suite."""

import json
from pathlib import Path

import pytest

from main import build_infra_from_resources


BASE_DIR = Path(__file__).resolve().parent.parent

REAL_RESOURCES_PATH = BASE_DIR / "data" / "normalized_resources.json"
RULES_PATH = BASE_DIR / "data" / "security_rules.yaml"


# -----------------------------

SAMPLE_RESOURCES = [
    {
        "id": "SampleSecurityGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "Sample group open to the world",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        },
        "semantic_properties": {
            "GroupDescription": "unknown",
            "SecurityGroupIngress[0].IpProtocol": "network_control",
            "SecurityGroupIngress[0].FromPort": "network_control",
            "SecurityGroupIngress[0].ToPort": "network_control",
            "SecurityGroupIngress[0].CidrIp": "exposure",
            "SecurityGroupIngress[1].IpProtocol": "network_control",
            "SecurityGroupIngress[1].FromPort": "network_control",
            "SecurityGroupIngress[1].ToPort": "network_control",
            "SecurityGroupIngress[1].CidrIp": "exposure"
        }
    },
    {
        "id": "SampleEC2Instance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-11111111111111111",
            "InstanceType": "t2.micro",
            "SecurityGroupIds": [
                "SampleSecurityGroup"
            ],
            "IamInstanceProfile": "SampleRole",
            "AssociatePublicIpAddress": True
        },
        "semantic_properties": {
            "ImageId": "unknown",
            "InstanceType": "unknown",
            "SecurityGroupIds[0]": "network_control",
            "IamInstanceProfile": "identity",
            "AssociatePublicIpAddress": "exposure"
        }
    },
    {
        "id": "SampleRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "sample-role",
            "Policies": [
                {
                    "PolicyName": "sample-bucket-access",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "SampleBucket"
                            }
                        ]
                    }
                }
            ]
        },
        "semantic_properties": {
            "RoleName": "unknown",
            "Policies[0].PolicyName": "unknown",
            "Policies[0].PolicyDocument.Statement[0].Effect": "unknown",
            "Policies[0].PolicyDocument.Statement[0].Action": "capability",
            "Policies[0].PolicyDocument.Statement[0].Resource": "connection"
        }
    },
    {
        "id": "SampleBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "sample-public-bucket",
            "AccessControl": "PublicRead"
        },
        "semantic_properties": {
            "BucketName": "unknown",
            "AccessControl": "unknown"
        }
    }
]


# A role that reaches one bucket twice: its policy names the bucket in a
PARALLEL_EDGE_RESOURCES = [
    {
        "id": "ParallelRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "parallel-role",
            "Policies": [
                {
                    "PolicyName": "named-and-wildcard",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "ParallelBucket"
                            },
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }
                        ]
                    }
                }
            ]
        },
        "semantic_properties": {
            "RoleName": "unknown",
            "Policies[0].PolicyName": "unknown",
            "Policies[0].PolicyDocument.Statement[0].Effect": "unknown",
            "Policies[0].PolicyDocument.Statement[0].Action": "capability",
            "Policies[0].PolicyDocument.Statement[0].Resource": "connection",
            "Policies[0].PolicyDocument.Statement[1].Effect": "unknown",
            "Policies[0].PolicyDocument.Statement[1].Action": "capability",
            "Policies[0].PolicyDocument.Statement[1].Resource": "capability"
        }
    },
    {
        "id": "ParallelBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "parallel-bucket",
            "AccessControl": "PublicRead"
        },
        "semantic_properties": {
            "BucketName": "unknown",
            "AccessControl": "unknown"
        }
    }
]


# A network_control edge that must NOT be reversed for traversal: a Lambda
GATE_DROPPED_RESOURCES = [
    {
        "id": "GateSecurityGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "Gate group, open to the world",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        },
        "semantic_properties": {
            "GroupDescription": "unknown",
            "SecurityGroupIngress[0].IpProtocol": "network_control",
            "SecurityGroupIngress[0].FromPort": "network_control",
            "SecurityGroupIngress[0].ToPort": "network_control",
            "SecurityGroupIngress[0].CidrIp": "exposure"
        }
    },
    {
        "id": "GateLambda",
        "type": "AWS::Lambda::Function",
        "raw_properties": {
            "FunctionName": "gate-function",
            "Role": "GateRole",
            "VpcConfig": {
                "SecurityGroupIds": [
                    "GateSecurityGroup"
                ]
            }
        },
        "semantic_properties": {
            "FunctionName": "unknown",
            "Role": "identity",
            "VpcConfig.SecurityGroupIds[0]": "network_control"
        }
    },
    {
        "id": "GateRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "gate-role",
            "Policies": [
                {
                    "PolicyName": "gate-bucket-access",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "GateBucket"
                            }
                        ]
                    }
                }
            ]
        },
        "semantic_properties": {
            "RoleName": "unknown",
            "Policies[0].PolicyName": "unknown",
            "Policies[0].PolicyDocument.Statement[0].Effect": "unknown",
            "Policies[0].PolicyDocument.Statement[0].Action": "capability",

            # "unknown" on the reference, so the edge is typed by the target's
            "Policies[0].PolicyDocument.Statement[0].Resource": "unknown"
        }
    },
    {
        "id": "GateBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "gate-bucket"
        },
        "semantic_properties": {
            "BucketName": "unknown"
        }
    }
]


@pytest.fixture
def sample_resource_dicts():
    """The hand-built resources as plain dictionaries, in normalized form."""

    return json.loads(json.dumps(SAMPLE_RESOURCES))


@pytest.fixture
def sample_infra(sample_resource_dicts):
    """The hand-built resources as a connected InfraModel."""

    return build_infra_from_resources(sample_resource_dicts)


@pytest.fixture
def parallel_edge_infra():
    """A role reaching one bucket through both passes, as a connected InfraModel."""

    return build_infra_from_resources(
        json.loads(json.dumps(PARALLEL_EDGE_RESOURCES))
    )


@pytest.fixture
def gate_dropped_infra():
    """A network_control edge the INBOUND_REACHABLE_TYPES gate must drop, as a"""

    return build_infra_from_resources(
        json.loads(json.dumps(GATE_DROPPED_RESOURCES))
    )


# -----------------------------

@pytest.fixture
def real_resources_path():
    """Path to data/normalized_resources.json."""

    return REAL_RESOURCES_PATH


@pytest.fixture
def rules_path():
    """Path to data/security_rules.yaml."""

    return RULES_PATH


@pytest.fixture
def objectives_path():
    """Path to data/objectives.yaml."""

    return BASE_DIR / "data" / "objectives.yaml"


@pytest.fixture
def real_resource_dicts(real_resources_path):
    """data/normalized_resources.json as a list of dictionaries."""

    with open(real_resources_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def real_infra(real_resource_dicts):
    """The shipped dataset as a connected InfraModel."""

    return build_infra_from_resources(real_resource_dicts)


# -----------------------------
# Objectives.
#
# path_finder now ends a path at any of the five objectives in
# data/objectives.yaml, so a fixture built of "one bucket is the prize" has
# several targets unless the test says otherwise. DATA_THEFT_ONLY is that
# "otherwise": it pins the objective set to the one the pre-objectives tests
# were implicitly written against, so those tests keep asserting what they meant.

def data_theft_only():
    """The data-theft objective alone, as path_finder's `objectives` argument."""

    from attack_path.path_finder import load_objectives

    return [
        objective
        for objective in load_objectives()
        if objective["id"] == "data_theft"
    ]


@pytest.fixture
def data_theft():
    """The data-theft objective alone."""

    return data_theft_only()
