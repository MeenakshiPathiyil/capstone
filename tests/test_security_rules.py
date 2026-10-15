"""Tests for data/security_rules.yaml — the rule knowledge, not the engine."""

import json
import re

import pytest

from engine.condition_evaluator import get_scope_elements
from engine.rule_engine import RuleEngine
from processing.attribute_extractor import process_resources


# The order a rule declares its keys in, as a sequence the keys a rule DOES carry
# must appear in. Not every rule carries every key: the canonical rules have
# `summary` and `parameters` and no `severity`, ours have `parameter_schema`, and
# only a rule that departs from its canonical original has `deviations`. So this
# is a relative-order check rather than an equality one, which still catches the
# thing it was written for — a rule whose keys are shuffled relative to its
# neighbours, in a file people read far more often than the engine does.
FIELD_ORDER = [
    "id",
    "origin",
    "source_id",
    "service",
    "resource_type",
    "semantic",
    "state",
    "summary",
    "deviations",
    "conditions",
    "parameters",
    "parameter_schema",
    "attack_techniques",
    "references"
]

# The canonical checks, by `source_id`. Several appear more than once in the file
# because a check is written once per resource type it applies to, which is the
# canonical file's own convention.
CANONICAL_SOURCE_IDS = {
    "RESTRICTED_INCOMING_TRAFFIC",
    "INCOMING_SSH_DISABLED",
    "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "RDS_STORAGE_ENCRYPTED",
    "REQUIRED_TAGS",
    "IAM_PASSWORD_POLICY",
    "ROOT_ACCOUNT_MFA_ENABLED",
    "CLOUD_TRAIL_ENABLED"
}

# Ours, kept because the canonical set has no equivalent. Deleting any of these
# does not lose one finding, it loses every attack path: see the section header
# in data/security_rules.yaml.
OUR_SOURCE_IDS = {
    "EC2_PUBLIC_IP",
    "ELB_INTERNET_FACING",
    "RDS_PUBLICLY_ACCESSIBLE",
    "S3_WILDCARD_POLICY",
    "EC2_IMDSV1_ENABLED",
    "IAM_WILDCARD_PERMISSIONS",
    "IAM_TRUST_POLICY_WILDCARD"
}

REQUIRED_SOURCE_IDS = CANONICAL_SOURCE_IDS | OUR_SOURCE_IDS

# Rules whose `resource_type` no CloudFormation template can declare. Kept in the
# file so it stays a faithful copy of the canonical set, and skipped by the
# fixture tests because there is no resource to write a fixture for.
UNTESTABLE_RESOURCE_TYPES = {"account"}

# Lowercase on purpose: security_state_graph/semantics.py indexes a lowercase weight table.
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}

# The seven the parser's semantic categorisation emits, plus `privilege`, which is
# ours. See the note at NON_PATH_SEMANTICS in security_state_graph/semantics.py.
ALLOWED_SEMANTICS = {
    "network_control",
    "exposure",
    "identity",
    "capability",
    "trust",
    "connection",
    "impact",

    "privilege"
}

# T1190, or T1098.001 for a sub-technique. Nothing else is an ATT&CK id.
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


# -----------------------------

VULNERABLE_RESOURCES = {

    # Service: "*" — the spelling our own dataset uses. Anyone who can call
    # sts:AssumeRole becomes this role, whatever its permissions policy says.
    "IAM_TRUST_POLICY_WILDCARD": {
        "id": "AnyoneCanAssumeRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "wide-open-trust",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "*"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        },
        "semantic_properties": {
            "RoleName": "unknown",
            "AssumeRolePolicyDocument.Statement[0].Effect": "unknown",
            "AssumeRolePolicyDocument.Statement[0].Principal.Service": "unknown",
            "AssumeRolePolicyDocument.Statement[0].Action": "capability"
        }
    },

    # No MetadataOptions at all, which is the common case and the insecure
    # default. A not_equals leaf would read this as hardened.
    "EC2_IMDSV1_ENABLED": {
        "id": "LegacyMetadataInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-0abcdef1234567890",
            "InstanceType": "t3.micro"
        },
        "semantic_properties": {
            "ImageId": "unknown",
            "InstanceType": "unknown"
        }
    },

    # The same weakness as RESTRICTED_COMMON_PORTS, declared as its own resource
    # instead of nested in the group. The rule engine indexes by resource_type, so
    # before SG_INGRESS_UNRESTRICTED existed nothing looked at this shape at all —
    # and real templates use it constantly.
    "SG_INGRESS_UNRESTRICTED": {
        "id": "VulnerableIngressRule",
        "type": "AWS::EC2::SecurityGroupIngress",
        "raw_properties": {
            "GroupId": "SomeSecurityGroup",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "0.0.0.0/0"
        },
        "semantic_properties": {
            "GroupId": "connection",
            "IpProtocol": "network_control",
            "FromPort": "network_control",
            "ToPort": "network_control",
            "CidrIp": "exposure"
        }
    },

    "RESTRICTED_COMMON_PORTS": {
        "id": "VulnerableSecurityGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "Remote desktop open to the world",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "CidrIp": "0.0.0.0/0"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    },

    "S3_PUBLIC_ACL": {
        "id": "VulnerableBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "vulnerable-public-bucket",
            "AccessControl": "PublicRead"
        }
    },

    "S3_WILDCARD_POLICY": {
        "id": "VulnerableBucketPolicy",
        "type": "AWS::S3::BucketPolicy",
        "raw_properties": {
            "Bucket": "VulnerableBucket",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "*"
                    }
                ]
            }
        }
    },

    "RDS_PUBLICLY_ACCESSIBLE": {
        "id": "VulnerableDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "vulnerable-db",
            "Engine": "mysql",
            "PubliclyAccessible": True
        }
    },

    "EC2_PUBLIC_IP": {
        "id": "VulnerableInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-22222222222222222",
            "InstanceType": "t2.micro",
            "AssociatePublicIpAddress": True
        }
    },

    "IAM_WILDCARD_PERMISSIONS": {
        "id": "VulnerableRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "vulnerable-admin-role",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Policies": [
                {
                    "PolicyName": "admin-access",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }
                        ]
                    }
                }
            ]
        }
    },

    "ELB_INTERNET_FACING": {
        "id": "VulnerableLoadBalancer",
        "type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "raw_properties": {
            "Name": "vulnerable-lb",
            "Scheme": "internet-facing",
            "Type": "application"
        }
    }
}


HARDENED_RESOURCES = {

    "IAM_TRUST_POLICY_WILDCARD": {
        "id": "NarrowTrustRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "narrow-trust",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        },
        "semantic_properties": {
            "RoleName": "unknown",
            "AssumeRolePolicyDocument.Statement[0].Effect": "unknown",
            "AssumeRolePolicyDocument.Statement[0].Principal.Service": "unknown",
            "AssumeRolePolicyDocument.Statement[0].Action": "capability"
        }
    },

    "EC2_IMDSV1_ENABLED": {
        "id": "HardenedMetadataInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-0abcdef1234567890",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required"}
        },
        "semantic_properties": {
            "ImageId": "unknown",
            "InstanceType": "unknown",
            "MetadataOptions.HttpTokens": "unknown"
        }
    },

    # Same port, same protocol, but scoped to the VPC. If this reports, the rule
    # is matching on the port alone and would flag every bastion in the corpus.
    "SG_INGRESS_UNRESTRICTED": {
        "id": "HardenedIngressRule",
        "type": "AWS::EC2::SecurityGroupIngress",
        "raw_properties": {
            "GroupId": "SomeSecurityGroup",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "10.0.0.0/8"
        },
        "semantic_properties": {
            "GroupId": "connection",
            "IpProtocol": "network_control",
            "FromPort": "network_control",
            "ToPort": "network_control",
            "CidrIp": "exposure"
        }
    },

    # 3389 is still here, and 0.0.0.0/0 is still here — one element apart.
    # An unscoped AND over the ingress list reports this group.
    "RESTRICTED_COMMON_PORTS": {
        "id": "HardenedSecurityGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "Web public, remote desktop restricted to the VPC",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "CidrIp": "0.0.0.0/0"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "CidrIp": "10.0.0.0/16"
                }
            ]
        }
    },

    # AccessControl is present and private. A rule keyed on the field existing
    # rather than on its value reports this bucket.
    "S3_PUBLIC_ACL": {
        "id": "HardenedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "hardened-private-bucket",
            "AccessControl": "Private",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True
            }
        }
    },

    # An Allow to one named account, then a Deny to everyone. Both halves of
    # "Allow to *" exist in the document; neither statement contains both.
    "S3_WILDCARD_POLICY": {
        "id": "HardenedBucketPolicy",
        "type": "AWS::S3::BucketPolicy",
        "raw_properties": {
            "Bucket": "HardenedBucket",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::111122223333:role/ReportingRole"
                        },
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::hardened-private-bucket/*"
                    },
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::hardened-private-bucket/*"
                    }
                ]
            }
        }
    },

    "RDS_PUBLICLY_ACCESSIBLE": {
        "id": "HardenedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "hardened-db",
            "Engine": "mysql",
            "PubliclyAccessible": False,
            "StorageEncrypted": True
        }
    },

    "EC2_PUBLIC_IP": {
        "id": "HardenedInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-33333333333333333",
            "InstanceType": "t2.micro",
            "AssociatePublicIpAddress": False,
            # Hardened against EC2_IMDSV1_ENABLED as well. A fixture that is
            # hardened for one instance rule and silent on another is not a clean
            # resource, and test_no_rule_reports_the_hardened_dataset is the
            # assertion that says so.
            "MetadataOptions": {"HttpTokens": "required"}
        }
    },

    # Wildcards everywhere except where they matter: the action is scoped to a
    # service, the Allow names one bucket, and the only "*" resource is a Deny.
    "IAM_WILDCARD_PERMISSIONS": {
        "id": "HardenedRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "hardened-scoped-role",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Policies": [
                {
                    "PolicyName": "scoped-bucket-access",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "arn:aws:s3:::hardened-private-bucket/*"
                            },
                            {
                                "Effect": "Deny",
                                "Action": "iam:*",
                                "Resource": "*"
                            }
                        ]
                    }
                }
            ]
        }
    },

    "ELB_INTERNET_FACING": {
        "id": "HardenedLoadBalancer",
        "type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "raw_properties": {
            "Name": "hardened-lb",
            "Scheme": "internal",
            "Type": "application"
        }
    }
}


# Fixture key -> the `id` of the rule that key's pair exercises.
#
# The fixture keys stayed as readable names when the canonical ruleset was
# adopted, because a fixture called S3_PUBLIC_ACL says what it is and
# "aws_config:S3_BUCKET_PUBLIC_READ_PROHIBITED:AWS::S3::Bucket" says where it
# came from. This is the join between the two.
FIXTURE_RULE_ID = {
    "RESTRICTED_COMMON_PORTS":
        "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroup",

    "SG_INGRESS_UNRESTRICTED":
        "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroupIngress",

    "SG_INGRESS_BLOCKED_PORT":
        "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroupIngress",

    "SG_SSH_OPEN":
        "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup",

    "S3_PUBLIC_ACL":
        "aws_config:S3_BUCKET_PUBLIC_READ_PROHIBITED:AWS::S3::Bucket",

    "S3_BUCKET_LEVEL_PUBLIC_ACCESS":
        "aws_config:S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED:AWS::S3::Bucket",

    "RDS_UNENCRYPTED":
        "aws_config:RDS_STORAGE_ENCRYPTED:AWS::RDS::DBInstance",

    "REQUIRED_TAGS_INSTANCE":
        "aws_config:REQUIRED_TAGS:AWS::EC2::Instance",

    "REQUIRED_TAGS_BUCKET":
        "aws_config:REQUIRED_TAGS:AWS::S3::Bucket",

    "REQUIRED_TAGS_DATABASE":
        "aws_config:REQUIRED_TAGS:AWS::RDS::DBInstance",

    "S3_WILDCARD_POLICY": "S3_WILDCARD_POLICY",
    "RDS_PUBLICLY_ACCESSIBLE": "RDS_PUBLICLY_ACCESSIBLE",
    "EC2_PUBLIC_IP": "EC2_PUBLIC_IP",
    "EC2_IMDSV1_ENABLED": "EC2_IMDSV1_ENABLED",
    "IAM_WILDCARD_PERMISSIONS": "IAM_WILDCARD_PERMISSIONS",
    "IAM_TRUST_POLICY_WILDCARD": "IAM_TRUST_POLICY_WILDCARD",
    "ELB_INTERNET_FACING": "ELB_INTERNET_FACING"
}

# The tag every REQUIRED_TAGS rule looks for. A hardened fixture of a tagged
# resource type has to carry it, or the resource is clean for the rule its own
# pair is about and reported by REQUIRED_TAGS, and
# test_hardened_resource_produces_no_finding_at_all fails for a reason that has
# nothing to do with the rule under test.
REQUIRED_TAG = [{"Key": "CostCenter", "Value": "capstone"}]

# Fully locked-down bucket settings, so a hardened bucket fixture is clean for
# every bucket rule and not only for its own.
BLOCKED_PUBLIC_ACCESS = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True
}


# -- Fixtures for the canonical rules adopted after the pairs above were written

VULNERABLE_RESOURCES.update({

    # A blocked port on the standalone ingress spelling. The nested spelling is
    # covered by RESTRICTED_COMMON_PORTS above; this is the shape that had no
    # rule indexed against it at all until the per-type copies were added.
    "SG_INGRESS_BLOCKED_PORT": {
        "id": "VulnerableRdpIngressRule",
        "type": "AWS::EC2::SecurityGroupIngress",
        "raw_properties": {
            "GroupId": "SomeSecurityGroup",
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "CidrIp": "0.0.0.0/0"
        }
    },

    # SSH open to the world, nested in a security group. Port 22 is not in the
    # blocked-port list, so this fixture is caught by INCOMING_SSH_DISABLED and
    # by nothing else, which is what makes it a pair for that rule alone.
    "SG_SSH_OPEN": {
        "id": "VulnerableSshSecurityGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "SSH open to the world",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    },

    # No PublicAccessBlockConfiguration at all, which is the common case and the
    # insecure default. The projection fills all four flags with False for
    # exactly this reason, so a rule asking `BlockPublicAcls equals false`
    # matches a template that never mentioned the block.
    "S3_BUCKET_LEVEL_PUBLIC_ACCESS": {
        "id": "UnblockedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "unblocked-bucket",
            "AccessControl": "Private",
            "Tags": REQUIRED_TAG
        }
    },

    "RDS_UNENCRYPTED": {
        "id": "UnencryptedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "unencrypted-db",
            "Engine": "mysql",
            "PubliclyAccessible": False,
            "StorageEncrypted": False,
            "Tags": REQUIRED_TAG
        }
    },

    "REQUIRED_TAGS_INSTANCE": {
        "id": "UntaggedInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-44444444444444444",
            "InstanceType": "t3.micro",
            "AssociatePublicIpAddress": False,
            "MetadataOptions": {"HttpTokens": "required"}
        }
    },

    "REQUIRED_TAGS_BUCKET": {
        "id": "UntaggedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "untagged-bucket",
            "AccessControl": "Private",
            "PublicAccessBlockConfiguration": dict(BLOCKED_PUBLIC_ACCESS)
        }
    },

    "REQUIRED_TAGS_DATABASE": {
        "id": "UntaggedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "untagged-db",
            "Engine": "mysql",
            "PubliclyAccessible": False,
            "StorageEncrypted": True
        }
    }
})


HARDENED_RESOURCES.update({

    # Same port, scoped to the VPC. If this reports, the rule is matching on the
    # port alone and would flag every bastion host in the corpus.
    "SG_SSH_OPEN": {
        "id": "HardenedSshSecurityGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "SSH restricted to the VPC",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "10.0.0.0/8"
                }
            ]
        }
    },

    "SG_INGRESS_BLOCKED_PORT": {
        "id": "HardenedRdpIngressRule",
        "type": "AWS::EC2::SecurityGroupIngress",
        "raw_properties": {
            "GroupId": "SomeSecurityGroup",
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "CidrIp": "10.0.0.0/8"
        }
    },

    "S3_BUCKET_LEVEL_PUBLIC_ACCESS": {
        "id": "BlockedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "blocked-bucket",
            "AccessControl": "Private",
            "PublicAccessBlockConfiguration": dict(BLOCKED_PUBLIC_ACCESS),
            "Tags": REQUIRED_TAG
        }
    },

    "RDS_UNENCRYPTED": {
        "id": "EncryptedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "encrypted-db",
            "Engine": "mysql",
            "PubliclyAccessible": False,
            "StorageEncrypted": True,
            "Tags": REQUIRED_TAG
        }
    },

    "REQUIRED_TAGS_INSTANCE": {
        "id": "TaggedInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-55555555555555555",
            "InstanceType": "t3.micro",
            "AssociatePublicIpAddress": False,
            "MetadataOptions": {"HttpTokens": "required"},
            "Tags": REQUIRED_TAG
        }
    },

    "REQUIRED_TAGS_BUCKET": {
        "id": "TaggedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "tagged-bucket",
            "AccessControl": "Private",
            "PublicAccessBlockConfiguration": dict(BLOCKED_PUBLIC_ACCESS),
            "Tags": REQUIRED_TAG
        }
    },

    "REQUIRED_TAGS_DATABASE": {
        "id": "TaggedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "tagged-db",
            "Engine": "mysql",
            "PubliclyAccessible": False,
            "StorageEncrypted": True,
            "Tags": REQUIRED_TAG
        }
    }
})


def harden_for_required_tags():
    """Give every hardened fixture of a tagged type the tag REQUIRED_TAGS wants.

    The pairs written before the canonical adoption predate REQUIRED_TAGS, so
    their hardened halves are untagged and are reported by it. Patched in one
    place rather than by hand, so a fixture added later cannot be forgotten.
    """

    # split on the first two colons, not the last: a composite id ends in a
    # resource type that contains colons of its own ("AWS::EC2::Instance").
    tagged_types = {
        rule_id.split(":", 2)[2]
        for rule_id in FIXTURE_RULE_ID.values()
        if rule_id.startswith("aws_config:REQUIRED_TAGS:")
    }

    for resource in HARDENED_RESOURCES.values():

        if resource["type"] not in tagged_types:
            continue

        resource["raw_properties"].setdefault("Tags", REQUIRED_TAG)


def harden_buckets_against_public_access():
    """Block public access on every hardened bucket fixture.

    Same reason as the tags: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED reads the
    absence of the block as the finding, so a hardened bucket that never mentions
    it is reported.
    """

    for resource in HARDENED_RESOURCES.values():

        if resource["type"] != "AWS::S3::Bucket":
            continue

        resource["raw_properties"].setdefault(
            "PublicAccessBlockConfiguration",
            dict(BLOCKED_PUBLIC_ACCESS)
        )


harden_for_required_tags()
harden_buckets_against_public_access()


FIXTURE_KEYS = sorted(FIXTURE_RULE_ID)

RULE_IDS = sorted(FIXTURE_RULE_ID.values())


# -----------------------------

def load_rules(rules_path):
    """The shipped rule set, in file order."""

    return RuleEngine(rules_path).rules


def rule_by_id(rules_path, rule_id):
    return next(
        rule
        for rule in load_rules(rules_path)
        if rule.get("id") == rule_id
    )


def prepared(resources):
    """Resources as the rule engine sees them in the real pipeline.

    project_all before process_resources, because the ruleset is written against
    the abstract vocabulary (`ingress.port`, `tags`, `BucketPolicy.AllowsPublicRead`)
    and process_resources only copies an `attributes` block that is already there.
    A test that skipped the projection would evaluate every canonical rule against
    an empty vocabulary, so every one of them would silently match nothing — which
    is precisely the bug this file exists to catch.
    """

    from processing.attributes import project_all

    return process_resources(project_all(list(resources)))


def matched_rule_ids(rules_path, resource):
    """Rule ids that fire on one normalized resource, through the real pipeline."""

    engine = RuleEngine(rules_path)

    findings = engine.evaluate_all(prepared([resource]))

    return {finding["rule_id"] for finding in findings}


def all_findings(rules_path, resources):
    engine = RuleEngine(rules_path)

    return engine.evaluate_all(prepared(resources))


# -----------------------------

@pytest.mark.parametrize("fixture_key", FIXTURE_KEYS)
def test_rule_matches_its_vulnerable_resource(rules_path, fixture_key):
    assert FIXTURE_RULE_ID[fixture_key] in matched_rule_ids(
        rules_path,
        VULNERABLE_RESOURCES[fixture_key]
    )


@pytest.mark.parametrize("fixture_key", FIXTURE_KEYS)
def test_rule_ignores_the_hardened_version(rules_path, fixture_key):
    """The half that catches an over-broad condition tree."""

    assert FIXTURE_RULE_ID[fixture_key] not in matched_rule_ids(
        rules_path,
        HARDENED_RESOURCES[fixture_key]
    )


@pytest.mark.parametrize("fixture_key", FIXTURE_KEYS)
def test_hardened_resource_produces_no_finding_at_all(rules_path, fixture_key):
    """Stronger than the test above: no *other* rule on the same resource type may
    fire on the hardened resource either.
    """

    assert matched_rule_ids(
        rules_path,
        HARDENED_RESOURCES[fixture_key]
    ) == set()


def test_every_rule_has_both_halves_declared():
    """Adding a rule to the YAML without adding its pair of fixtures would
    go unnoticed by the parametrized tests, so the three tables are checked to
    name the same fixtures.
    """

    assert set(VULNERABLE_RESOURCES) == set(FIXTURE_RULE_ID)
    assert set(HARDENED_RESOURCES) == set(FIXTURE_RULE_ID)


def test_every_testable_rule_has_a_fixture_pair(rules_path):
    """THE COVERAGE GUARD.

    A rule added to the YAML with no fixture pair is a rule nobody has shown
    fires on anything, and the parametrized tests above cannot notice it because
    they iterate over the fixtures. The only rules allowed to have no pair are the
    account-scoped ones, which no template can declare a resource for.
    """

    testable = {
        rule["id"]
        for rule in load_rules(rules_path)
        if rule.get("resource_type") not in UNTESTABLE_RESOURCE_TYPES
    }

    assert testable == set(FIXTURE_RULE_ID.values())


def test_fixture_resource_types_agree_with_their_rule(rules_path):
    """The engine indexes rules by resource_type, so a fixture typed wrongly would
    never reach its rule, and the hardened half would pass for free.
    """

    for fixture_key, rule_id in FIXTURE_RULE_ID.items():
        resource_type = rule_by_id(rules_path, rule_id)["resource_type"]

        assert VULNERABLE_RESOURCES[fixture_key]["type"] == resource_type
        assert HARDENED_RESOURCES[fixture_key]["type"] == resource_type


# -----------------------------

def test_every_rule_declares_the_required_fields(rules_path):
    """`severity` is deliberately not required. See SEVERITY_BY_SEMANTIC."""

    for rule in load_rules(rules_path):

        assert rule.get("id")
        assert rule.get("source_id")
        assert rule.get("resource_type")
        assert rule.get("semantic")
        assert rule.get("conditions")
        assert rule.get("attack_techniques")
        assert rule.get("summary")

        state = rule.get("state")

        assert isinstance(state, dict)
        assert state.get("id")
        assert state.get("display_name")


def test_no_rule_declares_a_severity(rules_path):
    """THE SEVERITY GUARD.

    Severity is derived from the semantic in security_state_graph/semantics, in one table, so
    that nobody has to defend a number rule by rule. A rule that declares its own
    severity wins over that table (see finding_severity), which is how the
    privilege escalation detector keeps its sharper values — but a *rule* doing it
    means the file has quietly gone back to per-rule numbers.
    """

    declaring = [
        rule["id"]
        for rule in load_rules(rules_path)
        if rule.get("severity")
    ]

    assert declaring == []


def test_rule_ids_are_unique(rules_path):
    ids = [rule["id"] for rule in load_rules(rules_path)]

    assert len(ids) == len(set(ids))


def test_the_required_checks_are_all_present(rules_path):
    source_ids = {rule["source_id"] for rule in load_rules(rules_path)}

    assert REQUIRED_SOURCE_IDS.issubset(source_ids)


def test_state_ids_are_unique_per_resource_type(rules_path):
    """A finding carries the state id, not the rule id, into the graph.

    Unique per resource type rather than outright: the canonical file writes one
    check once per type it applies to, so REQUIRED_TAGS raises
    `required_tag_missing` on three types and the two network checks each have a
    second copy for the standalone ingress spelling. Those are the same state on
    different resources, which is correct. Two *different* checks sharing a state
    id would not be.
    """

    seen = [
        (rule["state"]["id"], rule["resource_type"])
        for rule in load_rules(rules_path)
    ]

    assert len(seen) == len(set(seen))

    # And a state id must always mean the same check, whichever type it is on.
    by_state = {}

    for rule in load_rules(rules_path):
        state_id = rule["state"]["id"]

        assert by_state.setdefault(state_id, rule["source_id"]) == rule["source_id"]


def test_every_semantic_is_in_the_allowed_vocabulary(rules_path):
    for rule in load_rules(rules_path):
        assert rule["semantic"] in ALLOWED_SEMANTICS, rule["id"]


def test_every_semantic_has_a_path_role(rules_path):
    """THE SILENT-IGNORE GUARD.

    security_state_graph/semantics sorts semantics into ways in, authority gains, and neither.
    A semantic in none of those three is a finding the search reads and silently
    does nothing with, which is how `network_control` came to be reported and
    ignored for a whole commit while being the most important semantic in the
    canonical file.
    """

    from security_state_graph.semantics import (
        AUTHORITY_SEMANTICS,
        ENTRY_SEMANTICS,
        SEVERITY_BY_SEMANTIC
    )

    from security_state_graph.semantics import NON_PATH_SEMANTICS

    classified = (
        set(ENTRY_SEMANTICS) | set(AUTHORITY_SEMANTICS) | set(NON_PATH_SEMANTICS)
    )

    # Every semantic the PARSER can emit, not only the ones rules use today. A
    # semantic missing from the path-role map is a finding the search reads and
    # silently ignores, and checking only what is in use meant a new one slipped
    # through — which is how `connection` went unclassified.
    assert set(ALLOWED_SEMANTICS) - classified == set(), sorted(
        set(ALLOWED_SEMANTICS) - classified
    )

    for rule in load_rules(rules_path):
        semantic = rule["semantic"]

        assert semantic in classified, (rule["id"], semantic)

        # And it has to be weighable, or every finding of that semantic scores
        # as the unknown-severity default and the ranking stops meaning anything.
        assert SEVERITY_BY_SEMANTIC.get(semantic) in ALLOWED_SEVERITIES

    # A semantic cannot be both a way in and a gain of authority: is_exploitable
    # would then be satisfiable by the entry finding alone.
    assert not set(ENTRY_SEMANTICS) & set(AUTHORITY_SEMANTICS)


def test_the_ruleset_can_produce_a_path_at_all(rules_path):
    """An entry semantic and an authority semantic both have to exist.

    With only one of the two, every candidate route is rejected and the tool
    reports zero attack paths while still reporting findings — which is exactly
    what the canonical set does on its own, and why our five rules are kept.
    """

    from security_state_graph.semantics import (
        AUTHORITY_SEMANTICS,
        ENTRY_SEMANTICS
    )

    semantics = {rule["semantic"] for rule in load_rules(rules_path)}

    assert semantics & set(ENTRY_SEMANTICS)
    assert semantics & set(AUTHORITY_SEMANTICS)


def test_every_canonical_rule_declares_a_reference(rules_path):
    """Required of the canonical rules, which cite an AWS Config managed rule.

    Not required of ours: EC2_IMDSV1_ENABLED and the IAM wildcard rules are our
    own reading of a weakness and have no managed rule to point at. Claiming one
    would be a citation nobody can check, which is worse than none.
    """

    for rule in load_rules(rules_path):

        if rule.get("origin") != "aws_config":
            continue

        references = rule.get("references")

        assert isinstance(references, list), rule["id"]
        assert references, rule["id"]

        for reference in references:
            assert reference.get("source")
            assert reference.get("id")
            assert str(reference.get("url", "")).startswith("https://")


def test_field_order_is_consistent_in_every_rule(rules_path):
    """The keys a rule carries appear in the shared order.

    A relative-order check rather than an equality one, because the canonical
    rules and ours do not carry the same key set. See FIELD_ORDER.
    """

    for rule in load_rules(rules_path):

        keys = list(rule.keys())

        unknown = [key for key in keys if key not in FIELD_ORDER]

        assert unknown == [], (rule["id"], unknown)

        positions = [FIELD_ORDER.index(key) for key in keys]

        assert positions == sorted(positions), (rule["id"], keys)


# -----------------------------

def test_attack_techniques_are_well_formed(rules_path):
    """The exporter emits these verbatim as the "techniques" of an attack path, so
    each needs a well-formed id and a trimmed, non-empty name.
    """

    for rule in load_rules(rules_path):
        techniques = rule["attack_techniques"]

        assert isinstance(techniques, list)
        assert techniques

        for technique in techniques:
            assert ATTACK_ID_PATTERN.match(technique["id"])
            assert technique["name"]
            assert technique["name"].strip() == technique["name"]


def test_attack_technique_ids_are_unique_within_a_rule(rules_path):
    for rule in load_rules(rules_path):
        ids = [technique["id"] for technique in rule["attack_techniques"]]

        assert len(ids) == len(set(ids))


def test_the_same_technique_id_always_carries_the_same_name(rules_path):
    """T1190 is shared by four rules. Two spellings of one technique would be
    exported as two different strings for the same thing.
    """

    names = {}

    for rule in load_rules(rules_path):
        for technique in rule["attack_techniques"]:
            identifier = technique["id"]

            assert names.setdefault(identifier, technique["name"]) == technique["name"]


# -----------------------------

def test_rules_matching_over_a_list_use_scope(rules_path):
    """Phase 4 added "scope" and Phase 3 has to opt in."""

    def scopes_in(node):
        if isinstance(node, dict):
            found = [node["scope"]] if "scope" in node else []

            for value in node.values():
                found.extend(scopes_in(value))

            return found

        if isinstance(node, list):
            return [
                scope
                for item in node
                for scope in scopes_in(item)
            ]

        return []

    for rule_id in (
        "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroup",
        "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroupIngress",
        "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup",
        "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroupIngress"
    ):

        scopes = scopes_in(rule_by_id(rules_path, rule_id)["conditions"])

        # Every AND over the ingress list must be scoped to it, whatever the
        # branch count is — a new blocked port adds a branch and must not be able
        # to add an unscoped one. Unscoped, protocol/port/cidr can be satisfied by
        # three different ingress entries and the rule reports a clean group.
        assert scopes, rule_id
        assert set(scopes) == {"ingress"}, rule_id

    assert scopes_in(
        rule_by_id(rules_path, "S3_WILDCARD_POLICY")["conditions"]
    ) == ["PolicyDocument.Statement"]

    assert scopes_in(
        rule_by_id(rules_path, "IAM_WILDCARD_PERMISSIONS")["conditions"]
    ) == [
        "Policies.PolicyDocument.Statement",
        "AssumeRolePolicyDocument.Statement"
    ]


def test_scoping_the_existing_rule_did_not_lose_the_real_finding(
    rules_path,
    real_resource_dicts
):
    """The opt-in regression check the task asks for: OpenSecurityGroup opens 3389
    to the world on one ingress entry, and the scoped rules must still report it.
    """

    findings = all_findings(rules_path, real_resource_dicts)

    # AppSecurityGroup opens 22 only, so it is caught by INCOMING_SSH_DISABLED and
    # not by the blocked-port rule. Asserted per check rather than together,
    # because "some ingress rule fired on both groups" would pass even if the
    # scoping had collapsed one of them.
    from security_state_graph.semantics import finding_severity

    by_check = {
        "RESTRICTED_INCOMING_TRAFFIC": ["OpenSecurityGroup"],
        "INCOMING_SSH_DISABLED": ["AppSecurityGroup", "OpenSecurityGroup"]
    }

    for source_id, expected in by_check.items():

        matched = [
            finding
            for finding in findings
            if finding["source_id"] == source_id
        ]

        assert sorted(finding["resource"] for finding in matched) == expected

        for finding in matched:
            assert finding["semantic"] == "network_control"
            assert finding_severity(finding) == "high"


# -----------------------------

def test_at_least_six_findings_on_the_real_dataset(
    rules_path,
    real_resource_dicts
):
    """One rule produced one finding, and one finding produces no attack path."""

    findings = all_findings(rules_path, real_resource_dicts)

    assert len(findings) >= 6


def test_every_real_resource_a_rule_applies_to_is_covered(
    rules_path,
    real_resource_dicts
):
    """Both halves of rule coverage on the shipped dataset, phrased against the
    rule set itself: every resource of a type some rule applies to has a finding,
    and no other resource does.
    """

    # evaluate_findings, not the rule engine alone: privilege escalation
    # findings are part of what the graph joins, and a role that holds
    # iam:PassRole without a wildcard policy is covered by those and by no rule.
    from security_state_graph.state_graph import evaluate_findings
    from main import build_infra_from_resources

    findings = evaluate_findings(
        build_infra_from_resources(real_resource_dicts),
        rules_path
    )

    covered = {finding["resource"] for finding in findings}

    ruled_types = {
        rule["resource_type"]
        for rule in RuleEngine(rules_path).rules
        if isinstance(rule, dict) and rule.get("resource_type")
    }

    expected = {
        resource["id"]
        for resource in real_resource_dicts
        if resource["type"] in ruled_types
    }

    assert covered == expected

    # The dataset must actually exercise this distinction, or the split above is
    # two names for the same set and the second half of the claim is untested.
    assert expected
    assert {resource["id"] for resource in real_resource_dicts} - expected


def test_real_findings_carry_the_fields_the_graph_joins_on(
    rules_path,
    real_resource_dicts
):
    from security_state_graph.semantics import finding_severity

    resource_ids = {resource["id"] for resource in real_resource_dicts}
    source_ids = {rule["source_id"] for rule in load_rules(rules_path)}

    for finding in all_findings(rules_path, real_resource_dicts):

        assert finding["resource"] in resource_ids
        assert finding["source_id"] in source_ids
        assert finding["state"]
        assert finding["semantic"] in ALLOWED_SEMANTICS

        # The severity the graph joins on is the derived one, because the rules
        # no longer declare any.
        assert finding_severity(finding) in ALLOWED_SEVERITIES


def test_real_dataset_can_supply_both_halves_of_a_path(
    rules_path,
    real_resource_dicts
):
    """The minimum shape an attack path needs: something to enter through and
    something with the authority to reach the target. The shipped findings must
    supply both.
    """

    from security_state_graph.semantics import (
        AUTHORITY_SEMANTICS,
        ENTRY_SEMANTICS
    )

    findings = all_findings(rules_path, real_resource_dicts)

    semantics = {finding["semantic"] for finding in findings}

    assert semantics & set(ENTRY_SEMANTICS)
    assert semantics & set(AUTHORITY_SEMANTICS)


def test_no_rule_reports_the_hardened_dataset(rules_path):
    """Every hardened fixture evaluated together: a whole clean account produces
    no findings at all.
    """

    findings = all_findings(
        rules_path,
        [HARDENED_RESOURCES[key] for key in FIXTURE_KEYS]
    )

    assert findings == []


# -----------------------------

def scope_paths(node, found=None):
    """Every `scope:` value in a conditions tree, in document order."""

    if found is None:
        found = []

    if isinstance(node, dict):

        if isinstance(node.get("scope"), str):
            found.append(node["scope"])

        for value in node.values():
            scope_paths(value, found)

    elif isinstance(node, list):

        for item in node:
            scope_paths(item, found)

    return found


def test_every_scope_path_resolves_to_elements_on_the_shipped_dataset(
    rules_path,
    real_resource_dicts
):
    """THE SILENT-COLLAPSE GUARD FOR SCOPED RULES.

    A scope path that resolves to no elements makes its subtree False on every
    resource, so the rule quietly never fires. Every scope in the rule set must
    resolve to elements on at least one resource the rule applies to.
    """

    # The shipped dataset plus every vulnerable fixture, because some rules apply
    # to a resource type the 15-resource dataset does not contain — the standalone
    # AWS::EC2::SecurityGroupIngress spelling among them. Without the fixtures
    # those rules would have no resource to resolve against and the check would
    # have to be skipped for exactly the rules most likely to be wrong.
    resources = prepared(
        json.loads(json.dumps(
            list(real_resource_dicts) + list(VULNERABLE_RESOURCES.values())
        ))
    )

    checked = 0

    for rule in RuleEngine(rules_path).rules:

        scopes = scope_paths(rule.get("conditions"))

        if not scopes:
            continue

        applicable = [
            resource
            for resource in resources
            if resource.get("type") == rule.get("resource_type")
        ]

        assert applicable, rule.get("id")

        for scope in scopes:

            resolved = [
                get_scope_elements(resource, scope)
                for resource in applicable
            ]

            assert any(resolved), (rule.get("id"), scope)

            checked = checked + 1

    # The scoped rules are the privilege half of the rule set; if this loop ever
    # stops finding scopes, the test above passes for free.
    assert checked >= 4


# -----------------------------
# Grounding in the ATT&CK IaaS matrix.
#
# The ruleset used to cite T1133 (External Remote Services) and T1567.002
# (Exfiltration to Cloud Storage). Neither is in the IaaS matrix — cloud initial
# access is T1190/T1199/T1078, cloud exfiltration is T1048/T1537 — so the model
# was being fed technique ids that do not belong to the matrix we claim to use.
# Nothing detected that, because the technique list was prose.

def test_every_rule_technique_is_in_the_iaas_matrix(rules_path):
    """THE CITATION GUARD.

    Every technique a rule cites must be in the ATT&CK IaaS matrix, so the model
    is never fed an id from outside the matrix this project claims to use.
    """

    from engine.attack_catalog import is_known

    for rule in RuleEngine(rules_path).rules:

        for technique in rule.get("attack_techniques") or []:

            assert is_known(technique["id"]), (rule["id"], technique["id"])


def test_every_rule_technique_name_matches_the_matrix(rules_path):
    """A right id under a wrong name is a citation nobody can check."""

    from engine.attack_catalog import technique_name

    for rule in RuleEngine(rules_path).rules:

        for technique in rule.get("attack_techniques") or []:

            assert technique["name"] == technique_name(technique["id"]), (
                rule["id"],
                technique["id"]
            )
