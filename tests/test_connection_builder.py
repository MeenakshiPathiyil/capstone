"""Tests for the two edge-building passes."""

from engine.connection_builder import (
    action_covers_service,
    build_capability_edges,
    build_connections,
    infer_relation,
    is_wildcard_allow
)
from main import build_infra_from_resources
from models.cloud_resource import CloudResource


# -----------------------------

def all_edges(infra):
    """Every edge in the model as (source, target, type, relation) tuples."""

    return [
        (
            resource.id,
            connection["target"],
            connection["type"],
            connection["relation"]
        )
        for resource in infra.all_resources()
        for connection in resource.connections
    ]


def edges_from(infra, resource_id):
    """The edges leaving one resource, as (target, type, relation) tuples."""

    return [
        (edge[1], edge[2], edge[3])
        for edge in all_edges(infra)
        if edge[0] == resource_id
    ]


def targets_from(infra, resource_id, relation_type=None):
    """The ids one resource reaches, optionally narrowed to one edge type."""

    return [
        target
        for target, edge_type, _ in edges_from(infra, resource_id)
        if relation_type is None or edge_type == relation_type
    ]


# -----------------------------

# Properties that reference resources nobody declared. An unresolvable
# reference is not an edge, whatever its tag claims.
DANGLING_RESOURCES = [
    {
        "id": "DanglingInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-22222222222222222",
            "IamInstanceProfile": "MissingRole",
            "SecurityGroupIds": [
                "MissingSecurityGroup"
            ],
            "BackupBucket": "MissingBucket"
        },
        "semantic_properties": {
            "ImageId": "unknown",
            "IamInstanceProfile": "identity",
            "SecurityGroupIds[0]": "network_control",
            "BackupBucket": "unknown"
        }
    }
]

# A group that lists itself as its own ingress source — legal in AWS, and a
SELF_REFERENCE_RESOURCES = [
    {
        "id": "SelfReferencingGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "Members may talk to each other",
            "SourceSecurityGroupId": "SelfReferencingGroup",
            "MirrorOf": "SelfReferencingGroup"
        },
        "semantic_properties": {
            "GroupDescription": "unknown",
            "SourceSecurityGroupId": "network_control",
            "MirrorOf": "unknown"
        }
    },
    {
        "id": "SelfGrantingBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "self-granting-bucket",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "*"
                    }
                ]
            }
        },
        "semantic_properties": {
            "BucketName": "unknown",
            "PolicyDocument.Statement[0].Effect": "capability",
            "PolicyDocument.Statement[0].Action": "capability",
            "PolicyDocument.Statement[0].Resource": "capability"
        }
    }
]

# Least privilege, written out: one Allow, on one concrete ARN. The ARN ends in
# a wildcard, which is what makes an exact "*" test necessary.
SCOPED_POLICY_RESOURCES = [
    {
        "id": "ScopedRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": "scoped-role",
            "Policies": [
                {
                    "PolicyName": "one-bucket-read",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::scoped-bucket/*"
                            },
                            {
                                "Effect": "Deny",
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
            "Policies[0].PolicyDocument.Statement[0].Resource": "capability",
            "Policies[0].PolicyDocument.Statement[1].Effect": "unknown",
            "Policies[0].PolicyDocument.Statement[1].Action": "capability",
            "Policies[0].PolicyDocument.Statement[1].Resource": "capability"
        }
    },
    {
        "id": "ScopedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": "scoped-bucket"
        },
        "semantic_properties": {
            "BucketName": "unknown"
        }
    },
    {
        "id": "ScopedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "scoped-db",
            "Engine": "postgres"
        },
        "semantic_properties": {
            "DBInstanceIdentifier": "unknown",
            "Engine": "unknown"
        }
    }
]

# A bucket policy granting "*" while a database sits next to it in the same
RESOURCE_POLICY_RESOURCES = [
    {
        "id": "AttachedPolicy",
        "type": "AWS::S3::BucketPolicy",
        "raw_properties": {
            "Bucket": "AttachedBucket",
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
        },
        "semantic_properties": {
            "Bucket": "unknown",
            "PolicyDocument.Statement[0].Effect": "capability",
            "PolicyDocument.Statement[0].Principal": "capability",
            "PolicyDocument.Statement[0].Action": "capability",
            "PolicyDocument.Statement[0].Resource": "capability"
        }
    },
    {
        "id": "AttachedBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {"BucketName": "attached-bucket"},
        "semantic_properties": {"BucketName": "unknown"}
    },
    {
        "id": "UnrelatedDatabase",
        "type": "AWS::RDS::DBInstance",
        "raw_properties": {
            "DBInstanceIdentifier": "unrelated-db",
            "Engine": "postgres"
        },
        "semantic_properties": {
            "DBInstanceIdentifier": "unknown",
            "Engine": "unknown"
        }
    }
]

# One untagged reference per target type, so the inferred classification can be
INFERENCE_RESOURCES = [
    {
        "id": "ReferencingInstance",
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "AttachedRole": "InferenceRole",
            "AttachedGroup": "InferenceGroup",
            "AttachedBucket": "InferenceBucket",
            "AttachedBalancer": "InferenceBalancer",
            "AttachedAlarm": "InferenceQueueUnmapped",
            "TrustedBucket": "InferenceTrustBucket"
        },
        "semantic_properties": {
            "AttachedRole": "unknown",
            "AttachedGroup": "unknown",
            "AttachedBucket": "unknown",
            "AttachedBalancer": "unknown",
            "AttachedAlarm": "unknown",
            "TrustedBucket": "trust"
        }
    },
    {
        "id": "InferenceRole",
        "type": "AWS::IAM::Role",
        "raw_properties": {"RoleName": "inference-role"},
        "semantic_properties": {"RoleName": "unknown"}
    },
    {
        "id": "InferenceGroup",
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {"GroupDescription": "inference group"},
        "semantic_properties": {"GroupDescription": "unknown"}
    },
    {
        "id": "InferenceBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {"BucketName": "inference-bucket"},
        "semantic_properties": {"BucketName": "unknown"}
    },
    {
        "id": "InferenceTrustBucket",
        "type": "AWS::S3::Bucket",
        "raw_properties": {"BucketName": "inference-trust-bucket"},
        "semantic_properties": {"BucketName": "unknown"}
    },
    {
        "id": "InferenceBalancer",
        "type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "raw_properties": {"Name": "inference-lb"},
        "semantic_properties": {"Name": "unknown"}
    },
    # A type in no classification table at all. It is the fallback case, so it
    # has to be a type nothing else in the repo cares about — an alarm is inert
    # in every table (not data, not compute, not a principal, not traffic).
    {
        "id": "InferenceQueueUnmapped",
        "type": "AWS::CloudWatch::Alarm",
        "raw_properties": {"AlarmName": "inference-alarm"},
        "semantic_properties": {"AlarmName": "unknown"}
    }
]


# -----------------------------

def test_pre_existing_network_control_edge_survives(real_infra):
    """THE REGRESSION TEST."""

    assert ("OpenSecurityGroup", "network_control", "association") in edges_from(
        real_infra,
        "PublicEC2Instance"
    )

    # the flattener also emits the whole-list key "SecurityGroupIds"; that
    # must not produce a second, duplicate edge
    assert targets_from(real_infra, "PublicEC2Instance").count(
        "OpenSecurityGroup"
    ) == 1


def test_annotation_stays_authoritative_over_the_target_type(sample_infra):
    """A tag that *can* classify is not second-guessed. SampleRole reaches"""

    assert ("SampleBucket", "connection", "dependency") in edges_from(
        sample_infra,
        "SampleRole"
    )


# -----------------------------

def test_unclassified_reference_is_typed_by_the_target_type():
    """One untagged property per target type, classified by what it points at."""

    infra = build_infra_from_resources(INFERENCE_RESOURCES)

    edges = edges_from(infra, "ReferencingInstance")

    assert ("InferenceRole", "identity", "dependency") in edges
    assert ("InferenceGroup", "network_control", "association") in edges
    assert ("InferenceBucket", "connection", "dependency") in edges

    # a type the map does not know is still a reference, not a dropped edge
    assert ("InferenceBalancer", "traffic_path", "association") in edges
    # A type in no table at all still yields an edge, as a plain reference.
    assert ("InferenceQueueUnmapped", "connection", "dependency") in edges


def test_infer_relation_falls_back_for_an_unknown_target():
    infra = build_infra_from_resources(INFERENCE_RESOURCES)

    assert infer_relation(infra, "InferenceRole") == "identity"
    assert infer_relation(infra, "InferenceBalancer") == "traffic_path"
    assert infer_relation(infra, "InferenceQueueUnmapped") == "connection"

    # a target that is not in the model at all
    assert infer_relation(infra, "MissingResource") == "connection"


def test_dangling_reference_creates_no_edge():
    """Every property here names something that was never declared, including"""

    infra = build_infra_from_resources(DANGLING_RESOURCES)

    assert all_edges(infra) == []


def test_no_self_edges():
    """A resource referencing itself, once through an allowed category and once"""

    infra = build_infra_from_resources(SELF_REFERENCE_RESOURCES)

    assert all_edges(infra) == []


# -----------------------------

def test_wildcard_grant_reaches_every_data_resource(real_infra):
    """The privilege-escalation hop. OverPermissiveRole allows "*" on "*", which"""

    reached = targets_from(real_infra, "OverPermissiveRole", "capability")

    # a real IAM principal: the fan-out narrowing must not have touched it
    assert sorted(reached) == ["InsecureS3Bucket", "PublicRDS", "ReportsTable"]

    assert ("InsecureS3Bucket", "capability", "capability") in edges_from(
        real_infra,
        "OverPermissiveRole"
    )


def test_scoped_policy_does_not_fan_out():
    """THE DISCRIMINATING TEST."""

    infra = build_infra_from_resources(SCOPED_POLICY_RESOURCES)

    assert targets_from(infra, "ScopedRole", "capability") == []
    assert all_edges(infra) == []


def test_resource_attached_policy_does_not_fan_out():
    """THE OVER-CONNECTION."""

    infra = build_infra_from_resources(RESOURCE_POLICY_RESOURCES)

    assert targets_from(infra, "AttachedPolicy", "capability") == []

    assert edges_from(infra, "AttachedPolicy") == [
        ("AttachedBucket", "connection", "dependency")
    ]


def test_bucket_policy_reaches_only_the_bucket_it_is_attached_to(real_infra):
    """What is left after both fixes: one edge, to the bucket the policy names."""

    assert edges_from(real_infra, "PublicBucketPolicy") == [
        ("InsecureS3Bucket", "connection", "dependency")
    ]

    assert targets_from(real_infra, "PublicBucketPolicy").count(
        "InsecureS3Bucket"
    ) == 1


def test_wildcard_written_as_a_list_still_fans_out():
    """Resource: ["*"] is the same grant as Resource: "*", and Action: ["*"] is the"""

    resources = [
        {
            "id": "ListWildcardRole",
            "type": "AWS::IAM::Role",
            "raw_properties": {
                "RoleName": "list-wildcard-role",
                "Policies": [
                    {
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["*"],
                                    "Resource": ["*"]
                                }
                            ]
                        }
                    }
                ]
            },
            "semantic_properties": {
                "RoleName": "unknown"
            }
        },
        {
            "id": "ListWildcardSecret",
            "type": "AWS::SecretsManager::Secret",
            "raw_properties": {"Name": "db-password"},
            "semantic_properties": {"Name": "unknown"}
        },
        {
            "id": "ListWildcardKey",
            "type": "AWS::KMS::Key",
            "raw_properties": {"Description": "data key"},
            "semantic_properties": {"Description": "unknown"}
        }
    ]

    infra = build_infra_from_resources(resources)

    assert sorted(
        targets_from(infra, "ListWildcardRole", "capability")
    ) == ["ListWildcardKey", "ListWildcardSecret"]


def test_only_allow_statements_grant():
    """All four ways a statement fails to be an account-wide grant, and each of them"""

    assert is_wildcard_allow(
        {"Effect": "Allow", "Action": "*", "Resource": "*"}
    ) is True

    # Deny on "*" is a hardening measure, not an exposure
    assert is_wildcard_allow(
        {"Effect": "Deny", "Action": "*", "Resource": "*"}
    ) is False

    # the role's AssumeRolePolicyDocument allows, but grants no resource
    assert is_wildcard_allow(
        {"Effect": "Allow", "Action": "sts:AssumeRole"}
    ) is False

    # a concrete ARN is the scoping mechanism, trailing "*" and all
    assert is_wildcard_allow(
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::scoped-bucket/*"
        }
    ) is False

    # Action is required in IAM: a statement without one grants nothing, and
    # reading a missing field as a wildcard is how a fan-out gets invented
    assert is_wildcard_allow({"Effect": "Allow", "Resource": "*"}) is False


def test_an_action_scoped_grant_does_not_reach_another_service():
    """THE OVER-CONNECTION THIS SCOPING EXISTS TO PREVENT."""

    resources = [
        {
            "id": "ReaderRole",
            "type": "AWS::IAM::Role",
            "raw_properties": {
                "RoleName": "bucket-reader",
                "Policies": [
                    {
                        "PolicyName": "read-any-bucket",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*"
                                }
                            ]
                        }
                    }
                ]
            },
            "semantic_properties": {"RoleName": "unknown"}
        },
        {
            "id": "ReadableBucket",
            "type": "AWS::S3::Bucket",
            "raw_properties": {"BucketName": "readable"},
            "semantic_properties": {"BucketName": "unknown"}
        },
        {
            "id": "UnreachableDatabase",
            "type": "AWS::RDS::DBInstance",
            "raw_properties": {"DBInstanceIdentifier": "unreachable"},
            "semantic_properties": {"DBInstanceIdentifier": "unknown"}
        }
    ]

    infra = build_infra_from_resources(resources)

    # the bucket, because the grant really is account-wide within s3 ...
    assert targets_from(infra, "ReaderRole", "capability") == ["ReadableBucket"]

    # ... and not the database
    assert "UnreachableDatabase" not in targets_from(infra, "ReaderRole")

    # the same statement, read per service
    statement = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "*"
    }

    assert is_wildcard_allow(statement, "s3") is True
    assert is_wildcard_allow(statement, "rds") is False
    assert is_wildcard_allow(statement, "kms") is False

    # "s3:*" covers the service; "*" covers every service
    assert action_covers_service("s3:*", "s3") is True
    assert action_covers_service("s3:*", "rds") is False
    assert action_covers_service("*", "rds") is True
    assert action_covers_service(["rds:Describe*", "s3:GetObject"], "rds") is True
    assert action_covers_service("AdministratorAccess", "s3") is False


def test_a_conditional_grant_is_treated_as_scoped():
    """A Condition is how a wildcard is made narrow — a source IP range, an MFA"""

    resources = [
        {
            "id": "ConditionalRole",
            "type": "AWS::IAM::Role",
            "raw_properties": {
                "RoleName": "conditional-role",
                "Policies": [
                    {
                        "PolicyName": "office-network-only",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                    "Condition": {
                                        "IpAddress": {
                                            "aws:SourceIp": "10.0.0.0/8"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            "semantic_properties": {"RoleName": "unknown"}
        },
        {
            "id": "ConditionalBucket",
            "type": "AWS::S3::Bucket",
            "raw_properties": {"BucketName": "conditional"},
            "semantic_properties": {"BucketName": "unknown"}
        }
    ]

    infra = build_infra_from_resources(resources)

    assert targets_from(infra, "ConditionalRole", "capability") == []

    # the discriminating half: the same statement without the condition
    assert is_wildcard_allow(
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        "s3"
    ) is True

    assert is_wildcard_allow(
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
        },
        "s3"
    ) is False

    # an empty Condition block is not a condition
    assert is_wildcard_allow(
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {}
        },
        "s3"
    ) is True


def test_both_passes_are_idempotent(real_infra):
    """The passes are run by the pipeline; a later stage re-running one of them"""

    before = all_edges(real_infra)

    build_connections(real_infra)
    build_capability_edges(real_infra)

    assert all_edges(real_infra) == before


# -----------------------------

def test_compute_reaches_identity_through_its_instance_profile(real_infra):
    """The dataset's identity half, through the resource AWS actually puts in the"""

    assert (
        "OverPermissiveInstanceProfile", "identity", "dependency"
    ) in edges_from(real_infra, "PublicEC2Instance")

    assert ("OverPermissiveRole", "identity", "dependency") in edges_from(
        real_infra,
        "OverPermissiveInstanceProfile"
    )


def test_the_compute_to_data_chain_is_connected(real_infra):
    """The chain an attack path walks: instance -> profile -> role -> data."""

    assert "OverPermissiveInstanceProfile" in targets_from(
        real_infra,
        "PublicEC2Instance"
    )
    assert "OverPermissiveRole" in targets_from(
        real_infra,
        "OverPermissiveInstanceProfile"
    )
    assert "PublicRDS" in targets_from(real_infra, "OverPermissiveRole")


def test_the_instance_profile_does_not_fan_out_a_wildcard_it_does_not_hold(
    real_infra
):
    """AWS::IAM::InstanceProfile is in IAM_PRINCIPAL_TYPES, so the wildcard pass"""

    reached = targets_from(
        real_infra,
        "OverPermissiveInstanceProfile",
        "capability"
    )

    assert reached == []

    assert targets_from(real_infra, "OverPermissiveInstanceProfile") == [
        "OverPermissiveRole"
    ]


def test_parallel_edges_of_different_types_are_kept(parallel_edge_infra):
    """A design decision, stated as a test so the next phase inherits it."""

    types = sorted(
        edge_type
        for target, edge_type, _ in edges_from(parallel_edge_infra, "ParallelRole")
        if target == "ParallelBucket"
    )

    assert types == ["capability", "connection"]


def test_the_edge_store_refuses_an_exact_repeat():
    """The layer the suppression lives at, pinned."""

    resource = CloudResource(
        id="Repeater",
        type="AWS::IAM::Role",
        raw_properties={},
        semantic_properties={}
    )

    resource.add_connection("SomeBucket", "capability")
    resource.add_connection("SomeBucket", "capability")
    resource.add_connection("SomeBucket", "connection")

    assert [
        (connection["target"], connection["type"])
        for connection in resource.connections
    ] == [
        ("SomeBucket", "capability"),
        ("SomeBucket", "connection")
    ]


def test_real_dataset_edge_set_is_pinned(real_infra):
    """The true count, written out. This was "at least six" while the sixth edge"""

    edges = all_edges(real_infra)

    assert sorted(
        (source, target, edge_type)
        for source, target, edge_type, _ in edges
    ) == [
        ("AppInstanceProfile", "AppServerRole", "identity"),
        ("AppServerInstance", "AppInstanceProfile", "identity"),
        ("AppServerInstance", "AppSecurityGroup", "network_control"),

        # The pair carrying both a declared reference and a detected escalation:
        # the PassRole statement names DeploymentRole, and the catalogue reads the
        # same statement as PRIVESC_PASSROLE_LAMBDA_INVOKE.
        ("AppServerRole", "DeploymentRole", "escalation"),
        ("AppServerRole", "DeploymentRole", "identity"),

        ("DeploymentRole", "AppServerRole", "escalation"),
        ("DeploymentRole", "OverPermissiveRole", "escalation"),
        ("DeploymentRole", "ReportsTable", "capability"),
        ("IngestFunction", "DeploymentRole", "trust"),
        ("OverPermissiveInstanceProfile", "OverPermissiveRole", "identity"),
        ("OverPermissiveRole", "InsecureS3Bucket", "capability"),
        ("OverPermissiveRole", "PublicRDS", "capability"),
        ("OverPermissiveRole", "ReportsTable", "capability"),
        ("PublicBucketPolicy", "InsecureS3Bucket", "connection"),
        ("PublicEC2Instance", "OpenSecurityGroup", "network_control"),
        ("PublicEC2Instance", "OverPermissiveInstanceProfile", "identity")
    ], edges

    assert len(edges) == 16, edges


def test_every_edge_has_a_known_relation(real_infra):
    """"unknown" is what add_connection() falls through to for a category it was"""

    assert [
        edge
        for edge in all_edges(real_infra)
        if edge[3] == "unknown"
    ] == []


# -----------------------------
# Alignment with the upstream parser (capstone-feature-yaml-parser-normalization).
#
# parser/infra_parser.py is the source of normalized_resources.json. Its semantic
# vocabulary is NOT the same as ALLOWED_CATEGORIES here, and two of its outputs
# matter to the graph:
#
#   IamInstanceProfile  -> "identity"    (explicit KNOWN_FIELD_SEMANTICS entry)
#   Roles[0]            -> "capability"  (keyword-inferred, because there is no
#                                         iam::instanceprofile gating entry)
#
# "capability" is not in ALLOWED_CATEGORIES, so the compute -> identity chain
# depends on the target-type inference rather than on the annotation. If that
# fallback is ever removed the chain silently breaks and both attack paths vanish,
# which is why this is asserted against the value the parser really emits.

def test_a_parser_emitted_capability_annotation_still_links_profile_to_role(real_infra):
    profile = real_infra.get_resource("OverPermissiveInstanceProfile")

    assert profile.semantic_properties["Roles[0]"] == "capability"

    targets = [c["target"] for c in profile.connections]

    assert "OverPermissiveRole" in targets


def test_the_profile_link_is_typed_identity_despite_the_annotation(real_infra):
    """The relation comes from the target's type, not from the parser's word."""

    profile = real_infra.get_resource("OverPermissiveInstanceProfile")

    edge = [c for c in profile.connections if c["target"] == "OverPermissiveRole"][0]

    assert edge["type"] == "identity"
