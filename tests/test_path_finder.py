"""Tests for path finding, the exploitability policy and the risk score."""

import json

import pytest
import yaml

from attack_path.path_finder import (
    ATTACK_LEVEL_CRITICAL,
    ATTACK_LEVEL_HIGH,
    ATTACK_LEVEL_MEDIUM,
    CRITICAL_SCORE_THRESHOLD,
    DEFAULT_SEVERITY_WEIGHT,
    HIGH_SCORE_THRESHOLD,
    LENGTH_DAMPING_PER_HOP,
    MAX_DEPTH,
    PUBLIC_ENTRY_BOOST,
    SEVERITY_WEIGHTS,
    attack_level_for,
    build_attack_paths,
    data_targets,
    describe_path,
    entry_points,
    find_attack_paths,
    is_exploitable,
    is_public_entry,
    path_severity_total,
    score_path,
    severity_weight,
    walk_paths
)
from tests.conftest import data_theft_only
from security_state_graph.state_graph import SecurityStateGraph, evaluate_findings
from main import build_infra_from_resources


# -----------------------------

def role(resource_id, names=()):
    """An IAM role whose inline policy names `names`, one statement each."""

    statements = [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": name
        }
        for name in names
    ]

    semantics = {"RoleName": "unknown"}

    for index in range(len(statements)):

        prefix = f"Policies[0].PolicyDocument.Statement[{index}]"

        semantics[f"{prefix}.Effect"] = "unknown"
        semantics[f"{prefix}.Action"] = "capability"

        # "unknown" on the reference, so the edge is typed by the target's own
        # type — the same path through connection_builder the real dataset takes.
        semantics[f"{prefix}.Resource"] = "unknown"

    return {
        "id": resource_id,
        "type": "AWS::IAM::Role",
        "raw_properties": {
            "RoleName": resource_id.lower(),
            "Policies": [
                {
                    "PolicyName": f"{resource_id}-policy",
                    "PolicyDocument": {
                        "Statement": statements
                    }
                }
            ]
        },
        "semantic_properties": semantics
    }


def bucket(resource_id):
    """An S3 bucket, which is a DATA_TYPES target and reaches nothing."""

    return {
        "id": resource_id,
        "type": "AWS::S3::Bucket",
        "raw_properties": {
            "BucketName": resource_id.lower()
        },
        "semantic_properties": {
            "BucketName": "unknown"
        }
    }


def finding(resource_id, semantic, severity, rule_id=None, state=None):
    """One finding in the shape the rule engine emits."""

    return {
        "resource": resource_id,
        "rule_id": rule_id or f"TEST_{semantic.upper()}",
        "state": state or f"test_{semantic}_state",
        "semantic": semantic,
        "severity": severity
    }


def lambda_function(resource_id, security_group_id, role_id):
    """A Lambda function in a VPC: it names a security group the way a real"""

    return {
        "id": resource_id,
        "type": "AWS::Lambda::Function",
        "raw_properties": {
            "FunctionName": resource_id.lower(),
            "Role": role_id,
            "VpcConfig": {
                "SecurityGroupIds": [security_group_id]
            }
        },
        "semantic_properties": {
            "FunctionName": "unknown",
            "Role": "identity",
            "VpcConfig.SecurityGroupIds[0]": "network_control"
        }
    }


def security_group(resource_id):
    """A security group whose ingress opens port 22 to 0.0.0.0/0."""

    return {
        "id": resource_id,
        "type": "AWS::EC2::SecurityGroup",
        "raw_properties": {
            "GroupDescription": "open to the world",
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
    }


def instance(resource_id, security_group_id, profile_id):
    """An EC2 instance with a public address, in `security_group_id`, launched with"""

    return {
        "id": resource_id,
        "type": "AWS::EC2::Instance",
        "raw_properties": {
            "ImageId": "ami-00000000000000000",
            "InstanceType": "t2.micro",
            "SecurityGroupIds": [security_group_id],
            "IamInstanceProfile": profile_id,
            "AssociatePublicIpAddress": True
        },
        "semantic_properties": {
            "ImageId": "unknown",
            "InstanceType": "unknown",
            "SecurityGroupIds[0]": "network_control",
            "IamInstanceProfile": "identity",
            "AssociatePublicIpAddress": "exposure"
        }
    }


def graph_of(resource_dicts, findings):
    """A SecurityStateGraph over hand-built resources and hand-written findings."""

    return SecurityStateGraph(
        build_infra_from_resources(resource_dicts),
        findings
    )


def hop_lists(paths):
    """The hop sequences of a list of described paths."""

    return [path["hops"] for path in paths]


# -----------------------------

# The chain phases 1 and 2 exist to create: an attacker knocks on the open port,
KNOWN_PATH = [
    "OpenSecurityGroup",
    "PublicEC2Instance",
    "OverPermissiveInstanceProfile",
    "OverPermissiveRole",
    "InsecureS3Bucket"
]


@pytest.fixture
def real_graph(real_infra, rules_path):
    """The shipped dataset joined to the findings the shipped rules produce."""

    return SecurityStateGraph(
        real_infra,
        evaluate_findings(real_infra, rules_path)
    )


@pytest.fixture
def real_paths(real_graph):
    """The ranked attack paths of the shipped dataset."""

    return find_attack_paths(real_graph, objectives=data_theft_only())


# -----------------------------

# Ten resources in a line: nine roles each naming the next, ending at a bucket.
# Nine hops, so it is out of reach at max_depth=3 and in reach at nine.
CHAIN_IDS = [f"ChainRole{index}" for index in range(9)] + ["ChainBucket"]

CHAIN_RESOURCES = [
    role(CHAIN_IDS[index], [CHAIN_IDS[index + 1]])
    for index in range(9)
] + [
    bucket("ChainBucket")
]

CHAIN_FINDINGS = [
    finding("ChainRole0", "exposure", "high"),
    finding("ChainRole1", "privilege", "critical")
]


# A -> B -> C -> A, with C also reaching the data. The cycle is the reason the
# search carries the path as its own visited set.
CYCLE_RESOURCES = [
    role("CycleA", ["CycleB"]),
    role("CycleB", ["CycleC"]),
    role("CycleC", ["CycleA", "CycleBucket"]),
    bucket("CycleBucket")
]

CYCLE_FINDINGS = [
    finding("CycleA", "exposure", "high"),
    finding("CycleB", "privilege", "critical")
]


# Two routes out of one entry, carrying the same two findings over different
LENGTH_RESOURCES = [
    role("LengthEntry", ["ShortRole", "CleanRole"]),
    role("ShortRole", ["ShortBucket"]),
    role("CleanRole", ["DeepRole"]),
    role("DeepRole", ["DeepBucket"]),
    bucket("ShortBucket"),
    bucket("DeepBucket")
]

LENGTH_FINDINGS = [
    finding("LengthEntry", "exposure", "high"),
    finding("ShortRole", "privilege", "critical"),
    finding("DeepRole", "privilege", "critical")
]


@pytest.fixture
def chain_graph():
    return graph_of(CHAIN_RESOURCES, CHAIN_FINDINGS)


@pytest.fixture
def cycle_graph():
    return graph_of(CYCLE_RESOURCES, CYCLE_FINDINGS)


@pytest.fixture
def length_graph():
    return graph_of(LENGTH_RESOURCES, LENGTH_FINDINGS)


# -----------------------------

def test_entry_points_come_from_rule_metadata(real_graph):
    """An entry point is a node carrying a finding whose rule declared a semantic
    that means reachable from outside.

    Two semantics do, not one. `exposure` is the resource itself being readable
    or addressable from outside; `network_control` is an open door on it, which
    is what both canonical security-group rules carry. Recognising only
    `exposure` meant an open security group produced a finding and was not a way
    in, which is the most obvious entry point there is.
    """

    from attack_path.path_finder import ENTRY_SEMANTICS

    entries = entry_points(real_graph)

    assert "OpenSecurityGroup" in entries
    assert "PublicEC2Instance" in entries

    for entry_id in entries:

        assert any(
            state["semantic"] in ENTRY_SEMANTICS
            for state in real_graph.states_of(entry_id)
        )

    # PublicBucketPolicy's only finding is `semantic: privilege`, so it is a hop
    # and not a way in.
    assert "PublicBucketPolicy" not in entries

    # And both semantics are actually exercised by the shipped dataset, or the
    # loop above is a claim about one of them.
    found = {
        state["semantic"]
        for entry_id in entries
        for state in real_graph.states_of(entry_id)
        if state["semantic"] in ENTRY_SEMANTICS
    }

    assert found == set(ENTRY_SEMANTICS)


def test_targets_are_the_data_types_and_need_no_finding(real_graph):
    """Targets are selected by resource type, so a hardened database is still a"""

    targets = data_targets(real_graph)

    assert sorted(targets) == ["InsecureS3Bucket", "PublicRDS", "ReportsTable"]

    # a role is a hop towards the data, never the data itself
    assert "OverPermissiveRole" not in targets


def test_a_target_with_no_finding_is_still_a_target(cycle_graph):
    assert cycle_graph.states_of("CycleBucket") == []
    assert "CycleBucket" in data_targets(cycle_graph)


# -----------------------------

def test_the_known_multi_hop_path_is_found_with_its_exact_hops(real_paths):
    """THE HEADLINE ASSERTION."""

    assert KNOWN_PATH in hop_lists(real_paths)

    known = next(
        path
        for path in real_paths
        if path["hops"] == KNOWN_PATH
    )

    assert known["entry_id"] == "OpenSecurityGroup"
    assert known["target_id"] == "InsecureS3Bucket"
    assert known["length"] == 4

    # CRITICAL since EC2_IMDSV1_ENABLED landed: PublicEC2Instance carries a
    # second, `high` finding, which is the point of that rule — the hop from
    # "reached the instance" to "hold its role" now rests on a finding instead of
    # being assumed. The band moving is the rule working, not a regression.
    assert known["attack_level"] == ATTACK_LEVEL_CRITICAL

    # The whole findings, not just their ids: the export phase names techniques
    # per rule. Ten findings over four hops, in hop order, so the several
    # findings on one resource sit together.
    #
    # Asserted by `source_id` rather than `rule_id`, because a canonical rule id
    # is a composite of origin, check and resource type, and what this test is
    # about is which checks fired in which order.
    assert [
        finding["source_id"] for finding in known["states"]
    ] == [
        "RESTRICTED_INCOMING_TRAFFIC",
        "INCOMING_SSH_DISABLED",
        "REQUIRED_TAGS",
        "EC2_PUBLIC_IP",
        "EC2_IMDSV1_ENABLED",
        "IAM_WILDCARD_PERMISSIONS",
        "IAM_TRUST_POLICY_WILDCARD",
        "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
        "S3_BUCKET_PUBLIC_READ_PROHIBITED",
        "REQUIRED_TAGS"
    ]


def test_the_known_path_chains_its_conditions(real_paths):
    """THE DERIVATION ASSERTION.

    Every step's precondition has to appear in the previous step's
    postcondition, and the first step's precondition has to be something the
    attacker holds on arrival. That property is the difference between a path the
    search derived and a line drawn between resources that happen to reference
    each other.
    """

    known = next(
        path
        for path in real_paths
        if path["hops"] == KNOWN_PATH
    )

    steps = known["steps"]

    assert len(steps) == len(KNOWN_PATH) - 1

    held = set(initial_facts_for(known))

    for step in steps:

        assert step["precondition"], step

        for item in step["precondition"]:
            assert item in held, (step, sorted(held))

        held.update(step["postcondition"])

    # And the last step is what makes it a data-theft path: the attacker ends up
    # able to read the target, rather than merely adjacent to it.
    assert "data_access(InsecureS3Bucket)" in held


def initial_facts_for(path):
    """The facts the attacker holds at a described path's entry."""

    from security_state_graph.state_graph import build_state_graph

    return build_state_graph().initial_facts(path["entry_id"])


def test_every_real_path_starts_at_an_entry_and_ends_at_a_target(
    real_graph,
    real_paths
):
    entries = entry_points(real_graph)
    targets = data_targets(real_graph)

    assert real_paths

    for path in real_paths:

        assert path["hops"][0] in entries
        assert path["hops"][-1] in targets
        assert is_exploitable(real_graph, path["hops"])


def test_the_search_reads_the_traversal_view_not_the_stored_edges(real_paths):
    """Stored, the edge reads PublicEC2Instance -> OpenSecurityGroup, so a search"""

    from_group = [
        hops
        for hops in hop_lists(real_paths)
        if hops[0] == "OpenSecurityGroup"
    ]

    assert from_group

    for hops in from_group:
        assert hops[1] == "PublicEC2Instance"


def test_build_attack_paths_runs_end_to_end_and_writes_nothing(
    tmp_path,
    monkeypatch
):
    monkeypatch.chdir(tmp_path)

    paths = build_attack_paths()

    assert KNOWN_PATH in hop_lists(paths)
    assert list(tmp_path.iterdir()) == []


# -----------------------------

def test_max_depth_is_respected(chain_graph):
    """A nine-hop chain is unreachable at three hops and reachable at nine. The"""

    assert walk_paths(chain_graph, max_depth=3, objectives=data_theft_only()) == []
    assert find_attack_paths(chain_graph, max_depth=3, objectives=data_theft_only()) == []

    found = walk_paths(chain_graph, max_depth=9, objectives=data_theft_only())

    assert found == [CHAIN_IDS]
    assert len(found[0]) - 1 == 9


# -----------------------------

def test_a_cycle_terminates_and_no_path_repeats_a_node(cycle_graph):
    """CycleA -> CycleB -> CycleC -> CycleA is a loop the search has to leave. The"""

    paths = find_attack_paths(cycle_graph, objectives=data_theft_only())

    assert hop_lists(paths) == [
        ["CycleA", "CycleB", "CycleC", "CycleBucket"]
    ]

    for hops in hop_lists(paths):
        assert len(set(hops)) == len(hops)


def test_a_cycle_with_no_way_out_yields_nothing_rather_than_looping():
    """The same loop with the bucket removed. A search that revisited nodes would"""

    state_graph = graph_of(
        [
            role("LoopA", ["LoopB"]),
            role("LoopB", ["LoopC"]),
            role("LoopC", ["LoopA"])
        ],
        [
            finding("LoopA", "exposure", "high"),
            finding("LoopB", "privilege", "critical")
        ]
    )

    assert walk_paths(state_graph, objectives=data_theft_only()) == []
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []


# -----------------------------

def test_no_entry_points_gives_an_empty_list_not_a_crash():
    """A graph whose only finding is a privilege one has nowhere to start. That is"""

    state_graph = graph_of(
        [
            role("QuietRole", ["QuietBucket"]),
            bucket("QuietBucket")
        ],
        [
            finding("QuietRole", "privilege", "critical")
        ]
    )

    assert entry_points(state_graph) == []
    assert walk_paths(state_graph, objectives=data_theft_only()) == []
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []


def test_a_disconnected_target_is_never_reached():
    """LonelyBucket is in the account and nothing reaches it, so it must not appear"""

    state_graph = graph_of(
        [
            role("ReachEntry", ["ReachRole"]),
            role("ReachRole", ["ReachedBucket"]),
            bucket("ReachedBucket"),
            bucket("LonelyBucket")
        ],
        [
            finding("ReachEntry", "exposure", "high"),
            finding("ReachRole", "privilege", "critical"),
            finding("LonelyBucket", "exposure", "critical")
        ]
    )

    assert "LonelyBucket" in data_targets(state_graph)

    paths = find_attack_paths(state_graph, objectives=data_theft_only())

    assert hop_lists(paths) == [
        ["ReachEntry", "ReachRole", "ReachedBucket"]
    ]

    for path in paths:
        assert path["target_id"] != "LonelyBucket"


def test_an_entry_that_is_itself_a_target_is_not_a_zero_hop_path():
    """A publicly readable bucket is a finding the rule engine already reported."""

    state_graph = graph_of(
        [
            bucket("SelfBucket")
        ],
        [
            finding("SelfBucket", "exposure", "critical"),
            finding("SelfBucket", "privilege", "critical")
        ]
    )

    assert entry_points(state_graph) == ["SelfBucket"]
    assert data_targets(state_graph) == ["SelfBucket"]

    assert is_exploitable(state_graph, ["SelfBucket"]) is False
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []


# -----------------------------

def test_a_path_with_no_privilege_hop_is_rejected():
    """THE POLICY CLAUSE THAT DOES THE WORK."""

    resources = [
        role("NoPrivEntry", ["NoPrivRole"]),
        role("NoPrivRole", ["NoPrivBucket"]),
        bucket("NoPrivBucket")
    ]

    findings = [
        finding("NoPrivEntry", "exposure", "high"),
        finding("NoPrivBucket", "exposure", "critical")
    ]

    state_graph = graph_of(resources, findings)

    route = ["NoPrivEntry", "NoPrivRole", "NoPrivBucket"]

    # the search reached it ...
    assert walk_paths(state_graph, objectives=data_theft_only()) == [route]

    # ... and the policy refused it
    assert is_exploitable(state_graph, route) is False
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []

    # THE DISCRIMINATING HALF: the same graph, one privilege finding added
    escalated = graph_of(
        resources,
        findings + [finding("NoPrivRole", "privilege", "critical")]
    )

    assert is_exploitable(escalated, route) is True
    assert hop_lists(find_attack_paths(escalated, objectives=data_theft_only())) == [route]


def test_a_clean_intermediate_hop_is_allowed(length_graph):
    """CleanRole carries no findings and is still a legitimate step. The cost of"""

    assert length_graph.states_of("CleanRole") == []

    deep = ["LengthEntry", "CleanRole", "DeepRole", "DeepBucket"]

    assert is_exploitable(length_graph, deep) is True
    assert deep in hop_lists(find_attack_paths(length_graph, objectives=data_theft_only()))


def test_an_entry_carrying_no_state_is_rejected(length_graph):
    """Clause 1, asserted directly. entry_points() already guarantees it, but"""

    assert length_graph.states_of("CleanRole") == []

    assert is_exploitable(
        length_graph,
        ["CleanRole", "DeepRole", "DeepBucket"]
    ) is False


# -----------------------------

def test_severity_lookup_is_case_insensitive_and_not_the_fallback():
    """THE SILENT FAILURE GUARD."""

    assert severity_weight("high") == SEVERITY_WEIGHTS["high"]
    assert severity_weight("HIGH") == SEVERITY_WEIGHTS["high"]
    assert severity_weight("High") == SEVERITY_WEIGHTS["high"]

    assert severity_weight("high") != DEFAULT_SEVERITY_WEIGHT

    # the table itself is lowercase, which is the contract with the YAML
    assert list(SEVERITY_WEIGHTS) == [
        key.lower()
        for key in SEVERITY_WEIGHTS
    ]

    for severity in ["critical", "high", "medium", "low"]:
        assert severity_weight(severity) != DEFAULT_SEVERITY_WEIGHT


def test_an_unknown_or_missing_severity_falls_back_below_low():
    """A finding with a label nobody agreed on still counts, and must never be"""

    assert severity_weight("catastrophic") == DEFAULT_SEVERITY_WEIGHT
    assert severity_weight(None) == DEFAULT_SEVERITY_WEIGHT
    assert severity_weight(7) == DEFAULT_SEVERITY_WEIGHT

    assert DEFAULT_SEVERITY_WEIGHT < SEVERITY_WEIGHTS["low"]


def test_the_real_path_sums_the_severities_of_every_weakness(real_graph):
    """Every distinct weakness on the known path, counted once.

    Ten, not five. Several nodes carry more than one finding and they are
    different weaknesses, so each counts: PublicEC2Instance is both reachable
    (EC2_PUBLIC_IP) and hands over its role's credentials (EC2_IMDSV1_ENABLED),
    which is the behaviour test_two_different_weaknesses_on_one_node_both_count
    pins, and the reason the total is not one weight per hop.

    None of these rules declares a severity. Every weight below comes from
    SEVERITY_BY_SEMANTIC, which is what makes this test the check on that table:
    change a row there and this number moves.
    """

    total = path_severity_total(real_graph, KNOWN_PATH)

    assert total == (
        # OpenSecurityGroup: blocked port open, and SSH open. network_control.
        SEVERITY_WEIGHTS["high"]
        + SEVERITY_WEIGHTS["high"]

        # PublicEC2Instance: untagged (capability), public IP (exposure),
        # IMDSv1 (privilege).
        + SEVERITY_WEIGHTS["low"]
        + SEVERITY_WEIGHTS["high"]
        + SEVERITY_WEIGHTS["critical"]

        # OverPermissiveRole: wildcard grant, and anyone may assume it.
        + SEVERITY_WEIGHTS["critical"]
        + SEVERITY_WEIGHTS["critical"]

        # InsecureS3Bucket: public access unblocked, publicly readable, untagged.
        + SEVERITY_WEIGHTS["high"]
        + SEVERITY_WEIGHTS["high"]
        + SEVERITY_WEIGHTS["low"]
    )

    assert total != len(KNOWN_PATH) * DEFAULT_SEVERITY_WEIGHT


# -----------------------------

def test_with_identical_severities_the_longer_path_scores_lower(length_graph):
    """Both routes leave the same entry and carry the same two findings — one high,"""

    short = ["LengthEntry", "ShortRole", "ShortBucket"]
    deep = ["LengthEntry", "CleanRole", "DeepRole", "DeepBucket"]

    assert path_severity_total(length_graph, short) == path_severity_total(
        length_graph,
        deep
    )

    assert score_path(length_graph, short) > score_path(length_graph, deep)

    # and the gap is exactly one hop of damping
    assert score_path(length_graph, deep) == round(
        score_path(length_graph, short) * LENGTH_DAMPING_PER_HOP,
        2
    )


def test_damping_is_applied_per_hop_beyond_the_first(length_graph):
    """The first hop is free — the penalty is for the hops that have to be chained"""

    short = ["LengthEntry", "ShortRole", "ShortBucket"]

    raw = path_severity_total(length_graph, short)

    assert score_path(length_graph, short) == round(
        raw * LENGTH_DAMPING_PER_HOP,
        2
    )


# -----------------------------

def test_public_exposure_is_read_off_the_configuration(real_graph):
    """Derived from a property the extractor tagged `exposure` carrying a value"""

    assert is_public_entry(real_graph, "OpenSecurityGroup") is True
    assert is_public_entry(real_graph, "PublicEC2Instance") is True
    assert is_public_entry(real_graph, "OpenLoadBalancer") is True

    # a policy document says nothing about network reachability
    assert is_public_entry(real_graph, "PublicBucketPolicy") is False

    assert is_public_entry(real_graph, "NeverDeclared") is False


def test_an_exposure_property_that_is_switched_off_is_not_public():
    """PubliclyAccessible: false is the hardened case, and a truth test that only"""

    state_graph = graph_of(
        [
            {
                "id": "PrivateDB",
                "type": "AWS::RDS::DBInstance",
                "raw_properties": {
                    "DBInstanceIdentifier": "private-db",
                    "PubliclyAccessible": False
                },
                "semantic_properties": {
                    "DBInstanceIdentifier": "unknown",
                    "PubliclyAccessible": "exposure"
                }
            }
        ],
        []
    )

    assert is_public_entry(state_graph, "PrivateDB") is False


def test_a_public_entry_is_boosted(real_graph, length_graph):
    """The boost is what separates "exposed to the internet" from "exposed wider"""

    short = ["LengthEntry", "ShortRole", "ShortBucket"]

    assert is_public_entry(length_graph, "LengthEntry") is False

    # no boost: the score is the damped sum exactly
    assert score_path(length_graph, short) == round(
        path_severity_total(length_graph, short) * LENGTH_DAMPING_PER_HOP,
        2
    )

    # boost: the same arithmetic plus the multiplier. KNOWN_PATH is five
    # resources, so four hops, so damping applies three times.
    assert score_path(real_graph, KNOWN_PATH) == round(
        path_severity_total(real_graph, KNOWN_PATH)
        * (LENGTH_DAMPING_PER_HOP ** (len(KNOWN_PATH) - 2))
        * PUBLIC_ENTRY_BOOST,
        2
    )

    assert describe_path(real_graph, KNOWN_PATH)["public_entry"] is True


# -----------------------------

def test_results_are_sorted_descending(real_paths, length_graph):
    scores = [path["score"] for path in real_paths]

    assert len(scores) > 1
    assert scores == sorted(scores, reverse=True)

    length_scores = [
        path["score"]
        for path in find_attack_paths(length_graph, objectives=data_theft_only())
    ]

    assert length_scores == sorted(length_scores, reverse=True)


def test_equal_scores_are_ordered_deterministically():
    """Two mirror-image routes with identical states score identically, and the"""

    state_graph = graph_of(
        [
            role("TieEntry", ["TieRoleB", "TieRoleA"]),
            role("TieRoleA", ["TieBucketA"]),
            role("TieRoleB", ["TieBucketB"]),
            bucket("TieBucketA"),
            bucket("TieBucketB")
        ],
        [
            finding("TieEntry", "exposure", "high"),
            finding("TieRoleA", "privilege", "critical"),
            finding("TieRoleB", "privilege", "critical")
        ]
    )

    paths = find_attack_paths(state_graph, objectives=data_theft_only())

    assert [path["score"] for path in paths] == [
        paths[0]["score"],
        paths[0]["score"]
    ]

    assert hop_lists(paths) == [
        ["TieEntry", "TieRoleA", "TieBucketA"],
        ["TieEntry", "TieRoleB", "TieBucketB"]
    ]


# -----------------------------

def test_attack_level_thresholds_on_both_sides_of_every_cutoff():
    """Both cutoffs, three points each: exactly on it, just above, just below. The"""

    # -----------------------------

    assert attack_level_for(CRITICAL_SCORE_THRESHOLD) == ATTACK_LEVEL_CRITICAL
    assert attack_level_for(
        CRITICAL_SCORE_THRESHOLD + 0.01
    ) == ATTACK_LEVEL_CRITICAL
    assert attack_level_for(
        CRITICAL_SCORE_THRESHOLD - 0.01
    ) == ATTACK_LEVEL_HIGH

    # -----------------------------

    assert attack_level_for(HIGH_SCORE_THRESHOLD) == ATTACK_LEVEL_HIGH
    assert attack_level_for(HIGH_SCORE_THRESHOLD + 0.01) == ATTACK_LEVEL_HIGH
    assert attack_level_for(HIGH_SCORE_THRESHOLD - 0.01) == ATTACK_LEVEL_MEDIUM

    # -----------------------------

    assert attack_level_for(0.0) == ATTACK_LEVEL_MEDIUM

    assert CRITICAL_SCORE_THRESHOLD > HIGH_SCORE_THRESHOLD


def test_a_low_severity_path_lands_in_the_medium_band():
    """The bottom band is a genuine path carried by weak findings, not a rejected"""

    state_graph = graph_of(
        [
            role("WeakEntry", ["WeakRole"]),
            role("WeakRole", ["WeakBucket"]),
            bucket("WeakBucket")
        ],
        [
            finding("WeakEntry", "exposure", "low"),
            finding("WeakRole", "privilege", "low")
        ]
    )

    paths = find_attack_paths(state_graph, objectives=data_theft_only())

    assert hop_lists(paths) == [["WeakEntry", "WeakRole", "WeakBucket"]]
    assert paths[0]["attack_level"] == ATTACK_LEVEL_MEDIUM


# -----------------------------

def test_a_described_path_carries_everything_the_export_needs(real_graph):
    path = describe_path(real_graph, KNOWN_PATH)

    assert path["entry_id"] == KNOWN_PATH[0]
    assert path["target_id"] == KNOWN_PATH[-1]
    assert path["hops"] == KNOWN_PATH
    assert path["length"] == len(KNOWN_PATH) - 1
    assert path["length"] == 4
    assert path["public_entry"] is True
    assert path["score"] > 0
    assert path["attack_level"] in [
        ATTACK_LEVEL_CRITICAL,
        ATTACK_LEVEL_HIGH,
        ATTACK_LEVEL_MEDIUM
    ]

    # The states are the findings of the hops that have one, in path order. Not
    # One entry per FINDING, in hop order — not one per hop. PublicEC2Instance
    # carries two (EC2_PUBLIC_IP and EC2_IMDSV1_ENABLED), so it appears twice, and
    # a one-per-hop expectation would have quietly hidden the second.
    assert [state["resource"] for state in path["states"]] == [
        hop
        for hop in KNOWN_PATH
        for _ in real_graph.states_of(hop)
    ]

    assert "OverPermissiveInstanceProfile" not in [
        state["resource"] for state in path["states"]
    ]

    assert path["rule_ids"] == [
        state["rule_id"]
        for state in path["states"]
    ]


def test_describing_a_path_does_not_mutate_the_graph(real_graph):
    before = {
        node_id: list(node["states"])
        for node_id, node in real_graph.nodes.items()
    }

    find_attack_paths(real_graph, objectives=data_theft_only())

    assert {
        node_id: node["states"]
        for node_id, node in real_graph.nodes.items()
    } == before

    # the hop list is a copy, so a caller editing a report cannot edit the graph
    path = describe_path(real_graph, KNOWN_PATH)
    path["hops"].append("Injected")

    assert describe_path(real_graph, KNOWN_PATH)["hops"] == KNOWN_PATH


# -----------------------------

def test_a_privilege_finding_on_the_entry_is_not_an_escalation():
    """CLAUSE 2 IS POSITIONAL, AND THIS IS THE CASE THAT PROVES IT."""

    resources = [
        role("EntryRole", ["EntryBucket"]),
        bucket("EntryBucket")
    ]

    findings = [
        finding("EntryRole", "exposure", "critical"),
        finding("EntryRole", "privilege", "critical"),
        finding("EntryBucket", "exposure", "critical")
    ]

    state_graph = graph_of(resources, findings)

    route = ["EntryRole", "EntryBucket"]

    # the search reached it ...
    assert walk_paths(state_graph, objectives=data_theft_only()) == [route]

    # ... and the policy refused it, because the privilege state is the entry's
    assert is_exploitable(state_graph, route) is False
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []

    # THE DISCRIMINATING HALF: one interior hop carrying the same finding
    escalated = graph_of(
        [
            role("EntryRole", ["MiddleRole"]),
            role("MiddleRole", ["EntryBucket"]),
            bucket("EntryBucket")
        ],
        [
            finding("EntryRole", "exposure", "critical"),
            finding("MiddleRole", "privilege", "critical"),
            finding("EntryBucket", "exposure", "critical")
        ]
    )

    interior_route = ["EntryRole", "MiddleRole", "EntryBucket"]

    assert is_exploitable(escalated, interior_route) is True
    assert hop_lists(find_attack_paths(escalated, objectives=data_theft_only())) == [interior_route]


def test_a_privilege_finding_on_the_target_is_not_an_escalation():
    """The other end of the same clause. Authority discovered *at* the data cannot"""

    state_graph = graph_of(
        [
            role("ReachEntry", ["TargetBucket"]),
            bucket("TargetBucket")
        ],
        [
            finding("ReachEntry", "exposure", "high"),
            finding("TargetBucket", "privilege", "critical")
        ]
    )

    route = ["ReachEntry", "TargetBucket"]

    assert walk_paths(state_graph, objectives=data_theft_only()) == [route]

    assert is_exploitable(state_graph, route) is False
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []


def test_the_shipped_paths_carry_their_escalation_on_an_interior_hop(
    real_graph,
    real_paths
):
    """The policy, observed on the shipped dataset rather than on a fixture: every"""

    assert real_paths

    for path in real_paths:

        interior = path["hops"][1:-1]

        assert interior

        assert any(
            state.get("semantic") == "privilege"
            for node_id in interior
            for state in real_graph.states_of(node_id)
        ), path["hops"]


# -----------------------------

def test_a_route_that_is_the_tail_of_another_is_not_reported_twice():
    """One attack, enumerated once per entry along it."""

    state_graph = graph_of(
        [
            role("TailEntry", ["TailMiddle"]),
            role("TailMiddle", ["TailRole"]),
            role("TailRole", ["TailBucket"]),
            bucket("TailBucket")
        ],
        [
            finding("TailEntry", "exposure", "high"),
            finding("TailMiddle", "exposure", "high"),
            finding("TailRole", "privilege", "critical")
        ]
    )

    long_route = ["TailEntry", "TailMiddle", "TailRole", "TailBucket"]
    tail_route = ["TailMiddle", "TailRole", "TailBucket"]

    # the search finds both, and both satisfy the policy
    routes = walk_paths(state_graph, objectives=data_theft_only())

    assert long_route in routes
    assert tail_route in routes

    assert is_exploitable(state_graph, long_route) is True
    assert is_exploitable(state_graph, tail_route) is True

    # ... and only the longer one is reported
    assert hop_lists(find_attack_paths(state_graph, objectives=data_theft_only())) == [long_route]


def test_two_routes_to_one_target_through_different_hops_both_survive():
    """THE DISCRIMINATING HALF of the collapse."""

    state_graph = graph_of(
        [
            role("ForkEntry", ["ForkRoleA", "ForkRoleB"]),
            role("ForkRoleA", ["ForkBucket"]),
            role("ForkRoleB", ["ForkBucket"]),
            bucket("ForkBucket")
        ],
        [
            finding("ForkEntry", "exposure", "high"),
            finding("ForkRoleA", "privilege", "critical"),
            finding("ForkRoleB", "privilege", "critical")
        ]
    )

    reported = hop_lists(find_attack_paths(state_graph, objectives=data_theft_only()))

    assert sorted(reported) == [
        ["ForkEntry", "ForkRoleA", "ForkBucket"],
        ["ForkEntry", "ForkRoleB", "ForkBucket"]
    ]


# -----------------------------

def test_two_findings_of_one_weakness_on_one_node_count_once():
    """A redundant rule is not a second misconfiguration."""

    resources = [
        role("DupEntry", ["DupRole"]),
        role("DupRole", ["DupBucket"]),
        bucket("DupBucket")
    ]

    route = ["DupEntry", "DupRole", "DupBucket"]

    single = graph_of(
        resources,
        [
            finding("DupEntry", "exposure", "high"),
            finding("DupRole", "privilege", "critical")
        ]
    )

    duplicated = graph_of(
        resources,
        [
            finding("DupEntry", "exposure", "high"),
            finding(
                "DupEntry",
                "exposure",
                "high",
                rule_id="SG_OPEN_PORT_DUPLICATE"
            ),
            finding("DupRole", "privilege", "critical")
        ]
    )

    assert len(duplicated.states_of("DupEntry")) == 2

    assert path_severity_total(duplicated, route) == path_severity_total(
        single,
        route
    )

    assert score_path(duplicated, route) == score_path(single, route)


def test_two_different_weaknesses_on_one_node_both_count():
    """THE DISCRIMINATING HALF. The dedupe is per weakness, not per node: a node"""

    resources = [
        role("BothEntry", ["BothRole"]),
        role("BothRole", ["BothBucket"]),
        bucket("BothBucket")
    ]

    route = ["BothEntry", "BothRole", "BothBucket"]

    one = graph_of(
        resources,
        [
            finding("BothEntry", "exposure", "high"),
            finding("BothRole", "privilege", "critical")
        ]
    )

    two = graph_of(
        resources,
        [
            finding("BothEntry", "exposure", "high"),
            finding(
                "BothEntry",
                "exposure",
                "medium",
                rule_id="EC2_PUBLIC_IP",
                state="instance_with_public_ip"
            ),
            finding("BothRole", "privilege", "critical")
        ]
    )

    assert path_severity_total(two, route) == (
        path_severity_total(one, route) + SEVERITY_WEIGHTS["medium"]
    )


def test_a_redundant_rule_does_not_re_rank_the_shipped_paths(
    real_infra,
    rules_path,
    tmp_path
):
    """THE INVARIANT, END TO END, THROUGH THE REAL RULE LOADER."""

    with open(rules_path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)

    duplicate = json.loads(json.dumps(rules[0]))

    assert duplicate["source_id"] == "RESTRICTED_INCOMING_TRAFFIC"
    assert duplicate["resource_type"] == "AWS::EC2::SecurityGroup"

    # A second rule id reporting the same weakness id: the state is what says
    # "this is the same misconfiguration", and it is deliberately unchanged.
    duplicate["id"] = "SG_OPEN_RDP_DUPLICATE"

    padded_rules = tmp_path / "rules_with_a_duplicate.yaml"

    with open(padded_rules, "w", encoding="utf-8") as f:
        yaml.safe_dump(rules + [duplicate], f)

    shipped = find_attack_paths(
        SecurityStateGraph(
            real_infra,
            evaluate_findings(real_infra, rules_path)
        ),
        objectives=data_theft_only()
    )

    padded_graph = SecurityStateGraph(
        real_infra,
        evaluate_findings(real_infra, padded_rules)
    )

    padded = find_attack_paths(padded_graph, objectives=data_theft_only())

    # the duplicate really did fire, or this test proves nothing
    assert [
        state["rule_id"]
        for state in padded_graph.states_of("OpenSecurityGroup")
    ] == [
        "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroup",
        "aws_config:INCOMING_SSH_DISABLED:AWS::EC2::SecurityGroup",
        "SG_OPEN_RDP_DUPLICATE"
    ]

    assert hop_lists(padded) == hop_lists(shipped)
    assert [path["score"] for path in padded] == [
        path["score"] for path in shipped
    ]


# -----------------------------

def test_an_open_group_on_a_lambda_function_is_not_a_way_in():
    """THE FALSE FIRST HOP THE TYPE GATE EXISTS TO PREVENT."""

    state_graph = graph_of(
        [
            security_group("LambdaGroup"),
            lambda_function("PrivateLambda", "LambdaGroup", "LambdaRole"),
            role("LambdaRole", ["LambdaBucket"]),
            bucket("LambdaBucket")
        ],
        [
            finding("LambdaGroup", "exposure", "high"),
            finding("LambdaRole", "privilege", "critical")
        ]
    )

    # the relationship is still in the description of the infrastructure ...
    assert ("PrivateLambda", "LambdaGroup") in [
        (edge["source"], edge["target"])
        for edge in state_graph.edges
    ]

    # ... and it is not a hop in either direction
    assert state_graph.traversal_adjacency()["LambdaGroup"] == []
    assert "LambdaGroup" not in state_graph.traversal_adjacency()[
        "PrivateLambda"
    ]

    assert entry_points(state_graph) == ["LambdaGroup"]
    assert walk_paths(state_graph, objectives=data_theft_only()) == []
    assert find_attack_paths(state_graph, objectives=data_theft_only()) == []

    # THE DISCRIMINATING HALF: something that does listen, same shape
    listening = graph_of(
        [
            security_group("ListenGroup"),
            instance("ListenInstance", "ListenGroup", "ListenProfile"),
            {
                "id": "ListenProfile",
                "type": "AWS::IAM::InstanceProfile",
                "raw_properties": {
                    "InstanceProfileName": "listen-profile",
                    "Roles": ["ListenRole"]
                },
                "semantic_properties": {
                    "InstanceProfileName": "unknown",
                    "Roles[0]": "identity"
                }
            },
            role("ListenRole", ["ListenBucket"]),
            bucket("ListenBucket")
        ],
        [
            finding("ListenGroup", "exposure", "high"),
            finding("ListenRole", "privilege", "critical")
        ]
    )

    assert hop_lists(find_attack_paths(listening, objectives=data_theft_only())) == [
        [
            "ListenGroup",
            "ListenInstance",
            "ListenProfile",
            "ListenRole",
            "ListenBucket"
        ]
    ]


def test_one_route_is_reported_once(real_graph):
    """Two edges can join the same pair of resources — AppServerRole to
    DeploymentRole is both `identity` and `escalation` — and the search walks
    each. The route is the same route either way, so it must be reported once.

    Before this, 11 of 33 exported paths were byte-identical duplicates.
    """

    routes = walk_paths(real_graph)

    assert len(routes) == len({tuple(route) for route in routes})
