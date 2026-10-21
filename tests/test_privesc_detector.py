"""The privilege escalation catalogue and the detector that reads it.

Source of the catalogue:
https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation

The detector answers a question the YAML rule language cannot: does the set of
actions a principal holds *cover* the set a method needs, with wildcards on both
sides. So the covering itself is what these tests are mostly about.
"""

import pytest

from engine.attack_catalog import is_known
from engine.privesc_detector import (
    ESCALATION_TARGETS,
    action_matches,
    detect_methods,
    granted_actions,
    grants_full_admin,
    holds_every_action,
    load_methods,
    walk_statements
)


def statement(actions, effect="Allow", resource="*", condition=None):
    """One IAM statement, as the parser would leave it in raw_properties."""

    built = {"Effect": effect, "Action": actions, "Resource": resource}

    if condition is not None:
        built["Condition"] = condition

    return built


def policy(*statements):
    """A principal's raw_properties carrying `statements`."""

    return {
        "Policies": [
            {
                "PolicyName": "test",
                "PolicyDocument": {"Statement": list(statements)}
            }
        ]
    }


# -----------------------------
# The catalogue itself.

def test_the_catalogue_loads_and_every_entry_is_complete():
    methods = load_methods()

    assert methods

    for method in methods:
        assert method["id"]
        assert method["method"]
        assert method["requires"]
        assert method["escalates_to"] in ESCALATION_TARGETS
        assert method["severity"] == method["severity"].lower()
        assert method["techniques"]


def test_method_ids_are_unique():
    ids = [method["id"] for method in load_methods()]

    assert len(ids) == len(set(ids))


def test_every_cited_technique_is_in_the_iaas_matrix():
    """A catalogue entry may not invent a technique, or borrow a non-cloud one."""

    for method in load_methods():
        for technique_id in method["techniques"]:
            assert is_known(technique_id), (method["id"], technique_id)


def test_a_principal_scope_is_only_given_where_it_means_something():
    """`principal_types` narrows escalates_to: principal and nothing else."""

    for method in load_methods():

        if method.get("principal_types"):
            assert method["escalates_to"] == "principal"


def test_a_bad_escalation_target_is_a_load_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "methods:\n"
        "  - id: BAD\n"
        "    requires: ['iam:PassRole']\n"
        "    escalates_to: somewhere_else\n",
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_methods(bad)


def test_a_method_requiring_nothing_is_a_load_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "methods:\n"
        "  - id: BAD\n"
        "    requires: []\n"
        "    escalates_to: self\n",
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_methods(bad)


# -----------------------------
# Action covering. THE PART THE RULE LANGUAGE COULD NOT DO.

COVERING_CASES = [
    ("*", "iam:PassRole", True),                       # everything
    ("iam:*", "iam:PassRole", True),                   # whole service
    ("iam:PassRole", "iam:PassRole", True),            # exact
    ("IAM:passrole", "iam:PassRole", True),            # IAM is case-insensitive
    ("lambda:Create*", "lambda:CreateFunction", True),
    ("lambda:Create*", "lambda:InvokeFunction", False),
    ("s3:*", "iam:PassRole", False),                   # wrong service
    ("iam:PassRole", "iam:PassRolePolicy", False),     # not a prefix match
    ("i*", "iam:PassRole", False),                     # must not span services
    ("iam", "iam:PassRole", False),                    # no separator, not "*"
]


@pytest.mark.parametrize(
    "pattern,required,expected",
    COVERING_CASES,
    ids=["{}~{}".format(p, r) for p, r, _ in COVERING_CASES]
)
def test_action_matches(pattern, required, expected):
    assert action_matches(pattern, required) is expected


def test_a_service_wildcard_does_not_leak_across_services():
    """THE OVER-DETECTION THIS GUARD EXISTS FOR.

    A service wildcard covers every action in its own service and nothing in
    another. Letting it leak would credit a principal with escalation methods
    whose actions it does not hold.
    """

    assert not action_matches("ec2:*", "lambda:CreateFunction")
    assert not action_matches("lambda:*", "ec2:RunInstances")


def test_holds_every_action_needs_all_of_them():
    patterns = ["iam:PassRole", "lambda:CreateFunction"]

    assert holds_every_action(patterns, ["iam:PassRole"])
    assert holds_every_action(patterns, ["iam:PassRole", "lambda:CreateFunction"])

    # the third action of the method is missing
    assert not holds_every_action(
        patterns,
        ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
    )


# -----------------------------
# Reading the statements.

def test_statements_are_found_at_any_depth():
    found = walk_statements(policy(statement("iam:PassRole")))

    assert len(found) == 1
    assert found[0]["Action"] == "iam:PassRole"


def test_only_allow_statements_grant():
    assert granted_actions(policy(statement("iam:*"))) == ["iam:*"]

    assert granted_actions(
        policy(statement("iam:*", effect="Deny"))
    ) == []


def test_a_conditional_statement_grants_nothing():
    """Same choice as connection_builder: a conditional grant is a scoped grant."""

    conditional = policy(
        statement("iam:PassRole", condition={"StringEquals": {"aws:username": "x"}})
    )

    assert granted_actions(conditional) == []
    assert detect_methods(conditional) == []


def test_a_list_valued_action_is_read_as_several_patterns():
    granted = granted_actions(
        policy(statement(["iam:PassRole", "lambda:CreateFunction"]))
    )

    assert granted == ["iam:PassRole", "lambda:CreateFunction"]


def test_resource_scope_does_not_gate_detection():
    """A PassRole scoped to one role is still a complete escalation to it."""

    scoped = policy(
        statement(
            ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
            resource="arn:aws:iam::111122223333:role/Target"
        )
    )

    detected = [method["id"] for method in detect_methods(scoped)]

    assert "PRIVESC_PASSROLE_LAMBDA_INVOKE" in detected


# -----------------------------
# Detection.

def test_a_pass_role_lambda_grant_detects_exactly_that_method():
    props = policy(
        statement(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])
    )

    detected = [method["id"] for method in detect_methods(props)]

    assert "PRIVESC_PASSROLE_LAMBDA_INVOKE" in detected

    # and not the ones needing an action this principal does not hold
    assert "PRIVESC_PASSROLE_EC2" not in detected
    assert "PRIVESC_CREATE_ACCESS_KEY" not in detected


def test_a_single_action_method_is_detected_on_its_own():
    props = policy(statement("lambda:UpdateFunctionCode"))

    detected = [method["id"] for method in detect_methods(props)]

    assert detected == ["PRIVESC_LAMBDA_UPDATE_CODE"]


def test_a_least_privilege_principal_detects_nothing():
    props = policy(statement(["s3:GetObject", "logs:PutLogEvents"]))

    assert detect_methods(props) == []


def test_no_policy_at_all_detects_nothing():
    assert detect_methods({}) == []
    assert detect_methods({"RoleName": "plain"}) == []


def test_full_admin_is_collapsed_rather_than_enumerated():
    """THE SIGNAL-TO-NOISE DECISION.

    `Action: "*"` satisfies all 28 methods. Reporting 28 findings on one node is
    28 restatements of one fact, and the wildcard already has its own rule.
    """

    admin = policy(statement("*"))

    assert grants_full_admin(admin)
    assert detect_methods(admin) == []

    # the enumeration is still available to anything that wants it
    assert len(detect_methods(admin, collapse_admin=False)) == len(load_methods())


def test_a_service_wildcard_is_not_full_admin():
    """`iam:*` is enormous but it is not every action, so it is not collapsed."""

    props = policy(statement("iam:*"))

    assert not grants_full_admin(props)
    assert detect_methods(props)


# -----------------------------
# The shipped dataset.

def test_the_shipped_roles_detect_the_methods_they_hold(real_infra):
    def detected_for(resource_id):
        resource = real_infra.get_resource(resource_id)
        return [method["id"] for method in detect_methods(resource.raw_properties)]

    assert detected_for("AppServerRole") == ["PRIVESC_PASSROLE_LAMBDA_INVOKE"]
    assert detected_for("DeploymentRole") == ["PRIVESC_ATTACH_ROLE_POLICY"]

    # the wildcard admin is the collapsed case
    assert detected_for("OverPermissiveRole") == []
