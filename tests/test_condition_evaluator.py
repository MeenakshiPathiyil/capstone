"""Tests for the generic condition evaluator."""

import pytest

from engine.condition_evaluator import (
    compare,
    evaluate_expression,
    evaluate_leaf,
    get_field_values,
    get_scope_elements
)
from engine.rule_engine import RuleEngine


# -----------------------------

# 3389 is open to the world on the second ingress entry: genuinely vulnerable.
SAME_ELEMENT_GROUP = {
    "_structured": {
        "GroupDescription": "Remote desktop open to the world",
        "SecurityGroupIngress": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIp": "10.0.0.0/8"
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "CidrIp": "0.0.0.0/0"
            }
        ]
    }
}

# The false positive: 0.0.0.0/0 belongs to port 80, and 3389 is locked to an
CROSS_ELEMENT_GROUP = {
    "_structured": {
        "GroupDescription": "Web open to the world, remote desktop internal",
        "SecurityGroupIngress": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "CidrIp": "0.0.0.0/0"
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "CidrIp": "10.0.0.0/8"
            }
        ]
    }
}

# One resource carrying a value of every shape the operators need.
OPERATOR_RESOURCE = {
    "_structured": {
        "DBInstanceIdentifier": "public-rds-instance",
        "Engine": "postgres",
        "AllocatedStorage": 20,
        "PubliclyAccessible": True,
        "VpcSecurityGroups": [
            "OpenSecurityGroup",
            "DefaultSecurityGroup"
        ]
    }
}


def unrestricted_port(port, scope=None):
    """The shape of the shipped rule: this CIDR and this port, ANDed."""

    if scope:
        condition = {
            "operator": "AND",
            "scope": scope,
            "operands": [
                {
                    "field": "CidrIp",
                    "comparison": "equals",
                    "value": "0.0.0.0/0"
                },
                {
                    "field": "FromPort",
                    "comparison": "equals",
                    "value": port
                }
            ]
        }

    else:
        condition = {
            "operator": "AND",
            "operands": [
                {
                    "field": "SecurityGroupIngress.CidrIp",
                    "comparison": "equals",
                    "value": "0.0.0.0/0"
                },
                {
                    "field": "SecurityGroupIngress.FromPort",
                    "comparison": "equals",
                    "value": port
                }
            ]
        }

    return condition


def leaf(field, comparison, value):
    """One comparison, spelled the way security_rules.yaml spells it."""

    return {
        "field": field,
        "comparison": comparison,
        "value": value
    }


# -----------------------------

def test_scoped_and_matches_within_a_single_element():
    """0.0.0.0/0 and 3389 on the same ingress entry — a real exposure."""

    assert evaluate_expression(
        SAME_ELEMENT_GROUP,
        unrestricted_port(3389, scope="SecurityGroupIngress")
    ) is True


def test_scoped_and_does_not_match_across_different_elements():
    """THE REGRESSION TEST."""

    condition = unrestricted_port(3389, scope="SecurityGroupIngress")

    assert evaluate_expression(SAME_ELEMENT_GROUP, condition) is True
    assert evaluate_expression(CROSS_ELEMENT_GROUP, condition) is False


def test_scope_less_and_still_matches_across_elements():
    """The backward-compatibility contract, stated as a test."""

    assert evaluate_expression(
        CROSS_ELEMENT_GROUP,
        unrestricted_port(3389)
    ) is True

    assert evaluate_expression(
        SAME_ELEMENT_GROUP,
        unrestricted_port(3389)
    ) is True


def test_scoped_or_still_matches_across_elements():
    """Scope narrows an AND; it must not narrow the meaning of OR to less than"""

    condition = {
        "operator": "OR",
        "scope": "SecurityGroupIngress",
        "operands": [
            leaf("FromPort", "equals", 80),
            leaf("FromPort", "equals", 3389)
        ]
    }

    assert evaluate_expression(CROSS_ELEMENT_GROUP, condition) is True


def test_scope_applies_to_a_bare_leaf():
    """"scope" is a property of a condition node, not of AND specifically."""

    assert evaluate_expression(
        CROSS_ELEMENT_GROUP,
        dict(leaf("FromPort", "equals", 3389), scope="SecurityGroupIngress")
    ) is True

    assert evaluate_expression(
        CROSS_ELEMENT_GROUP,
        dict(leaf("FromPort", "equals", 8080), scope="SecurityGroupIngress")
    ) is False


def test_nested_scope_re_roots_at_the_inner_element():
    """A scoped subtree may scope again on a list inside the element it was"""

    resource = {
        "_structured": {
            "Policies": [
                {
                    "PolicyName": "read-only",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Resource": "*"
                            },
                            {
                                "Effect": "Allow",
                                "Resource": "SampleBucket"
                            }
                        ]
                    }
                },
                {
                    "PolicyName": "admin",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Resource": "*"
                            }
                        ]
                    }
                }
            ]
        }
    }

    wildcard_allow = {
        "operator": "AND",
        "scope": "PolicyDocument.Statement",
        "operands": [
            leaf("Effect", "equals", "Allow"),
            leaf("Resource", "equals", "*")
        ]
    }

    # Only the "admin" policy allows on "*" in one statement.
    assert evaluate_expression(
        resource,
        {
            "operator": "AND",
            "scope": "Policies",
            "operands": [
                leaf("PolicyName", "equals", "admin"),
                wildcard_allow
            ]
        }
    ) is True

    # "read-only" has Allow and "*" in it, but never in the same statement.
    assert evaluate_expression(
        resource,
        {
            "operator": "AND",
            "scope": "Policies",
            "operands": [
                leaf("PolicyName", "equals", "read-only"),
                wildcard_allow
            ]
        }
    ) is False


def test_scope_over_a_single_dictionary_is_one_element():
    """CloudFormation writes a one-entry list as a bare mapping often enough that"""

    resource = {
        "_structured": {
            "SecurityGroupIngress": {
                "FromPort": 3389,
                "CidrIp": "0.0.0.0/0"
            }
        }
    }

    assert evaluate_expression(
        resource,
        unrestricted_port(3389, scope="SecurityGroupIngress")
    ) is True


def test_missing_scope_path_returns_false():
    """A scope naming a list the resource does not have has no elements to OR."""

    assert evaluate_expression(
        OPERATOR_RESOURCE,
        unrestricted_port(3389, scope="SecurityGroupIngress")
    ) is False


def test_empty_scope_list_returns_false():
    resource = {"_structured": {"SecurityGroupIngress": []}}

    assert evaluate_expression(
        resource,
        unrestricted_port(3389, scope="SecurityGroupIngress")
    ) is False


def test_get_scope_elements_flattens_one_level_only():
    elements = get_scope_elements(
        SAME_ELEMENT_GROUP,
        "SecurityGroupIngress"
    )

    assert [element["FromPort"] for element in elements] == [22, 3389]


# -----------------------------

# (field, operator, value, expected). One table instead of nine near-identical
# tests; every operator keeps both its True and its False case.
OPERATOR_CASES = [
    ("Engine", "equals", "postgres", True),
    ("Engine", "equals", "mysql", False),
    ("Engine", "not_equals", "mysql", True),
    ("Engine", "not_equals", "postgres", False),
    ("VpcSecurityGroups", "contains", "OpenSecurityGroup", True),
    ("VpcSecurityGroups", "contains", "MissingSecurityGroup", False),
    ("DBInstanceIdentifier", "contains", "public", True),   # substring of a string
    ("AllocatedStorage", "contains", 20, False),            # a scalar contains nothing
    ("VpcSecurityGroups", "contains_any",
     ["MissingSecurityGroup", "DefaultSecurityGroup"], True),
    ("VpcSecurityGroups", "contains_any",
     ["MissingSecurityGroup", "OtherSecurityGroup"], False),
    ("VpcSecurityGroups", "contains_any", "OpenSecurityGroup", True),  # bare value
    ("Engine", "in", ["postgres", "mysql"], True),
    ("Engine", "in", ["oracle", "mysql"], False),
    ("Engine", "in", "postgres-and-mysql", False),          # "in" needs a list
    ("AllocatedStorage", "greater_than", 10, True),
    ("AllocatedStorage", "greater_than", 20, False),
    ("AllocatedStorage", "less_than", 100, True),
    ("AllocatedStorage", "less_than", 20, False),
    ("AllocatedStorage", "greater_than_or_equal", 20, True),
    ("AllocatedStorage", "greater_than_or_equal", 21, False),
    ("AllocatedStorage", "less_than_or_equal", 20, True),
    ("AllocatedStorage", "less_than_or_equal", 19, False),
]


@pytest.mark.parametrize(
    "field,operator,value,expected",
    OPERATOR_CASES,
    ids=[f"{o}-{e}" for _, o, _, e in OPERATOR_CASES]
)
def test_operators(field, operator, value, expected):
    assert evaluate_leaf(
        OPERATOR_RESOURCE,
        leaf(field, operator, value)
    ) is expected


def test_operator_aliases():
    """security_rules.yaml may say either spelling, and either key name."""

    assert compare("postgres", "eq", "postgres") is True
    assert compare("postgres", "neq", "mysql") is True

    assert evaluate_leaf(
        OPERATOR_RESOURCE,
        {"field": "Engine", "operator": "equals", "value": "postgres"}
    ) is True



def test_unsupported_operator_raises_value_error():
    """A typo in a rule must be loud, not silently False."""

    with pytest.raises(ValueError):
        compare("postgres", "matches_regex", "post.*")

    with pytest.raises(ValueError):
        evaluate_leaf(
            OPERATOR_RESOURCE,
            leaf("Engine", "matches_regex", "post.*")
        )


# -----------------------------

def test_and_or_not_nested_three_deep():
    """AND( leaf, OR( leaf, NOT( leaf ) ) ) — evaluated both ways round."""

    def condition(engine_name):
        return {
            "operator": "AND",
            "operands": [
                leaf("PubliclyAccessible", "equals", True),
                {
                    "operator": "OR",
                    "operands": [
                        leaf("AllocatedStorage", "greater_than", 1000),
                        {
                            "operator": "NOT",
                            "operand": leaf("Engine", "equals", engine_name)
                        }
                    ]
                }
            ]
        }

    # public, storage is not > 1000, and the engine is not mysql -> NOT is True
    assert evaluate_expression(OPERATOR_RESOURCE, condition("mysql")) is True

    # same tree, but now the innermost leaf is True, so NOT is False
    assert evaluate_expression(OPERATOR_RESOURCE, condition("postgres")) is False


def test_not_inverts_a_missing_field():
    """A missing field is False, so NOT over it is True. Stated so the next"""

    assert evaluate_expression(
        OPERATOR_RESOURCE,
        {
            "operator": "NOT",
            "operand": leaf("StorageEncrypted", "equals", True)
        }
    ) is True


def test_empty_operand_lists_and_malformed_nodes_return_false():
    assert evaluate_expression(OPERATOR_RESOURCE, {"operator": "AND"}) is False
    assert evaluate_expression(OPERATOR_RESOURCE, {"operator": "OR"}) is False
    assert evaluate_expression(OPERATOR_RESOURCE, {"operator": "NOT"}) is False
    assert evaluate_expression(OPERATOR_RESOURCE, "SecurityGroupIngress") is False
    assert evaluate_expression(OPERATOR_RESOURCE, None) is False


# -----------------------------

def test_missing_field_returns_false_instead_of_raising():
    """Rules are shared across resource types, so most fields are absent from"""

    assert evaluate_leaf(
        OPERATOR_RESOURCE,
        leaf("SecurityGroupIngress.CidrIp", "equals", "0.0.0.0/0")
    ) is False

    assert evaluate_leaf(
        OPERATOR_RESOURCE,
        leaf("BackupRetentionPeriod", "greater_than", 7)
    ) is False

    assert evaluate_leaf(OPERATOR_RESOURCE, leaf("", "equals", "x")) is False
    assert evaluate_leaf(OPERATOR_RESOURCE, leaf("Engine", "", "postgres")) is False


def test_missing_field_inside_a_scope_returns_false():
    """Only one element carries the key. The other must not raise on the way past."""

    resource = {
        "_structured": {
            "SecurityGroupIngress": [
                {"IpProtocol": "-1"},
                {"FromPort": 3389, "CidrIp": "0.0.0.0/0"}
            ]
        }
    }

    assert evaluate_expression(
        resource,
        unrestricted_port(3389, scope="SecurityGroupIngress")
    ) is True

    assert evaluate_expression(
        resource,
        unrestricted_port(1433, scope="SecurityGroupIngress")
    ) is False


def test_get_field_values_walks_dicts_and_lists():
    values = get_field_values(
        SAME_ELEMENT_GROUP["_structured"],
        "SecurityGroupIngress.CidrIp"
    )

    assert values == ["10.0.0.0/8", "0.0.0.0/0"]


def test_evaluator_falls_back_to_the_resource_itself():
    """_structured is what attribute extraction adds; a resource without it is"""

    assert evaluate_leaf(
        {"Engine": "postgres"},
        leaf("Engine", "equals", "postgres")
    ) is True


# -----------------------------

BLOCKED_PORT_RULE_ID = (
    "aws_config:RESTRICTED_INCOMING_TRAFFIC:AWS::EC2::SecurityGroup"
)


def blocked_port_parameters(rules_path):
    """The parameters of the shipped blocked-port rule.

    That rule declares its defaults as a `parameters` mapping, the canonical
    file's spelling, rather than as a `parameter_schema` list. Both resolve to
    the same substitution table, which is what this exercises.
    """

    engine = RuleEngine(rules_path)

    rule = next(
        rule
        for rule in engine.rules
        if rule.get("id") == BLOCKED_PORT_RULE_ID
    )

    return engine, engine._get_parameters(rule)


def test_exact_parameter_reference_resolves_to_the_typed_default(rules_path):
    """A "{blockedPortN}" reference must come back as an int, not as its string
    form: `"3389" == 3389` is False, so a string default would make the rule
    silently stop matching.

    blockedPort3 rather than blockedPort1 because the fixtures in this module are
    built around 3389, and that is the port that parameter holds.
    """

    engine, parameters = blocked_port_parameters(rules_path)

    assert parameters["blockedPort3"] == 3389

    resolved = engine._resolve_parameters(
        unrestricted_port("{blockedPort3}", scope="SecurityGroupIngress"),
        parameters
    )

    port_operand = resolved["operands"][1]

    assert port_operand["value"] == 3389
    assert isinstance(port_operand["value"], int)

    # the scope key survives substitution untouched
    assert resolved["scope"] == "SecurityGroupIngress"

    assert evaluate_expression(SAME_ELEMENT_GROUP, resolved) is True
    assert evaluate_expression(CROSS_ELEMENT_GROUP, resolved) is False


def test_embedded_parameter_reference_is_interpolated_into_the_string(rules_path):
    """The summary_template form: substituted in place, so it stays a string."""

    engine, parameters = blocked_port_parameters(rules_path)

    resolved = engine._resolve_parameters(
        "Security group allows unrestricted ingress on port {blockedPort1}.",
        parameters
    )

    assert resolved == (
        "Security group allows unrestricted ingress on port 20."
    )

    # more than one placeholder in one string
    assert engine._resolve_parameters(
        "{blockedPort1},{blockedPort2}",
        parameters
    ) == "20,21"

    # an unknown name is left alone rather than crashing the rule
    assert engine._resolve_parameters(
        "{notAParameter}",
        parameters
    ) == "{notAParameter}"


# -----------------------------

def test_the_shipped_ingress_rules_still_fire_on_the_real_dataset(
    rules_path,
    real_resource_dicts
):
    """Both ingress rules are scoped, so this is the check that scoping did not
    quietly stop them matching anything.

    project_all before process_resources: the rules resolve `ingress.port`
    against the projected vocabulary, and without the projection they evaluate
    against an empty one and match nothing at all.
    """

    from processing.attribute_extractor import process_resources
    from processing.attributes import project_all
    from security_state_graph.semantics import finding_severity

    engine = RuleEngine(rules_path)

    findings = engine.evaluate_all(
        process_resources(project_all(real_resource_dicts))
    )

    by_source = {}

    for finding in findings:
        by_source.setdefault(finding["source_id"], []).append(finding["resource"])

    # OpenSecurityGroup opens 22 and 3389, so both rules catch it.
    # AppSecurityGroup opens 22 only, so the blocked-port rule must not.
    assert by_source["RESTRICTED_INCOMING_TRAFFIC"] == ["OpenSecurityGroup"]
    assert by_source["INCOMING_SSH_DISABLED"] == [
        "OpenSecurityGroup",
        "AppSecurityGroup"
    ]

    blocked = next(
        finding
        for finding in findings
        if finding["source_id"] == "RESTRICTED_INCOMING_TRAFFIC"
    )

    assert blocked["state"] == "unrestricted_common_port_access"
    assert blocked["semantic"] == "network_control"
    assert finding_severity(blocked) == "high"


def test_the_shipped_rule_tree_matches_a_genuinely_open_group(rules_path):
    """The rule's own condition tree, run as it ships, against a group that is
    open on a blocked port.

    `_attributes` as well as `_structured`, because the shipped tree is written
    against the projected vocabulary (`protocol`, `port`, `cidr`) and would
    resolve nothing against raw CloudFormation property names.
    """

    from processing.attributes import project

    engine, parameters = blocked_port_parameters(rules_path)

    rule = next(
        rule
        for rule in engine.rules
        if rule.get("id") == BLOCKED_PORT_RULE_ID
    )

    conditions = engine._resolve_parameters(
        rule["conditions"],
        parameters
    )

    def projected(fixture):
        return {
            "_structured": fixture["_structured"],
            "_attributes": project({
                "id": "Group",
                "type": "AWS::EC2::SecurityGroup",
                "raw_properties": fixture["_structured"]
            })
        }

    assert evaluate_expression(projected(SAME_ELEMENT_GROUP), conditions) is True

    # And the cross-element group, where 0.0.0.0/0 and 3389 live on different
    # ingress entries, is still refused. That is what the scoping is for.
    assert evaluate_expression(
        projected(CROSS_ELEMENT_GROUP),
        conditions
    ) is False

    scoped = "scope" in conditions or any(
        "scope" in operand
        for operand in conditions.get("operands", [])
        if isinstance(operand, dict)
    )

    if scoped:
        assert evaluate_expression(CROSS_ELEMENT_GROUP, conditions) is False
    else:
        assert evaluate_expression(CROSS_ELEMENT_GROUP, conditions) is True


# -----------------------------
# Numeric coercion on the ordering comparisons.
#
# THEORY: these leaves read raw template values (evaluate_leaf resolves against
# `_structured`), and CloudFormation is hand-written, so a port arrives as 22 in
# one template and "22" in the next. Before coercion `"22" <= 3389` raised
# TypeError, the rule engine caught it and warned, and the effect was a rule that
# silently did not fire on half the templates it should have. These tests pin the
# coercion and, just as importantly, pin that `equals` does NOT coerce.

NUMERIC_RESOURCE = {
    "id": "PortShapes",
    "type": "AWS::EC2::SecurityGroupIngress",
    "_structured": {
        "IntPort": 22,
        "StrPort": "22",
        "FloatPort": 22.0,
        "PaddedPort": " 22 ",
        "Protocol": "-1",
        "Enabled": True,
        "NotANumber": "tcp"
    }
}


@pytest.mark.parametrize(
    "field,operator,value,expected",
    [
        # A string port compared against an integer bound, both directions.
        ("StrPort", "less_than_or_equal", 3389, True),
        ("StrPort", "greater_than_or_equal", 22, True),
        ("StrPort", "greater_than_or_equal", 23, False),
        ("StrPort", "less_than", 22, False),
        # An integer port against a string bound.
        ("IntPort", "less_than_or_equal", "3389", True),
        ("IntPort", "greater_than_or_equal", "23", False),
        # Floats and whitespace both resolve.
        ("FloatPort", "greater_than_or_equal", 22, True),
        ("PaddedPort", "less_than_or_equal", 22, True),
    ],
    ids=lambda item: str(item)
)
def test_ordering_comparisons_coerce_numeric_strings(field, operator, value, expected):
    assert evaluate_leaf(
        NUMERIC_RESOURCE,
        leaf(field, operator, value)
    ) is expected


def test_a_non_numeric_operand_is_no_match_rather_than_an_error():
    """The rule engine used to swallow a TypeError here and warn instead."""

    assert evaluate_leaf(
        NUMERIC_RESOURCE,
        leaf("NotANumber", "less_than_or_equal", 3389)
    ) is False


def test_a_boolean_is_refused_rather_than_treated_as_one():
    """True is 1 in Python. A rule comparing a port to a flag has a bug in it and
    must not be handed a plausible answer."""

    assert evaluate_leaf(
        NUMERIC_RESOURCE,
        leaf("Enabled", "greater_than_or_equal", 1)
    ) is False


def test_equals_does_not_coerce():
    """A rule saying IpProtocol equals "-1" must not also match the integer -1.
    Rules needing both spellings say so with `in`."""

    assert evaluate_leaf(
        NUMERIC_RESOURCE,
        leaf("Protocol", "equals", -1)
    ) is False

    assert evaluate_leaf(
        NUMERIC_RESOURCE,
        leaf("Protocol", "equals", "-1")
    ) is True

    assert evaluate_leaf(
        NUMERIC_RESOURCE,
        leaf("Protocol", "in", ["-1", -1])
    ) is True
