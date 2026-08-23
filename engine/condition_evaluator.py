"""
Generic condition evaluator.

Responsibilities:
- Resolve nested/list-based fields from a resource
- Evaluate simple comparisons
- Recursively evaluate AND / OR / NOT logical trees

The evaluator contains generic logic only.
AWS-specific security knowledge remains in security_rules.yaml.
"""

from typing import Any


def get_field_values(data: Any, field: str) -> list:
    """
    Retrieve all values matching a dotted field path.

    Supports nested dictionaries and lists.

    Example:
        SecurityGroupIngress.CidrIp

    can retrieve:

        [
            "0.0.0.0/0",
            "10.0.0.0/16"
        ]
    """

    parts = field.split(".")

    def resolve(current, remaining):
        if not remaining:
            return [current]

        part = remaining[0]
        results = []

        if isinstance(current, dict):
            if part in current:
                results.extend(
                    resolve(current[part], remaining[1:])
                )

        elif isinstance(current, list):
            for item in current:
                results.extend(
                    resolve(item, remaining)
                )

        return results

    return resolve(data, parts)


def compare(value, operator, expected):
    """
    Evaluate one comparison.
    """

    if operator in ("equals", "eq"):
        return value == expected

    if operator in ("not_equals", "neq"):
        return value != expected

    if operator == "contains":
        if isinstance(value, (list, str)):
            return expected in value
        return False

    if operator == "contains_any":
        if not isinstance(value, (list, str)):
            return False

        if isinstance(expected, list):
            return any(item in value for item in expected)

        return expected in value

    if operator == "in":
        if isinstance(expected, list):
            return value in expected

        return False

    if operator == "greater_than":
        return value > expected

    if operator == "less_than":
        return value < expected

    if operator == "greater_than_or_equal":
        return value >= expected

    if operator == "less_than_or_equal":
        return value <= expected

    raise ValueError(f"Unsupported comparison operator: {operator}")


def evaluate_leaf(resource, condition):
    """
    Evaluate a single field comparison.

    Example:

        {
            "field": "SecurityGroupIngress.CidrIp",
            "comparison": "equals",
            "value": "0.0.0.0/0"
        }
    """

    field = condition.get("field")
    operator = condition.get("comparison", condition.get("operator"))
    expected = condition.get("value")

    if not field or not operator:
        return False

    values = get_field_values(
        resource.get("_structured", resource),
        field
    )

    if not values:
        return False

    # A field can represent multiple list elements.
    # The condition is satisfied if at least one value matches.
    return any(
        compare(value, operator, expected)
        for value in values
    )


def evaluate_expression(resource, expression):
    """
    Recursively evaluate a logical condition tree.

    Supported:
        AND
        OR
        NOT
        leaf comparisons
    """

    if not isinstance(expression, dict):
        return False

    operator = expression.get("operator")

    # Logical AND
    if operator == "AND":
        operands = expression.get("operands", [])

        if not operands:
            return False

        return all(
            evaluate_expression(resource, operand)
            for operand in operands
        )

    # Logical OR
    if operator == "OR":
        operands = expression.get("operands", [])

        if not operands:
            return False

        return any(
            evaluate_expression(resource, operand)
            for operand in operands
        )

    # Logical NOT
    if operator == "NOT":
        operand = expression.get("operand")

        if operand is None:
            return False

        return not evaluate_expression(resource, operand)

    # Leaf comparison
    return evaluate_leaf(resource, expression)