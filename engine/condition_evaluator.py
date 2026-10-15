"""Generic condition evaluator."""

from typing import Any


def get_field_values(data: Any, field: str) -> list:
    """Retrieve all values matching a dotted field path."""

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


def resolve_field(resource: Any, field: str) -> list:
    """Every value `field` names, abstract vocabulary first.

    Two vocabularies reach here. `ingress.port` is an attribute the parser
    projected; `SecurityGroupIngress[0].CidrIp` is a raw CloudFormation path. The
    projection is tried first because an abstract name is a deliberate statement
    of what a rule means, and it is checked for emptiness rather than presence:
    an attribute block that exists but says nothing about this field should still
    fall through to the raw properties.
    """

    if not isinstance(resource, dict):
        return get_field_values(resource, field)

    attributes = resource.get("_attributes") or {}

    # The literal key first, before any dot-splitting.
    #
    # THEORY: two kinds of dotted name arrive here and they are not the same
    # shape. `ingress.port` is a walk: `ingress` is a list and `port` is a key on
    # each element. `BucketPolicy.AllowsPublicRead` is one flat key whose name
    # happens to contain a dot, because it is a conclusion drawn about a policy
    # rather than a path into one. Splitting it looked for a `BucketPolicy`
    # dictionary that does not exist, so every bucket rule resolved nothing and
    # quietly never fired.
    if field in attributes:
        return [attributes[field]]

    projected = get_field_values(attributes, field)

    if projected:
        return projected

    return get_field_values(resource.get("_structured", resource), field)


def get_scope_elements(resource: Any, scope: str) -> list:
    """Resolve a scope path to the elements a subtree is evaluated against."""

    # -----------------------------

    values = resolve_field(resource, scope)

    # -----------------------------

    # A path ending on a list resolves to the list itself, not to its items.

    elements = []

    for value in values:

        if isinstance(value, list):
            elements.extend(value)
        else:
            elements.append(value)

    return elements


def compare(value, operator, expected):
    """Evaluate one comparison."""

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

    # The complement of `in`, and not a synonym for "absent": a field that
    # resolves to nothing never reaches here, because evaluate_leaf returns False
    # on an empty resolution. So `not_in` means "present, and not one of these".
    #
    # A non-list `value` is a rule with a bug in it and returns False either way,
    # which is the same answer `in` gives rather than the opposite one.
    if operator == "not_in":
        if isinstance(expected, list):
            return value not in expected

        return False

    # -----------------------------

    # The ordering comparisons coerce first.
    #
    # THEORY: these leaves read raw template values, not the normalized ones —
    # evaluate_leaf resolves against `_structured`. CloudFormation is written by
    # hand, so a port arrives as 22 in one template and "22" in the next, and
    # `"22" <= 3389` is a TypeError on Python 3. The rule engine catches it, warns,
    # and moves on, so the effect is a rule that silently does not fire on half
    # the templates it should. Coercing here fixes it for every rule at once
    # rather than asking each rule to guess which spelling it will meet.
    #
    # Only the ordering operators coerce. `equals` must not: a rule saying
    # `IpProtocol equals "-1"` should not also match the integer -1 unless it says
    # so, and a rule matching an account id string must not match its numeric
    # twin. Rules that need both spellings use `in` with both values.

    if operator in ("greater_than", "less_than",
                    "greater_than_or_equal", "less_than_or_equal"):

        left, right = numeric_pair(value, expected)

        if left is None or right is None:
            return False

        if operator == "greater_than":
            return left > right

        if operator == "less_than":
            return left < right

        if operator == "greater_than_or_equal":
            return left >= right

        return left <= right

    raise ValueError(f"Unsupported comparison operator: {operator}")


def numeric_pair(value, expected):
    """Both operands as floats, or (None, None) when either is not a number.

    A non-numeric operand makes an ordering comparison meaningless rather than
    False, but the caller has nothing useful to return either way, so it reports
    no match instead of raising. Booleans are refused: `True` is 1 in Python, and
    a rule comparing a port to a flag is a rule with a bug in it, which should not
    be given a plausible answer.
    """

    return (as_number(value), as_number(expected))


def as_number(value):
    """`value` as a float, or None when it does not represent one."""

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None

    return None


def evaluate_leaf(resource, condition):
    """Evaluate a single field comparison."""

    field = condition.get("field")
    operator = condition.get("comparison", condition.get("operator"))
    expected = condition.get("value")

    if not field or not operator:
        return False

    values = resolve_field(resource, field)

    if not values:
        return False

    # A field can represent multiple list elements.
    # The condition is satisfied if at least one value matches.
    return any(
        compare(value, operator, expected)
        for value in values
    )


def evaluate_scoped(resource, expression):
    """Evaluate one subtree once per element of the scoped list, then OR."""

    scope = expression.get("scope")

    # -----------------------------

    # Without this the recursive call would scope forever.

    inner = {
        key: value
        for key, value in expression.items()
        if key != "scope"
    }

    if not scope:
        return evaluate_expression(resource, inner)

    # -----------------------------

    # Each element is wrapped the way attribute extraction wraps a resource,
    # so the subtree resolves its fields through the usual path.

    return any(
        evaluate_expression(
            {"_structured": element, "_attributes": element},
            inner
        )
        for element in get_scope_elements(resource, scope)
    )


def evaluate_expression(resource, expression):
    """Recursively evaluate a logical condition tree."""

    if not isinstance(expression, dict):
        return False

    # Element scoping — applies to whatever node carries the key
    if "scope" in expression:
        return evaluate_scoped(resource, expression)

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