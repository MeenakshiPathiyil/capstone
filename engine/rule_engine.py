"""
Generic security rule engine.

Pipeline:

normalized resources
        ↓
attribute extraction
        ↓
rule indexing
        ↓
parameter resolution
        ↓
condition evaluator
        ↓
True / False
        ↓
security finding
"""

import yaml
from collections import defaultdict

from engine.condition_evaluator import evaluate_expression


class RuleEngine:

    def __init__(self, rules_path):

        # -----------------------------
        # Load security rule knowledge
        # -----------------------------

        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            self.rules = []

        elif isinstance(data, dict) and "rules" in data:
            self.rules = data["rules"]

        elif isinstance(data, list):
            self.rules = data

        else:
            # Single rule file
            self.rules = [data]

        # -----------------------------
        # Build resource-type index
        # -----------------------------

        self.rule_index = self._build_index(self.rules)

    def _build_index(self, rules):
        """
        Hash-based rule index.

        Example:

        AWS::EC2::SecurityGroup
                ↓
        [rule1, rule2, rule3]

        AWS::S3::Bucket
                ↓
        [rule4, rule5]
        """

        index = defaultdict(list)

        for rule in rules:

            if not isinstance(rule, dict):
                continue

            resource_type = rule.get("resource_type")

            if resource_type:
                index[resource_type].append(rule)

        return index

    def evaluate_resource(self, resource):
        """
        Evaluate all rules applicable to one resource.
        """

        matches = []

        resource_type = resource.get("type")

        # Retrieve only relevant rules.
        rules = self.rule_index.get(resource_type, [])

        for rule in rules:

            try:

                # -----------------------------
                # Resolve rule parameters
                # -----------------------------

                parameters = self._get_parameters(rule)

                # -----------------------------
                # Resolve conditions
                # -----------------------------

                conditions = rule.get("conditions")

                if not conditions:
                    continue

                conditions = self._resolve_parameters(
                    conditions,
                    parameters
                )

                # -----------------------------
                # Evaluate condition tree
                # -----------------------------

                matched = evaluate_expression(
                    resource,
                    conditions
                )

                if matched:

                    state = rule.get("state")

                    # New format:
                    #
                    # state:
                    #   id: unrestricted_common_port_access
                    #
                    # Older format:
                    #
                    # state: some_state
                    #
                    if isinstance(state, dict):
                        state_id = state.get("id")
                    else:
                        state_id = state

                    matches.append({
                        "resource": resource.get("id"),
                        "rule_id": rule.get("id"),
                        "state": state_id,
                        "semantic": rule.get("semantic"),
                        "severity": rule.get("severity")
                    })

            except Exception as e:

                # A bad rule should not stop
                # evaluation of the entire rule set.
                print(
                    f"Warning: failed to evaluate "
                    f"{rule.get('id', 'unknown')}: {e}"
                )

        return matches

    def evaluate_all(self, resources):
        """
        Evaluate every resource against
        its applicable security rules.
        """

        results = []

        for resource in resources:
            results.extend(
                self.evaluate_resource(resource)
            )

        return results

    def _get_parameters(self, rule):
        """
        Extract parameters from parameter_schema.

        Example:

        blockedPort1:
            default: 3389

        becomes:

        {
            "blockedPort1": 3389
        }
        """

        parameters = {}

        schema = rule.get("parameter_schema", [])

        if not isinstance(schema, list):
            return parameters

        for parameter in schema:

            if not isinstance(parameter, dict):
                continue

            name = parameter.get("name")

            if not name:
                continue

            if "default" in parameter:
                parameters[name] = parameter["default"]

        return parameters

    def _resolve_parameters(self, value, parameters):
        """
        Recursively replace:

            "{blockedPort1}"

        with:

            3389

        Works inside dictionaries and lists.
        """

        if isinstance(value, dict):

            return {
                key: self._resolve_parameters(
                    item,
                    parameters
                )
                for key, item in value.items()
            }

        if isinstance(value, list):

            return [
                self._resolve_parameters(
                    item,
                    parameters
                )
                for item in value
            ]

        if isinstance(value, str):

            # Exact parameter reference
            if (
                value.startswith("{")
                and value.endswith("}")
            ):

                parameter_name = value[1:-1]

                if parameter_name in parameters:
                    return parameters[parameter_name]

            # Embedded parameter reference
            for name, parameter_value in parameters.items():

                placeholder = "{" + name + "}"

                if placeholder in value:
                    value = value.replace(
                        placeholder,
                        str(parameter_value)
                    )

            return value

        return value