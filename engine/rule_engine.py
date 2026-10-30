"""Generic security rule engine."""

import yaml
from collections import defaultdict

from engine.condition_evaluator import evaluate_expression


class RuleEngine:

    def __init__(self, rules_path):

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

        self.rule_index = self._build_index(self.rules)

        # Every rule that raised, as {"rule_id", "resource", "error"}. The print
        # below is for the command line; this list is for a caller that has to
        # report the failure rather than let it scroll past.
        self.evaluation_errors = []

    def _build_index(self, rules):
        """Hash-based rule index."""

        index = defaultdict(list)

        for rule in rules:

            if not isinstance(rule, dict):
                continue

            resource_type = rule.get("resource_type")

            if resource_type:
                index[resource_type].append(rule)

        return index

    def evaluate_resource(self, resource):
        """Evaluate all rules applicable to one resource."""

        matches = []

        resource_type = resource.get("type")

        # Retrieve only relevant rules.
        rules = self.rule_index.get(resource_type, [])

        for rule in rules:

            try:

                # -----------------------------

                parameters = self._get_parameters(rule)

                # -----------------------------

                conditions = rule.get("conditions")

                if not conditions:
                    continue

                conditions = self._resolve_parameters(
                    conditions,
                    parameters
                )

                # -----------------------------

                matched = evaluate_expression(
                    resource,
                    conditions
                )

                if matched:

                    state = rule.get("state")

                    # New format: the state is a dict carrying its id.
                    if isinstance(state, dict):
                        state_id = state.get("id")
                    else:
                        state_id = state

                    matches.append({
                        "resource": resource.get("id"),
                        "rule_id": rule.get("id"),

                        # The check this rule implements, without the origin and
                        # resource type the composite id wraps it in. Carried
                        # because the path layer has to make decisions about a
                        # check rather than about one of its three per-type
                        # copies: REQUIRED_TAGS is excluded from path roles by
                        # this field, not by three composite ids.
                        "source_id": rule.get("source_id") or rule.get("id"),

                        "state": state_id,
                        "semantic": rule.get("semantic"),

                        # Absent on canonical rules, which do not declare one.
                        # security_state_graph/semantics derives it from the semantic when it
                        # is missing. See SEVERITY_BY_SEMANTIC there.
                        "severity": rule.get("severity")
                    })

            except Exception as e:

                # A bad rule should not stop
                # evaluation of the entire rule set.
                print(
                    f"Warning: failed to evaluate "
                    f"{rule.get('id', 'unknown')}: {e}"
                )

                self.evaluation_errors.append({
                    "rule_id": rule.get("id", "unknown"),
                    "resource": resource.get("id"),
                    "error": str(e)
                })

        return matches

    def evaluate_all(self, resources):
        """Evaluate every resource against the rules indexed for its type."""

        results = []

        for resource in resources:
            results.extend(
                self.evaluate_resource(resource)
            )

        return results

    def _get_parameters(self, rule):
        """A rule's parameter defaults, in either of the two spellings.

        `parameters` is a plain name -> value mapping and is what the canonical
        ruleset uses. `parameter_schema` is a list of descriptors carrying a
        `default`, which is what the rules written on this branch use, and it
        documents each value's type and reason. Both resolve to the same
        substitution table, so a rule can be written either way and neither
        format has to be rewritten to be adopted.
        """

        parameters = {}

        declared = rule.get("parameters")

        if isinstance(declared, dict):
            parameters.update(declared)

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
        """Recursively replace {name} parameter references with their values."""

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