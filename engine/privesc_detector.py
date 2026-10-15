"""Match an IAM principal's policies against the privilege escalation catalogue.

Pipeline:

resource.raw_properties
        ↓
walk_statements()      every Effect/Action/Resource block, at any nesting depth
        ↓
granted_actions()      the Action patterns of the unconditional Allow statements
        ↓
detect_methods()       the catalogue entries every one of whose actions is held

THEORY (why this is not another YAML rule):
Every other detection in this repo is a condition tree in security_rules.yaml,
evaluated by engine/condition_evaluator.py, and a privilege escalation method
cannot be written that way. The question is not "does this field equal that
value" but "does the set of actions this principal holds *cover* the set of
actions the method needs", where both sides may be wildcards — `iam:*` has to
satisfy `iam:PassRole`. That is set covering with pattern matching, not a
comparison, so it lives in code and the catalogue stays as data.

THEORY (why Resource is not required to be "*"):
engine/connection_builder.is_wildcard_allow demands `Resource: "*"`, because it
is answering "can this principal reach every bucket in the account". This module
is answering a different question, and the same demand would break it:
`iam:PassRole` scoped to one role ARN is still a complete escalation *to that
role*. Requiring the wildcard would discard the narrowly-scoped grants, which is
to say most real ones. So a statement qualifies on Effect and Action, and the
Resource is left to say which target rather than whether.

WHAT IS NOT MODELLED, AND MATTERS:
This is not an IAM policy evaluator. A `Deny` statement that would cancel one of
these grants is skipped rather than subtracted, so a principal explicitly denied
`iam:PassRole` by a boundary or an SCP is still reported as holding it. Doing it
properly means implementing AWS's evaluation logic — explicit deny, permission
boundaries, SCPs, session policies, resource policies — against data the parser
does not currently carry. So this over-reports rather than under-reports, which
is the safer direction for a finding a human reviews, and it is written down
here rather than left for someone to discover.
"""

import yaml
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

METHODS_PATH = BASE_DIR / "data" / "privesc_methods.yaml"

ALLOW_EFFECT = "Allow"

WILDCARD = "*"

ACTION_SERVICE_SEPARATOR = ":"

CONDITION_KEY = "Condition"

# The keys that mark a dictionary as an IAM statement rather than any other
# nested object. Effect is the one no statement omits.
STATEMENT_MARKER = "Effect"

# What `escalates_to` may say. Kept here so a typo in the catalogue is a load
# error rather than a method that silently never draws an edge.
ESCALATION_TARGETS = ["self", "principal", "passable_role", "compute"]


def load_methods(path=METHODS_PATH):
    """The privilege escalation catalogue, validated on the way in."""

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    methods = (data or {}).get("methods") or []

    for method in methods:

        # -----------------------------

        target = method.get("escalates_to")

        if target not in ESCALATION_TARGETS:
            raise ValueError(
                "privesc method {} has escalates_to {!r}, expected one of {}"
                .format(method.get("id"), target, ESCALATION_TARGETS)
            )

        if not method.get("requires"):
            raise ValueError(
                "privesc method {} requires no actions".format(method.get("id"))
            )

    return methods


def walk_statements(properties):
    """Every IAM statement in a properties tree, at any depth."""

    found = []

    if isinstance(properties, dict):

        if STATEMENT_MARKER in properties:
            found.append(properties)

        for value in properties.values():
            found.extend(walk_statements(value))

    elif isinstance(properties, list):

        for item in properties:
            found.extend(walk_statements(item))

    return found


def statement_actions(statement):
    """The Action values of one statement, as a list."""

    action = statement.get("Action")

    if isinstance(action, list):
        return [item for item in action if isinstance(item, str)]

    if isinstance(action, str):
        return [action]

    return []


def actions_from_statements(statements):
    """Every action pattern a list of statements grants unconditionally."""

    patterns = []

    for statement in statements:

        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != ALLOW_EFFECT:
            continue

        # A conditional grant is one this module cannot claim is exercisable.
        # Same choice, and same reason, as connection_builder.is_wildcard_allow.
        if statement.get(CONDITION_KEY):
            continue

        for pattern in statement_actions(statement):

            if pattern not in patterns:
                patterns.append(pattern)

    return patterns


def granted_actions(properties):
    """Every action pattern the properties grant unconditionally."""

    return actions_from_statements(walk_statements(properties))


def action_matches(pattern, required):
    """True when a granted Action pattern covers a required action."""

    if not isinstance(pattern, str) or not isinstance(required, str):
        return False

    # "*" is every action in every service.
    if pattern == WILDCARD:
        return True

    pattern_lower = pattern.lower()
    required_lower = required.lower()

    if pattern_lower == required_lower:
        return True

    # -----------------------------

    # "iam:*" and "lambda:Create*". Split on the service separator so that a
    # trailing "*" is matched against the operation only — otherwise "i*" would
    # be read as covering every service beginning with i.
    if ACTION_SERVICE_SEPARATOR not in pattern_lower:
        return False

    if ACTION_SERVICE_SEPARATOR not in required_lower:
        return False

    pattern_service, pattern_operation = pattern_lower.split(
        ACTION_SERVICE_SEPARATOR, 1
    )

    required_service, required_operation = required_lower.split(
        ACTION_SERVICE_SEPARATOR, 1
    )

    if pattern_service != required_service:
        return False

    if pattern_operation == WILDCARD:
        return True

    if pattern_operation.endswith(WILDCARD):
        return required_operation.startswith(pattern_operation[:-1])

    return False


def holds_action(patterns, required):
    """True when any granted pattern covers `required`."""

    return any(
        action_matches(pattern, required)
        for pattern in patterns
    )


def holds_every_action(patterns, required_actions):
    """True when every action a method needs is covered."""

    return all(
        holds_action(patterns, required)
        for required in required_actions
    )


def grants_full_admin(properties):
    """True when the properties grant every action, i.e. `Action: "*"`.

    A principal holding "*" satisfies all 28 catalogue methods, and reporting 28
    findings on it is 28 restatements of one fact. The wildcard already has its
    own rule (IAM_WILDCARD_PERMISSIONS), so callers collapse to that instead of
    enumerating. Kept separate from detection so the enumeration is still
    available to anything that wants it.
    """

    return WILDCARD in granted_actions(properties)


def detect_methods(properties, methods=None, collapse_admin=True):
    """The catalogue entries whose required actions are all granted.

    With `collapse_admin`, a principal that already grants "*" returns nothing:
    it is the wildcard case, not 28 separate escalation methods.
    """

    if methods is None:
        methods = load_methods()

    return detect_from_patterns(
        granted_actions(properties),
        methods,
        collapse_admin
    )


def detect_from_patterns(patterns, methods=None, collapse_admin=True):
    """The catalogue entries satisfied by an already-collected action set.

    Split out of detect_methods so a caller that merged a principal's own
    statements with the ones attached to it from outside can reuse the matching
    without rebuilding the pattern list.
    """

    if methods is None:
        methods = load_methods()

    if not patterns:
        return []

    if collapse_admin and WILDCARD in patterns:
        return []

    return [
        method
        for method in methods
        if holds_every_action(patterns, method.get("requires") or [])
    ]


def detect_for_resource(resource, methods=None):
    """The methods a CloudResource's own policies grant it."""

    return detect_methods(resource.raw_properties, methods)


# -----------------------------
# Policies attached from the outside.
#
# THEORY (why a principal's own properties are not the whole story):
# detect_for_resource reads a resource's own raw_properties, which finds the
# permissions written inline on a role. Real templates frequently do not write
# them there. They declare `AWS::IAM::Policy` as a separate resource carrying a
# `Roles:` list, and the role itself holds no statements at all — 149 templates in
# the corpus do this against 429 with any PolicyDocument, and the WordPress stack
# whose escalation chain we could not see was one of them.
#
# So a principal's granted actions are its own statements plus those of every
# policy resource that names it. Attribution runs from the policy to the principal
# rather than the reverse, because that is the direction CloudFormation declares:
# the policy names its holders, the holder never names its policies.

# Where an attached policy lists the principals it applies to.
ATTACHMENT_FIELDS = ["Roles", "Users", "Groups"]

# The resource types that attach a policy to someone else. ManagedPolicy carries
# the same three lists as Policy.
ATTACHED_POLICY_TYPES = ["AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"]


def attachment_targets(properties):
    """The principal ids an attached policy names, across all three lists."""

    targets = []

    for field in ATTACHMENT_FIELDS:

        value = properties.get(field)

        if isinstance(value, str):
            targets.append(value)

        elif isinstance(value, list):

            for item in value:
                if isinstance(item, str):
                    targets.append(item)

    return targets


def attached_statements(infra):
    """principal id -> the statements attached to it by policy resources.

    A policy naming a principal that is not in the model is skipped: a template
    may attach to a role declared in another stack, and inventing a node for it
    would put a resource in the graph that the account being analysed does not
    contain.
    """

    attached = {}

    for resource in infra.all_resources():

        if resource.type not in ATTACHED_POLICY_TYPES:
            continue

        statements = walk_statements(resource.raw_properties)

        if not statements:
            continue

        for target in attachment_targets(resource.raw_properties):

            if infra.get_resource(target) is None:
                continue

            attached.setdefault(target, []).extend(statements)

    return attached


def granted_actions_for(resource, attached=None):
    """Every action `resource` holds: its own, plus anything attached to it."""

    patterns = list(granted_actions(resource.raw_properties))

    for pattern in actions_from_statements((attached or {}).get(resource.id, [])):

        if pattern not in patterns:
            patterns.append(pattern)

    return patterns


# -----------------------------
# Broad wildcard grants.
#
# THEORY (why the catalogue and the wildcard rule together are not enough):
# The catalogue matches *named* escalation actions, and IAM_WILDCARD_PERMISSIONS
# matches full `Action: "*"` written inline on the principal. A role holding
# `s3:*` / `rds:*` on `Resource: "*"` through an attached policy falls between
# them, and that is the commonest shape in real templates: cfngoat's EC2Role holds
# exactly that and produced no privilege finding at all.
#
# The inconsistency mattered because build_capability_edges reads the *same*
# grant and draws an edge for it. So the graph asserted "this role can read every
# bucket" while the exploitability policy, which looks for a `privilege` finding,
# saw nothing to escalate through — and rejected every path that went through the
# role the edges had just been drawn from. If a grant is strong enough to justify
# a capability edge, it is strong enough to be a finding.
#
# Two shapes, kept apart because they are not the same claim:
#   full admin  -> "*" on everything. Only reported when the wildcard rule could
#                  not have seen it, i.e. it arrived from an attached policy, so
#                  this never duplicates IAM_WILDCARD_PERMISSIONS.
#   broad grant -> "<service>:*". Serious but not total, so `high` not `critical`.

ADMIN_VIA_ATTACHED_STATE = "wildcard_admin_via_attached_policy"
BROAD_GRANT_STATE = "broad_service_wildcard_grant"

# Services whose wildcard is worth a finding on its own. Deliberately not "any
# service": `logs:*` or `cloudwatch:*` is untidy, not a route to the data.
BROAD_GRANT_SERVICES = [
    "iam", "sts", "s3", "rds", "dynamodb", "secretsmanager", "kms",
    "lambda", "ec2", "ecs", "glue", "sagemaker", "redshift", "elasticfilesystem"
]


def wildcard_services(patterns):
    """The services a pattern list grants wholesale, as "<service>:*"."""

    services = []

    for pattern in patterns or []:

        if not isinstance(pattern, str):
            continue

        if ACTION_SERVICE_SEPARATOR not in pattern:
            continue

        service, operation = pattern.split(ACTION_SERVICE_SEPARATOR, 1)

        if operation.strip() != WILDCARD:
            continue

        service = service.strip().lower()

        if service in BROAD_GRANT_SERVICES and service not in services:
            services.append(service)

    return services


def broad_grant_findings(resource, attached=None):
    """Privilege findings for wildcard grants the catalogue does not name.

    Returns the same shape as a rule engine finding, minus the resource id, which
    the caller adds. Empty when the principal holds nothing broad.
    """

    patterns = granted_actions_for(resource, attached)

    if not patterns:
        return []

    # -----------------------------

    if WILDCARD in patterns:

        # Inline "*" is IAM_WILDCARD_PERMISSIONS' job. Reporting it here too
        # would put two findings on one node for one fact.
        if grants_full_admin(resource.raw_properties):
            return []

        return [{
            "rule_id": ADMIN_VIA_ATTACHED_STATE.upper(),
            "state": ADMIN_VIA_ATTACHED_STATE,
            "severity": "critical",
            "services": [WILDCARD]
        }]

    # -----------------------------

    services = wildcard_services(patterns)

    if not services:
        return []

    return [{
        "rule_id": BROAD_GRANT_STATE.upper(),
        "state": BROAD_GRANT_STATE,
        "severity": "high",
        "services": services
    }]
