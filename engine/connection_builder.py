"""Turn resource properties into graph edges."""

from engine.flatten import flatten_dict

ALLOWED_CATEGORIES = ["identity", "network_control", "connection", "trust",
                      "traffic_path"]

TRAFFIC_PATH_CATEGORY = "traffic_path"

# The load balancer plumbing a request travels through.
#
# THEORY (why this is a list and RELATION_BY_TARGET_TYPE is derived from it):
# It was written as a second list beside a hand-copied set of table entries, and
# the two immediately disagreed — the list had the classic
# AWS::ElasticLoadBalancing::LoadBalancer and the table did not, so classic-ELB
# references fell through to DEFAULT_RELATION and the classic front door stayed
# disconnected while looking handled. Nothing read the list at all. Deriving the
# entries makes the divergence impossible.
TRAFFIC_PATH_TYPES = [
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::Listener",
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::EC2::LaunchTemplate",
    "AWS::AutoScaling::LaunchConfiguration"
]

# Fallback classifier: when the tag cannot say what an edge means, the type of
# the resource being pointed at can.
RELATION_BY_TARGET_TYPE = {
    "AWS::IAM::Role": "identity",
    "AWS::IAM::InstanceProfile": "identity",
    "AWS::EC2::SecurityGroup": "network_control",
    "AWS::S3::Bucket": "connection",
    "AWS::RDS::DBInstance": "connection",
    "AWS::RDS::DBCluster": "connection"
}

RELATION_BY_TARGET_TYPE.update({
    resource_type: TRAFFIC_PATH_CATEGORY
    for resource_type in TRAFFIC_PATH_TYPES
})

# An unclassifiable reference is still a reference.
DEFAULT_RELATION = "connection"

# Who a wildcard grant travels with. Only a principal carries "*" across
# services; a policy attached to a resource is scoped to that resource.
#
# THEORY (why AWS::IAM::Policy is NOT here):
# It was, and that made a policy document an actor. build_escalation_edges then
# drew "AttachedPolicy -> VictimRole escalation" — a hop no attacker can walk,
# because a policy cannot attach anything; whoever controls the role it is
# attached to can. It also produced the nonsensical edge from a policy to the
# very role holding it. A policy's permissions belong to the principals its
# Roles/Users/Groups lists name, which is what
# engine.privesc_detector.attached_statements resolves.
IAM_PRINCIPAL_TYPES = [
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::IAM::Group",
    "AWS::IAM::InstanceProfile"
]

# What a wildcard grant is worth reaching: the resources that hold the data.
DATA_TYPES = [
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    # Aurora. A corpus WordPress stack put its data here and the search walked
    # straight past it, because only ::DBInstance was listed.
    "AWS::RDS::DBCluster",
    "AWS::SecretsManager::Secret",
    "AWS::KMS::Key",
    "AWS::DynamoDB::Table",
    "AWS::EFS::FileSystem",
    "AWS::Redshift::Cluster",
    "AWS::SQS::Queue"
]

# The IAM action prefix that governs each data type. "s3:GetObject" on Resource
SERVICE_BY_TYPE = {
    "AWS::S3::Bucket": "s3",
    "AWS::RDS::DBInstance": "rds",
    "AWS::SecretsManager::Secret": "secretsmanager",
    "AWS::KMS::Key": "kms",
    "AWS::DynamoDB::Table": "dynamodb",
    "AWS::EFS::FileSystem": "elasticfilesystem",
    "AWS::RDS::DBCluster": "rds",
    "AWS::Redshift::Cluster": "redshift",
    "AWS::SQS::Queue": "sqs"
}

# Compute that runs code under an attached role, and is therefore worth hijacking:
# taking over the resource yields whatever its role holds. The target of the
# `hijack_compute` class in data/privesc_methods.yaml.
COMPUTE_TYPES = [
    "AWS::Lambda::Function",
    "AWS::EC2::Instance",
    # Production templates almost never declare a bare instance. They declare a
    # launch template and an auto scaling group, and the role arrives through the
    # template's IamInstanceProfile. Omitting these made the compute layer of
    # every real stack in the corpus invisible.
    "AWS::EC2::LaunchTemplate",
    # The pre-LaunchTemplate form. Every template in aws-refarch-wordpress and
    # ecs-refarch-cloudformation uses it, and it carries IamInstanceProfile the
    # same way, so omitting it hid the compute layer of those stacks entirely.
    "AWS::AutoScaling::LaunchConfiguration",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::Glue::DevEndpoint",
    "AWS::SageMaker::NotebookInstance",
    "AWS::ECS::Service"
]

# THEORY (why load balancer plumbing needs its own category):
# An internet-facing load balancer was an entry point with no outgoing edges, so
# every real stack in the corpus had an unreachable front door. Traffic flows
# LoadBalancer -> Listener -> TargetGroup -> AutoScalingGroup -> the instances a
# launch template describes, but CloudFormation declares those pointing at their
# *parent*, and inconsistently: a Listener names its LoadBalancerArn (child ->
# parent) and also names its TargetGroup (parent -> child). One reversal rule
# cannot be right for both, so security_state_graph.state_graph treats the category as
# bidirectional. The types are listed above, next to the table derived from them.

# The two edge categories privilege escalation adds, and what they mean.
#
# THEORY (why escalation edges are the point of the catalogue):
# build_capability_edges only ever draws principal -> data, so before these the
# graph could not represent "role A can become role B, which can read the
# database". Every multi-step escalation collapsed into either one hop or none.
# `escalation` is principal -> principal, so a chain of them is a chain of
# identities, which is what privilege escalation in a cloud account actually is.
ESCALATION_CATEGORY = "escalation"
HIJACK_CATEGORY = "hijack"

WILDCARD = "*"

# The separator in "s3:GetObject". An action with no separator that is not "*" is
ACTION_SERVICE_SEPARATOR = ":"

# The key that makes a grant conditional, and therefore not something this module
# can claim is exercisable.
CONDITION_KEY = "Condition"


def build_connections(infra):
    """Add one edge per property whose value names another resource."""

    for resource in infra.all_resources():

        flat_props = flatten_dict(resource.raw_properties)
        semantics = resource.semantic_properties

        for key, value in flat_props.items():

            # -----------------------------

            if not isinstance(value, str):
                continue

            if value not in infra.resources:
                continue

            # A resource referring to itself is not a hop an attacker can take.
            if value == resource.id:
                continue

            # -----------------------------

            category = semantics.get(key, "unknown")

            # The annotation wins when it can classify; otherwise the target's
            # own type does, rather than the edge being thrown away.
            if category not in ALLOWED_CATEGORIES:
                category = infer_relation(infra, value)

            resource.add_connection(value, category)


def build_capability_edges(infra):
    """Add a capability edge for every wildcard grant an IAM principal holds."""

    from engine.privesc_detector import attached_statements

    attached = attached_statements(infra)

    # -----------------------------

    data_ids = [
        (resource.id, resource.type)
        for resource in infra.all_resources()
        if resource.type in DATA_TYPES
    ]

    # -----------------------------

    for resource in infra.all_resources():

        # An S3 bucket policy's "*" means "anyone, on this bucket". Fanning it
        # out would hand a bucket policy an edge to a database.
        if resource.type not in IAM_PRINCIPAL_TYPES:
            continue

        for target_id, target_type in data_ids:

            if target_id == resource.id:
                continue

            # -----------------------------

            # The Action decides which services the grant covers, so the question
            if not grants_wildcard_for(
                resource,
                attached,
                SERVICE_BY_TYPE.get(target_type)
            ):
                continue

            resource.add_connection(target_id, "capability")


def build_escalation_edges(infra, methods=None):
    """Add an edge for every privilege escalation the catalogue detects.

    Reads data/privesc_methods.yaml through engine.privesc_detector, and turns
    each detected method into the edge its `escalates_to` describes:

        self          no edge — the principal becomes admin in place, which is a
                      finding about that node and not a move to another one
        principal     the principals of the types the method's API can act on —
                      `principal_types` in the catalogue, because AttachRolePolicy
                      reaches roles and CreateAccessKey reaches users
        passable_role the roles the granting statement actually names, or every
                      role when it names "*"
        compute       the compute resources that run under a role, whose role the
                      attacker inherits by taking the resource over

    A principal already holding `Action: "*"` is skipped: it satisfies all 28
    methods, and 28 edges out of one node says nothing the wildcard rule does not.
    """

    from engine.privesc_detector import (
        attached_statements,
        detect_from_patterns,
        granted_actions_for,
        load_methods
    )

    if methods is None:
        methods = load_methods()

    # A principal's permissions are its own statements plus those of every
    # AWS::IAM::Policy resource naming it. security_state_graph.state_graph.privesc_findings
    # already merged them; this did not, so a role whose escalation came from an
    # attached policy got a `privilege` finding and no edge to traverse.
    attached = attached_statements(infra)

    # -----------------------------

    principals = [
        resource
        for resource in infra.all_resources()
        if resource.type in IAM_PRINCIPAL_TYPES
    ]

    compute = [
        resource
        for resource in infra.all_resources()
        if resource.type in COMPUTE_TYPES
    ]

    # -----------------------------

    for resource in principals:

        patterns = granted_actions_for(resource, attached)

        if WILDCARD in patterns:
            continue

        detected = detect_from_patterns(patterns, methods)

        if not detected:
            continue

        for method in detected:

            target_kind = method.get("escalates_to")

            if target_kind == "self":
                continue

            if target_kind == "principal":
                # Scoped to the types the method's API acts on: AttachRolePolicy
                # reaches roles, CreateAccessKey reaches users. Unscoped it drew
                # edges to instance profiles, which no IAM API can target.
                allowed = method.get("principal_types") or IAM_PRINCIPAL_TYPES

                add_edges_to(
                    resource,
                    [
                        other.id
                        for other in principals
                        if other.type in allowed
                    ],
                    ESCALATION_CATEGORY
                )

            elif target_kind == "passable_role":
                add_edges_to(
                    resource,
                    passable_role_ids(
                        resource, infra, method, patterns, attached
                    ),
                    ESCALATION_CATEGORY
                )

            elif target_kind == "compute":
                add_edges_to(
                    resource,
                    [item.id for item in compute],
                    HIJACK_CATEGORY
                )


def add_edges_to(resource, target_ids, category):
    """Add one edge per target, skipping the resource itself."""

    for target_id in target_ids:

        if target_id == resource.id:
            continue

        resource.add_connection(target_id, category)


def passable_role_ids(resource, infra, method, patterns, attached=None):
    """The roles a pass_role method can actually reach.

    The statement that granted the method names what may be passed. A concrete
    name is honoured, because `iam:PassRole` scoped to one role escalates to that
    role and to nothing else — which is the whole reason this module does not
    demand `Resource: "*"`. Only a literal "*" fans out to every role.
    """

    roles = [
        other.id
        for other in infra.all_resources()
        if other.type == "AWS::IAM::Role"
    ]

    named = []

    statements = walk_grant_statements(resource.raw_properties)

    # The grant may live in an attached policy rather than inline, in which case
    # that policy's statement is the one naming what may be passed.
    statements = statements + [
        statement
        for statement in (attached or {}).get(resource.id, [])
        if isinstance(statement, dict)
    ]

    for statement in statements:

        # Only the statement that carries this method's actions says what the
        # method may pass. A different statement's Resource is a different grant.
        if not statement_grants_method(statement, method):
            continue

        target = statement.get("Resource")

        for value in (target if isinstance(target, list) else [target]):

            if value == WILDCARD:
                return roles

            if value in roles:
                named.append(value)

    return named


def walk_grant_statements(properties):
    """Every Allow statement in a properties tree."""

    from engine.privesc_detector import walk_statements

    return [
        statement
        for statement in walk_statements(properties)
        if statement.get("Effect") == "Allow"
        and not statement.get(CONDITION_KEY)
    ]


def statement_grants_method(statement, method):
    """True when one statement covers every action a method needs."""

    from engine.privesc_detector import holds_every_action, statement_actions

    return holds_every_action(
        statement_actions(statement),
        method.get("requires") or []
    )


def infer_relation(infra, target_id):
    """Classify an edge by the type of the resource it points at."""

    target = infra.get_resource(target_id)

    if target is None:
        return DEFAULT_RELATION

    return RELATION_BY_TARGET_TYPE.get(target.type, DEFAULT_RELATION)


def grants_wildcard(properties, service=None):
    """True when `properties` holds an unconditional Allow on Resource "*" whose"""

    if isinstance(properties, dict):

        if is_wildcard_allow(properties, service):
            return True

        return any(
            grants_wildcard(value, service)
            for value in properties.values()
        )

    if isinstance(properties, list):

        return any(
            grants_wildcard(item, service)
            for item in properties
        )

    return False


def grants_wildcard_for(resource, attached, service=None):
    """True when a principal holds an unconditional Allow on "*" for `service`,
    counting the policies attached to it as well as its own."""

    if grants_wildcard(resource.raw_properties, service):
        return True

    return any(
        is_wildcard_allow(statement, service)
        for statement in (attached or {}).get(resource.id, [])
        if isinstance(statement, dict)
    )


def action_covers_service(action, service):
    """True when an Action value grants something on `service`."""

    if isinstance(action, list):

        return any(
            action_covers_service(item, service)
            for item in action
        )

    if not isinstance(action, str):
        return False

    if action == WILDCARD:
        return True

    if service is None:
        return True

    # "s3:GetObject" -> "s3". An action with no separator is not a shape this
    # module can classify, so it does not qualify.
    if ACTION_SERVICE_SEPARATOR not in action:
        return False

    return action.split(ACTION_SERVICE_SEPARATOR, 1)[0] == service


def is_wildcard_allow(statement, service=None):
    """True for an unconditional Effect: Allow on Resource "*" whose Action reaches"""

    if statement.get("Effect") != "Allow":
        return False

    # A conditional grant is a scoped grant. See the THEORY note on why the
    # unevaluatable case resolves to "no edge".
    if statement.get(CONDITION_KEY):
        return False

    if not action_covers_service(statement.get("Action"), service):
        return False

    resource = statement.get("Resource")

    if isinstance(resource, list):
        return WILDCARD in resource

    return resource == WILDCARD
