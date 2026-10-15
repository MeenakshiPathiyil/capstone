"""Project CloudFormation properties into the abstract attribute vocabulary.

Pipeline:

raw_properties (what the template says)
        |
project()               per resource type
        |
attributes (what a rule asks about)
        |
the rule engine's condition leaves resolve against this

THEORY (why an abstract vocabulary at all):
data/security_rules.yaml is written against names like `ingress.port`,
`bucket.name` and `StorageEncrypted` rather than against
`SecurityGroupIngress[0].FromPort`. That indirection is the point. A rule written
against a CloudFormation path is a rule that only works on CloudFormation, and it
breaks the moment the same weakness is expressed a second way — an ingress rule
nested inside a security group and an `AWS::EC2::SecurityGroupIngress` declared
beside it are the same fact in two shapes, and a path-based rule has to be written
twice. Projected, they are one `ingress` list and one rule covers both.

So this module is the only place that knows CloudFormation's spelling. Add a
provider and you write another projector; the rules do not move.

THEORY (why some attributes are computed, not read):
Two of the canonical rules ask about `BucketAcl.AllowsPublicRead` and
`BucketPolicy.AllowsPublicRead`. Neither is a property. They are conclusions about
an ACL and a policy document, and something has to reach them: `AccessControl:
PublicRead` means the ACL allows public read, and a bucket policy with
`Principal: "*"` on a read action means the policy does. Those conclusions are
drawn here, once, rather than in every rule that wants to know.

This is a small evaluator and it can be wrong in ways reading a property cannot,
so each derivation is narrow and documented at the function that makes it.

THEORY (absence is a finding, not a gap):
`PublicAccessBlockConfiguration` missing entirely means public access is NOT
blocked — that is AWS's default and it is the insecure one. So the projection
fills those four flags with False when the block is absent, rather than leaving
them unset. A rule asking `BlockPublicAcls equals false` has to match a template
that never mentioned it, or it only ever catches people who explicitly opted in
to being insecure, which nobody does.

WHAT THIS DOES NOT DO:
  * No intrinsic-function evaluation. `!Ref Foo` has already become the string
    "Foo" by the time this runs, and `!GetAtt`/`Fn::Sub` are not resolved.
  * No cross-account or SCP reasoning.
  * A policy document built by Fn::Join is opaque, so its conclusions come out
    False rather than guessed at.
"""


# ── The attribute names, so a typo is a NameError and not a silent miss ──────

INGRESS = "ingress"

PROTOCOL = "protocol"
FROM_PORT = "from_port"
TO_PORT = "to_port"
CIDR = "cidr"

BUCKET_NAME = "bucket.name"

PUBLIC_ACCESS_BLOCK = "PublicAccessBlockConfiguration"

PUBLIC_ACCESS_FLAGS = [
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets"
]

BUCKET_ACL_PUBLIC_READ = "BucketAcl.AllowsPublicRead"
BUCKET_POLICY_PUBLIC_READ = "BucketPolicy.AllowsPublicRead"
BUCKET_POLICY_GRANTEE = "BucketPolicy.Grantee"

STORAGE_ENCRYPTED = "StorageEncrypted"

TAGS = "tags"


# ── Resource types ───────────────────────────────────────────────────────────

SECURITY_GROUP = "AWS::EC2::SecurityGroup"
SECURITY_GROUP_INGRESS = "AWS::EC2::SecurityGroupIngress"
S3_BUCKET = "AWS::S3::Bucket"
S3_BUCKET_POLICY = "AWS::S3::BucketPolicy"
RDS_INSTANCE = "AWS::RDS::DBInstance"

# The ACL values that make a bucket readable by anyone. AuthenticatedRead is
# deliberately absent: it means every AWS account, which is very bad and is not
# the same claim as "public".
PUBLIC_READ_ACLS = ["publicread", "publicreadwrite"]

# Every port, for an ingress entry that names a protocol of -1 (all) and so
# carries no port fields at all.
ALL_PORTS_LOW = 0
ALL_PORTS_HIGH = 65535

ALL_PROTOCOLS = ["-1", -1]

WILDCARD = "*"

# S3 actions that read object data. A policy granting one of these to everyone is
# what BucketAcl/BucketPolicy.AllowsPublicRead is asking about.
PUBLIC_READ_ACTIONS = ["s3:get", "s3:list", "s3:*", WILDCARD]


def as_list(value):
    """`value` as a list, treating None as empty and a scalar as one item."""

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def tag_keys(properties):
    """The Key of every tag, so a rule can ask `tags contains CostCenter`.

    CloudFormation writes tags as [{"Key": ..., "Value": ...}]; a rule wanting to
    know whether a tag is present should not have to walk that.
    """

    keys = []

    for tag in as_list(properties.get("Tags")):

        if isinstance(tag, dict) and "Key" in tag:
            keys.append(tag["Key"])

    return keys


def ingress_entries(properties, resource_type):
    """Every inbound rule as {protocol, from_port, to_port, cidr}.

    Both shapes project here: the list nested inside a security group, and a
    standalone AWS::EC2::SecurityGroupIngress, which is one entry. That is the
    whole argument for the abstract vocabulary — the two spellings are one fact,
    and before this the ruleset had to carry a duplicate rule for the second.
    """

    if resource_type == SECURITY_GROUP_INGRESS:
        raw = [properties]

    else:
        raw = (
            as_list(properties.get("SecurityGroupIngress"))
            + as_list(properties.get("Ingress"))
        )

    entries = []

    for item in raw:

        if not isinstance(item, dict):
            continue

        protocol = item.get("IpProtocol")

        from_port = item.get("FromPort")
        to_port = item.get("ToPort")

        # Protocol -1 is every protocol and every port, so the port fields are
        # absent. Filled in, or a range test on the entry cannot fire and the
        # widest possible rule reads as the narrowest.
        if protocol in ALL_PROTOCOLS:

            if from_port is None:
                from_port = ALL_PORTS_LOW

            if to_port is None:
                to_port = ALL_PORTS_HIGH

        # A single-port entry may name only one end.
        if from_port is None:
            from_port = to_port

        if to_port is None:
            to_port = from_port

        for cidr in (
            as_list(item.get("CidrIp"))
            + as_list(item.get("CidrIpv6"))
            + as_list(item.get("SourceSecurityGroupId"))
        ):
            entries.append({
                PROTOCOL: protocol,
                FROM_PORT: from_port,
                TO_PORT: to_port,
                CIDR: cidr
            })

        # An entry with no source at all is still an entry: the ports it opens
        # are a fact, and dropping it would hide a rule that names no CIDR.
        if not (
            item.get("CidrIp")
            or item.get("CidrIpv6")
            or item.get("SourceSecurityGroupId")
        ):
            entries.append({
                PROTOCOL: protocol,
                FROM_PORT: from_port,
                TO_PORT: to_port,
                CIDR: None
            })

    return entries


def public_access_block(properties):
    """The four block flags, defaulting to False when the block is absent.

    False is the honest default: AWS does not block public access unless told to,
    so a template that never mentions the block has all four off. Leaving them
    unset would mean a rule asking `BlockPublicAcls equals false` matched only
    templates that explicitly wrote `false`, which nobody does.
    """

    block = properties.get(PUBLIC_ACCESS_BLOCK)

    if not isinstance(block, dict):
        block = {}

    return {
        "%s.%s" % (PUBLIC_ACCESS_BLOCK, flag): bool(block.get(flag, False))
        for flag in PUBLIC_ACCESS_FLAGS
    }


def acl_allows_public_read(properties):
    """True when the bucket's canned ACL makes it readable by anyone.

    Narrow on purpose: only the two canned ACLs that literally mean public. A
    bucket granting public read through an explicit AccessControlPolicy grant is
    not read here, and that is a stated gap rather than a guess.
    """

    acl = properties.get("AccessControl")

    if not isinstance(acl, str):
        return False

    return acl.strip().lower() in PUBLIC_READ_ACLS


def statement_principals(statement):
    """Every principal a policy statement names, flattened to strings."""

    principal = statement.get("Principal")

    if isinstance(principal, str):
        return [principal]

    found = []

    if isinstance(principal, dict):

        for value in principal.values():
            found.extend(
                item for item in as_list(value) if isinstance(item, str)
            )

    return found


def statement_reads_objects(statement):
    """True when a statement's Action includes reading object data."""

    for action in as_list(statement.get("Action")):

        if not isinstance(action, str):
            continue

        lowered = action.strip().lower()

        if any(lowered.startswith(prefix) for prefix in PUBLIC_READ_ACTIONS):
            return True

    return False


def policy_statements(properties):
    """The Statement list of a bucket policy's PolicyDocument."""

    document = properties.get("PolicyDocument")

    if not isinstance(document, dict):
        return []

    return [
        statement
        for statement in as_list(document.get("Statement"))
        if isinstance(statement, dict)
    ]


def bucket_policy_facts(policy_properties):
    """The two conclusions a rule asks of a bucket policy.

    `AllowsPublicRead` is an Allow, to a wildcard principal, on a read action.
    All three have to hold: a wildcard principal on a write-only action is a
    different (also serious) problem, and reporting it under a rule named for
    public *read* would be a finding that says the wrong thing.

    `Grantee` is every principal the policy names, so a rule can check them
    against an allow-list.
    """

    allows_public_read = False
    grantees = []

    for statement in policy_statements(policy_properties):

        principals = statement_principals(statement)

        grantees.extend(principals)

        if statement.get("Effect") != "Allow":
            continue

        if WILDCARD not in principals:
            continue

        if statement_reads_objects(statement):
            allows_public_read = True

    return {
        BUCKET_POLICY_PUBLIC_READ: allows_public_read,
        BUCKET_POLICY_GRANTEE: grantees
    }


def project(resource, records=None):
    """The abstract attributes of one normalized resource record.

    `records` is every record in the template, needed because two of the facts a
    bucket rule asks about live on a *different* resource: an
    AWS::S3::BucketPolicy names its bucket, the bucket never names its policy. So
    the policy's conclusions are attributed to the bucket here, the same direction
    of attribution that engine/privesc_detector uses for an attached IAM policy.
    """

    properties = resource.get("raw_properties") or {}
    resource_type = resource.get("type")

    if not isinstance(properties, dict):
        properties = {}

    attributes = {TAGS: tag_keys(properties)}

    # -----------------------------

    if resource_type in (SECURITY_GROUP, SECURITY_GROUP_INGRESS):
        attributes[INGRESS] = ingress_entries(properties, resource_type)

    # -----------------------------

    if resource_type == S3_BUCKET:

        attributes[BUCKET_NAME] = properties.get("BucketName")
        attributes[BUCKET_ACL_PUBLIC_READ] = acl_allows_public_read(properties)

        attributes.update(public_access_block(properties))

        # Defaults, overwritten below if a policy resource names this bucket. A
        # bucket with no policy has no public-read policy, which is not the same
        # as the question being unanswerable.
        attributes[BUCKET_POLICY_PUBLIC_READ] = False
        attributes[BUCKET_POLICY_GRANTEE] = []

        for other in records or []:

            if other.get("type") != S3_BUCKET_POLICY:
                continue

            other_properties = other.get("raw_properties") or {}

            if other_properties.get("Bucket") != resource.get("id"):
                continue

            attributes.update(bucket_policy_facts(other_properties))

    # -----------------------------

    if resource_type == RDS_INSTANCE:
        attributes[STORAGE_ENCRYPTED] = bool(
            properties.get(STORAGE_ENCRYPTED, False)
        )

    return attributes


def project_all(records):
    """Every record with an `attributes` block added. Returns a new list."""

    return [
        dict(record, attributes=project(record, records))
        for record in records
    ]
