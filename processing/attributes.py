"""Project CloudFormation properties into the names the ruleset asks about.

`raw_properties` in, `attributes` out. The rules are written against
`ingress.port` and `bucket.name`, never `SecurityGroupIngress[0].FromPort`, so
this is the only file that knows CloudFormation's spelling. That is also why one
rule covers both spellings of an inbound rule — nested in a security group and
declared as a standalone AWS::EC2::SecurityGroupIngress — instead of needing two.

Two attributes are conclusions rather than properties: `BucketAcl.AllowsPublicRead`
and `BucketPolicy.AllowsPublicRead`. They are derived here, once, and each
derivation is documented where it is made.

An absent `PublicAccessBlockConfiguration` projects as all four flags False,
because that is AWS's default and it is the insecure one.

Not done: intrinsic functions (`!Ref Foo` is already the string "Foo" by now,
`!GetAtt` and `Fn::Sub` are not resolved), cross-account reasoning, and policy
documents built by `Fn::Join`, whose conclusions come out False rather than
guessed at.
"""


# -- The attribute names, so a typo is a NameError and not a silent miss -------

INGRESS = "ingress"

PROTOCOL = "protocol"
PORT = "port"
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


# -- Resource types -----------------------------------------------------------

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


class PortRange:
    """The ports one ingress entry opens, comparing equal to any of them.

    The rules ask `ingress.port equals 3389`; a template writes a range, and
    `FromPort: 0, ToPort: 65535` opens 3389 without naming it. So
    `PortRange(0, 65535) == 3389` is True, and neither the engine nor the ruleset
    has to know the range exists.
    """

    __slots__ = ("low", "high")

    def __init__(self, low, high):

        self.low = low
        self.high = high

    def __contains__(self, port):

        number = as_port(port)

        if number is None:
            return False

        return self.low <= number <= self.high

    def __eq__(self, other):

        # A range compared to another range is the same range, which is what a
        # golden-file comparison and a test assertion both mean by ==.
        if isinstance(other, PortRange):
            return (self.low, self.high) == (other.low, other.high)

        # Numbers only. `compare()` documents that `equals` must not coerce, so
        # PortRange(22) == "22" would make this one field the exception.
        if isinstance(other, bool) or not isinstance(other, (int, float)):
            return NotImplemented

        return other in self

    # Unhashable on purpose. PortRange(22) == 22 but hash(PortRange(22)) is not
    # hash(22), so a set or dict key holding both would keep them as two entries.
    # Nothing needs to hash one, and a loud failure beats a silent duplicate.
    __hash__ = None

    def __repr__(self):

        if self.low == self.high:
            return "PortRange(%s)" % self.low

        return "PortRange(%s-%s)" % (self.low, self.high)


def as_port(value):
    """`value` as an int port number, or None when it is not one."""

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(value)

    if isinstance(value, str):

        try:
            return int(value.strip())
        except ValueError:
            return None

    return None


def port_range(from_port, to_port):
    """A PortRange for one entry, or None when neither end is a number."""

    low = as_port(from_port)
    high = as_port(to_port)

    if low is None and high is None:
        return None

    if low is None:
        low = high

    if high is None:
        high = low

    # A template with the ends the wrong way round still opens the ports between
    # them, so the range is normalised rather than rejected.
    if low > high:
        low, high = high, low

    return PortRange(low, high)


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
    """Every inbound rule as {protocol, port, from_port, to_port, cidr}.

    Both shapes project here: the list nested inside a security group, and a
    standalone AWS::EC2::SecurityGroupIngress, which is one entry. That is the
    whole argument for the abstract vocabulary. The two spellings are one fact,
    and before this the ruleset had to carry a duplicate rule for the second.

    `port` is a PortRange over from_port..to_port, so a rule asking for one port
    matches an entry that opens a range containing it. `from_port` and `to_port`
    stay as plain numbers, because they are what the template said.
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

        entry = {
            PROTOCOL: protocol,
            PORT: port_range(from_port, to_port),
            FROM_PORT: from_port,
            TO_PORT: to_port
        }

        sources = (
            as_list(item.get("CidrIp"))
            + as_list(item.get("CidrIpv6"))
            + as_list(item.get("SourceSecurityGroupId"))
        )

        # An entry with no source at all is still an entry: the ports it opens
        # are a fact, and dropping it would hide a rule that names no CIDR.
        for cidr in sources or [None]:

            entries.append(dict(entry, **{CIDR: cidr}))

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
    the policy's conclusions are attributed to the bucket here, the same
    direction of attribution that engine/privesc_detector uses for an attached
    IAM policy.
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
