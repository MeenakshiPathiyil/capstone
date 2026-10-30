import argparse
import json
import sys
from pathlib import Path

import yaml

# Configuration
#
# Resolved against this file, not the working directory. They used to be bare
# relative paths read at import time, which meant the module only worked when run
# from one directory and could not be imported at all — the benchmark had to
# exec() the source to get at these functions.
BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_INPUT = BASE_DIR / "sample_yamls" / "cloudformation5.yml"
DEFAULT_OUTPUT = BASE_DIR / "data" / "normalized_resources.json"

# Explicit mappings for common cloud fields
KNOWN_FIELD_SEMANTICS = {
    "PublicIp": "exposure",
    "AssociatePublicIpAddress": "exposure",

    "SecurityGroup": "network_control",
    "SecurityGroups": "network_control",
    "SecurityGroupIds": "network_control",
    "GroupSet": "network_control",
    "IpProtocol": "network_control",
    "FromPort": "network_control",
    "ToPort": "network_control",

    "ConnectsTo": "connection",
    "InternetGatewayId": "connection",
    "InstanceId": "connection",
    "AllocationId": "connection",
    "GroupId": "connection",

    "IAMRole": "identity",
    "IamInstanceProfile": "identity",

    "Permissions": "capability",
    "Policies": "capability",
    "Action": "capability",
    "Resource": "capability",

    "AssumeRole": "trust",

    "Sensitive": "impact",
    "KmsKeyId": "impact",
    "Public": "exposure",

    "Ingress": "network_control",
    "SecurityGroupIngress": "network_control",

    "CidrIp": "exposure",
    "SourceSecurityGroupId": "connection", 
    "VpcId": "connection", 
    "SubnetId": "connection",
    "SubnetIds": "connection",
    "PubliclyAccessible": "exposure", 
    "BlockPublicAcls": "exposure", 
}

# Resource-aware security field gating
RESOURCE_SECURITY_FIELDS = {
    "ec2::instance": {
        "AssociatePublicIpAddress",
        "PublicIp",
        "SecurityGroup",
        "SecurityGroupIds",
        "GroupSet",
        "IAMRole",
        "IamInstanceProfile",
        "SubnetId",
        "ConnectsTo"
    },

    "ec2::securitygroupingress": {
        "GroupId",
        "IpProtocol",
        "FromPort",
        "ToPort",
        "CidrIp",
        "SourceSecurityGroupId"
    },

    "ec2::securitygroup": {
        "SecurityGroupIngress",
        "Ingress",
        "CidrIp",
        "FromPort",
        "ToPort",
        "IpProtocol"
    },

    "iam::role": {
        "Policies",
        "Permissions",
        "Action",
        "Resource",
        "AssumeRole"
    },

    "s3::bucket": {
        "Public",
        "PublicAccessBlockConfiguration",
        "BlockPublicAcls",
        "Tags",
        "Sensitive"
    },

    "rds::dbinstance": {
        "PubliclyAccessible",
        "Sensitive",
        "ConnectsTo"
    }
}

# Used when explicit field not found
SEMANTIC_KEYWORDS = {
    "exposure": ["public", "internet", "external", "cidrip"], 
    "capability": ["permission", "policy", "action"],
    "trust": ["assume", "role", "trust"],
    "impact": ["sensitive", "critical", "confidential", "kms"], 
    "connection": ["connect", "link", "peer", "source", "target"], 
    "network_control": ["security", "group", "ingress", "port"] 
}

# -- Intrinsic functions -------------------------------------------------------
#
# THEORY (one representation, whatever the spelling):
# CloudFormation spells every intrinsic function two ways. YAML has a short form,
# `!Ref Foo`, and both YAML and JSON have the long form, `{"Ref": "Foo"}`. They
# are the same template, so they must produce the same records and the same
# findings. They did not: the short form reached the pipeline as the plain string
# "Foo" and the long form as a dictionary, so a JSON template lost edges and a
# YAML one lost others.
#
# So loading happens in two steps. The YAML loader turns every short form into
# its long form, which makes a YAML template the same data as its JSON twin.
# Then resolve_intrinsics() rewrites every long form into the one representation
# the rest of the pipeline was written against:
#
#   Ref         the logical id, as the plain string "Foo". That is what makes
#               reference-matching work in engine/connection_builder: a value
#               that names a resource is an edge. A parameter with a Default
#               resolves to that default instead (see parameter_values()).
#   Fn::GetAtt  the logical id too, so `!GetAtt Group.GroupId`, `!GetAtt [Group,
#               GroupId]` and `{"Fn::GetAtt": ["Group", "GroupId"]}` all draw the
#               edge `!Ref Group` draws. The attribute name is dropped: Arn,
#               GroupId and DNSName all identify the same resource, and the graph
#               is about resources. The exception is `Child.Outputs.Name`, kept
#               dotted, because parser/nested.py resolves that shape through the
#               child stack's Outputs.
#   the rest    their argument, unevaluated. `!Sub 'arn:${AWS::Partition}:...'`
#               is the string and `!Join [",", [a, b]]` the list, which is what
#               the YAML loader always produced. A reference inside an argument
#               is still resolved, so `!If [Cond, !Ref Group, ...]` keeps its edge.
#
# Pseudo parameters (`AWS::Region`, `AWS::AccountId`, `AWS::Partition`,
# `AWS::NoValue`...) are not resolved: a Ref to one stays the plain string
# "AWS::Region" whichever way it was spelled.

REF = "Ref"
GET_ATT = "Fn::GetAtt"
CONDITION = "Condition"
GET_AZS = "Fn::GetAZs"

FUNCTION_PREFIX = "Fn::"

# Every function with a YAML short form `!Name` whose long form is `Fn::Name`.
# Ref, GetAtt and Condition are handled on their own because they resolve rather
# than collapse.
SHORT_FORM_FUNCTIONS = {
    "Base64", "Cidr", "FindInMap", "GetAZs", "ImportValue", "Join", "Select",
    "Split", "Sub", "Transform", "And", "Equals", "If", "Not", "Or",
    "Length", "ToJsonString"
}

COLLAPSED_FUNCTIONS = {FUNCTION_PREFIX + name for name in SHORT_FORM_FUNCTIONS}

# `!GetAtt Child.Outputs.Name` names a resource inside a nested stack. Kept
# dotted for parser/nested.py, which looks for this marker.
NESTED_OUTPUT_ATTRIBUTE = "Outputs."

# A Ref to one of these returns a list, which CloudFormation builds by splitting
# the comma-delimited parameter value.
LIST_PARAMETER_TYPES = ("CommaDelimitedList", "List<")

# A Ref to one of these returns the value stored in Systems Manager under the
# name the Default gives, not the Default itself, so the Default is not the value.
SSM_PARAMETER_TYPE = "AWS::SSM::Parameter::"


class CloudFormationLoader(yaml.SafeLoader):
    pass

def construct_tag_value(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)

    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)

    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)

    return None

def unknown_constructor(loader, tag_suffix, node):
    """A short-form tag as its long form, so YAML and JSON load the same data.

    A tag that is not a CloudFormation function keeps the old behaviour: its value,
    with the tag dropped.
    """

    value = construct_tag_value(loader, node)

    if tag_suffix == REF:
        return {REF: value}

    if tag_suffix == CONDITION:
        return {CONDITION: value}

    # The short form alone accepts "Logical.Attribute" as one scalar. Split on
    # the first dot only: attribute names can contain dots (Endpoint.Address).
    if tag_suffix == "GetAtt":
        if isinstance(value, str):
            value = value.split(".", 1)
        return {GET_ATT: value}

    if tag_suffix in SHORT_FORM_FUNCTIONS:
        return {FUNCTION_PREFIX + tag_suffix: value}

    return value

CloudFormationLoader.add_multi_constructor('!', unknown_constructor)


def parameter_values(template, passed_parameters=()):
    """parameter name -> the value a Ref to it resolves to, where one is known.

    THEORY (why a default is resolved):
    `CidrIp: !Ref SSHLocation` with `Default: 0.0.0.0/0` is SSH open to the
    internet in every stack deployed without overriding it, which is the common
    case. Read as the string "SSHLocation" it was not a CIDR at all, so the open
    SSH was missed.

    This is a conservative assumption, not a fact: the deployed value can be
    anything the operator passes. A parameter with no Default has no value to
    assume, so it is left out and a Ref to it keeps its existing representation,
    the parameter's name. Also left out:

      * `passed_parameters`, the ones a parent stack sets. The value passed wins
        over the Default, and parser/nested.py substitutes it by name.
      * AWS::SSM::Parameter::* types, whose Default names a stored parameter
        rather than being the value.

    The value is a string, as CloudFormation passes it, or a list of strings for
    a list type.
    """

    parameters = template.get("Parameters") if isinstance(template, dict) else None

    if not isinstance(parameters, dict):
        return {}

    values = {}

    for name, spec in parameters.items():

        if name in passed_parameters or not isinstance(spec, dict):
            continue

        if "Default" not in spec:
            continue

        parameter_type = str(spec.get("Type", ""))

        if parameter_type.startswith(SSM_PARAMETER_TYPE):
            continue

        default = spec["Default"]

        if parameter_type.startswith(LIST_PARAMETER_TYPES):

            items = default if isinstance(default, list) else str(default).split(",")

            values[name] = [parameter_string(item).strip() for item in items]

        else:
            values[name] = parameter_string(default)

    return values


def parameter_string(value):
    """A Default as the string CloudFormation passes, whatever YAML typed it as.

    YAML reads `Default: 22` as an int and `Default: true` as a bool; JSON
    templates usually quote both. CloudFormation passes either as a string.
    """

    if isinstance(value, bool):
        return "true" if value else "false"

    return value if isinstance(value, str) else str(value)


def get_att_target(argument):
    """The logical id a GetAtt names, or None when it cannot be read."""

    if isinstance(argument, str):
        argument = argument.split(".", 1)

    if not isinstance(argument, list) or len(argument) != 2:
        return None

    logical_id, attribute = argument

    if not isinstance(logical_id, str):
        return None

    if isinstance(attribute, str) and attribute.startswith(NESTED_OUTPUT_ATTRIBUTE):
        return "%s.%s" % (logical_id, attribute)

    return logical_id


def resolve_intrinsics(template, passed_parameters=()):
    """`template` with every intrinsic function in its one representation.

    See the THEORY block above for what each function becomes. Innermost first,
    so a Ref inside a Join is resolved before the Join collapses.
    """

    values = parameter_values(template, passed_parameters)

    def resolve(value):

        if isinstance(value, list):
            return [resolve(item) for item in value]

        if not isinstance(value, dict):
            return value

        value = {key: resolve(item) for key, item in value.items()}

        # A function is a mapping with exactly one key, the function's name. A
        # mapping with any other key beside it is ordinary data, such as an IAM
        # statement with a Condition block.
        if len(value) != 1:
            return value

        name, argument = next(iter(value.items()))

        if name == REF and isinstance(argument, str):
            return values.get(argument, argument)

        if name == GET_ATT:
            target = get_att_target(argument)
            return value if target is None else target

        # `!Condition Name` inside And/Or/Not. A string argument only, so an IAM
        # Condition block, which is a mapping, is never mistaken for one.
        if name == CONDITION and isinstance(argument, str):
            return argument

        # `!GetAZs` with nothing after it loads as "", the same function written
        # `"Fn::GetAZs": null` loads as None. Both mean the current region, which
        # CloudFormation documents as "".
        if name == GET_AZS and argument is None:
            return ""

        if name in COLLAPSED_FUNCTIONS:
            return argument

        return value

    return resolve(template)


def load_cloudformation_template(file_path, passed_parameters=()):
    """A YAML or JSON template, with its intrinsic functions resolved.

    `passed_parameters` names the parameters a parent stack sets, whose Defaults
    must not be assumed. See parameter_values().
    """

    # Load and parse a CloudFormation YAML template with error handling.
    try:
        with open(file_path, "r") as file:
            data = yaml.load(file, Loader=CloudFormationLoader)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"CloudFormation template not found: {file_path}\n"
            f"Please ensure the file exists at the specified path."
        ) from None
    except yaml.YAMLError as e:
        raise ValueError(
            f"Invalid YAML syntax in {file_path}:\n{e}\n"
            f"Please check the file for syntax errors."
        ) from e
    except Exception as e:
        raise RuntimeError(
            f"Unexpected error loading {file_path}: {e}"
        ) from e

    return resolve_intrinsics(data, passed_parameters)


def normalize_scalar(value):

    # Convert string booleans like "true"/"false" into Python bools for consistent inference checks.
    if isinstance(value, str):
        low = value.strip().lower()
        if low == "true":
            return True
        if low == "false":
            return False
    return value


# Load CloudFormation template with error handling

# Handles realistic CloudFormation nesting
def flatten_properties(data, parent_key=""):
    flat = {}

    if isinstance(data, dict):
        for key, value in data.items():

            # Skip UserData completely
            if key == "UserData":
                continue

            new_key = f"{parent_key}.{key}" if parent_key else key
            flat.update(flatten_properties(value, new_key))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_key = f"{parent_key}[{i}]"
            flat.update(flatten_properties(item, new_key))

    else:
        # Normalize scalar values so later semantic inference sees booleans and other common scalar encodings correctly.
        flat[parent_key] = normalize_scalar(data)

    return flat

def get_allowed_fields(resource_type):
    
    # Look up resource-specific security field whitelist.
    # Extract service and resource from CloudFormation type
    parts = resource_type.lower().split("::")
    
    # Build lookup key: "ec2::instance", "s3::bucket", etc.
    if len(parts) >= 3:
        resource_key = f"{parts[-2]}::{parts[-1]}"
    else:
        resource_key = resource_type.lower()
    
    # Check for exact match in RESOURCE_SECURITY_FIELDS
    return RESOURCE_SECURITY_FIELDS.get(resource_key, set())

# Semantic inference
def infer_semantic_category(field_name, resource_type, value):

    field_lower = field_name.lower()
    resource_lower = resource_type.lower()

    if "associatepublicipaddress" in field_lower:
        if value is True:
            return "exposure"

    if "source" in field_lower:
        if value == "0.0.0.0/0":
            return "exposure"

    if field_name == "Scheme" and value == "internet-facing":
        return "exposure"

    if "sensitive" in field_lower:
        if value is True:
            return "impact"

    if str(value).lower() == "sensitive":
        return "impact"

    if "assumerole" in str(value).lower():
        return "trust"

    if "action" in field_lower:
        return "capability"

    if "iam" in resource_lower:
        if "role" in field_lower or "permission" in field_lower:
            return "capability"

    for category, keywords in SEMANTIC_KEYWORDS.items():
        for keyword in keywords:
            if keyword in field_lower:
                return category

    return "unknown"


# Extract semantic properties
def extract_semantic_properties(flat_properties, resource_type):

    semantic_properties = {}

    allowed_fields = get_allowed_fields(resource_type)

    for field, value in flat_properties.items():

        # Extract actual field name from flattened key
        short_field = field.split(".")[-1].split("[")[0]

        # Step 1: resource-aware gating
        # Only apply gating when there is a resource-specific allowed set.
        # If no allowed_fields are defined for this resource type, allow keyword-based inference and explicit mappings to proceed.
        if allowed_fields and short_field not in allowed_fields and short_field not in KNOWN_FIELD_SEMANTICS:
            semantic_properties[field] = "unknown"
            continue

        # Step 2: explicit semantic mappings
        if short_field in KNOWN_FIELD_SEMANTICS:
            semantic_properties[field] = KNOWN_FIELD_SEMANTICS[short_field]

        # Step 3: fallback semantic inference
        else:
            semantic_properties[field] = infer_semantic_category(
                field,
                resource_type,
                value
            )

    return semantic_properties

# Normalization Pipeline


def validate_template(data):
    """Raise unless the template has the shape the normalizer needs."""

    if not isinstance(data, dict) or "Resources" not in data:
        raise ValueError("Missing Resources section")

    for resource_name, resource_data in data["Resources"].items():

        if resource_data is None:
            raise ValueError(f"{resource_name} is malformed or empty")

        if "Type" not in resource_data:
            raise ValueError(f"{resource_name} missing Type")

        if "Properties" not in resource_data:
            resource_data["Properties"] = {}

    return data


def normalize(data):
    """A validated template as the normalized resource records."""

    normalized_resources = []

    for resource_name, resource_data in data["Resources"].items():

        raw_properties = resource_data["Properties"]

        flat_properties = flatten_properties(raw_properties)

        semantic_properties = extract_semantic_properties(
            flat_properties,
            resource_data["Type"]
        )

        normalized_resources.append({
            "id": resource_name,
            "type": resource_data["Type"],
            "raw_properties": raw_properties,
            "semantic_properties": semantic_properties
        })

    return normalized_resources


def parse(path=DEFAULT_INPUT):
    """A CloudFormation template on disk as normalized resource records.

    The one entry point worth importing. The abstract `attributes` the rules
    read are projected later, by processing/attributes.py, when the pipeline
    builds its infrastructure model.
    """

    return normalize(
        validate_template(
            load_cloudformation_template(str(path))
        )
    )


def write(records, path=DEFAULT_OUTPUT):
    """Write records as the JSON the infrastructure model reads."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2)
        handle.write("\n")

    return path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Normalize a CloudFormation template for the infra model"
    )

    parser.add_argument(
        "--in",
        dest="input_path",
        default=str(DEFAULT_INPUT),
        help="CloudFormation template to read (default: %(default)s)"
    )

    parser.add_argument(
        "--out",
        dest="output_path",
        default=str(DEFAULT_OUTPUT),
        help="Where to write normalized_resources.json (default: %(default)s)"
    )

    args = parser.parse_args(argv)

    records = parse(args.input_path)

    write(records, args.output_path)

    print("Normalized %d resources -> %s" % (len(records), args.output_path))

    return 0


if __name__ == "__main__":
    sys.exit(main())
