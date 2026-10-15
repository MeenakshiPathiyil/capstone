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
DEFAULT_OUTPUT = BASE_DIR / "normalized_resources.json"

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

class CloudFormationLoader(yaml.SafeLoader):
    pass

def unknown_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)

    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)

    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)

    return None

CloudFormationLoader.add_multi_constructor('!', unknown_constructor)


def load_cloudformation_template(file_path):
    
    # Load and parse a CloudFormation YAML template with error handling.
    try:
        with open(file_path, "r") as file:
            data = yaml.load(file, Loader=CloudFormationLoader)
            return data
    except FileNotFoundError:
        raise FileNotFoundError(
            f"CloudFormation template not found: {file_path}\n"
            f"Please ensure the file exists at the specified path."
        )
    except yaml.YAMLError as e:
        raise ValueError(
            f"Invalid YAML syntax in {file_path}:\n{e}\n"
            f"Please check the file for syntax errors."
        )
    except Exception as e:
        raise RuntimeError(
            f"Unexpected error loading {file_path}: {e}"
        )


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


def parse(path=DEFAULT_INPUT, project=True):
    """A CloudFormation template on disk as normalized resource records.

    With `project`, each record also carries an `attributes` block: the abstract
    vocabulary the rules are written against (`ingress.port`, `bucket.name`,
    `StorageEncrypted`). See parser/attributes.py for why that indirection exists.
    Projection is a second pass because two of the facts a bucket rule asks about
    live on a different resource, so it needs the whole template.
    """

    records = normalize(
        validate_template(
            load_cloudformation_template(str(path))
        )
    )

    if not project:
        return records

    from parser.attributes import project_all

    return project_all(records)


def _parse_unprojected(path=DEFAULT_INPUT):
    """A CloudFormation template on disk as normalized resource records.

    The one entry point worth importing. Everything above is a helper, and the
    module body no longer does anything, so importing this file is free.
    """

    return normalize(
        validate_template(
            load_cloudformation_template(str(path))
        )
    )


def write(records, path=DEFAULT_OUTPUT):
    """Write records as the JSON the infrastructure model reads."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as handle:
        json.dump(records, handle, indent=2)

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
