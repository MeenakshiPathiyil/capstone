import yaml
import json

# Configuration
INPUT_FILE = "../sample_yamls/cloudformation5.yml"
OUTPUT_FILE = "../normalized_resources.json"

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
data = load_cloudformation_template(INPUT_FILE)

# print(json.dumps(data, indent=2))


# Validation
if "Resources" not in data:
    raise ValueError("Missing Resources section")

for resource_name, resource_data in data["Resources"].items():

    if resource_data is None:
        raise ValueError(f"{resource_name} is malformed or empty")

    if "Type" not in resource_data:
        raise ValueError(f"{resource_name} missing Type")

    if "Properties" not in resource_data:
        resource_data["Properties"] = {}


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


with open(OUTPUT_FILE, "w") as outfile:
    json.dump(normalized_resources, outfile, indent=2)

