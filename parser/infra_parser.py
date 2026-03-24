import yaml
import json

# Configuration
INPUT_FILE = "../sample_yamls/cloudformation1.yml"
OUTPUT_FILE = "../normalized_resources.json"

# Explicit mappings for common cloud fields
KNOWN_FIELD_SEMANTICS = {
    "PublicIp": "exposure",
    "AssociatePublicIpAddress": "exposure",

    "SecurityGroup": "network_control",
    "SecurityGroupIds": "network_control",
    "GroupSet": "network_control",

    "ConnectsTo": "connection",
    "InternetGatewayId": "connection",

    "IAMRole": "identity",
    "IamInstanceProfile": "identity",

    "Permissions": "capability",
    "Policies": "capability",
    "Action": "capability",
    "Resource": "capability",

    "AssumeRole": "trust",

    "Sensitive": "impact",
    "Public": "exposure",

    "Ingress": "network_control",
    "SecurityGroupIngress": "network_control",

    "CidrIp": "exposure"
}

# Used when explicit field not found
SEMANTIC_KEYWORDS = {
    "exposure": ["public", "internet", "external", "cidr", "source"],
    "capability": ["permission", "policy", "action"],
    "trust": ["assume", "role", "trust"],
    "impact": ["sensitive", "critical", "confidential"],
    "connection": ["connect", "link", "peer"],
    "network_control": ["security", "group", "ingress"]
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

with open(INPUT_FILE, "r") as file:
    data = yaml.load(file, Loader=CloudFormationLoader)

# print(json.dumps(data, indent=2))


# Validation
if "Resources" not in data:
    raise ValueError("Missing Resources section")

for resource_name, resource_data in data["Resources"].items():

    if resource_data is None:
        raise ValueError(f"{resource_name} is malformed or empty")

    if not isinstance(resource_data, dict):
        raise ValueError(f"{resource_name} must be a dictionary")

    if "Type" not in resource_data:
        raise ValueError(f"{resource_name} missing Type")

    if "Properties" not in resource_data:
        raise ValueError(f"{resource_name} missing Properties")


# Handles realistic CloudFormation nesting
def flatten_properties(data, parent_key=""):
    flat = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            flat.update(flatten_properties(value, new_key))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_key = f"{parent_key}[{i}]"
            flat.update(flatten_properties(item, new_key))

    else:
        flat[parent_key] = data

    return flat


# Semantic inference
def infer_semantic_category(field_name, resource_type, value):

    field_lower = field_name.lower()
    resource_lower = resource_type.lower()

    # Special cloud-aware rules
    if "associatepublicipaddress" in field_lower:
        if value is True:
            return "exposure"

    if "cidrip" in field_lower:
        if value == "0.0.0.0/0":
            return "exposure"

    if "source" in field_lower:
        if value == "0.0.0.0/0":
            return "exposure"

    if "sensitive" in field_lower:
        if value is True:
            return "impact"

    if "action" in field_lower:
        return "capability"

    if "iam" in resource_lower:
        if "role" in field_lower or "permission" in field_lower:
            return "capability"
        
    if str(value).lower() == "sensitive":
        return "impact"

    # Generic keyword inference
    for category, keywords in SEMANTIC_KEYWORDS.items():
        for keyword in keywords:
            if keyword in field_lower:
                return category

    return "unknown"


# Extract semantic properties
def extract_semantic_properties(flat_properties, resource_type):

    semantic_properties = {}

    for field, value in flat_properties.items():

        short_field = field.split(".")[-1]

        if short_field in KNOWN_FIELD_SEMANTICS:
            semantic_properties[field] = KNOWN_FIELD_SEMANTICS[short_field]

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
        "flat_properties": flat_properties,
        "semantic_properties": semantic_properties
    })


with open(OUTPUT_FILE, "w") as outfile:
    json.dump(normalized_resources, outfile, indent=2)

