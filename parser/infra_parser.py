import yaml
import json

with open("../sample_yamls/archetype1_a.yml", "r") as file:
    data = yaml.safe_load(file)

# print(data)

if "Resources" not in data:
    raise ValueError("Missing Resources section")

for resource_name, resource_data in data["Resources"].items():
    if "Type" not in resource_data:
        raise ValueError(f"{resource_name} missing Type")
    if "Properties" not in resource_data:
        raise ValueError(f"{resource_name} missing Properties")
    
for resource_name, resource_data in data["Resources"].items():
    resource_type = resource_data["Type"]
    properties = resource_data["Properties"]

    # print(resource_name)
    # print(resource_type)
    # print(properties)

KNOWN_FIELD_SEMANTICS = {
    "PublicIp": "exposure",
    "SecurityGroup": "network_control",
    "ConnectsTo": "connection",
    "IAMRole": "identity",
    "Permissions": "capability",
    "AssumeRole": "trust",
    "Sensitive": "impact"
}

SEMANTIC_KEYWORDS = {
    "exposure": ["public", "ingress", "external", "internet", "source"],
    "capability": ["permission", "policy", "action"],
    "trust": ["assume", "role", "trust"],
    "impact": ["sensitive", "critical", "confidential"],
    "connection": ["connect", "link", "peer"]
}

def infer_semantic_category(field_name, resource_type, value):
    field_lower = field_name.lower()
    resource_lower = resource_type.lower()

    # Step 1: context-aware special rules FIRST

    if field_name == "InternetGatewayId":
        if "ec2::instance" in resource_lower:
            return "connection"

    if field_name == "Ingress":
        if isinstance(value, list):
            for rule in value:
                source = rule.get("Source")

                if source == "0.0.0.0/0":
                    return "exposure"

                elif source.startswith("10.") or source.startswith("192.168") or source.startswith("172."):
                    return "connection"

    if field_name == "Sensitive":
        if value is True:
            return "impact"

    # Step 2: resource-type-aware refinement

    if "iam" in resource_lower:
        if "role" in field_lower or "permission" in field_lower:
            return "capability"

    # Step 3: generic keyword inference LAST

    for category, keywords in SEMANTIC_KEYWORDS.items():
        for keyword in keywords:
            if keyword in field_lower:
                return category

    return "unknown"

def extract_semantic_properties(properties, resource_type):
    semantic_properties = {}

    for field, value in properties.items():

        if field in KNOWN_FIELD_SEMANTICS:
            semantic_properties[field] = KNOWN_FIELD_SEMANTICS[field]

        else:
            semantic_properties[field] = infer_semantic_category(field, resource_type, value)

    return semantic_properties

normalized_resources = []

for resource_name, resource_data in data["Resources"].items():

    raw_properties = resource_data["Properties"]
    semantic_properties = extract_semantic_properties(raw_properties, resource_data["Type"])

    normalized_resources.append({
        "id": resource_name,
        "type": resource_data["Type"],
        "raw_properties": raw_properties,
        "semantic_properties": semantic_properties
    })
print(json.dumps(normalized_resources, indent=2))
# for resource in normalized_resources:
#     print("\n--------------------------------")
#     print(f"Resource ID: {resource['id']}")
#     print(f"Type: {resource['type']}")

#     print("\nRaw Properties:")
#     for key, value in resource["raw_properties"].items():
#         print(f"  {key}: {value}")

#     print("\nSemantic Properties:")
#     for key, value in resource["semantic_properties"].items():
#         print(f"  {key} → {value}")

#     print("--------------------------------")