import yaml

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
    "Ingress": "exposure",
    "SecurityGroup": "exposure",
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

def infer_semantic_category(field_name):
    field_lower = field_name.lower()

    for category, keywords in SEMANTIC_KEYWORDS.items():
        for keyword in keywords:
            if keyword in field_lower:
                return category

    return "unknown"

def extract_semantic_properties(properties):
    semantic_properties = {}

    for field, value in properties.items():

        if field in KNOWN_FIELD_SEMANTICS:
            semantic_properties[field] = KNOWN_FIELD_SEMANTICS[field]

        else:
            semantic_properties[field] = infer_semantic_category(field)

    return semantic_properties

normalized_resources = []

for resource_name, resource_data in data["Resources"].items():

    raw_properties = resource_data["Properties"]
    semantic_properties = extract_semantic_properties(raw_properties)

    normalized_resources.append({
        "id": resource_name,
        "type": resource_data["Type"],
        "raw_properties": raw_properties,
        "semantic_properties": semantic_properties
    })

for resource in normalized_resources:
    print("\n--------------------------------")
    print(f"Resource ID: {resource['id']}")
    print(f"Type: {resource['type']}")

    print("\nRaw Properties:")
    for key, value in resource["raw_properties"].items():
        print(f"  {key}: {value}")

    print("\nSemantic Properties:")
    for key, value in resource["semantic_properties"].items():
        print(f"  {key} → {value}")

    print("--------------------------------")