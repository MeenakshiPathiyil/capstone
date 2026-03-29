#imp file
#this converts the properties to relationships
from engine.flatten import flatten_dict

ALLOWED_CATEGORIES = ["identity", "network_control", "connection", "trust"]

def build_connections(infra):
    for resource in infra.all_resources():
        flat_props = flatten_dict(resource.raw_properties)
        semantics = resource.semantic_properties

        for key, value in flat_props.items():
            category = semantics.get(key, "unknown")

            # Rule 1: Only certain categories create connections
            if category not in ALLOWED_CATEGORIES:
                continue

            # Rule 2: Value must match another resource ID
            if isinstance(value, str) and value in infra.resources:
                resource.add_connection(value, category)