# this file represents one cloud resource
class CloudResource:
    def __init__(self, id, type, raw_properties, semantic_properties,
                 attributes=None):
        self.id = id
        # unique name like "WebServer"

        self.type = type
        # "AWS::EC2::Instance"

        self.raw_properties = raw_properties
        self.semantic_properties = semantic_properties

        self.attributes = attributes or {}
        # the abstract vocabulary the rules are written against, projected by
        # the parser (parser/attributes.py). Empty when the record predates
        # projection, in which case rules fall back to raw property paths.

        self.connections = []
        # connections are edges

    def add_connection(self, target, relation_type):
        relation_map = {
            "identity": "dependency",
            "network_control": "association",
            "trust": "trust",
            "connection": "dependency",
            "capability": "capability",
            # A detected privilege escalation, and the hijack of compute that
            # carries a role. See data/privesc_methods.yaml.
            "escalation": "escalation",
            "hijack": "escalation",
            # Load balancer plumbing. An association like network_control: it
            # governs how traffic reaches a resource, it does not depend on it.
            "traffic_path": "association"
        }
        # capability = a wildcard grant reaching a resource it never names,

        # one edge per target per relation_type. the flattener hands the
        for connection in self.connections:
            if (
                connection["target"] == target
                and connection["type"] == relation_type
            ):
                return

        self.connections.append({
            "target": target,
            "type": relation_type,
            "relation": relation_map.get(relation_type, "unknown")
        })

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "connections": self.connections
        }