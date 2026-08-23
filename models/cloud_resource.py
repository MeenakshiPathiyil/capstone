# this file represents one cloud resource
class CloudResource:
    def __init__(self, id, type, raw_properties, semantic_properties):
        self.id = id
        # unique name like "WebServer"

        self.type = type
        # "AWS::EC2::Instance"

        self.raw_properties = raw_properties
        self.semantic_properties = semantic_properties

        self.connections = []
        # connections are edges

    def add_connection(self, target, relation_type):
        relation_map = {
            "identity": "dependency",
            "network_control": "association",
            "trust": "trust",
            "connection": "dependency"
        }

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