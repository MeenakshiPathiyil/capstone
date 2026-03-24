class InfraModel:
    def __init__(self):
        self.resources = {}

    def add_resource(self, resource):
        self.resources[resource.id] = resource

    def get_resource(self, resource_id):
        return self.resources.get(resource_id)

    def all_resources(self):
        return self.resources.values()

    def to_dict(self):   # ✅ INSIDE class
        output = []

        for resource in self.all_resources():
            output.append({
                "id": resource.id,
                "type": resource.type,
                "properties": resource.properties,
                "connections": resource.connections
            })

        return output