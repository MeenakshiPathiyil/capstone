#this is the final infra model
class InfraModel:
    def __init__(self):
        self.resources = {}

    def add_resource(self, resource):
        self.resources[resource.id] = resource

    def get_resource(self, id):
        return self.resources.get(id)

    def all_resources(self):
        return self.resources.values()

    def to_dict(self):
        return [r.to_dict() for r in self.all_resources()]
    
