#this file reprsents one cloud resource
class CloudResource:
    def __init__(self, resource_id, resource_type, properties):
        self.id = resource_id
        #unique name like "webserver"
        self.type = resource_type
        #"AWS::EC2::Instance"
        self.properties = properties
        #the yaml data thats been normalized
        
        # This will store connections , its the graph edge list
        self.connections = []
        #WebServer to WebRole

    def add_connection(self, target):
        # Avoid duplicates
        if target not in self.connections:
            self.connections.append(target)

    def __repr__(self):
        return f"{self.id} -> {self.connections}"