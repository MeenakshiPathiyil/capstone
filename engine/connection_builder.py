#imp file
#this converts the properties to relationships
def build_connections(infra):
    for resource in infra.all_resources():
        props = resource.properties

        # IAM Role connection
        if "iam_role" in props:
            target = props["iam_role"]
            if target in infra.resources:
                resource.add_connection(target)

        # Security Group connection
        if "security_group" in props:
            target = props["security_group"]
            if target in infra.resources:
                resource.add_connection(target)

        # Generic connections
        if "connects_to" in props:
            targets = props["connects_to"]

            if isinstance(targets, list):
                for t in targets:
                    if t in infra.resources:
                        resource.add_connection(t)
            else:
                if targets in infra.resources:
                    #this prevents invalid connections
                    resource.add_connection(targets)