from models.cloud_resource import CloudResource
from models.infra_model import InfraModel
from engine.connection_builder import build_connections

import json

# STEP 1: Create InfraModel
infra = InfraModel()

# STEP 2: Dummy data
dummy_data = [
 {
   "id": "WebServer",
   "type": "AWS::EC2::Instance",
   "properties": {
     "public": True,
     "iam_role": "WebRole",
     "security_group": "WebSG"
   }
 },
 {
   "id": "WebRole",
   "type": "AWS::IAM::Role",
   "properties": {}
 },
 {
   "id": "WebSG",
   "type": "AWS::EC2::SecurityGroup",
   "properties": {}
 }
]

# STEP 3: Convert to objects
for r in dummy_data:
    res = CloudResource(r["id"], r["type"], r["properties"])
    infra.add_resource(res)

# STEP 4: Build connections
build_connections(infra)

# STEP 5: Print (optional)
for r in infra.all_resources():
    print(r)

# STEP 6: Convert to dict
data = infra.to_dict()

# STEP 7: Save JSON
with open("infra_output.json", "w") as f:
    json.dump(data, f, indent=4)