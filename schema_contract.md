# Schema Contract – Normalized Resource Format (v1.0)
This document defines the normalized data format produced by the parser and consumed by the infrastructure modeling module. It ensures consistency, enables parallel development, and prevents integration issues.

YAML
  ↓
Parser + Semantic Mapping
  ↓
Normalized JSON
  ↓
Infra Model + Connections
  ↓
Infra Graph

## Top Level Output Format
```
[
  {
    "id": "ResourceName",
    "type": "AWS::Service::Type",
    "raw_properties": { ... },
    "semantic_properties": { ... }
  }
]
```

## Field Definitions

### id (string)
```
"id": "WebServer"
```

### type (string)
```
"type": "AWS::EC2::Instance"
```

### raw_properties (object)
```
"raw_properties": {
  "iam_role": "WebRole",
  "NetworkInterfaces": [
    {
      "GroupSet": ["WebSG"]
    }
  ]
}
```

### semantic_properties (object)
```
"semantic_properties": {
  "iam_role": "identity",
  "NetworkInterfaces[0].GroupSet[0]": "network_control"
}
```
## Semantic Categories
```
SEMANTIC_CATEGORIES = [
    "exposure",
    "network_control",
    "identity",
    "capability",
    "trust",
    "impact",
    "connection",
    "unknown"
]
```
## Meaning of Semantic Categories
| Category        | Meaning                                |
| --------------- | -------------------------------------- |
| exposure        | Public access / internet exposure      |
| network_control | Ports, firewall rules, security groups |
| identity        | IAM roles / identities                 |
| capability      | Permissions (e.g. S3 access)           |
| trust           | Role assumption / trust relationships  |
| impact          | Data sensitivity / critical assets     |
| connection      | Explicit structural linkage            |
| unknown         | Unclassified                           |

## Parsed and Normalized YAML output
```
[
  {
    "id": "ResourceName",
    "type": "AWS::Service::Type",
    "raw_properties": { ... },
    "semantic_properties": { ... }
  }
]
```
## InfraModel Output
```
[
  {
    "id": "WebServer",
    "type": "AWS::EC2::Instance",
    "connections": [
      {
        "target": "WebRole",
        "type": "identity",
        "relation": "dependency"
      }
    ]
  }
]
```

## How to run v2.0
```
python3 infra_parser.py

python3 main.py
```



