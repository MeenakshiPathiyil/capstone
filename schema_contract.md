# Schema Contract – Normalized Resource Format (v1.0)
This document defines the normalized data format produced by the parser and consumed by the infrastructure modeling module. It ensures consistency, enables parallel development, and prevents integration issues.

## Top Level Output Format
```
  {
    "id": "string",
    "type": "string",
    "properties": { }
  }
```

## Field Definitions
| Field      | Type       | Required | Description                     |
| ---------- | ---------- | -------- | ------------------------------- |
| id         | string     | Yes      | Unique resource identifier      |
| type       | string     | Yes      | Cloud resource type             |
| properties | dictionary | Yes      | Normalized key-value attributes |

## Normalization Rules
exposure
network_control
identity
capability
trust
impact
connection
unknown

## How to run with Dummy Data
```
python -m tests.test_infra
```



