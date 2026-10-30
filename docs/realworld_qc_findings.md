# Real-world QC: issues left for the ruleset owners

An independent QC run put 35 public templates (aws-cloudformation-templates and
the SAM test inputs), 11 YAML/JSON twin pairs and 32 synthetic cases through the
analyser. This is the list of what it got wrong that is **not** a parser bug.
Each item has a minimal template that reproduces it and a suggested direction.
Nothing here has been changed.

The parser bugs it found are fixed in `parser/infra_parser.py` and
`processing/attributes.py` (branch `fix/parser-cfn-intrinsics`), and are listed
at the end so they are not reported twice.

## 1. Admin through `ManagedPolicyArns` is not detected

A role with the AWS managed `AdministratorAccess` policy gets no privilege
finding, so an instance carrying it is never a privilege step. Only inline
`Policies` and `AWS::IAM::Policy` resources are read.

```yaml
Role:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement: [{Effect: Allow, Principal: {Service: ec2.amazonaws.com}, Action: sts:AssumeRole}]
    ManagedPolicyArns: [!Sub 'arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess']
```

Direction: treat a managed policy ARN ending in `:policy/AdministratorAccess`
(and probably `PowerUserAccess`, `IAMFullAccess`) as a full-admin grant in
`engine/privesc_detector.py`. After the parser fix the value is always the plain
string above, whether written `!Sub` or `Fn::Sub`. SAM's
`Policies: [AdministratorAccess]` is the same grant (see item 4).

## 2. `rds_storage_unencrypted` fires on read replicas and cluster members, and starts paths

A read replica inherits encryption from its source, and an Aurora instance
inherits it from its cluster, so neither ever sets `StorageEncrypted`. The rule
fires on both. Its semantic is `exposure`, so the finding also makes the
database an entry point: `RDS_MySQL_With_Read_Replica` produces one path whose
entry is the replica.

```yaml
MainDB:
  Type: AWS::RDS::DBInstance
  Properties: {Engine: MySQL, DBInstanceClass: db.t3.micro, AllocatedStorage: '5', StorageEncrypted: true}
ReplicaDB:
  Type: AWS::RDS::DBInstance
  Properties: {SourceDBInstanceIdentifier: !Ref MainDB, DBInstanceClass: db.t3.micro}
ClusterMember:
  Type: AWS::RDS::DBInstance
  Properties: {Engine: aurora-mysql, DBClusterIdentifier: !Ref Cluster, DBInstanceClass: db.r5.large}
```

Direction: skip the rule when `SourceDBInstanceIdentifier` or
`DBClusterIdentifier` is set (and check the cluster instead, see item 3). Give
it an `impact` semantic: unencrypted storage is a property of the prize, not a
way in.

## 3. Coverage gaps

None of these produce a finding today.

```yaml
# ALB with no Scheme: internet-facing is the AWS default
Alb:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties: {Subnets: [subnet-1, subnet-2]}
# Classic ELB, internet-facing by default
Classic:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    Listeners: [{LoadBalancerPort: '80', InstancePort: '80', Protocol: HTTP}]
    AvailabilityZones: !GetAZs ''
# EKS with a public API endpoint (the default when ResourcesVpcConfig omits it)
Cluster:
  Type: AWS::EKS::Cluster
  Properties:
    RoleArn: !GetAtt ClusterRole.Arn
    ResourcesVpcConfig: {SubnetIds: [subnet-1], EndpointPublicAccess: true}
# API Gateway method with no authorizer
Method:
  Type: AWS::ApiGateway::Method
  Properties: {RestApiId: !Ref Api, ResourceId: !Ref Res, HttpMethod: ANY, AuthorizationType: NONE}
# Lambda function URL with no auth
Url:
  Type: AWS::Lambda::Url
  Properties: {AuthType: NONE, TargetFunctionArn: !GetAtt Fn.Arn}
# Aurora cluster, unencrypted (no rule reads AWS::RDS::DBCluster)
Cluster:
  Type: AWS::RDS::DBCluster
  Properties: {Engine: aurora-mysql, MasterUsername: a, MasterUserPassword: b, StorageEncrypted: false}
# Public IP through a network interface or an Elastic IP, not AssociatePublicIpAddress
Web:
  Type: AWS::EC2::Instance
  Properties:
    ImageId: ami-1
    NetworkInterfaces: [{AssociatePublicIpAddress: true, DeviceIndex: '0', SubnetId: subnet-1}]
IPAddress:
  Type: AWS::EC2::EIP
  Properties: {InstanceId: !Ref Web}
```

Direction: one rule each. `ELB_INTERNET_FACING` should treat an absent `Scheme`
as internet-facing and also cover `AWS::ElasticLoadBalancing::LoadBalancer`.
`EC2_PUBLIC_IP` should read `NetworkInterfaces[*].AssociatePublicIpAddress`, and
an `AWS::EC2::EIP` or `AWS::EC2::EIPAssociation` naming an instance should make
it public. Remember `tests/test_type_registry.py` when adding a type.

## 4. `Fn::ForEach` is unsupported; transforms and macros are not expanded

A template using `Fn::ForEach` (`AWS::LanguageExtensions`) is rejected with
`Fn::ForEach::Tables missing Type`. A resource-level `Fn::Transform` is rejected
the same way. SAM templates (`AWS::Serverless-2016-10-31`) and macro templates
parse, but the `AWS::Serverless::*` and macro resources are analysed as written,
so a SAM function with `Policies: [AdministratorAccess]` behind a public API
yields nothing.

```yaml
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Tables:
    - TableName
    - [Points, Scores]
    - ${TableName}:
        Type: AWS::DynamoDB::Table
        Properties: {BillingMode: PAY_PER_REQUEST}
```

```yaml
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      Policies: [AdministratorAccess]
      Events: {Any: {Type: Api, Properties: {Path: /{proxy+}, Method: ANY}}}
```

Direction: report these templates as unsupported with a clear message instead of
a validation error or a silent empty result. Expanding them means running the
transform (for example `sam validate` or `cfn-lint`'s SAM translator, or
`aws cloudformation get-template --template-stage Processed`) before the parser.

## 5. `Condition`s are ignored

A resource with a `Condition` that can never be true is analysed as deployed,
and both branches of `Fn::If` are kept as a list, so a property set through
`!If` matches no rule.

```yaml
Conditions:
  Never: !Equals [a, b]
  IsPublic: !Equals [!Ref Exposure, public]
Resources:
  Cond:
    Type: AWS::S3::Bucket
    Condition: Never
  Db:
    Type: AWS::RDS::DBInstance
    Properties: {PubliclyAccessible: !If [IsPublic, true, false]}
```

Direction: evaluate `Conditions` using parameter defaults (the parser now
resolves those), drop resources whose condition is false, and pick the `Fn::If`
branch. Until then, say in the output that conditions were not evaluated.

## 6. Path semantics

- **Entry points are security groups.** `network_control` is an entry semantic,
  so the path starts at the group rather than the internet-facing resource
  behind it (`PublicLoadBalancerSG -> PublicLoadBalancer` in `ECS public-vpc`,
  `Ing -> SG -> Web` for a standalone ingress rule).
- **A public SSH instance only gets a MEDIUM `denial_of_service` path.** Open SSH
  to an instance with a public IP is a foothold, but with no privilege step after
  it the only objective that qualifies is denial of service.
- **"Interactive shell" on a load balancer.** `ACT_REACH_EXPOSED_ADMIN_SERVICE`
  outputs `access: interactive shell` for whatever the group fronts, including an
  ALB.
- **`exposed_ports: [0]` for all-protocols rules.** The action reads
  `ingress.from_port`, which is 0 for `IpProtocol: -1`; it means every port.

```yaml
SG:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: ssh and everything
    SecurityGroupIngress:
      - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}
      - {IpProtocol: '-1', CidrIp: 0.0.0.0/0}
Web:
  Type: AWS::EC2::Instance
  Properties:
    ImageId: ami-1
    SecurityGroupIds: [!Ref SG]
    NetworkInterfaces: [{AssociatePublicIpAddress: true, DeviceIndex: '0', GroupSet: [!Ref SG]}]
    MetadataOptions: {HttpTokens: required}
Alb:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties: {Scheme: internet-facing, SecurityGroups: [!Ref SG]}
```

Direction: make the exposed resource the entry and keep the group as evidence on
the first hop; add an "initial access" objective for a reachable shell; condition
the shell output on the target being compute; export `ingress.port` as a range
(`0-65535`, or `all`) rather than `from_port`.

## 7. Noise

- **`REQUIRED_TAGS` dominates.** It is most of the findings on most real
  templates and says nothing about attack paths.
- **IMDSv1 is rated critical.** `EC2_IMDSV1_ENABLED` has `semantic: privilege`,
  and privilege maps to critical in `SEVERITY_BY_SEMANTIC`, so every instance
  without `HttpTokens: required` is a critical finding on its own.
- **An S3 bucket with no `PublicAccessBlockConfiguration` becomes an entry
  point.** The absent block projects as all flags off (AWS's historical default;
  new buckets have blocked public access by default since April 2023), and the
  rule's semantic is `exposure`.
- **`192.168.1.0/0` is not recognised as open.** The rules compare the CIDR to the
  literal `0.0.0.0/0`. `EC2InstanceWithSecurityGroupSample` ships with
  `SSHLocation` defaulting to `192.168.1.0/0`, which is every address.

```yaml
Parameters:
  SSHLocation: {Type: String, Default: 192.168.1.0/0}
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: ssh
      SecurityGroupIngress: [{IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: !Ref SSHLocation}]
```

Direction: report `REQUIRED_TAGS` separately from security findings; give IMDSv1
a severity of its own (high) without changing its path role; treat a bucket
without a block as `impact` (or not an entry) unless a policy or ACL also makes
it public; compare CIDRs by prefix length (`/0` is open, whatever the address),
for example in `processing/attributes.ingress_entries`.

## 8. Duplicate JSON keys are last-wins

A JSON template with two resources under the same logical id keeps only the last,
silently. CloudFormation rejects the template.

```json
{"Resources": {
  "A": {"Type": "Vendor::Thing::Z", "Properties": {"a": 1}},
  "A": {"Type": "AWS::S3::Bucket"}}}
```

Direction: reject duplicate keys while loading (a YAML loader that checks
mapping keys, which also covers JSON), with an error naming the key.

## 9. `iam:PassRole` + `ec2:RunInstances` on `*` makes path search blow up

Each such role gets an escalation edge to every role it can pass, so the number
of simple paths grows combinatorially with the number of roles. In the QC run 30
resources took over 30 s, and a 500-resource template ran for more than 25
minutes in the CLI (55,444 paths, attack graph truncated at `MAX_STATES`).

```yaml
# repeat N times with i = 0..N-1
Role{i}:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement: [{Effect: Allow, Principal: {Service: ec2.amazonaws.com}, Action: sts:AssumeRole}]
    Policies:
      - PolicyName: p
        PolicyDocument:
          Statement: [{Effect: Allow, Action: [iam:PassRole, ec2:RunInstances], Resource: '*'}]
```

Direction: cap the path search (a total path budget, or k best paths per
entry and objective) and say so in the output when the cap is hit; prune by
keeping only the best-scoring path per (entry, target, objective); collapse
roles that are interchangeable (same grants, same trust) into one node.

## Resolved by the parser fixes

These were reported by the QC run and are fixed, so they are not on the list above.

- `Ref` to a parameter with a `Default` now resolves to the default
  (`CidrIp: !Ref SSHLocation` with `0.0.0.0/0` is open SSH;
  `Scheme: !Ref ALBScheme` with `internet-facing` is internet-facing). A
  parameter with no default keeps its name, which is a conservative assumption:
  the deployed value may differ.
- `!GetAtt A.B`, `!GetAtt [A, B]` and `{"Fn::GetAtt": [A, B]}` all resolve to `A`
  and draw the same edge as `!Ref A`.
- YAML and JSON copies of a template give identical records, edges and findings
  (all 11 QC twin pairs now agree; two pairs still differ in raw properties
  because the upstream YAML and JSON files are different templates).
- `StorageEncrypted: 'false'` reads as unencrypted, and
  `PubliclyAccessible: 'true'` as public.
