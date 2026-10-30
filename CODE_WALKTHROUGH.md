# Code walkthrough

Every file, in plain language, with real examples from our own data.

Read top to bottom the first time — the files are in the order the data flows
through them. After that, jump to whatever you are changing.

---

## First: what is a security state graph?

Without it you have two separate lists.

**List A — what is connected to what** (from reading the config file)

```
PublicEC2Instance  ->  OverPermissiveInstanceProfile  ->  OverPermissiveRole  ->  PublicRDS
```

**List B — what is misconfigured** (from checking the rules)

```
OpenSecurityGroup    open to the whole internet
PublicEC2Instance    has a public IP, and leaks its credentials
OverPermissiveRole   can do anything, and anyone can assume it
PublicRDS            publicly reachable, password stored in plain text
```

Neither list is an attack. List A does not know anything is wrong. List B does not
know these four things touch each other.

**The security state graph is the two lists stapled together** — a map where every
box also carries its problems:

```
OpenSecurityGroup              [open to internet]        <- a way IN
        | network_control
PublicEC2Instance              [public IP, IMDSv1]       <- reachable, leaks creds
        | identity
OverPermissiveInstanceProfile  (nothing wrong)           <- a clean stepping stone
        | identity
OverPermissiveRole             [wildcard, open trust]    <- power is gained here
        | capability
PublicRDS                      [public, plaintext pw]    <- the PRIZE
```

Now it is an attack. Same facts, joined.

**What it does:** it makes the chain *searchable*. Once the problems live on the
map you can ask "is there a route from something a stranger can touch, through
something that hands over permissions, to something worth stealing?" That question
is meaningless against two flat lists.

Our graph right now: **15 boxes, 16 arrows, 14 problems.** Three boxes have no
problems at all and two of them are still on attack paths — clean things can be
steps in an attack, which is why you cannot just search the broken ones.

---

# Stage 0 — reading the config file

## `parser/infra_parser.py`

Turns a CloudFormation YAML file into a flat list of resource records.

```python
parse("sample_yamls/cloudformation5.yml")
# [{"id": "PublicEC2Instance",
#   "type": "AWS::EC2::Instance",
#   "raw_properties": {...},          <- the original, still nested
#   "semantic_properties": {...}}, ...]
```

**`load_cloudformation_template(path)`** reads the YAML. The only clever bit is a
custom loader that tolerates CloudFormation's shorthand. Normally `!Ref Foo` would
crash a YAML parser; here it becomes the plain string `"Foo"`.

**That single decision is what makes the whole graph possible.** Later, when we see
a property whose value is the string `"OpenSecurityGroup"` and there is a resource
called `OpenSecurityGroup`, that is an arrow.

**`resolve_intrinsics(template)`** makes that true for every spelling. The JSON
long form `{"Ref": "OpenSecurityGroup"}` and `!GetAtt OpenSecurityGroup.GroupId`
also become `"OpenSecurityGroup"`, so a JSON template and its YAML twin draw the
same arrows. A `Ref` to a parameter with a `Default` becomes the default, so
`CidrIp: !Ref SSHLocation` with `Default: 0.0.0.0/0` reads as open SSH. That is
an assumption, since the deployed value can differ; with no default the
parameter's name stays. The docstring in `parser/infra_parser.py` lists every
function.

**`flatten_properties(data)`** turns nesting into dotted paths:

```python
{"Policies": [{"PolicyDocument": {"Statement": [{"Action": "s3:*"}]}}]}
# becomes
{"Policies[0].PolicyDocument.Statement[0].Action": "s3:*"}
```

Why? Because a category belongs to one leaf value, not to a whole subtree.

**`extract_semantic_properties(flat, type)`** tags every flattened path with a
category. It tries three things in order: an explicit table of ~35 known field
names (`IamInstanceProfile` → `identity`), then keyword guessing (a field with
"public" in it → `exposure`), then gives up and says `unknown`.

> **The trap that cost us the whole graph.** About 40% of real properties end up
> `unknown`, *including genuine references to other resources*. The original stage-1
> code did `if category == "unknown": skip`, which threw away almost every arrow —
> 1 arrow across 7 resources. `unknown` does **not** mean "no arrow". See
> `build_connections` below for how it is handled now.

**`parse()` / `write()` / `main()`** — the entry points. `parse()` is the one worth
importing; `main()` is the command line. Everything used to run at import time,
which meant the file could not be imported at all.

## `parser/nested.py`

Merges multi-file setups.

Real infrastructure is not one file. AWS's own WordPress reference architecture
puts the load balancer in one file, the servers in another and the database in a
third, joined by `AWS::CloudFormation::Stack`. Read one file at a time, **none of
them contains an attack** — the front door is in one file and the prize is in
another.

`parse_merged(parent)` follows the children and merges them. Three things have to
be resolved, and getting any of them wrong makes the merge useless:

1. **`TemplateURL` is an S3 web address, not a file path.**
   `https://s3.amazonaws.com/some-bucket/infrastructure/vpc.yaml` — the bucket
   tells us nothing, but the tail `infrastructure/vpc.yaml` is the folder layout.
   Matched against local files by longest suffix.

2. **Names are only unique inside one file.** Two children can both call something
   `SecurityGroup`. So every child's IDs get its stack name as a prefix —
   `Network.OpenGroup` — and the child's own internal references are rewritten to
   match, or merging breaks the arrows the child already had.

3. **Children talk through the parent, never directly.**
   ```
   parent:  SecurityGroup: !GetAtt Network.Outputs.OpenGroup
   child:   Parameters: SecurityGroup   ...   !Ref SecurityGroup
   ```
   So `!GetAtt Network.Outputs.OpenGroup` is resolved through that child's
   `Outputs` block to the resource it names, and the child's parameter name is
   replaced with the answer. **Skip this step and the children merge as
   disconnected islands** — which looks like it worked and finds nothing.

Verified on the real thing: **72 resources merged from 12 files.**

---

# Stage 1 — drawing the arrows

## `models/cloud_resource.py`

One box and its outgoing arrows.

```python
resource.add_connection("OverPermissiveRole", "identity")
```

Two things it does: refuses to store the same `(target, category)` twice, and maps
a category to a readable relation (`identity` → `dependency`, `network_control` →
`association`). The duplicate guard lives here rather than in the caller because
this class owns the list, so it is the only place that can hold the rule for
*every* producer.

## `models/infra_model.py`

A dictionary of boxes, keyed by name. `add_resource`, `get_resource`,
`all_resources`. That is genuinely all it is.

## `utils/helpers.py` and `engine/flatten.py`

`flatten_dict` — the same flattening as the parser, used downstream. It also
normalizes types, so `"22"` becomes `22` and `"true"` becomes `True`.

`engine/flatten.py` is 5 lines: it re-exports the one in `utils/helpers.py`. There
used to be two different implementations that disagreed, so one was made an alias
of the other.

## `processing/attribute_extractor.py`

Wraps each resource so the rule engine can read it two ways at once: the flat
paths for simple matching, and `_structured` (the original nesting) for conditions
that need to walk lists.

## `engine/connection_builder.py` — the important file

Three passes over the resources. Each draws a different kind of arrow.

### Pass 1: `build_connections()` — plain references

```python
for key, value in flatten_dict(resource.raw_properties).items():
    if not isinstance(value, str):    continue   # only strings can name a resource
    if value not in infra.resources:  continue   # not pointing at anything real
    if value == resource.id:          continue   # no arrow to itself

    category = semantics.get(key, "unknown")
    if category not in ALLOWED_CATEGORIES:
        category = infer_relation(infra, value)   # <- ask the TARGET's type

    resource.add_connection(value, category)
```

Those last three lines are the fix that made the graph exist. When the hand-written
tag cannot classify the arrow, **the type of the thing being pointed at** does:
pointing at an IAM role is `identity`, at a firewall is `network_control`, at a
bucket is `connection`. That took the graph from 1 arrow to 6.

### Pass 2: `build_capability_edges()` — wildcard permissions

A policy saying `Action: "s3:*"` on `Resource: "*"` grants access to every bucket
in the account. But `"*"` is not the name of a resource, so pass 1 sees nothing.

This pass draws a `capability` arrow from the principal to every data resource the
grant actually covers. `SERVICE_BY_TYPE` is what scopes it — `s3:*` reaches
buckets, not databases. That is where `OverPermissiveRole -> PublicRDS` in our
graph comes from.

`grants_wildcard_for()` also counts policies attached from *outside* the role,
because most real templates put permissions in a separate `AWS::IAM::Policy`
resource rather than on the role itself.

### Pass 3: `build_escalation_edges()` — privilege escalation

Reads `data/privesc_methods.yaml` — 28 known ways to escalate in AWS IAM. Each
method says what it escalates **to**, and that becomes the arrow:

| `escalates_to` | Arrow drawn |
|---|---|
| `self` | none. The principal becomes admin where it stands — a finding, not a move. |
| `principal` | to other IAM principals *of the type that method's API can actually act on* |
| `passable_role` | to the roles the granting statement names |
| `compute` | to compute resources, whose role the attacker inherits by taking it over |

**This pass is why we can call it an attack graph.** Passes 1 and 2 only ever draw
*principal → data*. Two rows above are *principal → principal*, so a chain of them
is a chain of identities — which is what cloud privilege escalation is. In our
graph that is `DeploymentRole -> OverPermissiveRole`: one role becoming another.

The `principal_types` scoping matters. `iam:AttachRolePolicy` attaches a policy to
a **role**, so drawing an arrow from it to an instance profile is a hop nobody can
walk. Before that scoping existed, every path was reported twice — once with a
phantom detour through a profile, once without.

### The arrow categories

| Category | Means | Flipped for searching? |
|---|---|---|
| `identity` | a resource carries an identity | no |
| `network_control` | a firewall sits in front of a resource | **yes** |
| `traffic_path` | load balancer plumbing | **walkable both ways** |
| `capability` | a wildcard grant reaches data | no |
| `escalation` | a detected privilege escalation | no |
| `hijack` | takeover of compute that holds a role | no |
| `connection` / `trust` | plain references | no |

Flipping is explained under `state_graph.py`.

### The helper functions

- **`infer_relation(infra, target_id)`** — looks up the target's type in
  `RELATION_BY_TARGET_TYPE`, falls back to `connection`.
- **`action_covers_service(action, service)`** — does `s3:GetObject` grant
  something on `s3`? Splits on the colon.
- **`is_wildcard_allow(statement, service)`** — an `Allow` on `Resource: "*"`
  covering that service, with **no `Condition`**. A conditional grant is one we
  cannot claim is usable, so it draws no arrow.
- **`passable_role_ids(...)`** — for a `PassRole` method, which roles the statement
  actually names. A concrete name is honoured; only a literal `"*"` fans out to
  every role.

---

# Stage 2 — finding the problems

Two separate detectors, because they ask different kinds of question.

## `engine/rule_engine.py`

Loads `data/security_rules.yaml`, then **indexes the rules by resource type** so an
S3 rule is never evaluated against a database. For each resource it evaluates the
matching rules and turns a match into a finding:

```python
{"resource": "OpenSecurityGroup",
 "rule_id": "RESTRICTED_COMMON_PORTS",
 "state": "unrestricted_common_port_access",
 "semantic": "exposure",
 "severity": "high"}
```

`_get_parameters` / `_resolve_parameters` handle a rule's `parameter_schema`, so a
rule can say `value: "{blockedPort1}"` and have `3389` substituted in. That keeps
the port list editable at the top of the rule instead of buried in its conditions.

A rule that throws is caught, warned about, and skipped — one bad rule must not
stop the other nine.

## `engine/condition_evaluator.py`

Evaluates one rule's conditions. Understands `AND`, `OR`, `NOT` and leaf
comparisons.

**`get_field_values(data, "SecurityGroupIngress.CidrIp")`** walks the nested
structure and returns *every* matching value — across all list items.

**`compare(value, operator, expected)`** — the operators: `equals`, `not_equals`,
`contains`, `contains_any`, `in`, and the four orderings.

Two things here exist because of real bugs:

### `scope:` — the two-different-entries bug

A firewall rule asks two things: is this open to the internet, and is this a
dangerous port. `get_field_values` gathers values across **all** firewall entries,
so the two conditions could be satisfied by **two different entries**:

```yaml
SecurityGroupIngress:
  - { FromPort: 80,   CidrIp: 0.0.0.0/0 }     # public, harmless port
  - { FromPort: 3389, CidrIp: 10.0.0.0/8 }    # dangerous port, private
# old evaluator: "0.0.0.0/0" present AND 3389 present -> MATCH (wrong)
```

`scope: SecurityGroupIngress` evaluates the subtree **once per entry** and ORs the
results, forcing the `AND` to hold inside one entry. Leave `scope:` out and you get
the old behaviour, so nothing else changed.

### Numeric coercion — the silently-dead-rule bug

These comparisons read raw template values, and templates are hand-written: a port
arrives as `22` in one file and `"22"` in the next. `"22" <= 3389` raises an error
in Python, the rule engine caught it and warned, and the effect was **a rule that
quietly did not fire on half the templates it should**.

`as_number()` now coerces both sides for the four ordering operators only.
`equals` deliberately does **not** coerce — a rule saying `IpProtocol equals "-1"`
should not also match the integer `-1` unless it says so. Rules needing both use
`in: ["-1", -1]`.

## `engine/privesc_detector.py`

IAM escalation. In code, not YAML, and the reason is worth understanding.

A rule compares a field to a value. This asks whether the set of actions a role
**holds** covers the set a method **needs**, with wildcards on both sides:

```
granted: ["iam:*", "lambda:Create*"]
needed : ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]

  iam:*           covers iam:PassRole            yes
  lambda:Create*  covers lambda:CreateFunction   yes
  lambda:Create*  covers lambda:InvokeFunction   NO   -> method not detected
```

That is set-covering with pattern matching. No condition tree expresses it.

**`walk_statements(properties)`** — finds every IAM statement anywhere in a
properties tree, at any depth. It looks for the `Effect` key as its marker.

**`actions_from_statements(statements)`** — the actions those statements grant.
Skips anything that is not `Allow`, and skips anything carrying a `Condition`,
because a conditional grant is one we cannot claim is exercisable.

**`action_matches(pattern, required)`** — the wildcard logic, and the subtle part:

```python
if pattern == "*":                    return True     # everything
if pattern.lower() == required.lower(): return True   # exact

# split on ":" so a trailing * matches the OPERATION only
p_service, p_operation = pattern.lower().split(":", 1)
r_service, r_operation = required.lower().split(":", 1)
if p_service != r_service:            return False
if p_operation == "*":                return True     # "iam:*"
if p_operation.endswith("*"):         return r_operation.startswith(p_operation[:-1])
```

Without the split, `i*` would be read as covering every service beginning with
"i" — including `iam`. The split makes it mean "operations beginning with i, in
service i", which matches nothing, which is correct.

**`holds_every_action(patterns, required)`** — **all** required actions, not any.
A method needing three permissions is not satisfied by two.

**`grants_full_admin(properties)`** — does it grant `"*"`? Used to skip the
enumeration: `Action: "*"` satisfies all 28 methods, and reporting 28 findings on
one node is 28 restatements of one fact.

**`attached_statements(infra)`** — the one most people will miss. A role's
permissions are often **not written on the role**:

```yaml
EC2Policy:
  Type: AWS::IAM::Policy
  Properties:
    Roles: [EC2Role]                 # <- this policy belongs to EC2Role
    PolicyDocument:
      Statement: [{Effect: Allow, Action: ["s3:*"], Resource: "*"}]
```

`EC2Role`'s own properties contain nothing. This function walks every
`AWS::IAM::Policy` resource, reads its `Roles` / `Users` / `Groups` list, and
attributes its statements to the principals it names. **149 of 2,000 corpus
templates do it this way.**

**`granted_actions_for(resource, attached)`** — a principal's own actions plus
everything attached to it. This is the function everything else should call.

**`broad_grant_findings(resource, attached)`** — the fix that unblocked real
attack paths. A role holding `s3:*` on `*` is a serious problem that the 28 named
methods do not cover and the "full admin" rule misses (it is broad, not total).
Before this existed, the graph drew capability arrows from such a role while the
path search saw no escalation to travel through — **so it rejected every path
through the very role those arrows came from.** The principle: if a grant is strong
enough to justify an arrow, it is strong enough to be a finding.

## `engine/attack_catalog.py`

Reads `data/attack_techniques.yaml`, which is the MITRE ATT&CK cloud matrix as a
file.

- **`is_known(id)`** — is this a real cloud technique? A test uses this to reject
  any rule citing something outside the matrix.
- **`technique_name(id)`** — the official name, so we cannot cite a right ID under
  a wrong name.
- **`parent_id("T1098.001")`** → `"T1098"` — a sub-technique falls back to its
  parent for ordering.
- **`phase_rank(id)`** — where in the kill chain this sits, as a number to sort by.
  Initial access is 0, impact is 11.

This exists because the ordering used to be a hardcoded dictionary inside the
exporter, which drifts and cannot be checked against anything. Turning it into a
file immediately caught three technique IDs we were citing that are not in the
cloud matrix at all.

---

# Stage 3 — the join

## `security_state_graph/state_graph.py`

This is the security state graph.

**`evaluate_findings(infra)`** runs both detectors and concatenates their results.
They produce the same shape, so nothing downstream cares which one found what.

**`privesc_findings(infra)`** is the escalation half: for each IAM principal, work
out its effective permissions (own + attached), then emit a finding per detected
method plus any broad-grant finding.

**`SecurityStateGraph.__init__(infra, findings)`** does the actual join, in three
steps:

```python
# 1. every resource becomes a node
self.nodes[resource.id] = {"id":…, "type":…, "raw_properties":…,
                           "semantic_properties":…, "states": []}

# 2. every connection becomes an edge
self.edges.append({"source":…, "target":…, "category":…, "relation":…})

# 3. every finding is stamped onto its node
node = self.nodes.get(finding["resource"])
if node is None:
    self.orphan_findings.append(finding)   # stale finding, warn and continue
else:
    node["states"].append(finding)
```

Step 3 is the whole point of the class, and it is three lines. The join key is
`finding["resource"] == resource.id`. A finding naming a resource that does not
exist is recorded as an *orphan* rather than crashing — we had exactly that
problem once, with a stale findings file referencing deleted resources.

### The two arrow lists

**`traversal_edges()`** builds a **second** list of arrows, in the direction an
attacker moves.

Our config says `PublicEC2Instance -> OpenSecurityGroup` — "this server uses this
firewall". But the attacker travels **in through the firewall, onto the server**.
So `network_control` arrows are flipped.

`traffic_path` (load balancer plumbing) is **walkable both ways** instead, and the
reason is worth knowing because the first attempt got it wrong: a Listener names
its LoadBalancer (child → parent, so flip) *and* names its TargetGroup (parent →
child, so do not). One rule per category cannot be right for both.

`admits_inbound()` gates the flip: an arrow is only reversed into a resource whose
type actually receives connections. Both lists are kept in the saved file, so the
flip is inspectable instead of hidden in code.

**`traversal_adjacency()`** turns the traversal list into a
`{node: [reachable nodes]}` dictionary, so the search does not re-derive it per
hop.

### The rest

- **`highest_severity(states, weight_of)`** — the *worst* severity on a node, by
  weight not alphabetically. `critical` must beat `high` even though "c" < "h".
- **`entry_reason` / `target_reason`** — a sentence explaining why a node is or is
  not an entry point. Purely so the saved file is readable by a human.
- **`edge_sort_key` / `sorted_edges`** — deterministic ordering, so two runs
  produce byte-identical output and the golden-file tests mean something.
- **`to_dict()` / `write_state_graph()`** — the saved artifact. Deliberately drops
  `raw_properties`, since it would double the file size and nothing reads it back.
- **`build_state_graph()`** — the one-line entry point: reads both data files,
  builds everything, returns the graph.

---

# Stage 4 — finding the routes

## `attack_path/path_finder.py`

**`entry_points(graph)`** — every node with an `exposure` finding. Read off rule
metadata, never hardcoded by resource type, so a new rule automatically produces
new entry points.

**`objectives_of(graph, node)`** — which attacker goals this node can be the end
of. Reads `data/objectives.yaml`. A node can serve several: a database is both a
data-theft target and a ransomware target.

**`walk_paths()` → `extend_path()`** — the search. Plain recursive depth-first:

```python
for neighbor in adjacency.get(current, []):
    if neighbor in path:      continue          # <- the entire cycle guard
    extended = path + [neighbor]
    if neighbor in targets:   routes.append(extended)   # record on ARRIVAL
    if len(extended) - 1 < max_depth:
        extend_path(..., extended, ...)                 # and keep walking
```

Two details worth noticing. `if neighbor in path: continue` is the only cycle
protection needed — a loop cannot be extended, so it dies. And it records a target
**and keeps going**, so a database that is both a prize and a stepping stone is
reported *and* travelled through.

**`is_exploitable(graph, path, objective)`** — the filter. A route survives if:

1. it has at least two nodes,
2. the entry node carries a finding,
3. an **interior** hop carries a `privilege` finding — *unless the objective says
   it is not needed*.

Clause 3 says *interior* deliberately: authority you already had at the entry, or
that only exists at the destination, is not a step where power changes hands.

The "unless" is the objectives layer. Denial of service is the one that proves the
design — you reach a public endpoint and flood it, no escalation anywhere. A single
global rule would have thrown that away as "not an attack".

**`path_severity_total()`** — sums severity weights, counting each **distinct
weakness once** per `(node, state)`. Two different problems on one node both count;
the same problem reported twice does not.

**`score_path()`**:

```
severity weights   critical 10 · high 6 · medium 3 · low 1 · unknown 0.5
+ the objective's base weight        (ransomware 5.0, data theft 4.0, DoS 1.0 …)
× 0.85 for every hop beyond the first      (longer chains need more to go right)
× 1.25 if the entry point is publicly exposed
-> bands: CRITICAL >= 24, HIGH >= 13, else MEDIUM
```

`severity_weight()` looks the label up **lowercased**, because the rule files write
`severity: high`. An uppercase-keyed table would silently score everything at the
fallback of 0.5 — there is a test specifically for this.

**Every number above is our own judgement, not measured against real incidents.**
Say so when asked.

**`is_subsumed(route, routes)`** — drops a route that is a strict tail of a longer
one, so the same attack is not reported twice at different lengths.

**`find_attack_paths()`** — puts it together: walk, filter, drop subsumed, then emit
**one path per route per objective**. A route ending at a database is a data-theft
path *and* a ransomware path: same hops, different intent, different techniques,
different story for the AI to write. Collapsing them to the worst one would hide
data theft behind ransomware on every database.

## `attack_path/exporter.py`

Writes `output/attack_paths.json`, the handshake with `scenario_generation/`.

**`technique_index(rules_path)`** — builds `{rule_id: [techniques]}` by reading
every rule's `attack_techniques`.

**`path_techniques(path, index)`** — collects the techniques of every finding along
the path, deduplicates, **then adds the objective's own techniques**, then sorts by
kill-chain phase. That middle step matters: the findings along a path describe how
the attacker *arrived*, never what they *did on arrival*. Without it a ransomware
path would carry no impact-tactic technique at all.

**`render_techniques()`** — the exact string format the model was trained on:
`"T1190 - Exploit Public-Facing Application, T1133 - ..."`.

**`path_surfaces()` / `render_surfaces()`** — turns the resource types along a path
into the attack-surface vocabulary from the training data.

**`export_record()`** — one path as the seven keys:

```python
{"source_id":    "AP-001",
 "source_name":  "OpenSecurityGroup -> PublicEC2Instance -> ...",
 "industry":     "Information technology service activities (ISIC J62)",
 "attack_level": "CRITICAL",
 "techniques":   "T1190 - Exploit Public-Facing Application, ...",
 "surfaces":     "Internet-facing services / user endpoints, ...",
 "objective":    "Ransomware or destruction"}
```

Every value is forced to `str`, because the prompt template puts them all into an
f-string. **That key set is a contract**, pinned by tests on both sides,
because a missing key is a crash *after* seven billion parameters are on the GPU.

The `objective` key is why AP-001 and AP-002 are distinguishable: they share every
hop and every surface, so without it the model would receive two identical records
and write a data-theft story for a ransomware path.

## `attack_path/renderer.py`

Writes the diagram twice — Mermaid (renders anywhere, nothing to install) and
Graphviz DOT (for a print-quality image) — from the same dictionary, so they cannot
disagree.

- **`safe_token(id)` / `node_tokens(graph)`** — resource names are not valid
  diagram identifiers (`AWS::S3::Bucket` is not a token, and `end` is a Mermaid
  keyword). So the real name becomes the *label* and the identifier is derived,
  with collisions resolved by a counter.
- **`escape_mermaid` / `escape_dot`** — the trap this exists for: our path names
  contain `->`, which is also Mermaid's own arrow operator. An unescaped label does
  not fail loudly — it parses as extra graph structure, so you get a diagram
  containing nodes that are not in the account and no error anywhere. Every label
  is quoted, with no exceptions.
- **`emphasis_index(paths)`** — which arrows are on a ranked path, read off the hop
  list (never by re-parsing the display name).
- **`drawable_edges()`** — merges parallel arrows. `AppServerRole -> DeploymentRole`
  is **both** `identity` (declared) and `escalation` (detected); drawing two arrows
  is noise and drawing only the first threw away the more informative half. Merged,
  labelled with both.
- **`node_label_lines()`** — shape carries the role, fill carries severity, **and
  both are written into the label as text**, so the diagram survives a greyscale
  photocopy or a bad projector.

---

# The runners

| File | Does |
|---|---|
| `runner/graph_runner.py` | the whole pipeline, one command. Refuses to overwrite a good export with an empty one, so a broken run cannot destroy the deliverable. |
| `runner/rule_runner.py` | stage 2 alone — prints the finding count |
| `main.py` | stage 1 alone — prints the arrows |
| `runner/benchmark.py` | measures the rules against a corpus of real templates. Recall, false-positive rate, findings per rule. |
| `runner/harvest_corpus.py` | rebuilds that corpus by cloning 13 public GitHub repos |

---

# The data files — editable without touching code

| File | Contains |
|---|---|
| `data/security_rules.yaml` | our 10 misconfiguration rules |
| `data/privesc_methods.yaml` | 28 IAM escalation techniques |
| `data/objectives.yaml` | 5 attacker goals |
| `data/attack_techniques.yaml` | the MITRE ATT&CK cloud matrix |
| `data/normalized_resources.json` | the test account (15 resources) |

Adding a rule: copy an existing one, keep the field order (a test checks it), and
remember three things — **severity lowercase**, `semantic` is `exposure` or
`privilege` and decides whether your rule can start a path, and every technique ID
must exist in `attack_techniques.yaml` **with the matrix's name for it**.

Then write a positive *and* a hardened negative fixture. The negative one is what
catches a rule that fires on everything.

---

# If you change something

```bash
python3 -m pytest -q          # every test in the repo, about 25 seconds. Run it constantly.
```

The golden files in `tests/` pin the exact output. If you change behaviour on
purpose, read the diff, then regenerate them, including the copy scenario
generation reads (a test fails if it falls behind):

```bash
python3 -m runner.graph_runner
for f in output/graph_*.json output/attack_graph_*.json output/attack_path*.json \
         output/security_state_graph.mmd output/security_state_graph.dot; do
    cp "$f" "tests/golden_$(basename "$f")"
done
cp tests/golden_attack_paths.json scenario_generation/evaluation/inputs/attack_paths.json
```

**Two habits worth keeping:**

**Type lists must agree.** If you add a resource type to `DATA_TYPES` you must also
add it to an objective's `resource_types`, or the graph draws arrows to it and no
route can ever end there. This happened three times in one day and nothing failed
each time. `tests/test_type_registry.py` now tells you where else to add it.

**When a test fails, suspect your change before the test.** A deduplication was
once added to hide duplicate paths; a test objected; the test was right and the
duplicates were a real bug elsewhere.
