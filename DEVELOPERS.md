# Developer guide

For anyone picking this up who has not seen the changes. Plain language, no
assumed knowledge of the codebase.

Read sections 1–3 to understand the shape of it. Read section 4 when you need to
change something. Section 7 is what is left to do.

---

## 1. What the project does

You give it a cloud configuration file. It works out how an attacker could break
in, step by step, and hands each route to a fine-tuned AI, which writes it up as
an attack scenario.

The one sentence that explains the design: **a list of problems is not an attack.**
Ordinary scanners tell you "this bucket is public" and "this role is
over-permissive" as two unrelated facts. This project connects them into "someone
on the internet can reach this server, borrow its identity, and read that bucket."
That chain is the product.

---

## 2. The five stages

Data flows one way. Each stage reads the previous stage's output and nothing else,
which is why you can work on one without understanding the others.

```
   a CloudFormation .yml file
              |
   [0] PARSE          parser/infra_parser.py
              |       normalized_resources.json
              v
   [1] CONNECT        engine/connection_builder.py
              |       resources + typed edges, in memory
              v
   [2] DETECT         engine/rule_engine.py            (misconfigurations)
              |       engine/privesc_detector.py       (IAM escalations)
              |       a list of "findings"
              v
   [3] JOIN           security_state_graph/state_graph.py
              |       the security state graph
              v
   [4] SEARCH         attack_path/path_finder.py
              |       output/attack_paths.json
              v
   [5] GENERATE       scenario_generation/prompt_generator.py   (needs a GPU)
                      tri-modal attack scenarios
```

**Stages 0–4 run on a laptop in about a second.** Stage 5 needs a GPU because it
loads a 7-billion-parameter model.

### The vocabulary you need

| Word | Means |
|---|---|
| **resource** | one thing in the cloud — a server, a bucket, a firewall, an IAM role. A *node*. |
| **edge** | a connection between two resources, with a *category* saying what kind |
| **finding** | one rule firing on one resource. "This bucket is world-readable." |
| **state** | a finding attached to its node. The "security state" in the project's name. |
| **semantic** | what a rule is *about*: `exposure` (reachable from outside) or `privilege` (grants too much) |
| **entry point** | a node with an `exposure` finding. Where an attacker starts. |
| **objective** | what the attacker wants. Data theft, ransomware, etc. Defines what counts as an endpoint. |
| **path** | a chain from an entry point to an objective that passes the exploitability rules |

---

## 3. Run it

```bash
cd capstone-feature-infra-model
pip3 install -r requirements.txt      # PyYAML and pytest, nothing else
python3 -m runner.graph_runner
```

```
Done. 15 resources, 16 edges, 22 security findings, 22 attack paths.
  AP-001  CRITICAL  OpenSecurityGroup -> PublicEC2Instance -> OverPermissiveInstanceProfile
                    -> OverPermissiveRole -> PublicRDS
```

Other entry points, for looking at one stage at a time:

```bash
python3 main.py                 # stage 1 only: saves the connection graph
python3 -m runner.rule_runner   # stage 2 only: writes the findings
python3 -m pytest -q            # every test in the repo
python3 -m runner.benchmark --corpus <dir>   # how good the rules are, against real templates
```

To see the graph: open `output/security_state_graph.mmd`, copy all of it, paste
into <https://mermaid.live>.

---

## 4. The code, file by file

### Stage 0 — the parser

**`parser/infra_parser.py`** turns a CloudFormation template into a
flat list of resource records.

```python
parse("sample_yamls/cloudformation5.yml")
# -> [{"id": ..., "type": ..., "raw_properties": {...}, "semantic_properties": {...}}, ...]
```

- `load_cloudformation_template()` reads the YAML. It uses a custom loader so that
  CloudFormation's `!Ref Foo` shorthand does not crash the parser — `!Ref Foo`
  becomes the plain string `"Foo"`. **That is what makes reference-matching work
  later**: if a property's value is the string `"Foo"` and there is a resource
  called `Foo`, that is an edge.
- `resolve_intrinsics()` gives every intrinsic function one representation,
  whichever way it is spelled (YAML `!Ref Foo` or long form `{"Ref": "Foo"}`, so
  a YAML template and its JSON twin produce the same records):
  - `Ref` to a resource, and `Fn::GetAtt` in all three spellings, become the
    logical id `"Foo"`, so `!GetAtt Group.GroupId` draws the edge `!Ref Group`
    draws. `!GetAtt Child.Outputs.Name` stays dotted for `parser/nested.py`.
  - `Ref` to a parameter with a `Default` becomes that default, as a string.
    This is an assumption (the deployed value can differ), made because the
    default is what most stacks run with: `CidrIp: !Ref SSHLocation` with
    `Default: 0.0.0.0/0` is open SSH. No default, an SSM parameter type, or a
    value passed by a parent stack: the parameter's name stays.
  - Pseudo parameters (`AWS::Region`, `AWS::AccountId`...) are never resolved.
  - Every other function (`Fn::Sub`, `Fn::Join`, `Fn::If`...) becomes its
    argument, unevaluated, with any reference inside it resolved.
- `flatten_properties()` turns nested properties into dotted paths, so
  `{"Policies": [{"Action": "s3:*"}]}` becomes
  `{"Policies[0].Action": "s3:*"}`.
- `extract_semantic_properties()` tags every flattened path with a category
  (`exposure`, `identity`, `capability`, `unknown`…) using a lookup table of ~35
  known field names, then keyword guessing, then `unknown`.

**Important:** `unknown` is the *most common* category and does **not** mean "no
edge". About 40% of real properties end up `unknown`, including genuine references
to other resources. Stage 1 handles that — see below.

**`parser/nested.py`** merges nested stacks. Real infrastructure is
split across files joined by `AWS::CloudFormation::Stack`, so a chain can start in
one file and end in another. This reads the parent, follows each child, and merges
them into one list. It resolves three things:

1. `TemplateURL` is an S3 URL, not a path — matched to a local file by longest
   path suffix.
2. Resource IDs are only unique per file, so each child's IDs get its stack name
   as a prefix (`Network.OpenGroup`), and the child's internal references are
   rewritten to match.
3. Children talk through the parent: `!GetAtt Child.Outputs.Thing` is resolved
   through that child's `Outputs` block, and child parameter names are substituted
   with what the parent passed in. **Without step 3 the children merge as
   disconnected islands** — which looks like success and finds nothing.

---

### Stage 1 — building the graph

**`models/cloud_resource.py`** — one resource and its outgoing edges.
The only interesting part is `add_connection()`, which refuses to store the same
`(target, category)` twice, and maps a category to a human-readable relation.

**`models/infra_model.py`** — a dictionary of all resources. That is all
it is.

**`engine/connection_builder.py`** — the important file. Three passes.

**Pass 1: `build_connections()`** — the plain references.

```python
for key, value in flatten_dict(resource.raw_properties).items():
    if not isinstance(value, str):        continue   # only strings name resources
    if value not in infra.resources:      continue   # not a reference to anything
    if value == resource.id:              continue   # no self-edges

    category = semantics.get(key, "unknown")
    if category not in ALLOWED_CATEGORIES:
        category = infer_relation(infra, value)      # <- fall back to the TARGET's type

    resource.add_connection(value, category)
```

The last three lines are the fix that made the graph work at all. The original
code did `if category not in ALLOWED_CATEGORIES: continue` — it threw the edge
away when the hand-written tag said `unknown`, which was almost always. Result: 1
edge across 7 resources. Now, if the tag cannot classify the edge, the *type of
the thing being pointed at* does: pointing at an IAM role is `identity`, at a
security group is `network_control`.

**Pass 2: `build_capability_edges()`** — wildcard permissions.

An IAM policy saying `Action: "s3:*"` on `Resource: "*"` grants access to every
bucket, but `"*"` is not the name of a resource, so pass 1 finds nothing. This
pass draws an edge from the principal to every data resource the grant covers.
`SERVICE_BY_TYPE` is what scopes it — `s3:*` reaches buckets, not databases.

**Pass 3: `build_escalation_edges()`** — privilege escalation.

Reads `data/privesc_methods.yaml` (28 known AWS IAM escalation techniques). Each
method declares what it escalates *to*, and that becomes the edge:

| `escalates_to` | Edge drawn |
|---|---|
| `self` | none — the principal becomes admin in place, which is a finding not a move |
| `principal` | to other IAM principals *of the types the method's API can act on* |
| `passable_role` | to the roles the granting statement actually names |
| `compute` | to compute resources, whose role the attacker inherits |

**This pass is why the project can claim to build an attack graph.** Passes 1 and
2 only ever draw *principal → data*. Two of the four rows above are *principal →
principal*, so a chain of them is a chain of identities — which is what cloud
privilege escalation actually is.

#### The edge categories

| Category | Meaning | Reversed for traversal? |
|---|---|---|
| `identity` | a resource carries an identity | no |
| `network_control` | a firewall fronts a resource | **yes** |
| `traffic_path` | load balancer plumbing | **both directions** |
| `capability` | a wildcard grant reaches data | no |
| `escalation` | a detected privilege escalation | no |
| `hijack` | takeover of compute that holds a role | no |
| `connection` / `trust` | plain references | no |

The reversal column matters and is explained in section 5.

---

### Stage 2 — finding problems

Two separate detectors, because they ask different kinds of question.

**`engine/rule_engine.py`** — declarative rules.

Loads `data/security_rules.yaml`, indexes the rules by resource type (so an S3
rule is never evaluated against a database), then for each resource evaluates the
matching rules' condition trees. A match becomes a finding:

```python
{"resource": "OpenSecurityGroup", "rule_id": "RESTRICTED_COMMON_PORTS",
 "state": "unrestricted_common_port_access", "semantic": "exposure",
 "severity": "high"}
```

**`engine/condition_evaluator.py`** — evaluates one rule's conditions.
Understands `AND` / `OR` / `NOT` and comparisons (`equals`, `contains`,
`less_than_or_equal`…).

Two things here are worth knowing:

*`scope:`* — a rule can say `scope: SecurityGroupIngress`, which evaluates its
subtree once per item in that list and ORs the results. This exists because of a
real bug: a firewall rule checking "open to the internet" AND "dangerous port"
was matching those two conditions on **two different firewall entries**. A group
with port 80 public and port 3389 locked down was reported as wide open. `scope:`
forces an `AND` to hold *within one entry*.

*numeric coercion* — the ordering comparisons (`less_than` etc.) convert both
sides to numbers first, because templates are hand-written and a port arrives as
`22` in one file and `"22"` in the next. Comparing a string to an integer used to
raise an error that was silently swallowed, so the rule quietly did not fire.
`equals` deliberately does **not** coerce.

**`engine/privesc_detector.py`** — IAM escalation, in code not YAML.

Why not a rule? A rule compares a field to a value. This asks whether the set of
actions a role *holds* covers the set a method *needs*, with wildcards on both
sides:

```
granted: ["iam:*", "lambda:Create*"]
needed : ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]

  iam:*           covers iam:PassRole            yes
  lambda:Create*  covers lambda:CreateFunction   yes
  lambda:Create*  covers lambda:InvokeFunction   NO  -> method not detected
```

That is set-covering with pattern matching. Key functions:

- `action_matches(pattern, required)` — the wildcard logic. Splits on `:` so a
  trailing `*` only matches the operation. Without the split, `i*` would wrongly
  cover every service starting with "i".
- `holds_every_action()` — all required actions must be held, not any.
- `attached_statements(infra)` — **important.** A role's permissions are often not
  written on the role. Real templates declare `AWS::IAM::Policy` as a separate
  resource with a `Roles: [SomeRole]` list. This walks those and attributes their
  statements to the roles they name. 149 of 2,000 corpus templates do it that way.
- `broad_grant_findings()` — a role holding `s3:*` on `*` is a real problem that
  the 28 named methods do not cover and the "full admin" rule misses. Without
  this, the graph would draw capability edges from a role while the exploitability
  policy saw nothing to escalate through — which blocked every real attack path we
  tried to find.

**`engine/attack_catalog.py`** — reads
`data/attack_techniques.yaml` (the MITRE ATT&CK cloud matrix) so technique IDs and
their kill-chain ordering come from data rather than being hardcoded.

---

### Stage 3 — the join

**`security_state_graph/state_graph.py`**. This is the "security state graph".

```python
graph = build_state_graph()          # reads the two data files, does everything
graph.nodes["PublicEC2Instance"]
# {"type": "AWS::EC2::Instance",
#  "states": [{"rule_id": "EC2_PUBLIC_IP", "semantic": "exposure", ...},
#             {"rule_id": "EC2_IMDSV1_ENABLED", "semantic": "privilege", ...}],
#  "is_entry": True, "entry_reason": "exposure finding: EC2_PUBLIC_IP",
#  "is_target": False, ...}
```

- `evaluate_findings(infra)` runs both detectors and concatenates their output.
  They produce the same shape, so nothing downstream cares where a finding came
  from.
- `SecurityStateGraph.__init__` joins them: `finding["resource"]` matches
  `resource.id`. A finding naming a resource that does not exist is counted as an
  *orphan* and skipped rather than crashing.
- `traversal_edges()` builds a **second edge list** — see section 5.
- `to_dict()` / `write_state_graph()` serialise it to one file per block,
  `output/graph_{summary,nodes,edges,traversal_edges}.json`.

---

### Stage 4 — finding the paths

**`attack_path/path_finder.py`**.

`walk_paths()` → `extend_path()` is a plain recursive depth-first search:

```python
for neighbor in adjacency.get(current, []):
    if neighbor in path:            continue      # <- the entire cycle guard
    extended = path + [neighbor]
    if neighbor in targets:         routes.append(extended)   # record on arrival
    if len(extended) - 1 < max_depth:
        extend_path(..., extended, ...)                       # and keep going
```

Note it records a target **and keeps walking**, so a database that is both a prize
and a stepping stone is reported *and* traversed.

`is_exploitable()` then filters. A route survives if:

1. it has at least 2 nodes,
2. the entry node carries a finding,
3. an **interior** hop carries a `privilege` finding — *unless the objective says
   it is not needed*.

Clause 3 says *interior* deliberately: authority you already had at the entry, or
that only exists at the target, is not a step where power changes hands.

The "unless" is the objectives layer. `data/objectives.yaml` defines five goals,
each with its own qualifying resource types and its own `requires_privilege` flag.
Denial of service is the one that proves the design — you reach a public endpoint
and flood it, no escalation anywhere, and a single global rule would have thrown
that away as "not an attack".

`score_path()`:

```
severity weights   critical 10 · high 6 · medium 3 · low 1   (each weakness once)
+ the objective's base weight
× 0.85 for every hop beyond the first        (longer chains are less likely)
× 1.25 if the entry point is publicly exposed
→ bands: CRITICAL ≥ 24, HIGH ≥ 13, else MEDIUM
```

**Every number there is our own judgement, not measured.** Say so if asked.

**`attack_path/exporter.py`** writes `output/attack_paths.json` — one record
per path with exactly seven keys. That key set is the contract with
`scenario_generation/`, pinned by tests on both sides, because a missing key is a crash
*after* seven billion parameters are loaded onto a GPU.

**`attack_path/renderer.py`** writes the diagram twice — Mermaid (renders
anywhere, no install) and Graphviz DOT (for a print-quality image). Both come from
the same dictionary, so they cannot disagree.

**`risk_scoring/`** is a second, contextual opinion on each path. It does not
change the score above, the bands, the order or the export. `analyze()` runs it
over every path through `risk_scoring/integration/pipeline_adapter.py`:

```
impact     tag-derived criticality base (unknown 50), +10 sensitive data,
           +10 production, + up to 20 for blast radius (downstream resources
           relative to the graph median)
exposure   90 if the target is itself an entry point, 65 via the path,
           40 after a foothold
path ease  100 x e^(-0.4 x (hops - 1))
score      100 x (I/100)^0.45 x (E/100)^0.35 x (A/100)^0.20
```

Impact reads the target's CloudFormation tags (`Environment`, `Criticality`,
`DataClassification`, `SensitiveData` and close variants, listed in the
adapter). A template without them scores every target as unknown. These
weights are also judgement, not measurement.

---

### Runners

| File | Does |
|---|---|
| `runner/graph_runner.py` | the whole pipeline, one command. Refuses to overwrite a good export with an empty one. |
| `runner/rule_runner.py` | stage 2 alone |
| `main.py` | stage 1 alone |
| `runner/benchmark.py` | measures the rules against a corpus of real templates |
| `runner/harvest_corpus.py` | rebuilds that corpus from 13 public GitHub repos |

---

## 5. Two design decisions you will trip over

### Why there are two edge lists

Edges are stored the way the template declares them. CloudFormation says
*"this instance uses this security group"* — so the edge is
`PublicEC2Instance → OpenSecurityGroup`.

But an attacker travels the other way: **in through the firewall, onto the
instance.** So `traversal_edges()` produces a second list with `network_control`
edges flipped. Both are kept in the JSON so the flip is inspectable rather than
hidden in code.

`traffic_path` (load balancer plumbing) is **bidirectional**, not flipped, and the
reason is worth knowing because the first attempt got it wrong: a Listener names
its LoadBalancer (child → parent, so flip) *and* names its TargetGroup (parent →
child, so do not). One rule per category cannot be right for both, so these edges
are walkable both ways.

### The type lists must agree

Several lists have to stay in sync, and when they drift nothing fails — the
feature just silently does not work. This happened three times in one day:
`AWS::RDS::DBCluster` was added to `DATA_TYPES` so the graph would draw edges to
Aurora, but not to any objective's `resource_types`, so no route could ever *end*
there. The fix did nothing and every test still passed.

`tests/test_type_registry.py` now enforces the contracts. **If you add a resource
type anywhere, run the tests — they will tell you the other places to add it.**

---

## 6. The data files — how to add things without touching code

There are **two** rulesets, and they do different jobs. This is the split the
architecture diagram draws:

| File | Maps | Produces |
|---|---|---|
| `data/security_rules.yaml` | configuration → capabilities | the security state graph |
| `data/attack_transitions.yaml` | capabilities → actions | the attack graph |

### `data/security_rules.yaml` (21 rules)

Copy an existing rule. Keep the field order (a test checks it). Required:

- `semantic` — one of `network_control`, `exposure`, `privilege`, `identity`,
  `trust`, `capability`, `impact`. This decides whether your rule can start a
  path or satisfy the escalation requirement, so it is load-bearing. The mapping
  is `ENTRY_SEMANTICS` and `AUTHORITY_SEMANTICS` in `security_state_graph/semantics.py`.
- **No `severity`.** A test fails if a rule declares one. It is derived from the
  semantic through `SEVERITY_BY_SEMANTIC` in `security_state_graph/semantics.py`, so there is
  one table to defend rather than a number per rule.
- `attack_techniques` — must exist in `data/attack_techniques.yaml` **with the
  matrix's name for that ID**. If you need a technique that is not in the file, add
  it there first — that friction is deliberate, it forces the check that it is
  really a cloud technique.
- `scope:` — use it wherever conditions are ANDed over a list (firewall entries,
  policy statements), or your rule can match on the wrong item.

Write a positive **and** a hardened negative fixture in
`tests/test_security_rules.py`. The negative one is what catches an over-broad
condition.

### `data/attack_transitions.yaml` (14 actions)

The attack graph layer. One entry is an **action**: something an attacker does,
carrying the four fields the review deck's Task 5 names.

- `precondition` / `postcondition` — facts about **attacker state**, written as
  `internet_reachable` or `foothold(target)`. They chain: a step is only legal if
  its precondition is in what the attacker already holds. This is what makes a
  path valid.
- `input` / `output` — the **data** the action reads and produces. Not booleans.
  This is what lets a generated scenario name a port and a finding instead of
  saying "the attacker gained access".
- `applies_to` — tested against one state graph edge. Every key present must
  hold; a key that is *not* in `APPLIES_TO_KEYS` in
  `tests/test_transitions.py` is a constraint that silently does not constrain,
  which is why that test exists.
- `stop_after_match: true` — this action shadows any later one on the same edge.
  Use it so a specific action beats its generic sibling.

**It does not have to be complete.** An edge no action matches still gets a
step, `fallback_action` in `security_state_graph/transitions.py`, which claims
nothing and has a null technique. So an unwritten rule costs detail and never a
path. Every run prints how many hops fell
back, and `attack_graph_summary.json` records it as
`edges_from_the_fallback_table`. On the shipped account and on all 438 corpus
templates that number is zero — keep it there.

### The other three data files

| File | Add to it when |
|---|---|
| `data/privesc_methods.yaml` | you want a new IAM escalation technique. No code needed. |
| `data/objectives.yaml` | you want a new attacker goal, or a new resource type to count as an endpoint |
| `data/attack_techniques.yaml` | you need a technique ID that is not there yet |

---

## 7. What is done and what is left

### Done

- Stages 0–4 run end to end, and every stage is tested.
- Nested stacks merge, so multi-file architectures can be analysed.
- The graph, the paths and the diagram are all written to `output/`.
- Measured against 2,441 real templates from public GitHub repos.
- The hardcoded fake attack path is gone from the generator.

### Left

| # | What | Who / what it needs |
|---|---|---|
| 1 | **Run the generator on the real paths** | a GPU. This is the project's actual final output and nobody has done it. |
| 2 | **Run the Gemini judge** | an API key |
| 4 | More rules | see the note below before spending time on it |
| 5 | Network topology (subnets, routing) | substantial; would make "internet-facing" rigorous instead of a heuristic |
| 6 | Model the server-takeover step properly | there is an IMDSv1 rule now, but it is still a modelling assumption |

**On adding rules to raise the detection rate:** we measured this. The corpus
labels each template for the *single check its fixture tests*, and there are 401
distinct checks across 747 known-bad templates — the top 20 cover only 21%. So the
detection percentage measures how much of KICS's check set we have reimplemented,
not how good the tool is. Chasing it turns this into a worse Checkov. Prefer rules
that create entry points or privilege findings, because those change what the
pipeline can *find*.

### Known limits, say them before the panel asks

- Our dataset is **15 made-up resources**, not a real account.
- **This is not an IAM policy evaluator.** A `Deny` that would cancel a grant is
  skipped, not subtracted. It over-reports, which is the safer direction.
- **No network topology.** "Internet-facing" means an open address range plus a
  resource type that listens.
- Every scoring constant is our judgement. MITRE ATT&CK and Rhino Security Labs
  are real cited sources; the policy and the weights are not.

---

## 8. If you break something

- `python3 -m pytest -q` runs every test in about 25 seconds. Run it constantly.
- The golden files in `tests/` pin the exact output. If you change behaviour on
  purpose, read the diff, then regenerate them, including the copy scenario
  generation reads:

```bash
python3 -m runner.graph_runner
for f in output/graph_*.json output/attack_graph_*.json output/attack_path*.json \
         output/security_state_graph.mmd output/security_state_graph.dot; do
    cp "$f" "tests/golden_$(basename "$f")"
done
cp tests/golden_attack_paths.json scenario_generation/evaluation/inputs/attack_paths.json
```
- If a test fails after your change, **suspect your change before the test.** This
  already happened once: a deduplication was added to hide duplicate paths, a test
  objected, and the test was right — the duplicates were a real bug elsewhere.
