# The graph pipeline: from cloud configuration to ranked attack paths

Reads a normalized cloud configuration, works out which resources are
misconfigured and which IAM principals can escalate, joins those findings onto
the connection graph, and ranks the routes an attacker could walk from the
internet to an objective.

The ranked routes are exported for `scenario_generation/`, which turns each one
into an attack narrative with a fine-tuned Mistral-7B.

## Running it

```bash
pip3 install -r requirements.txt
python3 -m runner.graph_runner
```

```
Done. 15 resources, 16 edges, 21 security findings, 22 attack paths.
Attack graph: 22 attacker states, 19 actions, 7 distinct ATT&CK techniques.
  AP-001  CRITICAL  OpenSecurityGroup -> PublicEC2Instance -> OverPermissiveInstanceProfile -> OverPermissiveRole -> InsecureS3Bucket
  ...
```

19 of the 22 paths are exported: the three MEDIUM ones are left out.

`python3 main.py` builds and saves the connection graph alone;
`python3 -m runner.rule_runner` writes the 21 findings alone, to
`output/output_states.json`.

## External sources

Three, and everything else is our own design. Say so plainly if asked — claiming
a standard we do not have is the only thing here that would not survive scrutiny.

| Source | What we take from it |
|---|---|
| [MITRE ATT&CK — Cloud/IaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/) | `data/attack_techniques.yaml` — the 12 tactics in kill-chain order and their techniques. Supplies every technique id we cite and the order a path's techniques are reported in. |
| [Rhino Security Labs — AWS IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation) | `data/privesc_methods.yaml` — 28 escalation methods, each with the IAM actions it needs and what it escalates to. |
| AWS Config managed rules | The shape and intent of `data/security_rules.yaml`. Each rule cites its source. |

**Ours, not sourced:** the exploitability policy, the scoring weights and bands,
the objective taxonomy's base weights, and the choice of which resource types
count as targets.

## Inputs and outputs

| File | |
|---|---|
| `data/normalized_resources.json` | input: the parser's output for `sample_yamls/cloudformation5.yml` |
| `data/security_rules.yaml` | input — declarative misconfiguration rules |
| `data/privesc_methods.yaml` | input — the IAM escalation catalogue |
| `data/objectives.yaml` | input — what counts as the end of an attack |
| `data/attack_techniques.yaml` | input — the ATT&CK IaaS matrix |
| `output/graph_{summary,nodes,edges,traversal_edges}.json` | the security state graph: nodes with findings, both edge lists, summary |
| `output/attack_graph_{summary,nodes,edges}.json` | the attack graph: attacker states and the actions between them |
| `output/security_state_graph.mmd` | the graph as a Mermaid diagram |
| `output/security_state_graph.dot` | the graph as Graphviz DOT |
| `output/attack_paths.json` | ranked routes, in the seven-key format scenario generation reads |
| `output/attack_path_steps.json` | each exported route hop by hop, with its score |
| `data/infra_output.json` | the connection graph on its own |

`output/` is not tracked. Every file in it has a golden copy under `tests/`
(`golden_*`), and the tests fail when a run stops matching one.

Rendering the diagram needs no Python dependency — paste the `.mmd` into
<https://mermaid.live> or a ```` ```mermaid ```` block, or
`brew install graphviz && dot -Tpng output/security_state_graph.dot -o graph.png`.

**Diagram key.** Shape carries the role — rounded is an entry point, cylinder a
data target, hexagon both, rectangle an ordinary resource. Fill carries the worst
severity; grey means no rule fired. Thick red edges are hops on a ranked path. A
pair joined by more than one category is labelled with all of them
(`escalation + identity`). Roles and severities are also written into each label,
so the diagram survives a greyscale print.

## Measured before and after

| | Before | After |
|---|---|---|
| Rules | 1 | 20 |
| Escalation methods in the catalogue | 0 | 28 |
| Findings | 1 | 21 |
| Edges | 1 | 16 |
| Ranked attack paths | 0 | 22 (19 exported) |
| Attack objectives | 1 (implicit) | 5 |

## Design decisions

**1. Edge direction is reversed for `network_control`.** Edges are stored as the
template declares them, so `PublicEC2Instance -> OpenSecurityGroup`. An attacker
travels the other way — in through the group, onto the instance. The traversal
view flips `network_control` and leaves `identity`, `capability`, `escalation` and
`hijack` forward. Both lists are in the JSON artifact so the flip is inspectable.
Drawing the declared direction would show a path running backwards through its
own arrows.

**2. Privilege escalation is detected in code, not in the rule language.**
`engine/condition_evaluator.py` compares a field to a value. An escalation method
asks whether the actions a principal *holds* cover the actions a method *needs*,
with wildcards on both sides — set covering, not comparison. So the catalogue is
data and the matching is `engine/privesc_detector.py`, whose findings join the
rule engine's in `security_state_graph.state_graph.evaluate_findings`.

**3. Escalation edges are what make this an attack graph.** `build_capability_edges`
only ever drew principal → data, so the graph could not represent *role A becomes
role B, which reads the database*. Each catalogue method declares what it
escalates to, and `principal_types` scopes it to the API's real target —
`iam:AttachRolePolicy` reaches roles, `iam:CreateAccessKey` reaches users.
Without that scoping every path was reported twice, once with a detour through an
instance profile no IAM API can act on.

**4. A wildcard admin is collapsed, not enumerated.** `Action: "*"` satisfies all
28 methods. Reporting 28 findings on one node is 28 restatements of one fact, so
a principal granting `*` produces the wildcard rule's finding and nothing else.

**5. The endpoint is an objective, not a data store.** The search used to end at a
hardcoded list of data types, which defined every non-theft attack out of
existence: an attacker who *encrypts* the same database walks an identical route
and was reported as nothing. `data/objectives.yaml` gives five objectives, each
with its own qualifying types and its own policy. One route serving several
objectives yields one path per objective — a theft narrative and a ransomware
narrative are different scenarios for the generator to write.

**6. The privilege requirement belongs to the objective.** Reading a database
needs credentials you were not given. Flooding a public load balancer does not.
A single global policy therefore *rejects* denial of service, which is a real
attack, so `requires_privilege` is per objective. `identity_takeover` additionally
requires its target to carry a `privilege` finding — every role is a role, and
without that gate every hop of every escalation chain became an endpoint.

**7. Scoring.** Severity weights `critical 10 / high 6 / medium 3 / low 1`, looked
up lower-cased because the rule files write `severity: high`. Each distinct
weakness counts once. Plus the objective's base weight. Damped 0.85 per hop beyond
the first, since a longer chain needs more to go right for the attacker, and
multiplied by 1.25 when the entry is publicly exposed. Bands `CRITICAL >= 40`,
`HIGH >= 30`, else `MEDIUM` — re-anchored when objective weights joined the score,
because the old pair put 26 of 27 paths in CRITICAL. **These constants are ours
and are not calibrated against incident data.** They order routes within one
account and are not comparable across accounts.

## What this does not claim

- **The dataset is 15 synthetic resources**, not a real cloud account. The
  pipeline works; "works on real infrastructure" is not demonstrated.
- **This is not an IAM policy evaluator.** A `Deny` that would cancel a detected
  grant is skipped rather than subtracted, so a principal denied `iam:PassRole`
  by a boundary or an SCP is still reported as holding it. It over-reports rather
  than under-reports, which is the safer direction for a human-reviewed finding.
- **Credential theft is assumed, not modelled.** Nothing derives "I control this
  instance" from "port 22 is open". The chain asserts that step.
- **There is no network topology.** No subnets, route tables or gateways, so
  "internet-facing" means an open CIDR plus a resource type that listens.
- **Techniques are per rule and per objective, not per hop**, so a path inherits
  every technique of every finding along it rather than the ones specific to each
  transition.
- **No clustering or paging.** An account with hundreds of resources renders a
  correct diagram that is not worth looking at.

## Two contracts

Breaking either breaks scenario generation, so both are pinned by tests.

1. `output/attack_paths.json` records carry exactly `source_id`, `source_name`,
   `industry`, `attack_level`, `techniques`, `surfaces`, `objective`, all strings.
2. `severity` is lowercase everywhere, and every rule and catalogue method cites
   `attack_techniques` that exist in `data/attack_techniques.yaml` — the guard
   that caught two non-IaaS citations (`T1133`, `T1567.002`) the ruleset had been
   feeding the model.

## Tests

```bash
python3 -m pytest -q tests
```

Dependencies are the standard library plus PyYAML, with pytest for the tests.
