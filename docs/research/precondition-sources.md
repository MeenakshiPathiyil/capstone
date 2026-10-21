# How MITRE ATT&CK and Rhino express preconditions and postconditions

Primary sources only. ATT&CK web pages were fetched live; field-level claims are
verified against the STIX bundle, because the website renders a subset of it.

- Site: <https://attack.mitre.org/matrices/enterprise/cloud/iaas/>, technique pages under `https://attack.mitre.org/techniques/`
- STIX used: `enterprise-attack.json` from <https://github.com/mitre-attack/attack-stix-data> — the `x-mitre-collection` object self-identifies as **"Enterprise ATT&CK" version 19.2, modified 2026-08-05**. Historical checks used `enterprise-attack/enterprise-attack-14.1.json` and `-17.1.json` from the same repo.
- Rhino: <https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation> (README.md fetched raw from `master`).

## 1. ATT&CK has no precondition field

**There is no `precondition`, `prerequisite`, or `requirements` field, on the page or in the data.** Across all 858 `attack-pattern` objects in v19.2, the only `x_mitre_*` keys present are:

`x_mitre_attack_spec_version`, `x_mitre_deprecated`, `x_mitre_domains`, `x_mitre_is_subtechnique`, `x_mitre_modified_by_ref`, `x_mitre_platforms`, `x_mitre_version` (all 858); `x_mitre_contributors` (520); `x_mitre_remote_support` (53); `x_mitre_impact_type` (38).

Notably absent: `x_mitre_permissions_required`, `x_mitre_effective_permissions`, **and `x_mitre_data_sources`**. Data sources are now separate objects (`x-mitre-data-source` 38, `x-mitre-data-component` 109, `x-mitre-detection-strategy` 699, `x-mitre-analytic` 1758). The rendered technique pages match: sections are **Procedure Examples, Mitigations, Detection Strategy, References** — no permissions row.

What functions as a precondition, in descending order of rigour:

1. **Prose in `description`.** This is the only place ATT&CK states prerequisites, and it does so informally. T1552.005: *"If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources."* T1098.001: *"In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys…"* — an explicit, technique-referencing precondition, but in prose, not a field.
2. **`kill_chain_phases`** (the "Tactic" row on the page). A list, not an order.
3. **`x_mitre_platforms`** — an environment constraint, not attacker state.
4. **Sub-technique relationship** (`x_mitre_is_subtechnique` + a `subtechnique-of` relationship) — specialisation, not sequencing.

## 2. Tactic order is NOT licensed as a precondition chain

ATT&CK explicitly disclaims it. FAQ, <https://attack.mitre.org/resources/faq/>:

> "ATT&CK Tactics are unordered and may not all occur in a single intrusion because adversary tactical goals change throughout an operation, whereas the Cyber Kill Chain uses ordered phases to describe high level adversary objectives."

The matrix column order (`x-mitre-matrix.tactic_refs`, v19.2: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact) is presentation order. The IaaS matrix page carries no note about ordering or prerequisites between columns. **Treating tactic order as a precondition chain is our modelling choice, not ATT&CK's claim.** Note also that ATT&CK's own order puts Credential Access *after* Privilege Escalation, which is the reverse of what our graph does.

## 3. What the attacker HOLDS

"Permissions Required" / "Effective Permissions" **existed and were removed**. In v14.1, `x_mitre_permissions_required` appeared on 286 techniques and `x_mitre_effective_permissions` on 37. Their complete value vocabularies were OS-level only:

- `x_mitre_permissions_required`: `User` (193), `Administrator` (165), `SYSTEM` (72), `root` (36), `Remote Desktop Users` (1)
- `x_mitre_effective_permissions`: `SYSTEM` (22), `Administrator` (18), `root` (11), `User` (10)

By v17.1 both are gone from every attack-pattern. **Even when they existed, none of T1190, T1552.005, or T1098.001 carried either field** (verified in v14.1) — so the field never described cloud identity state, and no cloud technique ever had it.

Where ATT&CK does name held state is in **tactic descriptions**:
- Initial Access: *"gain their initial foothold within a network… Footholds gained through initial access may allow for continued access"*
- Credential Access: *"Using legitimate credentials can give adversaries access to systems"*
- Privilege Escalation: *"The adversary is trying to gain higher-level permissions."*
- Collection: *"The adversary is trying to gather data of interest to their goal."*

## 4. The three techniques, verbatim (v19.2)

| | T1190 | T1552.005 | T1098.001 |
|---|---|---|---|
| Name | Exploit Public-Facing Application | Cloud Instance Metadata API | Additional Cloud Credentials |
| `kill_chain_phases` | `initial-access` | `credential-access` | `persistence`, `privilege-escalation` |
| Sub-technique of | — (`x_mitre_is_subtechnique: false`) | T1552 | T1098 |
| `x_mitre_platforms` | Containers, ESXi, IaaS, Linux, macOS, Network Devices, Windows | IaaS | IaaS, Identity Provider, SaaS |
| `x_mitre_version` | 2.8 | 1.4 | 2.8 |
| Permissions/Requirements | absent | absent | absent |

T1190 description opens: *"Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network."*

## 5–7. Rhino: a consistent four-heading schema

The repository contains **only three files** — `README.md`, `LICENSE`, `.gitignore` (GitHub trees API). There are no per-method scripts. Every one of the 28 methods uses exactly this structure:

```
## 15. Passing a role to a new Lambda function, then invoking it
### How-To/Exploit Link(s)
### Description
### Required Permission(s)
### Potential Impact
```

`Required Permission(s)` is a bullet list of raw IAM action strings, ANDed, with optionality marked inline: method 17 lists `iam:PassRole`, `lambda:CreateFunction`, `lambda:CreateEventSourceMapping`, `dynamodb:PutItem` (possibly), `dynamodb:CreateTable` (possibly).

**Postconditions — `Potential Impact`, verbatim:**

- **#9 Attaching a policy to a role** (policy-write): *"An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a role, giving them full administrator access to the AWS environment."* — the only shape that names a concrete end state.
- **#15 Lambda PassRole**: *"This would give a user access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account."*
- **#28 Existing SageMaker notebook**: *"This would give an attacker access to the privileges associated with the SageMaker service role that is attached to that Jupyter notebook, which could range from no privilege escalation to full administrator access to the account."*

The dominant postcondition idiom is **"the privileges associated with <role>"** — parametrised by identity, with an explicitly *unbounded* range ("no privilege escalation to full administrator"). Rhino does not assert administrator; it asserts a bound.

**Prerequisites beyond the permission — yes, but only in `Description` prose.** Verbatim: #15 *"passing an existing IAM role to a new Lambda function"*; #18 *"could update the code in an existing Lambda function with an IAM role attached… They would then need to wait for it to be invoked if they were not able to do so directly"*; #14 *"change the assume role policy document of any existing role"*; #17 *"They then would need to either create a DynamoDB table or use an existing one"*; #2 *"If a policy that they have access to has versions that are not the default"*. These are real, quotable resource-existence preconditions — but they live in prose, not in a field, and Rhino attaches no severity or rating of its own. Our `severity: critical` vs `high` split in `data/privesc_methods.yaml` is a *derived* reading of this prose. **Rhino publishes no severity field; that ranking is ours.** (Not verified: whether the linked Rhino blog post ranks them — out of scope, it is not the repository.)

## Conclusion: what vocabulary is jointly licensed

**Neither source provides a precondition/postcondition vocabulary. Both express preconditions only as unstructured prose. The four-fact vocabulary is an invention — but three of the four facts are lexically grounded in ATT&CK's own tactic descriptions.**

Licensed terms, with owners:

| Our fact | Source-grounded? | Grounding |
|---|---|---|
| `internet_reachable` | Partly | ATT&CK T1190 says *"Internet-facing host or system"* — an attribute of the target, never a fact the attacker holds. The reification is ours. |
| `foothold(x)` | **Yes, the word is ATT&CK's** | Initial Access tactic: *"initial foothold within a network"*, *"Footholds gained through initial access"*. The parametrisation `(x)` is ours. |
| `credential(x)` | **Yes** | Credential Access tactic; Rhino's *"request the associated AWS keys from the EC2 instance meta data"* (#3). |
| `data_access(x)` | Weakest | ATT&CK's Collection tactic says *"gather data"* — an activity, not a held state. `data_access` is closest to invented. |

**On "privilege" as a held state:** ATT&CK does not use it that way — the noun appears as the tactic name "Privilege Escalation", and its description says *"gain higher-level permissions"*, i.e. permissions, on a system, not a state predicate. **Rhino does**: "the privileges associated with the role", "the privileges that are attached to any role in the account" — a role-parametrised held privilege set (71 occurrences of "privilege" in the README). So the only source that licenses privilege-as-state is Rhino, and it licenses it *parametrised by identity*, not as a boolean.

The defensible source-grounded alternative is therefore **not** a different four facts; it is to stop claiming booleans where Rhino claims a bound. Rhino's own postcondition is `privileges_of(role) ∈ [nothing, administrator]`. Our `output: {privilege: administrator}` in `ACT_WRITE_ROLE_POLICY` (`data/attack_transitions.yaml:308`) asserts the top of that range as certain, which Rhino explicitly does not — its strongest form (#7–#9) is conditional on the attacker attaching `AdministratorAccess`. That gap is citable and fixable; the four-fact vocabulary itself is an unavoidable invention, and saying so with the above attribution table is the honest framing.
