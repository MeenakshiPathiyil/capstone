# Provenance claims the code does not support

The review deck states where the two rulesets come from. Three of those claims
are not met by anything in this repository. None of them is a code defect — each
is either a citation to add or a sentence to change in the deck, and both are
decisions for whoever owns the ruleset.

## 1. CAPEC is claimed and absent

Rev1, p10, on the attack transition rules:

> Derived from attacker knowledge sources such as MITRE ATT&CK, **CAPEC attack
> patterns**, and real-world incident chains

MITRE ATT&CK holds up: every action in `data/attack_transitions.yaml` cites an
IaaS technique id, and `tests/test_transitions.py` rejects any id not in
`data/attack_techniques.yaml` and any tactic the matrix does not file that
technique under.

CAPEC does not. The string "CAPEC" appears once in the repository, inside a
comment quoting this very sentence. There are no CAPEC ids anywhere. Neither are
there incident-chain citations.

**Options.** Add a `capec` field to each action where a defensible mapping exists
— CAPEC-1 (Accessing Functionality Not Properly Constrained by ACLs) fits the
initial-access actions, for instance — or strike CAPEC from the deck. Adding ids
without checking each one would repeat the mistake this file exists to record: an
earlier version of the code claimed its tactic ordering was ATT&CK's when ATT&CK
explicitly disclaims ordering.

## 2. CIS Benchmarks, Security Hub and Prowler are claimed and absent

Rev1, p10, on the semantic security rules:

> Derived from authoritative sources such as **CIS Benchmarks**, cloud provider
> security services (**AWS Security Hub**, Azure Defender, GCP Security Command
> Center), and open-source tools like **Prowler**

`data/security_rules.yaml` says the canonical rules are derived from **AWS Config
managed rules**, and each carries a `references` entry pointing at the AWS Config
documentation for that rule. That is a real, checkable provenance — it is simply
not the one the deck names.

**Options.** Change the deck to say AWS Config, or map the existing rules to their
CIS Benchmark control numbers. The second is genuine work and would strengthen
the ruleset; it is not something to assert without doing.

## 3. The risk score is described as a model

Rev1, p11 pairs "rule-based reasoning for graph construction" with "ML for risk
scoring", and lists a *Vulnerability Intelligence Dataset* of actively exploited
CVEs.

What exists is a hand-weighted arithmetic formula in `graph/path_finder.py`. No
model, no training, no CVE data. `graph/conditions.py` states plainly that there
is no CVE and no patch level anywhere in the model.

**Options.** This one is a roadmap item rather than a misstatement — Task 7 says
only "assign a risk score", which the formula does. But if the deck keeps the
word "ML", the gap should be named as future work rather than left to be read as
built.

## What is soundly cited

- **ATT&CK technique ids and names**, enforced by test against the published IaaS
  matrix.
- **Rhino Security Labs' 28 IAM escalation methods** in
  `data/privesc_methods.yaml`. Note the severity split is *our* reading of Rhino's
  prose — Rhino publishes no severity field. Its own two fields,
  `Required Permission(s)` and `Potential Impact`, are precisely a precondition
  and a postcondition, and are the strongest source-grounded backing the
  pre/postcondition model has.
- **AWS Config managed rules** for the canonical security ruleset.

See `docs/research/precondition-sources.md` for how each source expresses
prerequisites and results.
