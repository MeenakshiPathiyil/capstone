# Cloud attack path analysis

Reads a cloud infrastructure file, works out what is misconfigured, and derives
the routes an attacker could take through it. The routes are handed to a
fine-tuned language model in `scenario_generation/`, which writes them up as
attack scenarios.

## Language

### The two graphs

**Security state graph**:
The account's resources, the references between them, and what is wrong with each
one. A node is a resource.
_Avoid_: state graph, security graph, infra graph

**Attack graph**:
The states an attacker can be in and the actions that move between them. A node
is an attacker state, not a resource, so one resource appears in it as many times
as there are distinct situations an attacker can reach it in.
_Avoid_: attack tree, exploit graph

**Traversal view**:
The security state graph's edges turned to face the direction an attacker travels,
which is the reverse of the declared direction for some kinds of reference.
_Avoid_: reversed graph, attack direction graph

### What the attacker holds

**Fact**:
One thing that is true of an attacker's progress. There are four:
`internet_reachable`, `foothold(x)`, `credential(x)`, `data_access(x)`.
_Avoid_: predicate, assertion, condition, state variable

**Attacker state**:
A resource together with the set of facts held on arriving at it. Two routes that
reach the same resource holding different facts are in different states.
_Avoid_: node, position, situation

**Foothold**:
The attacker can run code on a resource.
_Avoid_: shell, access, compromise

**Credential**:
The attacker holds an identity and can act as it.
_Avoid_: token, key, role access

### What the rules say

**Capability**:
Something the configuration permits, derived from a resource's properties by a
security rule. The security state graph is the account expressed as capabilities.
_Avoid_: weakness, permission, ability

**Finding**:
One security rule matching one resource. Carries the state it raised, its
semantic, and which check produced it.
_Avoid_: violation, issue, alert, vulnerability

**State** (of a finding):
The named condition a finding reports, such as `unrestricted_ssh_access`. A
property of the finding, not to be confused with an attacker state.
_Avoid_: status, condition

**Semantic**:
What a finding means for movement through the graph: whether it is a way in, a
gain of authority, or neither.
_Avoid_: category, class, kind

**Action**:
Something an attacker does, defined by a transition rule. Carries the four fields
below. An action is the unit the attack graph's edges are made of.
_Avoid_: step, exploit, technique, move

**Transition rule**:
A rule mapping a capability to an action. Lives in the attack transition ruleset.
_Avoid_: attack rule, action rule, edge rule

### The four fields of an action

**Precondition**:
The facts an attacker must already hold for the action to be available. Any one of
them suffices.
_Avoid_: requires, guard, prerequisite

**Postcondition**:
The facts the attacker holds as a result of taking the action.
_Avoid_: effect, result, gain

**Input**:
The data the action reads: which resource, which port, which finding justifies it.
Not a fact and not a boolean.
_Avoid_: parameters, arguments, context

**Output**:
The data the action produces, such as the kind of access obtained.
_Avoid_: result, return, product

### Routes through the graph

**Entry point**:
A resource carrying a finding whose semantic means it is reachable from outside
the account.
_Avoid_: source, start node, ingress

**Objective**:
What an attacker is trying to achieve, and which resources count as having
achieved it.
_Avoid_: goal, target type, intent

**Attack path**:
A route from an entry point to a resource satisfying an objective, where every
action's precondition is met by the preceding action's postcondition.
_Avoid_: chain, route, kill chain, scenario

**Scenario**:
The written narrative a language model produces from an attack path. Belongs to
`scenario_generation/`, never to the graph pipeline.
_Avoid_: report, story, narrative
