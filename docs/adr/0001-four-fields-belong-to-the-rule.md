# Precondition, postcondition, input and output belong to the rule

The review deck's Task 5 reads "implement the four fields shown explicitly in the
architecture diagram for each node/edge in the security state graph", which sounds
like the four fields are properties of nodes and edges. The diagram it refers to
says otherwise: the four boxes are drawn *inside* the box labelled "Rules for
capabilities → Actions". They are fields of an action rule. So they are declared
once per action in the attack transition ruleset, and an attack graph edge carries
them because it is an instance of an action, not because an edge is a thing that
has preconditions.

## Considered options

**Put all four on every node too.** Rejected. A node is an attacker state; the
facts it holds are arguably its precondition, but it has no honest `input` or
`output` — those describe reading and producing data, which is something an
action does and a state does not. Satisfying the checklist would have meant
copying values from adjacent edges onto nodes, producing a field that is
present, populated, and meaningless.

**Attach the four fields to security state graph nodes (resources).** Rejected
for the same reason plus a worse one: a resource's properties are the same
whoever is attacking it, so a precondition on a resource cannot depend on what
the attacker holds, which is the entire point of a precondition.

## Consequences

Reading the deck's prose against the code, it will look as though Task 5 is only
half done. It is not: the fields are where the diagram puts them. Anyone
reviewing this should be shown the diagram, not the task list.

Nodes therefore carry `facts` — the set the attacker holds in that state — and
nothing else from the four. `facts` is not renamed `precondition`, because a
state's facts are what *is* true, while a precondition is what *must be* true for
something else to happen.
