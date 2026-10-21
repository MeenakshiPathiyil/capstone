# The transition ruleset is the only place conditions are declared

Following ADR 0001, conditions belong to actions. But there were two places that
declared them: the transition ruleset, and a table in code keyed by edge category
that supplied a precondition/postcondition pair for any edge no rule matched.
Every consumer therefore had to handle both shapes, and the two disagreed about 2
of the 16 edges in the shipped account — the exported edge list stated
preconditions the path search did not enforce.

The category table exists for a good reason: it is what makes an incomplete
ruleset safe, so a hop nobody has written a rule for still yields a step rather
than silently deleting every path through it. The resolution is that this table
was always a set of rules and should be written as one. Each edge category gets a
default action in the ruleset, matched last. The guarantee survives, and there is
one place to read to find out what an action requires.

`security_state_graph/facts.py` keeps only the fact vocabulary — the four fact
names and the helpers for testing and accumulating them — which is the part all
three modules legitimately share.

## Consequences

The security state graph's edges no longer carry `action`, `precondition` or
`postcondition`. They describe what the template declares and which way an
attacker travels it, and nothing about attacker capability. Conditions appear in
the attack graph, which is where actions are. This removes a field from
`graph_traversal_edges.json` that readers may have started relying on.

A default action is still a claim, so each one has to be defensible on its own
terms. They carry no ATT&CK technique and no tactic, because a category says what
a hop is structurally and nothing about which attacker behaviour it is. A run
reports how many steps used a default, and that number reaching zero is the goal.
