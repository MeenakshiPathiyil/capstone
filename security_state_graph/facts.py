"""The four facts an attacker can hold, and the helpers that chain them.

    internet_reachable   can send traffic in from outside
    foothold(x)          can run code on x
    credential(x)        holds x's identity
    data_access(x)       can read or write x's data

A step is legal when its precondition is already held, and taking it adds its
postcondition. That chaining is what makes a route a derivation rather than a
line drawn between resources that reference each other.

The conditions themselves are in data/attack_transitions.yaml, one pair per
action. Holding a fact says the step is possible given the configuration, not
that it would succeed: there is no exploit, no CVE and no patch level here.
"""

# -- The facts ----------------------------------------------------------------

INTERNET_REACHABLE = "internet_reachable"

FOOTHOLD = "foothold"
CREDENTIAL = "credential"
DATA_ACCESS = "data_access"

# Which end of the edge a fact is about. A precondition is nearly always about
# the source (what the attacker already reached) and a postcondition about the
# target (what they gain by taking the hop).
SOURCE = "source"
TARGET = "target"


def fact(name, resource_id=None):
    """One fact as the string the report and the fact set both use.

    `internet_reachable` is about the whole environment and carries no resource,
    so it stays bare. Everything else is scoped to a resource, because "the
    attacker has a foothold" is not a fact and "the attacker has a foothold on
    AppServerInstance" is.
    """

    if resource_id is None:
        return name

    return "%s(%s)" % (name, resource_id)


def resolve(pairs, edge):
    """A list of (fact name, end) pairs as concrete fact strings for `edge`."""

    resolved = []

    for name, end in pairs:

        if end is None:
            resolved.append(fact(name))
            continue

        resolved.append(fact(name, edge[end]))

    return resolved


def precondition_met(edge, facts):
    """True when `facts` satisfies any one of `edge`'s preconditions.

    A hop with no precondition is always available. That is the honest reading of
    "this category makes no claim about what the attacker holds", and it is why
    such a category also grants nothing: it cannot be the reason a path exists.
    """

    required = edge.get("precondition")

    if not required:
        return True

    return any(item in facts for item in required)


def facts_after(edge, facts):
    """`facts` plus whatever taking `edge` gains the attacker."""

    return facts | set(edge.get("postcondition") or [])
