"""Read the ATT&CK IaaS matrix, and answer questions about a technique id.

THEORY (what this replaces):
graph/exporter.py ordered a path's techniques with two hardcoded structures — a
list of kill-chain phase names and a dict of eleven technique ids mapped to them.
Both were written by hand, neither could be checked against anything, and a rule
citing a twelfth technique got silently sorted to the end. The ordering is now a
function of data/attack_techniques.yaml, which is the IaaS matrix, so:

  * the phase order is ours, not ATT&CK's — ATT&CK does not order its tactics
  * a technique's phase is the tactic ATT&CK files it under
  * a technique absent from the matrix is *detectable*, which lets
    tests/test_security_rules.py reject a rule citing something outside IaaS

THEORY (why the name lives here too):
data/privesc_methods.yaml cites techniques by id alone, because repeating
"T1098: Account Manipulation" against 28 methods is 28 chances to mistype a name
that already exists once in the matrix file. So an id is resolved to its official
name here, and the catalogue stays a list of ids.
"""

import yaml
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

TECHNIQUES_PATH = BASE_DIR / "data" / "attack_techniques.yaml"

# The separator in "T1098.001". A sub-technique is filed under its parent's
# tactic unless the matrix gives the sub-technique its own entry.
SUB_TECHNIQUE_SEPARATOR = "."


def load_catalog(path=TECHNIQUES_PATH):
    """The matrix as {"tactics": [...], "techniques": {id: {...}}}."""

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    tactics = data.get("tactics") or []

    techniques = {}

    for entry in data.get("techniques") or []:

        technique_id = entry.get("id")

        if not technique_id:
            continue

        tactic = entry.get("tactic")

        # A tactic the tactic list does not contain cannot be ordered, and is a
        # typo rather than a new phase.
        if tactic not in tactics:
            raise ValueError(
                "technique {} has tactic {!r}, which is not in the tactic list"
                .format(technique_id, tactic)
            )

        techniques[str(technique_id)] = {
            "id": str(technique_id),
            "name": str(entry.get("name") or ""),
            "tactic": tactic,
            "also": entry.get("also") or []
        }

    return {"tactics": tactics, "techniques": techniques}


_CACHE = {}


def catalog(path=TECHNIQUES_PATH):
    """The parsed matrix, read once per path."""

    key = str(path)

    if key not in _CACHE:
        _CACHE[key] = load_catalog(path)

    return _CACHE[key]


def parent_id(technique_id):
    """"T1098.001" -> "T1098". An id with no sub-technique is itself."""

    return str(technique_id).split(SUB_TECHNIQUE_SEPARATOR, 1)[0]


def is_known(technique_id, path=TECHNIQUES_PATH):
    """True when the id, or its parent, is in the IaaS matrix."""

    techniques = catalog(path)["techniques"]

    return (
        str(technique_id) in techniques
        or parent_id(technique_id) in techniques
    )


def technique_name(technique_id, path=TECHNIQUES_PATH):
    """The matrix's name for an id, or "" when it is not in the matrix."""

    techniques = catalog(path)["techniques"]

    entry = techniques.get(str(technique_id))

    if entry is None:
        entry = techniques.get(parent_id(technique_id))

    if entry is None:
        return ""

    return entry["name"]


def tactic_of(technique_id, path=TECHNIQUES_PATH):
    """The primary tactic of an id, falling back to its parent's."""

    techniques = catalog(path)["techniques"]

    entry = techniques.get(str(technique_id))

    if entry is None:
        entry = techniques.get(parent_id(technique_id))

    if entry is None:
        return None

    return entry["tactic"]


def tactics(path=TECHNIQUES_PATH):
    """The tactic names, in the order an attacker moves through them."""

    return list(catalog(path)["tactics"])


def phase_rank(technique_id, path=TECHNIQUES_PATH):
    """Sort key placing a technique at its tactic's position in the chain.

    An unknown technique sorts last rather than raising: the ruleset test is the
    place that refuses an off-matrix citation, and an exporter that crashed on
    one would take the whole pipeline down over a typo in a name field.
    """

    order = catalog(path)["tactics"]

    tactic = tactic_of(technique_id, path)

    if tactic is None or tactic not in order:
        return len(order)

    return order.index(tactic)


def resolve(technique_ids, path=TECHNIQUES_PATH):
    """Ids -> [{"id", "name"}], in the order given, names from the matrix."""

    resolved = []

    for technique_id in technique_ids or []:

        resolved.append({
            "id": str(technique_id),
            "name": technique_name(technique_id, path)
        })

    return resolved
