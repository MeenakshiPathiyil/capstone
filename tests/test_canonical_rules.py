"""data/security_rules.yaml keeps the canonical ruleset as its owner wrote it.

rulesets/canonical_rules.yaml is Meenakshi's ruleset. Every one of its rules has
to be in data/security_rules.yaml with her id, source, service, semantic, state,
summary, parameters and references. Conditions are left out of the comparison:
this engine writes them in its own syntax, and a change in what one matches is
recorded under the rule's `deviations:` instead.
"""

from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parent.parent
CANONICAL = ROOT / "rulesets" / "canonical_rules.yaml"
SHIPPED = ROOT / "data" / "security_rules.yaml"

KEPT_FIELDS = ("origin", "source_id", "service", "resource_type", "semantic",
               "state", "summary", "parameters", "references")


def load(path):
    return {rule["id"]: rule for rule in yaml.safe_load(path.read_text(encoding="utf-8"))}


def comparable(value):
    """Her file writes "no parameters" as {} and folded summaries end in a
    newline here; neither is a difference in the rule."""

    if isinstance(value, str):
        return value.strip()
    if value in (None, {}, []):
        return None
    return value


CANONICAL_RULES = load(CANONICAL)
SHIPPED_RULES = load(SHIPPED)


def test_every_canonical_rule_ships():
    assert set(CANONICAL_RULES) - set(SHIPPED_RULES) == set()


@pytest.mark.parametrize("rule_id", sorted(CANONICAL_RULES))
def test_a_canonical_rule_keeps_its_owners_fields(rule_id):

    hers = CANONICAL_RULES[rule_id]
    ours = SHIPPED_RULES[rule_id]

    for field in KEPT_FIELDS:
        assert comparable(ours.get(field)) == comparable(hers.get(field)), field
