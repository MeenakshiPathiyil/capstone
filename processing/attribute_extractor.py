"""Wrap a resource so a rule can read it the two ways rules are written.

THEORY (two vocabularies, one wrapper):
A condition leaf names either an abstract attribute the parser projected
(`ingress.port`, `bucket.name`) or a raw CloudFormation path
(`SecurityGroupIngress[0].CidrIp`). Both have to resolve, because the canonical
ruleset is written in the first and older rules in the second. So the wrapper
carries both and the evaluator tries `_attributes` before `_structured`.

Abstract first, deliberately: an abstract name is a deliberate statement about
what the rule means, and a raw path that happens to collide with one should not
win.
"""

from utils.helpers import flatten_dict


def extract_attributes(resource):
    """Convert raw_properties into rule-friendly format."""

    raw = resource.get("raw_properties", {})
    flat = flatten_dict(raw)

    return {
        **resource,                                  # original resource
        **flat,                                      # flattened raw attributes
        "_structured": raw,                          # original nesting
        "_attributes": resource.get("attributes") or {}   # the abstract vocabulary
    }


def process_resources(resources):
    """Apply extraction to all resources."""
    return [extract_attributes(r) for r in resources]
