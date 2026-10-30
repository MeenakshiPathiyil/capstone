"""Tests for data/remediations.yaml - the fix shown for each finding.

The catalog is keyed by rule `source_id` and privesc method `id`, so it can drift
from the two files it describes in exactly two ways: an id gains no entry, or an
entry keeps an id that was renamed or mistyped. Both are caught here, along with
the snippets, which are CloudFormation and so must at least be well-formed YAML.
"""

from pathlib import Path

import pytest
import yaml

from engine.privesc_detector import BROAD_GRANT_RULE_IDS
from main import build_infra_from_resources
from parser.infra_parser import normalize, validate_template
from security_state_graph.state_graph import evaluate_findings


ROOT = Path(__file__).resolve().parent.parent
REMEDIATIONS = ROOT / "data" / "remediations.yaml"
RULES = ROOT / "data" / "security_rules.yaml"
METHODS = ROOT / "data" / "privesc_methods.yaml"


class CloudFormationLoader(yaml.SafeLoader):
    """SafeLoader that accepts the short-form tags (!Ref, !Sub, !GetAtt ...).

    A snippet is a CloudFormation fragment and CloudFormation writes intrinsic
    functions as YAML tags that plain safe_load rejects. The tag is not what is
    being tested, so it is read as the value it wraps.
    """


def construct_tagged(loader, tag_suffix, node):

    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)

    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)

    return loader.construct_mapping(node, deep=True)


CloudFormationLoader.add_multi_constructor("!", construct_tagged)


def load(path):

    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def catalog():

    return load(REMEDIATIONS)


@pytest.fixture(scope="module")
def rules_by_source_id():
    """Every rule in data/security_rules.yaml, grouped by `source_id`."""

    grouped = {}

    for rule in load(RULES):
        grouped.setdefault(rule["source_id"], []).append(rule)

    return grouped


@pytest.fixture(scope="module")
def method_ids():
    """The ids the "methods" section is keyed by: the catalogue's escalation
    methods, plus the wildcard grants the detector reports without one."""

    return {method["id"] for method in load(METHODS)["methods"]} | set(
        BROAD_GRANT_RULE_IDS
    )


def entries(catalog):
    """(section, id, entry) for every rule and method entry."""

    for section in ("rules", "methods"):
        for entry_id, entry in catalog[section].items():
            yield section, entry_id, entry


def test_catalog_has_only_rules_and_methods(catalog):

    assert set(catalog) == {"rules", "methods"}


def test_every_rule_source_id_has_an_entry(catalog, rules_by_source_id):
    """One fix per check: a rule with no entry would show the user no remedy."""

    missing = set(rules_by_source_id) - set(catalog["rules"])

    assert not missing, sorted(missing)


def test_every_privesc_method_has_an_entry(catalog, method_ids):

    missing = method_ids - set(catalog["methods"])

    assert not missing, sorted(missing)


def test_no_entry_for_an_unknown_rule(catalog, rules_by_source_id):
    """A typo here is an entry nothing will ever look up."""

    unknown = set(catalog["rules"]) - set(rules_by_source_id)

    assert not unknown, sorted(unknown)


def test_no_entry_for_an_unknown_method(catalog, method_ids):

    unknown = set(catalog["methods"]) - method_ids

    assert not unknown, sorted(unknown)


def test_every_entry_has_a_fix_and_an_https_url(catalog):

    for section, entry_id, entry in entries(catalog):

        fix = entry.get("fix")

        assert isinstance(fix, str) and fix.strip(), (section, entry_id)

        url = entry.get("url")

        assert isinstance(url, str) and url.startswith("https://"), (
            section,
            entry_id
        )


def test_entries_carry_only_known_keys(catalog):

    for section, entry_id, entry in entries(catalog):

        allowed = {"fix", "url"}

        if section == "rules":
            allowed = allowed | {"snippet", "by_resource_type"}

        assert set(entry) <= allowed, (section, entry_id, set(entry) - allowed)


def test_method_urls_point_into_the_rhino_readme(catalog):

    prefix = (
        "https://github.com/RhinoSecurityLabs/"
        "AWS-IAM-Privilege-Escalation#"
    )

    for method_id, entry in catalog["methods"].items():

        if method_id in BROAD_GRANT_RULE_IDS:
            continue

        assert entry["url"].startswith(prefix), method_id
        assert len(entry["url"]) > len(prefix), method_id


def test_no_entry_uses_an_em_dash(catalog):

    assert "\u2014" not in REMEDIATIONS.read_text(encoding="utf-8")


def test_by_resource_type_names_a_type_the_check_targets(
    catalog,
    rules_by_source_id
):
    """An override for a type the check never fires on could never be shown."""

    for source_id, entry in catalog["rules"].items():

        targeted = {rule["resource_type"] for rule in rules_by_source_id[source_id]}

        for resource_type in entry.get("by_resource_type") or {}:

            assert resource_type in targeted, (source_id, resource_type)


def test_by_resource_type_overrides_carry_a_snippet(catalog):

    for source_id, entry in catalog["rules"].items():

        for resource_type, override in (entry.get("by_resource_type") or {}).items():

            assert set(override) == {"snippet"}, (source_id, resource_type)
            assert override["snippet"].strip(), (source_id, resource_type)


def test_every_snippet_parses_as_yaml(catalog):

    checked = 0

    for source_id, entry in catalog["rules"].items():

        snippets = [entry.get("snippet")] + [
            override.get("snippet")
            for override in (entry.get("by_resource_type") or {}).values()
        ]

        for snippet in snippets:

            if snippet is None:
                continue

            assert isinstance(snippet, str) and snippet.strip(), source_id

            parsed = yaml.load(snippet, Loader=CloudFormationLoader)

            assert isinstance(parsed, dict), (source_id, snippet)

            checked += 1

    # Most checks carry a snippet; if the loop stops finding them the assertions
    # above pass for free.
    assert checked >= 10


# Two roles the escalation catalogue names no method for, one of each wildcard
# shape: administrator through an attached policy, and a service-wide grant.
WILDCARD_GRANTS = """
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Service: ec2.amazonaws.com}
            Action: sts:AssumeRole
  AdminPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: everything
      Roles: [!Ref AdminRole]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
  DataRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Service: ec2.amazonaws.com}
            Action: sts:AssumeRole
  DataPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: s3-all
      Roles: [!Ref DataRole]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "s3:*"
            Resource: "*"
"""


def test_every_finding_the_pipeline_produces_has_an_entry(catalog):
    """Every finding comes from a rule, an escalation method or a broad grant,
    and each is looked up in the catalog the way app/api/remediations.py does:
    rules by source_id, everything else by rule_id."""

    template = yaml.load(WILDCARD_GRANTS, Loader=CloudFormationLoader)

    infra = build_infra_from_resources(normalize(validate_template(template)))

    findings = evaluate_findings(infra)

    produced = {finding["rule_id"] for finding in findings}

    # The template really does exercise both wildcard shapes.
    assert set(BROAD_GRANT_RULE_IDS) <= produced

    rule_ids = {rule["id"] for rule in load(RULES)}

    for finding in findings:

        if finding["rule_id"] in rule_ids:
            assert finding["source_id"] in catalog["rules"], finding["rule_id"]

        else:
            assert finding["rule_id"] in catalog["methods"], finding["rule_id"]


def test_the_wildcard_grant_entries_name_aws_documentation(catalog):

    for finding_id in BROAD_GRANT_RULE_IDS:

        url = catalog["methods"][finding_id]["url"]

        assert url.startswith("https://docs.aws.amazon.com/IAM/latest/UserGuide/"), (
            finding_id
        )
