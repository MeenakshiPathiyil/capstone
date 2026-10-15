"""A nested-stack architecture has to merge into one graph before it has a path.

THEORY (what this file is for):
Production infrastructure is not one template. The reference architectures on
GitHub put the VPC in one file, the load balancer in another, the compute in a
third and the database in a fourth, joined by AWS::CloudFormation::Stack. Read one
file at a time, none of them contains an attack chain — the front door is in one
file and the data is in another — so a scanner reading single templates cannot see
the thing an attack graph exists to find. Of 24 templates harvested from two
reference-architecture repositories, zero had all four chain ingredients, and that
was the only reason.

tests/fixtures/nested/ is that shape, deliberately and minimally:

    network.yaml   a security group with SSH open to the world, and nothing else
    web.yaml       an instance, its profile, and a role holding s3:* on *
    data.yaml      a bucket, and nothing else
    parent.yaml    the three stacks, passing the group into web by parameter

Every hop of the attack is real and no single file holds two of them. The tests
below assert both halves of the claim: unmerged there is no path, merged there is
one. The second assertion alone would pass on a merge that silently concatenated
without resolving anything, so the first is what gives it meaning.
"""

import sys
from pathlib import Path

import pytest

from engine.connection_builder import (
    build_capability_edges,
    build_connections,
    build_escalation_edges
)
from attack_path.path_finder import entry_points, find_attack_paths, objective_targets
from security_state_graph.state_graph import SecurityStateGraph, evaluate_findings
from models.cloud_resource import CloudResource
from models.infra_model import InfraModel


BASE_DIR = Path(__file__).resolve().parent.parent

FIXTURE_DIR = BASE_DIR / "tests" / "fixtures" / "nested"
PARENT = FIXTURE_DIR / "parent.yaml"

RULES_PATH = BASE_DIR / "data" / "security_rules.yaml"

# The stage-0 parser is a sibling checkout, not a package — the same reason
# runner/benchmark.py has to locate it rather than import it directly.
PARSER_REPO = Path.home() / "Downloads" / "capstone-feature-yaml-parser-normalization"

# The hops the merged account must produce, in the merged namespace. Written out
# because the namespacing is the part most likely to break quietly: an id that
# loses its prefix collides with its sibling, and an id that keeps one it should
# not stops matching the reference that names it.
EXPECTED_HOPS = [
    "Network.OpenGroup",
    "Web.WebInstance",
    "Web.WebProfile",
    "Web.WebRole",
    "Data.ReportsBucket"
]


requires_parser = pytest.mark.skipif(
    not (PARSER_REPO / "parser" / "nested.py").exists(),
    reason="stage-0 parser checkout not present"
)


def load_nested():
    """parse_merged from the sibling parser checkout."""

    if str(PARSER_REPO) not in sys.path:
        sys.path.insert(0, str(PARSER_REPO))

    from parser.nested import parse_merged  # noqa: E402 - path set above

    return parse_merged


def graph_from(records):
    """The full pipeline over a list of normalized records.

    build_infra_from_resources rather than assembling the model by hand: it also
    projects the abstract attributes the ruleset is written against, and a model
    built without them evaluates every canonical rule against an empty
    vocabulary. Built by hand, this helper reported no finding on a security
    group with SSH open to the world.
    """

    from main import build_infra_from_resources

    infra = build_infra_from_resources(records)

    return SecurityStateGraph(infra, evaluate_findings(infra, RULES_PATH))


@pytest.fixture
def merged():
    records, report = load_nested()(PARENT, root=FIXTURE_DIR)
    return records, report


@pytest.fixture
def unmerged():
    """Each child parsed on its own, the way single-file analysis sees them."""

    parse_merged = load_nested()

    return {
        path.stem: parse_merged(path, root=FIXTURE_DIR, follow_stacks=False)[0]
        for path in sorted(FIXTURE_DIR.glob("*.yaml"))
        if path.name != "parent.yaml"
    }


# -----------------------------

@requires_parser
def test_no_single_file_contains_an_attack_path(unmerged):
    """THE HALF THAT GIVES THE OTHER HALF MEANING.

    Each child is a real template with a real weakness, and not one of them has a
    path, because no one file holds an entry and a target.
    """

    for name, records in unmerged.items():

        paths = find_attack_paths(graph_from(records))

        assert paths == [], "%s produced a path on its own" % name


@requires_parser
def test_every_child_stack_is_merged(merged):
    records, report = merged

    assert report["skipped"] == []
    assert {entry["stack"] for entry in report["merged"]} == {"Network", "Web", "Data"}

    assert len(records) > 0


@requires_parser
def test_ids_are_namespaced_by_their_stack(merged):
    """Logical ids are only unique within a template, so a merge that keeps them
    bare lets two children collide."""

    records, _ = merged
    ids = {record["id"] for record in records}

    for expected in EXPECTED_HOPS:
        assert expected in ids

    # The bare forms must be gone, or a reference could bind to the wrong node.
    assert "OpenGroup" not in ids
    assert "WebRole" not in ids


@requires_parser
def test_the_cross_stack_parameter_is_resolved(merged):
    """web.yaml names its group by parameter; the parent passes
    !GetAtt Network.Outputs.OpenGroup. Unresolved, the web tier is an island."""

    records, _ = merged

    instance = next(r for r in records if r["id"] == "Web.WebInstance")

    assert instance["raw_properties"]["SecurityGroupIds"] == ["Network.OpenGroup"]


@requires_parser
def test_the_merged_account_has_the_entry_and_the_target(merged):
    records, _ = merged
    state_graph = graph_from(records)

    assert "Network.OpenGroup" in entry_points(state_graph)
    assert "Data.ReportsBucket" in objective_targets(state_graph)


@requires_parser
def test_the_merged_account_yields_the_cross_file_path(merged):
    """THE HEADLINE ASSERTION: the chain exists only once the files are merged."""

    records, _ = merged

    paths = find_attack_paths(graph_from(records))

    assert paths, "merging produced no attack path"

    assert EXPECTED_HOPS in [path["hops"] for path in paths]


@requires_parser
def test_the_cross_file_path_is_a_data_theft_path(merged):
    """Not merely reachable — an objective an attacker would actually pursue, with
    the escalation on an interior hop."""

    records, _ = merged

    paths = [
        path
        for path in find_attack_paths(graph_from(records))
        if path["hops"] == EXPECTED_HOPS
    ]

    objectives = {path["objective"] for path in paths}

    assert "data_theft" in objectives

    theft = next(path for path in paths if path["objective"] == "data_theft")

    assert theft["entry_id"] == "Network.OpenGroup"
    assert theft["target_id"] == "Data.ReportsBucket"
    assert theft["score"] > 0


@requires_parser
def test_a_cycle_does_not_recurse_forever(tmp_path):
    """A template that includes itself terminates and is reported, rather than
    running until the interpreter gives up."""

    parse_merged = load_nested()

    (tmp_path / "loop.yaml").write_text(
        "AWSTemplateFormatVersion: \"2010-09-09\"\n"
        "Resources:\n"
        "  Self:\n"
        "    Type: AWS::CloudFormation::Stack\n"
        "    Properties:\n"
        "      TemplateURL: https://s3.amazonaws.com/b/loop.yaml\n"
    )

    records, report = parse_merged(tmp_path / "loop.yaml", root=tmp_path)

    assert any(entry["reason"] == "cycle" for entry in report["skipped"])


@requires_parser
def test_an_unresolvable_template_url_is_reported_not_guessed(tmp_path):
    """A child that is not on disk leaves a boundary the graph could not cross,
    and says so. Inventing a node for it would put a resource in the graph that
    the account does not contain."""

    parse_merged = load_nested()

    (tmp_path / "top.yaml").write_text(
        "AWSTemplateFormatVersion: \"2010-09-09\"\n"
        "Resources:\n"
        "  Missing:\n"
        "    Type: AWS::CloudFormation::Stack\n"
        "    Properties:\n"
        "      TemplateURL: https://s3.amazonaws.com/b/nowhere/absent.yaml\n"
    )

    records, report = parse_merged(tmp_path / "top.yaml", root=tmp_path)

    assert [entry["stack"] for entry in report["skipped"]] == ["Missing"]
    assert "not found" in report["skipped"][0]["reason"]

    # The Stack resource itself survives as an ordinary node.
    assert [record["id"] for record in records] == ["Missing"]
