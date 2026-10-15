"""The one test that says the module is finished."""

import json
from pathlib import Path

from attack_path.scoring import (
    ATTACK_LEVEL_CRITICAL,
    ATTACK_LEVEL_HIGH,
    ATTACK_LEVEL_MEDIUM
)
from attack_path.renderer import DOT_PATH, MERMAID_PATH
from security_state_graph.attack_graph import ATTACK_GRAPH_FILES
from security_state_graph.state_graph import GRAPH_FILES
from runner import graph_runner


# The six keys the consumer reads, transcribed from
CONSUMER_KEYS = [
    "source_id",
    "source_name",
    "industry",
    "attack_level",
    "techniques",
    "surfaces",
    "objective"
]

# The bands attack_level is allowed to take, so a typo in a band name is a
# failure here rather than a string the model has never been trained on.
ATTACK_LEVELS = [
    ATTACK_LEVEL_CRITICAL,
    ATTACK_LEVEL_HIGH,
    ATTACK_LEVEL_MEDIUM
]

# The floors the phase was specified against. Findings and paths are the plan's
# numbers; edges is five for the reason documented above.
MINIMUM_EDGES = 5
MINIMUM_FINDINGS = 6
MINIMUM_PATHS = 1

# A second account, not the one this repository was written against. See
SECOND_ACCOUNT = Path(__file__).resolve().parent / "fixtures" / "second_account.json"


# -----------------------------

def artifacts_in(tmp_path):
    """Every artifact path as run_pipeline() keyword arguments, all under tmp_path.

    `graph_files` is a dict of its own because the graph is written as one file
    per block, so the runner takes the whole table rather than a single path.
    """

    return {
        "output_path": tmp_path / "attack_paths.json",
        "graph_files": {
            name: tmp_path / path.name
            for name, path in GRAPH_FILES.items()
        },
        "attack_graph_files": {
            name: tmp_path / path.name
            for name, path in ATTACK_GRAPH_FILES.items()
        },
        "mermaid_path": tmp_path / "security_state_graph.mmd",
        "dot_path": tmp_path / "security_state_graph.dot",
        "steps_path": tmp_path / "attack_path_steps.json"
    }


def test_every_artifact_run_pipeline_writes_can_be_redirected():
    """THE TEST-POLLUTION GUARD.

    Every path run_pipeline writes to has to be redirectable, or a test writes
    into the repository's real output/ directory. That is not hypothetical: this
    file's helper was missing `steps_path` for one commit, and the tests
    overwrote the shipped attack_path_steps.json with the empty result of a
    fixture run.

    Read off the signature rather than listed, so a new artifact added to the
    runner fails here until this helper redirects it too.
    """

    import inspect

    writable = {
        name
        for name in inspect.signature(graph_runner.run_pipeline).parameters
        if name.endswith("_path") or name.endswith("_files")
    }

    # infra_path and rules_path are inputs, not artifacts.
    writable -= {"infra_path", "rules_path"}

    redirected = set(artifacts_in(Path("/tmp/unused")))

    assert writable - redirected == set(), sorted(writable - redirected)


def graph_blocks(keywords):
    """The four written blocks, reassembled into the dict to_dict() produced.

    The blocks live in separate files now; a test asserting a relationship
    between two of them should not have to know that.
    """

    return {
        name: json.loads(path.read_text(encoding="utf-8"))
        for name, path in keywords["graph_files"].items()
    }


def artifact_paths(keywords):
    """Every path in `keywords`, flattening the graph_files table."""

    paths = []

    for value in keywords.values():
        if isinstance(value, dict):
            paths.extend(value.values())
        else:
            paths.append(value)

    return paths


def run(tmp_path, **overrides):
    """The real pipeline over the shipped dataset, writing into tmp_path."""

    keywords = artifacts_in(tmp_path)
    keywords.update(overrides)

    return graph_runner.run_pipeline(**keywords)


# -----------------------------

def test_the_pipeline_produces_resources_edges_findings_and_paths(
    tmp_path,
    real_resource_dicts
):
    """The whole phase in one assertion block: 1 edge -> 6, 1 finding -> 7,"""

    state_graph, paths, records = run(tmp_path)

    assert len(state_graph.nodes) == len(real_resource_dicts)
    assert len(state_graph.edges) >= MINIMUM_EDGES
    assert graph_runner.count_findings(state_graph) >= MINIMUM_FINDINGS
    assert len(paths) >= MINIMUM_PATHS

    # Fewer records than paths: Task 8 filters the export to the high-risk ones.
    # test_only_high_risk_paths_reach_the_export is the assertion about which.
    assert records
    assert len(records) <= len(paths)


# -----------------------------

# -----------------------------

def test_the_export_carries_exactly_the_consumer_contract(tmp_path):
    """Not a subset and not a superset. A missing key is a KeyError inside an"""

    _, _, records = run(tmp_path)

    assert records

    for record in records:
        assert sorted(record.keys()) == sorted(CONSUMER_KEYS)


# -----------------------------

def test_the_runner_writes_a_loadable_file_and_nothing_else(
    tmp_path,
    monkeypatch
):
    """Written where it was told, and not into the working directory — the bug"""

    keywords = artifacts_in(tmp_path)

    written = keywords["output_path"]

    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    _, _, records = graph_runner.run_pipeline(**keywords)

    assert written.exists()
    assert list(cwd.iterdir()) == []

    with open(written, "r", encoding="utf-8") as f:
        loaded = json.load(f)

    assert loaded == records


def test_one_run_produces_all_four_artifacts(tmp_path):
    """THE ARTIFACTS EXIST BECAUSE THE ONE COMMAND WRITES THEM."""

    keywords = artifacts_in(tmp_path)

    state_graph, paths, records = graph_runner.run_pipeline(**keywords)

    for path in artifact_paths(keywords):
        assert path.exists(), path
        assert path.stat().st_size > 0, path

    artifact = graph_blocks(keywords)

    assert artifact["summary"]["resources"] == len(state_graph.nodes)
    assert artifact["summary"]["edges"] == len(state_graph.edges)
    assert len(artifact["nodes"]) == len(state_graph.nodes)

    mermaid = keywords["mermaid_path"].read_text(encoding="utf-8")
    dot = keywords["dot_path"].read_text(encoding="utf-8")

    assert mermaid.split("\n")[0] == "flowchart LR"
    assert dot.split("\n")[0].startswith("digraph ")

    # the renders depict the graph that was written beside them
    for node in artifact["nodes"]:
        assert node["id"] in mermaid
        assert node["id"] in dot

    # and they emphasise the paths the export ranked
    for record, path in zip(records, paths):
        assert record["source_id"] in mermaid
        assert record["source_id"] in dot
        assert path["hops"][0] in mermaid


def test_the_default_artifacts_land_in_output(tmp_path):
    """The constants, not a run: the shipped output/attack_paths.json is the file"""

    assert graph_runner.OUTPUT_PATH.name == "attack_paths.json"
    assert graph_runner.OUTPUT_PATH.parent.name == "output"
    assert graph_runner.OUTPUT_PATH.is_absolute()

    assert graph_runner.INFRA_PATH == (
        graph_runner.BASE_DIR / "data" / "normalized_resources.json"
    )
    assert graph_runner.RULES_PATH == (
        graph_runner.BASE_DIR / "data" / "security_rules.yaml"
    )

    assert graph_runner.MERMAID_PATH == MERMAID_PATH
    assert graph_runner.DOT_PATH == DOT_PATH

    for path in list(GRAPH_FILES.values()) + [
        graph_runner.MERMAID_PATH,
        graph_runner.DOT_PATH
    ]:
        assert path.parent == graph_runner.BASE_DIR / "output"
        assert path.is_absolute()

    # The infrastructure model is the one artifact that does NOT live in output/:
    # main.py has always written it to data/, and moving it would break anyone
    # reading it there.
    assert graph_runner.INFRA_OUTPUT_PATH == (
        graph_runner.BASE_DIR / "data" / "infra_output.json"
    )

    # every artifact a distinct file: 4 graph blocks + export + 2 renders + model
    assert len(
        set(GRAPH_FILES.values())
        | {
            graph_runner.OUTPUT_PATH,
            graph_runner.MERMAID_PATH,
            graph_runner.DOT_PATH,
            graph_runner.INFRA_OUTPUT_PATH
        }
    ) == len(GRAPH_FILES) + 4


GOLDEN_DIR = Path(__file__).resolve().parent


def test_the_artifacts_without_their_own_golden_test_match_their_golden_files(tmp_path):
    """The attack graph and the per-step export, byte for byte. The export and
    the state graph blocks are pinned in test_exporter.py and test_state_graph.py;
    output/ itself is not tracked, so these goldens are what review sees."""

    keywords = artifacts_in(tmp_path)
    graph_runner.run_pipeline(**keywords)

    produced = dict(keywords["attack_graph_files"])
    produced["steps"] = keywords["steps_path"]

    for name, path in produced.items():
        golden = GOLDEN_DIR / ("golden_" + path.name)
        assert path.read_text(encoding="utf-8") == golden.read_text(encoding="utf-8"), (
            "%s changed: read the diff, then copy it over %s" % (path.name, golden.name)
        )


def test_two_runs_produce_the_same_bytes(tmp_path):
    """Determinism, end to end, for every artifact the runner writes. The ranking"""

    first = artifacts_in(tmp_path / "first")
    second = artifacts_in(tmp_path / "second")

    graph_runner.run_pipeline(**first)
    graph_runner.run_pipeline(**second)

    for one, two in zip(artifact_paths(first), artifact_paths(second)):

        assert one.read_text(encoding="utf-8") == two.read_text(
            encoding="utf-8"
        ), one.name


# -----------------------------

def test_the_pipeline_finds_a_path_in_a_second_independent_account(tmp_path):
    """THE GENERALITY CLAIM, AND WHY IT NEEDED ITS OWN DATASET."""

    state_graph, paths, records = run(
        tmp_path,
        infra_path=SECOND_ACCOUNT
    )

    assert len(state_graph.nodes) == 6
    assert state_graph.orphan_findings == []

    assert paths

    hops = [tuple(path["hops"]) for path in paths]

    assert (
        "AppSecurityGroup",
        "AppServer",
        "AppServerProfile",
        "AppServerRole",
        "ApiCredentials"
    ) in hops

    # the secret is a target with no finding of its own
    assert state_graph.states_of("ApiCredentials") == []

    # the bucket is in the account, is a data resource, and is not reachable:
    # "secretsmanager:*" is not a grant on S3
    assert "PrivateBackupBucket" in state_graph.nodes

    assert [
        path
        for path in paths
        if path["target_id"] == "PrivateBackupBucket"
    ] == []

    # The bands are not the shipped account's, which is the whole point of this
    # dataset: nothing here reaches CRITICAL.
    #
    # Which band the routes DO land in is not asserted. It is a function of the
    # score thresholds, and those have been re-anchored three times as the
    # severity model changed — see the note on CRITICAL_SCORE_THRESHOLD. Pinning
    # a specific band here would be pinning the constants, and the claim worth
    # making is the relative one: this account is less bad than the shipped one,
    # and the records come out worst first.
    bands = [record["attack_level"] for record in records]

    assert ATTACK_LEVEL_CRITICAL not in bands

    order = [ATTACK_LEVEL_CRITICAL, ATTACK_LEVEL_HIGH, ATTACK_LEVEL_MEDIUM]

    assert bands == sorted(bands, key=order.index)

    # And the routes really are ordered worst first, which the band list alone
    # cannot show once they all land in the same band. The exported record
    # carries only the seven-key contract, so the scores come from the paths.
    assert [path["score"] for path in paths] == sorted(
        (path["score"] for path in paths),
        reverse=True
    )

    for record in records:
        assert sorted(record.keys()) == sorted(CONSUMER_KEYS)


def test_the_shipped_path_depends_on_the_instance_profile_reference(tmp_path):
    """WHAT THE DEMONSTRATION RESTS ON, WRITTEN DOWN."""

    with open(graph_runner.INFRA_PATH, "r", encoding="utf-8") as f:
        resources = json.load(f)

    for resource in resources:

        if resource["id"] == "PublicEC2Instance":
            del resource["raw_properties"]["IamInstanceProfile"]
            del resource["semantic_properties"]["IamInstanceProfile"]

    without_profile = tmp_path / "without_the_profile.json"

    with open(without_profile, "w", encoding="utf-8") as f:
        json.dump(resources, f, indent=2)

    state_graph, paths, records = run(
        tmp_path / "collapsed",
        infra_path=without_profile
    )

    # everything upstream of the path search still works ...
    assert len(state_graph.nodes) == len(resources)
    assert graph_runner.count_findings(state_graph) >= MINIMUM_FINDINGS

    # ... and the search has nothing to find
    assert "OverPermissiveInstanceProfile" not in state_graph.traversal_adjacency()[
        "PublicEC2Instance"
    ]

    # The App chain reaches the same data without going through this reference,
    # so the account is not path-free. What the reference is load-bearing for is
    # the original OverPermissive chain: no path may enter through
    # PublicEC2Instance any more.
    # A denial-of-service route still reaches the instance, because that needs no
    # escalation and the instance is itself a DoS target. What the reference was
    # load-bearing for is everything past it: with the profile gone, no route
    # through this instance reaches an identity or any data.
    through_instance = [
        path
        for path in paths
        if "PublicEC2Instance" in path["hops"]
    ]

    assert through_instance

    for path in through_instance:
        assert path["objective"] == "denial_of_service"
        assert path["hops"][-1] == "PublicEC2Instance"

    assert [
        path
        for path in paths
        if "OverPermissiveInstanceProfile" in path["hops"]
    ] == []


# -----------------------------

def test_a_zero_path_run_does_not_overwrite_a_good_export(tmp_path):
    """THE FAILURE THAT LOOKED LIKE A SUCCESS."""

    empty_rules = tmp_path / "no_rules.yaml"
    empty_rules.write_text("[]\n", encoding="utf-8")

    keywords = artifacts_in(tmp_path)

    export = keywords["output_path"]

    # a good export, produced by a real run
    _, good_paths, good_records = graph_runner.run_pipeline(**keywords)

    assert good_paths
    before = export.read_text(encoding="utf-8")

    # the collapsed run, over the same four paths
    _, paths, records = graph_runner.run_pipeline(
        rules_path=empty_rules,
        **keywords
    )

    assert paths == []
    assert records == []

    assert export.read_text(encoding="utf-8") == before

    with open(export, "r", encoding="utf-8") as f:
        assert json.load(f) == good_records


def test_the_refusal_does_not_extend_to_the_graph_artifacts(tmp_path):
    """WHY ONLY THE EXPORT IS PROTECTED."""

    empty_rules = tmp_path / "no_rules.yaml"
    empty_rules.write_text("[]\n", encoding="utf-8")

    keywords = artifacts_in(tmp_path)

    _, good_paths, _ = graph_runner.run_pipeline(**keywords)

    assert good_paths

    export_before = keywords["output_path"].read_text(encoding="utf-8")

    _, paths, _ = graph_runner.run_pipeline(rules_path=empty_rules, **keywords)

    assert paths == []

    # the export is untouched ...
    assert keywords["output_path"].read_text(encoding="utf-8") == export_before

    # ... and the three descriptions were rewritten to say the account has no
    # findings, which is what the collapsed run actually saw
    artifact = graph_blocks(keywords)

    # Not zero: privilege escalation findings do not come from the rule engine
    # (security_state_graph.state_graph.privesc_findings), so emptying the ruleset removes every
    # rule finding and leaves those. What matters is that no rule finding
    # survived, which is what collapsed the paths.
    surviving = {
        finding["rule_id"]
        for node in artifact["nodes"]
        for finding in node["states"]
    }

    assert surviving
    assert all(rule_id.startswith("PRIVESC_") for rule_id in surviving)
    assert artifact["summary"]["resources"] > 0
    # Only the privesc findings remain on the nodes, for the reason above.
    assert all(
        all(
            finding["rule_id"].startswith("PRIVESC_")
            for finding in node["states"]
        )
        for node in artifact["nodes"]
    )

    for key in ["mermaid_path", "dot_path"]:

        text = keywords[key].read_text(encoding="utf-8")

        assert "none - no route survived" in text, key
        assert "AP-001" not in text, key




def test_only_high_risk_paths_reach_the_export(tmp_path):
    """Task 8: "Filter the scored paths to select only the high-risk ones above a
    defined threshold."

    The export is what the scenario generator reads, so the filter belongs there.
    attack_path_steps.json keeps every path, because that is the audit trail for
    what the search actually found.
    """

    from attack_path.scoring import ATTACK_LEVEL_MEDIUM

    _, paths, records = run(tmp_path)

    assert ATTACK_LEVEL_MEDIUM in [path["attack_level"] for path in paths]
    assert ATTACK_LEVEL_MEDIUM not in [record["attack_level"] for record in records]

    # and the threshold is a choice, not a constant
    _, all_paths, all_records = run(
        tmp_path / "everything",
        min_level=ATTACK_LEVEL_MEDIUM
    )

    assert len(all_records) == len(all_paths)
