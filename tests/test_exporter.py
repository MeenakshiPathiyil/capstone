"""Tests for the export, which is the seam between this repository and the other one."""

import json
import re
from pathlib import Path

import pytest

from engine.attack_catalog import tactics as KILL_CHAIN_TACTICS
from attack_path.exporter import (
    DEFAULT_INDUSTRY,
    DEFAULT_SURFACE,
    EXPORT_KEYS,
    SURFACE_BY_TYPE,
    base_technique_id,
    build_export,
    export_attack_paths,
    export_record,
    path_surfaces,
    path_techniques,
    phase_rank,
    render_techniques,
    source_id_for,
    technique_index,
    write_export
)
from attack_path.path_finder import find_attack_paths
from security_state_graph.state_graph import SecurityStateGraph, build_state_graph


# -----------------------------

# Read off scenario_generation/prompt_generator.py's format_model_input(), which
# formats each of these keys of a record into the model's prompt.
THE_CONTRACT = {
    "source_id",
    "source_name",
    "industry",
    "attack_level",
    "techniques",
    "surfaces",
    "objective"
}

# The MITRE format the consumer's system instruction promises the model: "Use
# real MITRE ATT&CK technique IDs exactly as provided."
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# The full surface vocabulary of the training data, copied from
# scenario_generation/dataset_pipeline/parse_stix.py.
TRAINING_DATA_SURFACES = {
    "Internet-facing services / user endpoints",
    "Application runtime environment",
    "System configuration / registry / cron",
    "OS / IAM permission model",
    "Security tooling / logging infrastructure",
    "Credential stores / memory / network traffic",
    "Internal network / cloud metadata services",
    "Internal network / trust relationships",
    "File system / cloud storage / databases",
    "Outbound network / DNS / HTTP channels",
    "Data egress points / cloud APIs",
    "Production systems / backups / data integrity"
}

GOLDEN_FILE = Path(__file__).resolve().parent / "golden_attack_paths.json"

# The copy scenario generation reads, so its notebooks can ship it.
SCENARIO_INPUT = (
    Path(__file__).resolve().parent.parent
    / "scenario_generation" / "evaluation" / "inputs" / "attack_paths.json"
)


# -----------------------------

# A describe_path()-shaped path, written by hand so the technique ordering can be
# controlled: its rule ids are listed out of kill-chain order on purpose.
HAND_WRITTEN_PATH = {
    "entry_id": "HandGroup",
    "target_id": "HandBucket",
    "hops": ["HandGroup", "HandInstance", "HandRole", "HandBucket"],
    "length": 3,
    "attack_level": "CRITICAL",
    "rule_ids": ["LATE_RULE", "EARLY_RULE", "UNMAPPED_RULE"]
}

# The technique table those rule ids index into. Includes a technique with no
# place in the kill chain (T9999) and one shared by two rules (T1190).
HAND_WRITTEN_INDEX = {
    "LATE_RULE": [
        {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
        {"id": "T1530", "name": "Data from Cloud Storage"}
    ],
    "EARLY_RULE": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1078", "name": "Valid Accounts"}
    ],
    "UNMAPPED_RULE": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T9999", "name": "Technique From The Future"}
    ]
}


@pytest.fixture
def real_graph(real_resources_path, rules_path):
    """The shipped dataset, joined to the findings the shipped rules produce."""

    return build_state_graph(real_resources_path, rules_path)


@pytest.fixture
def real_records(real_graph, rules_path):
    """The shipped dataset exported, without writing anything to disk."""

    return build_export(
        real_graph,
        find_attack_paths(real_graph),
        technique_index(rules_path)
    )


@pytest.fixture
def sample_graph(sample_infra):
    """The hand-built infra as a graph with no findings on it."""

    return SecurityStateGraph(sample_infra, [])


# -----------------------------

def test_export_keys_are_exactly_the_keys_the_consumer_reads():
    """The one assertion this file exists for. A key the consumer reads and the
    export does not write is a KeyError in the other repository, so the two sets
    must match exactly.
    """

    assert set(EXPORT_KEYS) == THE_CONTRACT

    # No duplicates hiding inside the list form.
    assert len(EXPORT_KEYS) == len(THE_CONTRACT)


def test_every_record_carries_exactly_the_contract_keys(real_records):
    assert real_records, "the shipped dataset produced no paths to export"

    for record in real_records:
        assert set(record.keys()) == THE_CONTRACT


# -----------------------------

def test_every_exported_value_is_a_str(real_records):
    for record in real_records:
        for key, value in record.items():
            assert isinstance(value, str), f"{record['source_id']}.{key}"


def test_values_stay_strings_when_the_path_carries_none(sample_graph):
    """A path with no attack_level and no rule ids still exports six strings. The
    consumer formats each one straight into the prompt, so None must become an
    empty string rather than the text "None".
    """

    empty_path = {
        "hops": ["SampleBucket"],
        "attack_level": None,
        "rule_ids": None
    }

    record = export_record(sample_graph, empty_path, 1, {})

    for key, value in record.items():
        assert isinstance(value, str), key

    assert record["attack_level"] == ""
    assert record["techniques"] == ""


# -----------------------------

def test_techniques_are_deduped():
    techniques = path_techniques(HAND_WRITTEN_PATH, HAND_WRITTEN_INDEX)

    ids = [technique["id"] for technique in techniques]

    assert ids.count("T1190") == 1
    assert len(ids) == len(set(ids))


def test_techniques_are_in_kill_chain_order():
    """The rule ids in HAND_WRITTEN_PATH declare their techniques out of order on
    purpose: the first rule leads with lateral movement. The export sorts them
    into kill-chain order regardless.
    """

    techniques = path_techniques(HAND_WRITTEN_PATH, HAND_WRITTEN_INDEX)

    ranks = [phase_rank(technique["id"]) for technique in techniques]

    assert ranks == sorted(ranks)

    # And specifically: initial access first, not the lateral-movement technique
    # that the first rule in the list declared.
    assert techniques[0]["id"] == "T1190"


def test_an_unmapped_technique_trails_rather_than_leads():
    """An unknown id must not be promoted to the front of the kill chain, because
    it has no phase to stand in. It ranks after every known tactic instead.
    """

    techniques = path_techniques(HAND_WRITTEN_PATH, HAND_WRITTEN_INDEX)

    ids = [technique["id"] for technique in techniques]

    assert ids[-1] == "T9999"
    assert phase_rank("T9999") == len(KILL_CHAIN_TACTICS())


def test_sub_techniques_inherit_their_parents_phase():
    assert base_technique_id("T1078.004") == "T1078"
    assert base_technique_id("T1078") == "T1078"
    assert phase_rank("T1078.004") == phase_rank("T1078")


def test_exported_technique_ids_match_the_attack_format(real_records):
    """Each id in the rendered string is a real ATT&CK id: the consumer's system
    instruction tells the model to use the ids exactly as provided.
    """

    for record in real_records:

        assert record["techniques"], record["source_id"]

        for entry in record["techniques"].split(", "):

            technique_id = entry.split(" - ")[0]

            assert ATTACK_ID_PATTERN.match(technique_id), entry


def test_rendering_matches_the_training_data_shape():
    rendered = render_techniques([
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1078", "name": "Valid Accounts"}
    ])

    assert rendered == (
        "T1190 - Exploit Public-Facing Application, T1078 - Valid Accounts"
    )


def test_a_nameless_technique_renders_as_its_bare_id():
    """No dangling " - ", because the model imitates whatever it is shown."""

    assert render_techniques([{"id": "T1190", "name": ""}]) == "T1190"


def test_technique_index_reads_the_shipped_rules(rules_path):
    index = technique_index(rules_path)

    assert index, "no rules were indexed"

    # Phase 3 put attack_techniques on every rule; without them the export can
    # name no techniques at all, which is the whole point of the seam.
    for rule_id, techniques in index.items():
        assert techniques, f"{rule_id} declares no attack_techniques"

        for technique in techniques:
            assert ATTACK_ID_PATTERN.match(technique["id"]), rule_id
            assert technique["name"]


def test_a_rule_with_no_techniques_indexes_to_an_empty_list(tmp_path):
    """Absent rather than empty would make every caller branch on two different
    shapes of "no techniques".
    """

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- id: NO_TECHNIQUES\n"
        "  resource_type: AWS::S3::Bucket\n"
        "  severity: low\n",
        encoding="utf-8"
    )

    index = technique_index(rules_file)

    # Empty, not absent — every caller can subscript without branching.
    assert index["NO_TECHNIQUES"] == []

    # The index also carries the privilege escalation catalogue, whose entries
    # are keyed by method id rather than rule id, so it is not only this rule.
    assert "PRIVESC_ATTACH_ROLE_POLICY" in index


# -----------------------------

def test_surfaces_follow_the_hops_and_are_deduped(sample_graph):
    surfaces = path_surfaces(sample_graph, HAND_WRITTEN_PATH)

    # HandGroup / HandInstance / HandRole / HandBucket are not in sample_graph,
    # so every hop degrades to the default — and the four collapse to one.
    assert surfaces == [DEFAULT_SURFACE]

    real_hops = {
        "hops": [
            "SampleSecurityGroup",
            "SampleEC2Instance",
            "SampleRole",
            "SampleBucket"
        ]
    }

    assert path_surfaces(sample_graph, real_hops) == [
        SURFACE_BY_TYPE["AWS::EC2::SecurityGroup"],
        SURFACE_BY_TYPE["AWS::EC2::Instance"],
        SURFACE_BY_TYPE["AWS::IAM::Role"],
        SURFACE_BY_TYPE["AWS::S3::Bucket"]
    ]


def test_the_target_surface_is_never_dropped(real_records, real_graph):
    """Surfaces are never truncated, so the last hop, the data the attacker
    came for, always appears in the exported surfaces.
    """

    for record, path in zip(
        real_records,
        find_attack_paths(real_graph)
    ):

        target_type = real_graph.node(path["target_id"])["type"]

        assert SURFACE_BY_TYPE[target_type] in record["surfaces"]


def test_surfaces_use_the_training_data_vocabulary():
    """Every phrase this module can emit is one of the twelve the training data was
    written with, so the model is never shown a surface it was not trained on.
    """

    for surface in list(SURFACE_BY_TYPE.values()) + [DEFAULT_SURFACE]:
        assert surface in TRAINING_DATA_SURFACES, surface


# -----------------------------

def test_source_ids_are_rank_ordered_and_zero_padded(real_records):
    assert [record["source_id"] for record in real_records] == [
        source_id_for(rank)
        for rank in range(1, len(real_records) + 1)
    ]

    assert real_records[0]["source_id"] == "AP-001"

    # Zero padding, so a lexical sort of the ids is also a rank sort.
    assert source_id_for(10) == "AP-010"
    assert sorted([source_id_for(2), source_id_for(10)]) == ["AP-002", "AP-010"]


def test_source_name_is_the_hop_chain(real_records, real_graph):
    for record, path in zip(real_records, find_attack_paths(real_graph)):
        assert record["source_name"] == " -> ".join(path["hops"])


def test_industry_defaults_and_can_be_overridden(real_graph, rules_path):
    records = build_export(
        real_graph,
        find_attack_paths(real_graph),
        technique_index(rules_path)
    )

    assert all(
        record["industry"] == DEFAULT_INDUSTRY
        for record in records
    )

    overridden = build_export(
        real_graph,
        find_attack_paths(real_graph),
        technique_index(rules_path),
        "Education (ISIC P)"
    )

    assert all(
        record["industry"] == "Education (ISIC P)"
        for record in overridden
    )


# -----------------------------

def test_an_empty_path_list_still_writes_valid_json(tmp_path):
    """"No attack paths" is an answer the consumer loops over zero times. A missing
    file is not, so an empty export is still written as valid JSON.
    """

    target = tmp_path / "attack_paths.json"

    write_export([], target)

    text = target.read_text(encoding="utf-8")

    assert text.strip() == "[]"
    assert json.loads(text) == []


def test_write_export_creates_its_directory_and_overwrites(tmp_path):
    target = tmp_path / "output" / "attack_paths.json"

    write_export([{"source_id": "AP-001"}], target)
    write_export([], target)

    assert json.loads(target.read_text(encoding="utf-8")) == []


def test_the_export_is_deterministic(tmp_path):
    """Two runs over the same dataset produce the same bytes; otherwise the golden
    file comparison below would fail for no reason.
    """

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    export_attack_paths(output_path=first)
    export_attack_paths(output_path=second)

    assert (
        first.read_text(encoding="utf-8")
        == second.read_text(encoding="utf-8")
    )


# -----------------------------

def test_the_full_export_matches_the_golden_file(tmp_path):
    """The whole file, byte for byte. Every other test here asserts one property;
    this one catches any change none of them anticipated.
    """

    produced = tmp_path / "attack_paths.json"

    export_attack_paths(output_path=produced)

    assert produced.read_text(encoding="utf-8") == GOLDEN_FILE.read_text(
        encoding="utf-8"
    ), (
        "the export changed — read the diff, then regenerate the golden file "
        "(see 'If you break something' in DEVELOPERS.md)"
    )


def test_scenario_generation_reads_the_current_export():
    """Its copy has to move with the golden file, or the scenarios are written
    for attack paths the graph no longer produces."""

    assert SCENARIO_INPUT.read_bytes() == GOLDEN_FILE.read_bytes(), (
        "copy tests/golden_attack_paths.json to %s" % SCENARIO_INPUT
    )
