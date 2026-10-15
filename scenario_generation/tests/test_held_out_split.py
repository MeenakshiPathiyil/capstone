"""test_held_out_split.py"""

import json

import pytest

import data_split
import judge_eval

from .conftest import DATASET, DATASET_MISSING_REASON


pytestmark = pytest.mark.skipif(not DATASET.exists(), reason=DATASET_MISSING_REASON)


# ── The split itself ──────────────────────────────────────────────────────────

def test_seeded_split_is_disjoint():
    records = data_split.load_records(DATASET)
    split = data_split.compute_split(records, test_size=10, val_frac=0.15, seed=42)

    test_ids = data_split.ids_of(split["test"])
    pool_ids = data_split.ids_of(split["train"]) | data_split.ids_of(split["val"])

    assert len(split["test"]) == 10
    assert test_ids
    assert test_ids.isdisjoint(pool_ids)
    assert len(test_ids) + len(pool_ids) == len(records)


def test_split_is_deterministic():
    """Same seed, same held-out records — the evaluator depends on this."""
    records = data_split.load_records(DATASET)
    first = data_split.compute_split(records, test_size=10, seed=42)
    second = data_split.compute_split(records, test_size=10, seed=42)
    assert ([r["source_id"] for r in first["test"]]
            == [r["source_id"] for r in second["test"]])


# ── What judge_eval actually judges ───────────────────────────────────────────

def test_resolved_records_are_the_seeded_held_out_split(tmp_path):
    artifact = tmp_path / "test_inputs.jsonl"
    entries = judge_eval.resolve_test_records(DATASET, artifact, test_size=10, seed=42)

    expected = data_split.compute_split(
        data_split.load_records(DATASET), test_size=10, val_frac=0.15, seed=42)
    assert ([r["source_id"] for r in entries]
            == [r["source_id"] for r in expected["test"]])


def test_resolved_records_are_disjoint_from_the_training_split(tmp_path):
    artifact = tmp_path / "test_inputs.jsonl"
    entries = judge_eval.resolve_test_records(DATASET, artifact, test_size=10, seed=42)

    split = data_split.compute_split(
        data_split.load_records(DATASET), test_size=10, val_frac=0.15, seed=42)
    trained_on = {r["source_id"] for r in split["train"]} | {r["source_id"] for r in split["val"]}

    judged = {r["source_id"] for r in entries}
    assert judged
    assert judged.isdisjoint(trained_on)


def test_resolution_writes_the_shared_artifact(tmp_path):
    """The same file fine_tune.py excludes — one artifact, not two opinions."""
    artifact = tmp_path / "test_inputs.jsonl"
    entries = judge_eval.resolve_test_records(DATASET, artifact, test_size=10, seed=42)

    assert artifact.exists()
    persisted = [json.loads(line) for line in artifact.read_text().splitlines() if line.strip()]
    assert [r["source_id"] for r in persisted] == [r["source_id"] for r in entries]


def test_every_judged_record_has_what_the_prompt_needs(tmp_path):
    entries = judge_eval.resolve_test_records(
        DATASET, tmp_path / "test_inputs.jsonl", test_size=10, seed=42)
    for idx, entry in enumerate(entries, start=1):
        assert entry.get("instruction"), entry
        assert entry.get("input"), entry
        assert judge_eval.record_source_id(entry, idx) != f"entry_{idx:02d}"


def test_falls_back_to_the_persisted_artifact_when_the_dataset_is_absent(tmp_path):
    """training_data.jsonl is gitignored, so a Colab session may only carry"""
    artifact = tmp_path / "test_inputs.jsonl"
    expected = judge_eval.resolve_test_records(DATASET, artifact, test_size=10, seed=42)

    entries = judge_eval.resolve_test_records(tmp_path / "no_dataset.jsonl", artifact)
    assert [r["source_id"] for r in entries] == [r["source_id"] for r in expected]


def test_missing_dataset_and_missing_artifact_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        judge_eval.resolve_test_records(tmp_path / "nope.jsonl", tmp_path / "nope.jsonl")
