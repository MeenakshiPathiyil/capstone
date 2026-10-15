"""The test set is the records the shipped adapter never trained on."""

import importlib.util
import json

import pytest

import data_split

from .conftest import DATASET, EVALUATION_DIR


TEST_INPUTS = EVALUATION_DIR / "test_inputs.jsonl"


@pytest.fixture
def split():
    return data_split.split(data_split.load_records(DATASET))


def ids(records):
    return {r["source_id"] for r in records}


def test_the_split_partitions_the_dataset(split):
    assert (len(split["train"]), len(split["val"]), len(split["test"])) == (54, 10, 17)
    assert ids(split["test"]) == set(data_split.HELD_OUT_SOURCE_IDS)
    assert ids(split["train"]).isdisjoint(ids(split["val"]))
    assert ids(split["test"]).isdisjoint(ids(split["train"]) | ids(split["val"]))


def test_the_split_is_deterministic(split):
    again = data_split.split(data_split.load_records(DATASET))
    assert [r["source_id"] for r in again["val"]] == [r["source_id"] for r in split["val"]]


@pytest.mark.skipif(importlib.util.find_spec("datasets") is None,
                    reason="needs the `datasets` package")
def test_the_held_out_ids_are_the_original_notebooks_split():
    """Recomputed the way the original Colab notebook split the data before
    training the shipped adapter."""
    from datasets import Dataset

    records = data_split.load_records(DATASET)
    kept = [r for r in records if r.get("output") and r.get("input")]
    held_out = Dataset.from_list([{"i": i} for i in range(len(kept))]).train_test_split(
        test_size=0.2, seed=42)["test"]["i"]

    assert {data_split.source_id(kept[i]) for i in held_out} == set(data_split.HELD_OUT_SOURCE_IDS)


def test_the_committed_test_inputs_are_the_held_out_records(split, tmp_path):
    expected = tmp_path / "test_inputs.jsonl"
    data_split.write_test_inputs(expected, split["test"])

    assert TEST_INPUTS.read_text(encoding="utf-8") == expected.read_text(encoding="utf-8")


def test_a_test_file_with_a_trained_on_record_is_refused(split, tmp_path):
    """The 10-record file evaluation used before was all training data."""
    stale = tmp_path / "test_inputs.jsonl"
    data_split.write_test_inputs(stale, split["test"][:3] + split["train"][:1])

    with pytest.raises(ValueError, match=split["train"][0]["source_id"]):
        data_split.read_test_inputs(stale)


def test_every_held_out_record_has_what_the_prompt_needs():
    for record in data_split.read_test_inputs(TEST_INPUTS):
        assert record["instruction"] and record["input"] and record["output"], record["source_id"]
        assert json.dumps(record)
