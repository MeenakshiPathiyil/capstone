"""The train / validation / test split, shared by training and evaluation.

The test set is the 17 records the shipped adapter never trained on. The
original Colab notebook split the 81 records of dataset/training_data.jsonl with
`datasets` train_test_split(test_size=0.2, seed=42) and trained on the other 64.
Their ids are frozen here rather than recomputed, so the split cannot move out
from under the adapter; tests/test_held_out_split.py recomputes them with
`datasets` when it is installed.

Validation is carved from the other 64, for a retrain's eval loss and early
stopping, so model selection never looks at the test set.

The test records are also written to evaluation/test_inputs.jsonl, which is
committed and shipped to the Colab notebooks.
"""

from __future__ import annotations

import json
import random
from pathlib import Path


DEFAULT_TEST_INPUTS = "evaluation/test_inputs.jsonl"

HELD_OUT_SOURCE_IDS = (
    "C0011", "C0013", "C0015", "C0017", "C0023", "C0027", "C0037", "C0043",
    "C0046", "C0049", "C0051", "C0055", "G0010", "G0020", "G0049", "G0119",
    "G1047",
)

# The fields kept in test_inputs.jsonl. `output` is the reference answer, used
# only for comparison and never shown to the model.
TEST_FIELDS = ("idx", "source_id", "instruction", "input", "output")


def load_records(jsonl_path: str | Path) -> list[dict]:
    """Every record of a JSONL file, skipping blank lines."""
    with open(jsonl_path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def source_id(record: dict) -> str:
    """The record's stable id."""
    return record["_meta"]["source_id"]


def split(records: list[dict], val_frac: float = 0.15, seed: int = 42) -> dict:
    """{"train", "val", "test"}, each a list of records with `idx` and `source_id` added."""
    annotated = [dict(record, idx=i, source_id=source_id(record))
                 for i, record in enumerate(records)]

    test = [r for r in annotated if r["source_id"] in HELD_OUT_SOURCE_IDS]
    missing = set(HELD_OUT_SOURCE_IDS) - {r["source_id"] for r in test}
    if missing:
        raise ValueError(f"held-out records missing from the dataset: {sorted(missing)}")

    pool = [r for r in annotated if r["source_id"] not in HELD_OUT_SOURCE_IDS]
    order = list(range(len(pool)))
    random.Random(seed).shuffle(order)
    val_idx = set(order[:max(1, round(val_frac * len(pool)))])

    return {
        "train": [r for i, r in enumerate(pool) if i not in val_idx],
        "val": [r for i, r in enumerate(pool) if i in val_idx],
        "test": test,
    }


def write_test_inputs(path: str | Path, test_records: list[dict]) -> None:
    """Write the held-out records as JSONL."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in test_records:
            f.write(json.dumps({k: record[k] for k in TEST_FIELDS}, ensure_ascii=False) + "\n")


def read_test_inputs(path: str | Path) -> list[dict]:
    """The held-out records written by write_test_inputs.

    Raises if the file holds a record the adapter was trained on, so a stale or
    hand-made test file cannot pass training data off as unseen.
    """
    records = load_records(path)
    trained_on = [r["source_id"] for r in records if r["source_id"] not in HELD_OUT_SOURCE_IDS]
    if trained_on:
        raise ValueError(f"{path} holds records the adapter was trained on: {trained_on}. "
                         "Regenerate it with: python evaluation/make_test_inputs.py")
    return records
