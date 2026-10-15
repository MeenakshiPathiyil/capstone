"""
data_split.py
-------------
THE single source of truth for splitting the dataset into train / validation /
test. Persisting the split here (and reading it everywhere) removes the old
train/eval mismatch where finetuning.py did its own random split while
make_test_inputs.py treated a different file's tail as "unseen" — so the
"unseen" test set was not guaranteed unseen.

How it works
------------
* The split is computed once, deterministically, from a single seed, keyed on
  each record's stable ``_meta.source_id``.
* The held-out **test** records are written to ``evaluation/test_inputs.jsonl``.
* finetuning.py trains on the **complement** of that file (train + val only);
  make_test_inputs.py creates it; evaluate.py reads it. Everyone shares one
  artifact, so train ∩ test is provably empty.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Optional


DEFAULT_TEST_INPUTS = "evaluation/test_inputs.jsonl"


def load_records(jsonl_path: str | Path) -> list[dict]:
    """Read a JSONL dataset, skipping blank / malformed lines."""
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def source_id(record: dict, idx: int) -> str:
    """Stable id for a record: its _meta.source_id, else a positional fallback."""
    sid = (record.get("_meta") or {}).get("source_id")
    return sid if sid else f"idx-{idx}"


def _annotate(records: list[dict]) -> list[dict]:
    """Attach the original index + canonical source_id to each record (copy)."""
    out = []
    for i, rec in enumerate(records):
        item = dict(rec)
        item["idx"] = i
        item["source_id"] = source_id(rec, i)
        out.append(item)
    return out


def compute_split(records: list[dict], test_size: int = 10,
                  val_frac: float = 0.15, seed: int = 42) -> dict:
    """
    Deterministically split annotated records into test / val / train.

    test_size : number of held-out test records (default 10).
    val_frac  : fraction of the *remaining* pool used for validation
                (always at least 1 record so eval_loss can be computed).
    Returns {"train": [...], "val": [...], "test": [...]} with records sorted by
    original index within each split.
    """
    annotated = _annotate(records)
    n = len(annotated)
    if test_size >= n:
        raise ValueError(f"test_size={test_size} >= dataset size {n}")

    order = list(range(n))
    random.Random(seed).shuffle(order)

    test_idx = order[:test_size]
    pool_idx = order[test_size:]
    val_count = max(1, round(val_frac * len(pool_idx)))
    val_count = min(val_count, len(pool_idx) - 1)  # keep at least 1 for train
    val_idx = pool_idx[:val_count]
    train_idx = pool_idx[val_count:]

    by_idx = {item["idx"]: item for item in annotated}
    pick = lambda idxs: [by_idx[i] for i in sorted(idxs)]
    return {"train": pick(train_idx), "val": pick(val_idx), "test": pick(test_idx)}


# ── Persisted test-set artifact ────────────────────────────────────────────────

# Fields we keep in test_inputs.jsonl. `output` is the reference completion (for
# eval comparison only — never fed to the model as input).
TEST_FIELDS = ("idx", "source_id", "instruction", "input", "output")


def write_test_inputs(path: str | Path, test_records: list[dict]) -> None:
    """Persist the held-out test records to a JSONL artifact."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in test_records:
            row = {k: rec.get(k, "") for k in TEST_FIELDS}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_test_inputs(path: str | Path) -> list[dict]:
    """Read the held-out test artifact."""
    return load_records(path)


def ids_of(records: list[dict]) -> set:
    """Set of canonical ids (idx, source_id) tuples for intersection checks."""
    out = set()
    for i, rec in enumerate(records):
        out.add((rec.get("idx", i), rec.get("source_id") or source_id(rec, i)))
    return out


def ensure_test_inputs(data_path: str | Path,
                       test_inputs_path: str | Path = DEFAULT_TEST_INPUTS,
                       test_size: int = 10, val_frac: float = 0.15,
                       seed: int = 42) -> dict:
    """
    Return the split for ``data_path``, creating ``test_inputs_path`` from the
    deterministic split if it does not exist yet. When it already exists, the
    test split is taken from the persisted artifact (source of truth) and the
    train/val pool is the complement, so all callers agree.
    """
    records = load_records(data_path)
    split = compute_split(records, test_size=test_size, val_frac=val_frac, seed=seed)

    test_path = Path(test_inputs_path)
    if not test_path.exists():
        write_test_inputs(test_path, split["test"])
        return split

    # Artifact exists. If it matches the seed-derived split exactly, use the
    # canonical split so train/val are identical regardless of who created the
    # file first (finetuning vs make_test_inputs).
    persisted_ids = {row.get("source_id") for row in read_test_inputs(test_path)}
    if persisted_ids == {r["source_id"] for r in split["test"]}:
        return split

    # A custom / hand-edited artifact: respect it and derive the complement.
    print(f"[i] {test_path} differs from the seed-derived split; using the persisted test set.")
    annotated = _annotate(records)
    pool = [r for r in annotated if r["source_id"] not in persisted_ids]
    test = [r for r in annotated if r["source_id"] in persisted_ids]
    order = list(range(len(pool)))
    random.Random(seed).shuffle(order)
    val_count = max(1, min(round(val_frac * len(pool)), len(pool) - 1))
    val_idx = set(order[:val_count])
    val = [pool[i] for i in sorted(val_idx)]
    train = [pool[i] for i in range(len(pool)) if i not in val_idx]
    return {"train": train, "val": val, "test": test}
