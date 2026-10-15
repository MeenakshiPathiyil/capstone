"""
Create the held-out, unseen test set used for evaluation.

This writes evaluation/test_inputs.jsonl — the SINGLE split artifact shared by
finetuning.py (which trains on the complement) and evaluate.py (which scores the
held-out set). The split is deterministic (seeded) and keyed on each record's
stable _meta.source_id, so "unseen" is guaranteed unseen.

Previously this script read a non-existent dataset/inputs/training_inputs.jsonl
and keyed on a top-level source_id the dataset didn't have. It now reads the real
dataset and uses the shared fine_tuning/data_split module.

Usage (run from scenario_generation/):
    python evaluation/make_test_inputs.py
    python evaluation/make_test_inputs.py --data dataset/training_data.jsonl \
        --out evaluation/test_inputs.jsonl --test_size 10 --seed 42
"""

import argparse
import sys
from pathlib import Path

# Import the shared split module from fine_tuning/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fine_tuning"))
import data_split  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create the deterministic held-out test set")
    parser.add_argument("--data", default="dataset/training_data.jsonl",
                        help="Path to the full dataset JSONL")
    parser.add_argument("--out", default=data_split.DEFAULT_TEST_INPUTS,
                        help="Output path for the held-out test set")
    parser.add_argument("--test_size", type=int, default=10,
                        help="Number of unseen entries to hold out (default: 10)")
    parser.add_argument("--val_frac", type=float, default=0.15,
                        help="Validation fraction of the train pool (for reporting)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducible splitting")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite an existing test_inputs.jsonl")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    data_path = Path(args.data)
    out_path = Path(args.out)

    if not data_path.exists():
        print(f"[!] Dataset not found: {data_path}")
        sys.exit(1)

    if out_path.exists() and not args.force:
        existing = data_split.read_test_inputs(out_path)
        print(f"[i] {out_path} already exists with {len(existing)} entries "
              "(use --force to regenerate).")
        sys.exit(0)

    records = data_split.load_records(data_path)
    print(f"[+] Loaded {len(records)} records from {data_path}")

    split = data_split.compute_split(
        records, test_size=args.test_size, val_frac=args.val_frac, seed=args.seed)
    data_split.write_test_inputs(out_path, split["test"])

    # Safety: the held-out set must not overlap the train/val pool.
    test_ids = data_split.ids_of(split["test"])
    pool_ids = data_split.ids_of(split["train"]) | data_split.ids_of(split["val"])
    assert test_ids.isdisjoint(pool_ids), "Held-out test set overlaps the train pool!"

    print(f"[✓] Wrote {len(split['test'])} unseen entries to: {out_path}")
    print(f"    Train {len(split['train'])} / Val {len(split['val'])} / "
          f"Test {len(split['test'])} (seed={args.seed})")
    print(f"    Held-out source_ids: {', '.join(r['source_id'] for r in split['test'])}")


if __name__ == "__main__":
    main()
