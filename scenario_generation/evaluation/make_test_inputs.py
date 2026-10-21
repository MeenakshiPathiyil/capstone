"""
Write evaluation/test_inputs.jsonl, the held-out records evaluation scores.

They are the 17 records the shipped adapter never trained on; see
fine_tuning/data_split.py for where that split comes from. The file is
committed, so this only needs rerunning if the dataset changes.

Usage (run from scenario_generation/):
    python evaluation/make_test_inputs.py
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fine_tuning"))
import data_split  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the held-out test records")
    parser.add_argument("--data", default="dataset/training_data.jsonl",
                        help="The full dataset (default: %(default)s)")
    parser.add_argument("--out", default=data_split.DEFAULT_TEST_INPUTS,
                        help="Where to write the held-out records (default: %(default)s)")
    args = parser.parse_args()

    test = data_split.split(data_split.load_records(args.data))["test"]
    data_split.write_test_inputs(args.out, test)
    print(f"[OK] Wrote {len(test)} held-out records to {args.out}")


if __name__ == "__main__":
    main()
