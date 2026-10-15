"""Create an unseen 10-entry test set from training_inputs.jsonl."""

import argparse
import json
import random
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sample unseen test inputs for evaluation")
    parser.add_argument(
        "--inputs",
        default="dataset/inputs/training_inputs.jsonl",
        help="Path to training_inputs.jsonl",
    )
    parser.add_argument(
        "--out",
        default="evaluation/test_inputs.jsonl",
        help="Output path for sampled test set",
    )
    parser.add_argument(
        "--train_count",
        type=int,
        default=80,
        help="Number of initial entries used in training (default: 80)",
    )
    parser.add_argument(
        "--sample_size",
        type=int,
        default=10,
        help="Number of unseen entries to sample (default: 10)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible sampling",
    )
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict]:
    items = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def write_jsonl(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def main() -> None:
    args = parse_args()

    try:
        inputs_path = Path(args.inputs)
        out_path = Path(args.out)

        if not inputs_path.exists():
            print(f"[!] Input file not found: {inputs_path}")
            sys.exit(1)

        print(f"[+] Reading inputs from: {inputs_path}")
        all_entries = read_jsonl(inputs_path)
        print(f"[+] Total entries loaded: {len(all_entries)}")

        if args.train_count >= len(all_entries):
            print(
                "[!] train_count is too large. "
                f"Got train_count={args.train_count}, total={len(all_entries)}"
            )
            sys.exit(1)

        unseen_entries = all_entries[args.train_count :]
        if len(unseen_entries) < args.sample_size:
            print(
                "[!] Not enough unseen entries to sample. "
                f"Requested {args.sample_size}, available {len(unseen_entries)}"
            )
            sys.exit(1)

        random.seed(args.seed)
        sampled = random.sample(unseen_entries, args.sample_size)

        write_jsonl(out_path, sampled)
        print(f"[✓] Saved {len(sampled)} unseen entries to: {out_path}")

        source_ids = [item.get("source_id", "unknown") for item in sampled]
        print(f"[+] Sampled source_ids: {', '.join(source_ids)}")

    except KeyboardInterrupt:
        print("\n[!] Sampling interrupted by user")
        sys.exit(130)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in input file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to create test inputs: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
