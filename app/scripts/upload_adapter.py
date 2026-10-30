"""Upload the LoRA adapter to a private Hugging Face model repo.

Only allowlisted files leave the adapter folder: the adapter config and
weights, the model card and the tokenizer files when present. Training
checkpoints, generated outputs and the chat template stay local (the adapter
is never prompted through a chat template; see fine_tuning/prompt_format.py).

The repo is created private if it does not exist; an existing public repo is
refused. The printed commit SHA is the ADAPTER_REVISION the Space must pin.

    python -m app.scripts.upload_adapter --repo-id OWNER/NAME --dry-run
    python -m app.scripts.upload_adapter --repo-id OWNER/NAME

Authentication comes from HF_TOKEN or `hf auth login`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.api import scenario_contract as contract
from app.scripts._common import REPO_ROOT, ScriptError, hf_api, run, sha256_file


DEFAULT_ADAPTER_DIR = REPO_ROOT / "scenario_generation" / "fine_tuning" / "output"
REQUIRED_FILES = ("adapter_config.json", "adapter_model.safetensors")
OPTIONAL_FILES = (
    "README.md",
    "tokenizer.json",
    "tokenizer.model",
    "tokenizer_config.json",
    "special_tokens_map.json",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.upload_adapter",
        description="Upload the allowlisted LoRA adapter files to a private model repo and print the commit SHA.")
    parser.add_argument("--repo-id", required=True, help="destination model repo, OWNER/NAME")
    parser.add_argument("--adapter-dir", type=Path, default=DEFAULT_ADAPTER_DIR,
                        help=f"local adapter folder (default: {DEFAULT_ADAPTER_DIR.relative_to(REPO_ROOT)})")
    parser.add_argument("--dry-run", action="store_true", help="check and list the files, upload nothing")
    return parser


def collect_files(adapter_dir: Path) -> list[Path]:
    """The allowlisted files present in adapter_dir; the required ones must be."""
    if not adapter_dir.is_dir():
        raise ScriptError(f"adapter folder not found: {adapter_dir}")
    missing = [name for name in REQUIRED_FILES if not (adapter_dir / name).is_file()]
    if missing:
        raise ScriptError(f"{adapter_dir} is missing {', '.join(missing)}")
    names = list(REQUIRED_FILES) + [name for name in OPTIONAL_FILES if (adapter_dir / name).is_file()]
    return [adapter_dir / name for name in names]


def check_adapter_config(adapter_dir: Path) -> dict:
    """The adapter config, if it is a LoRA adapter for the evaluated base model."""
    try:
        config = json.loads((adapter_dir / "adapter_config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScriptError(f"cannot read adapter_config.json: {exc}") from exc
    if config.get("base_model_name_or_path") != contract.BASE_MODEL_ID:
        raise ScriptError(
            f"adapter base model is {config.get('base_model_name_or_path')!r}, expected {contract.BASE_MODEL_ID}")
    if config.get("peft_type") != "LORA":
        raise ScriptError(f"adapter peft_type is {config.get('peft_type')!r}, expected LORA")
    return config


def upload(api, repo_id: str, files: list[Path]) -> str:
    """Create or reuse the private repo, commit the files and return the commit SHA."""
    from huggingface_hub import CommitOperationAdd

    api.create_repo(repo_id, repo_type="model", private=True, exist_ok=True)
    info = api.model_info(repo_id)
    if not info.private:
        raise ScriptError(f"{repo_id} exists and is public; refusing to upload the adapter there")
    commit = api.create_commit(
        repo_id,
        operations=[CommitOperationAdd(path_in_repo=path.name, path_or_fileobj=str(path)) for path in files],
        commit_message="Upload LoRA adapter",
        repo_type="model",
    )
    return commit.oid


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not contract.is_repo_id(args.repo_id):
        raise ScriptError(f"--repo-id must be OWNER/NAME, got {args.repo_id!r}")

    files = collect_files(args.adapter_dir)
    config = check_adapter_config(args.adapter_dir)
    print(f"Adapter: LoRA r={config.get('r')} alpha={config.get('lora_alpha')} "
          f"targets={sorted(config.get('target_modules') or [])} peft={config.get('peft_version')}")
    print(f"Files for {args.repo_id} (private):")
    for path in files:
        print(f"  {path.name:28} {path.stat().st_size:>12,} bytes  sha256 {sha256_file(path)}")
    if args.dry_run:
        print("Dry run: nothing uploaded.")
        return 0

    sha = upload(hf_api(), args.repo_id, files)
    print(f"Commit SHA: {sha}")
    print(f"Pin it in the Space with: --adapter-repo {args.repo_id} --adapter-revision {sha}")
    return 0


if __name__ == "__main__":
    run(main)
