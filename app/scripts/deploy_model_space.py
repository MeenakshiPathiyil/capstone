"""Create or update the private ZeroGPU model Space.

Steps, in order:
  1. Check the pinned revisions locally (full commit SHAs, known recipe).
  2. Confirm read-only that both revisions exist and the adapter repo is private.
  3. Create the Space private if it does not exist; refuse a public one.
  4. Set the non-secret variables BASE_REVISION, ADAPTER_REPO,
     ADAPTER_REVISION and LOADING_RECIPE, before the upload so the build that
     the upload triggers starts with them.
  5. Upload app/model_space/ plus app/api/scenario_contract.py, the only copy
     of the contract the Space gets.
  6. Report the runtime stage and hardware, optionally waiting for it to settle.

The HF_TOKEN secret is never set here: add it yourself in the Space settings.
ZeroGPU hardware is also chosen there.

    python -m app.scripts.deploy_model_space --space-id OWNER/NAME \\
        --adapter-repo OWNER/ADAPTER --base-revision SHA --adapter-revision SHA --dry-run

Authentication comes from HF_TOKEN or `hf auth login`.
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
import time
from pathlib import Path

from app.api import scenario_contract as contract
from app.scripts._common import CONTRACT_FILE, MODEL_SPACE_DIR, ScriptError, hf_api, run


SPACE_FILES = ("app.py", "model_runtime.py", "requirements.txt", "README.md")
ZERO_GPU = "zero-a10g"
SETTLED_STAGES = {"RUNNING", "BUILD_ERROR", "RUNTIME_ERROR", "CONFIG_ERROR", "PAUSED", "STOPPED", "NO_APP_FILE"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.deploy_model_space",
        description="Create or update the private model Space with pinned base and adapter revisions.")
    parser.add_argument("--space-id", required=True, help="destination Space, OWNER/NAME")
    parser.add_argument("--adapter-repo", required=True, help="private adapter model repo, OWNER/NAME")
    parser.add_argument("--base-revision", required=True,
                        help=f"full commit SHA of {contract.BASE_MODEL_ID} to load")
    parser.add_argument("--adapter-revision", required=True,
                        help="full commit SHA of the adapter repo (printed by upload_adapter)")
    parser.add_argument("--loading-recipe", default=contract.NF4_UNMERGED, choices=sorted(contract.LOADING_RECIPES),
                        help=f"default: {contract.NF4_UNMERGED}, the evaluated recipe")
    parser.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                        help="poll the runtime until it settles or this many seconds pass (default: report once)")
    parser.add_argument("--dry-run", action="store_true", help="check and list what would change, contact nothing")
    return parser


def space_variables(args) -> dict[str, str]:
    """The Space variables, after the contract has validated them."""
    contract.make_provenance(
        model_revision=args.base_revision,
        adapter_repo=args.adapter_repo,
        adapter_revision=args.adapter_revision,
        loading_recipe=args.loading_recipe,
    )
    return {
        "BASE_REVISION": args.base_revision,
        "ADAPTER_REPO": args.adapter_repo,
        "ADAPTER_REVISION": args.adapter_revision,
        "LOADING_RECIPE": args.loading_recipe,
    }


def stage_files(destination: Path) -> list[str]:
    """Copy the allowlisted Space files and the contract into destination."""
    for name in SPACE_FILES:
        source = MODEL_SPACE_DIR / name
        if not source.is_file():
            raise ScriptError(f"missing {source}")
        shutil.copy2(source, destination / name)
    shutil.copy2(CONTRACT_FILE, destination / CONTRACT_FILE.name)
    return sorted(path.name for path in destination.iterdir())


def check_revisions(api, args) -> None:
    """Read-only: both pinned revisions exist and the adapter repo is private."""
    from huggingface_hub.errors import HfHubHTTPError

    for repo_id, revision in ((contract.BASE_MODEL_ID, args.base_revision),
                              (args.adapter_repo, args.adapter_revision)):
        try:
            info = api.model_info(repo_id, revision=revision)
        except HfHubHTTPError as exc:
            raise ScriptError(f"cannot read {repo_id} at {revision}: {type(exc).__name__}") from exc
        if info.sha != revision:
            raise ScriptError(f"{repo_id} resolved {revision} to {info.sha}; pass the full commit SHA")
        if repo_id == args.adapter_repo and not info.private:
            raise ScriptError(f"adapter repo {repo_id} is public; it must be private")


def ensure_private_space(api, space_id: str) -> None:
    api.create_repo(space_id, repo_type="space", space_sdk="gradio", private=True, exist_ok=True)
    if not api.space_info(space_id).private:
        raise ScriptError(f"Space {space_id} exists and is public; refusing to deploy to it")


def _plain(value) -> str | None:
    """An enum member's value (SpaceStage, SpaceHardware) or the string itself."""
    return None if value is None else str(getattr(value, "value", value))


def report_runtime(api, space_id: str, wait: int) -> str:
    """Print the runtime stage (polling up to wait seconds) and return it."""
    deadline = time.monotonic() + max(wait, 0)
    while True:
        runtime = api.get_space_runtime(space_id)
        stage = _plain(runtime.stage)
        hardware, requested = _plain(runtime.hardware), _plain(runtime.requested_hardware)
        print(f"Runtime: stage={stage} hardware={hardware} requested={requested}")
        if stage in SETTLED_STAGES or time.monotonic() >= deadline:
            break
        time.sleep(min(15, max(deadline - time.monotonic(), 1)))
    if ZERO_GPU not in {hardware, requested}:
        print("Hardware is not ZeroGPU yet: select it in the Space settings (Settings -> Hardware).")
    return stage


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not contract.is_repo_id(args.space_id):
        raise ScriptError(f"--space-id must be OWNER/NAME, got {args.space_id!r}")
    try:
        variables = space_variables(args)
    except contract.ScenarioContractError as exc:
        raise ScriptError(str(exc)) from exc

    with tempfile.TemporaryDirectory(prefix="model_space_") as tmp:
        staged = stage_files(Path(tmp))
        print(f"Space {args.space_id} (private), files: {', '.join(staged)}")
        for key, value in variables.items():
            print(f"  variable {key}={value}")
        if args.dry_run:
            print("Dry run: nothing contacted or changed.")
            return 0

        api = hf_api()
        check_revisions(api, args)
        ensure_private_space(api, args.space_id)
        for key, value in variables.items():
            api.add_space_variable(args.space_id, key, value)
        commit = api.upload_folder(
            repo_id=args.space_id,
            repo_type="space",
            folder_path=tmp,
            commit_message="Deploy scenario model Space",
            delete_patterns=["*.py", "*.txt"],
        )
        print(f"Space commit: {commit.oid}")

    print("Reminder: add the HF_TOKEN secret yourself in the Space settings "
          "(Settings -> Variables and secrets). It only needs read access to the private adapter repo; "
          "the base model is not gated.")
    report_runtime(api, args.space_id, args.wait)
    return 0


if __name__ == "__main__":
    run(main)
