"""Export a saved analysis's selected paths as a pre-generation bundle.

Reads app/.cache/analyses/<uuid>/analysis.json and writes a folder to upload
to Kaggle as a dataset:

    bundle.json           analysis provenance, the prompt format and its
                          version, optional pinned model provenance, and per
                          path: source_id, the seven-key record and the exact
                          prompt
    scenario_contract.py  copied from app/api       the notebook runs this
    model_runtime.py      copied from app/model_space exact code, checked
    requirements.txt      copied from app/model_space against the hashes in
                                                      bundle.json

Pinning the model revisions is optional here; without them the notebook
asks for them. No Hugging Face access is needed.

    python -m app.scripts.export_records --analysis-id UUID --out bundle_dir \\
        [--prompt-format training]
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from app.api import scenario_contract as contract
from app.scripts._common import (
    CONTRACT_FILE,
    DEFAULT_CACHE_DIR,
    MODEL_SPACE_DIR,
    ScriptError,
    exported_records,
    load_analysis,
    run,
    sha256_file,
)


BUNDLE_VERSION = 1
BUNDLE_FILE = "bundle.json"
ANALYSIS_FIELDS = (
    "id", "created_at", "input_name", "input_sha256", "industry", "min_level",
    "schema_version", "analyser_commit",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.export_records",
        description="Write the selected seven-key records of a saved analysis, with prompts and "
                    "provenance, to a bundle folder for pregenerate_kaggle.ipynb.")
    parser.add_argument("--analysis-id", required=True, help="saved analysis UUID")
    parser.add_argument("--out", type=Path, required=True, help="bundle folder to create")
    parser.add_argument("--paths", nargs="+", metavar="AP_ID",
                        help="only these selected paths, e.g. AP-001 AP-003 (default: all selected)")
    parser.add_argument("--prompt-format", choices=sorted(contract.PROMPT_VERSIONS),
                        default=contract.DEFAULT_PROMPT_FORMAT,
                        help="prompt format of the exported prompts; use the one the app's "
                             "SCENARIO_PROMPT_FORMAT will be set to (default: %(default)s)")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
                        help="app cache root (default: CAPSTONE_CACHE_DIR or app/.cache)")
    pins = parser.add_argument_group("model provenance (optional, all or none)")
    pins.add_argument("--base-revision", help=f"full commit SHA of {contract.BASE_MODEL_ID}")
    pins.add_argument("--adapter-repo", help="adapter model repo, OWNER/NAME")
    pins.add_argument("--adapter-revision", help="full commit SHA of the adapter repo")
    pins.add_argument("--loading-recipe", default=contract.NF4_UNMERGED, choices=sorted(contract.LOADING_RECIPES))
    parser.add_argument("--force", action="store_true", help="overwrite an existing bundle folder")
    return parser


def pinned_provenance(args) -> dict | None:
    given = [args.base_revision, args.adapter_repo, args.adapter_revision]
    if not any(given):
        return None
    if not all(given):
        raise ScriptError("pass --base-revision, --adapter-repo and --adapter-revision together, or none")
    try:
        return contract.make_provenance(
            model_revision=args.base_revision,
            adapter_repo=args.adapter_repo,
            adapter_revision=args.adapter_revision,
            loading_recipe=args.loading_recipe,
        )
    except contract.ScenarioContractError as exc:
        raise ScriptError(str(exc)) from exc


def build_bundle(
    analysis_id: str,
    analysis: dict,
    wanted: list[str] | None,
    provenance: dict | None,
    prompt_format: str = contract.DEFAULT_PROMPT_FORMAT,
) -> dict:
    prompt_version = contract.prompt_version_for(prompt_format)
    records = exported_records(analysis)
    if wanted:
        unknown = [source_id for source_id in wanted if source_id not in records]
        if unknown:
            raise ScriptError(f"not selected paths in this analysis: {', '.join(unknown)}")
        records = {source_id: records[source_id] for source_id in wanted}
    if not records:
        raise ScriptError("the analysis has no selected paths to export")

    items = []
    for source_id, record in records.items():
        try:
            prompt = contract.build_prompt(record, prompt_format)
        except contract.ScenarioContractError as exc:
            raise ScriptError(f"{source_id}: {exc}") from exc
        item = {"source_id": source_id, "record": record, "prompt": prompt}
        if provenance:
            item["cache_key"] = contract.cache_key(prompt, provenance, prompt_version)
        items.append(item)

    return {
        "bundle_version": BUNDLE_VERSION,
        "created_at": contract.utc_now(),
        "prompt_format": prompt_format,
        "prompt_version": prompt_version,
        "analysis_id": analysis_id,
        "analysis": {field: analysis.get(field) for field in ANALYSIS_FIELDS if field in analysis},
        "provenance": provenance,
        "items": items,
    }


def write_bundle(out: Path, bundle: dict, force: bool) -> None:
    if out.exists() and any(out.iterdir()) and not force:
        raise ScriptError(f"{out} exists and is not empty; pass --force to overwrite")
    out.mkdir(parents=True, exist_ok=True)
    copies = {
        CONTRACT_FILE.name: CONTRACT_FILE,
        "model_runtime.py": MODEL_SPACE_DIR / "model_runtime.py",
        "requirements.txt": MODEL_SPACE_DIR / "requirements.txt",
    }
    for name, source in copies.items():
        shutil.copy2(source, out / name)
    bundle["files"] = {name: sha256_file(out / name) for name in sorted(copies)}
    (out / BUNDLE_FILE).write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    provenance = pinned_provenance(args)
    analysis = load_analysis(args.cache_dir, args.analysis_id)
    if analysis is None:
        raise ScriptError(f"no saved analysis {args.analysis_id} under {args.cache_dir}")
    bundle = build_bundle(args.analysis_id, analysis, args.paths, provenance, args.prompt_format)
    write_bundle(args.out, bundle, args.force)
    print(f"Wrote {len(bundle['items'])} record(s) to {args.out / BUNDLE_FILE}: "
          f"{', '.join(item['source_id'] for item in bundle['items'])} "
          f"(prompt format {bundle['prompt_format']}, version {bundle['prompt_version']})")
    if provenance is None:
        print("Model revisions not pinned; the notebook will ask for them.")
    return 0


if __name__ == "__main__":
    run(main)
