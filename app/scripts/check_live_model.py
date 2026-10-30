"""Check the deployed model Space with real generations, in both prompt formats.

Neither prompt format has been evaluated through the app. This script spends a
few ZeroGPU calls to show how the adapter behaves on each, so the format can be
chosen from output instead of from reasoning:

    structured-p1   the app's default prompt (five facts lines, OBJECTIVE, PROMPT FOCUS)
    training        the exact text the adapter was trained on (five facts lines only)

It calls /metadata (no GPU) and stops if the Space does not carry the pinned
revisions given here. Then, for each sample path (default AP-001 and AP-019 of
scenario_generation/evaluation/inputs/attack_paths.json), it generates once per
format, plus one control: held-out record C0027 of
scenario_generation/evaluation/test_inputs.jsonl in the training format, which
is the adapter's best case. Every result is checked with
scenario_contract.validate_result and its sections are parsed. A table is
printed and every full output goes to a JSON file.

Each generation spends ZeroGPU quota (paths x 2 formats + 1 control calls,
5 by default).

The Hugging Face token comes from HF_TOKEN or `hf auth login` and is never
printed or written. With --import, results that pass validation are stored in
the app cache as source "live"; the app finds them for a path whose prompt in
the same format is identical. They are not linked to any analysis.

    python -m app.scripts.check_live_model --space-id OWNER/SPACE \\
        --adapter-repo OWNER/REPO --adapter-revision SHA [--base-revision SHA] \\
        [--paths AP-001 AP-019] [--import]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable

from app.api import scenario_cache as cache
from app.api import scenario_contract as contract
from app.api.config import REPO_ROOT
from app.scripts._common import DEFAULT_CACHE_DIR, ScriptError, run


# The verified main of mistralai/Mistral-7B-Instruct-v0.3 before the adapter was trained.
DEFAULT_BASE_REVISION = "c170c708c41dac9275d15a8fff4eca08d52bab71"
DEFAULT_PATHS = ("AP-001", "AP-019")
CONTROL_ID = "C0027"

ATTACK_PATHS_FILE = REPO_ROOT / "scenario_generation" / "evaluation" / "inputs" / "attack_paths.json"
TEST_INPUTS_FILE = REPO_ROOT / "scenario_generation" / "evaluation" / "test_inputs.jsonl"
DEFAULT_OUTPUT_DIR = DEFAULT_CACHE_DIR / "live_check"

GENERATE_API = "/generate"
METADATA_API = "/metadata"
SNIPPET_CHARS = 300

# What a case's prompt is: "path" cases come from an app export record and can
# be imported into the cache, the control cannot.
CONTROL_FORMAT = "training (control)"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.check_live_model",
        description="Generate with the live model Space in both prompt formats, plus a training-format "
                    "control, and compare the outputs. Spends ZeroGPU quota on every generation.")
    parser.add_argument("--space-id", required=True, help="the model Space, OWNER/NAME")
    parser.add_argument("--adapter-repo", required=True, help="the adapter repo the Space loaded, OWNER/NAME")
    parser.add_argument("--adapter-revision", required=True, help="full commit SHA of the adapter repo")
    parser.add_argument("--base-revision", default=DEFAULT_BASE_REVISION,
                        help=f"full commit SHA of {contract.BASE_MODEL_ID} (default: %(default)s)")
    parser.add_argument("--loading-recipe", default=contract.NF4_UNMERGED, choices=sorted(contract.LOADING_RECIPES))
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS), metavar="AP_ID",
                        help="sample paths from the evaluation attack_paths.json (default: %(default)s)")
    parser.add_argument("--max-new-tokens", type=int, default=contract.MAX_NEW_TOKENS)
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds to wait for each generation")
    parser.add_argument("--output", type=Path,
                        help="JSON file for the full results (default: <cache dir>/live_check/<time>.json)")
    parser.add_argument("--import", dest="import_results", action="store_true",
                        help="store results that pass validation in the app cache as source 'live'")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
                        help="app cache root for --import (default: CAPSTONE_CACHE_DIR or app/.cache)")
    parser.add_argument("--yes", action="store_true", help="do not wait for Enter before spending quota")
    return parser


# -- Cases ---------------------------------------------------------------------

def load_sample_records(wanted: list[str], path: Path = ATTACK_PATHS_FILE) -> dict[str, dict[str, str]]:
    """{source_id: seven-key record} for the wanted sample paths."""
    try:
        records = {item["source_id"]: item for item in json.loads(path.read_text(encoding="utf-8"))}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ScriptError(f"cannot read {path}: {exc}") from exc
    unknown = [source_id for source_id in wanted if source_id not in records]
    if unknown:
        raise ScriptError(
            f"not in {path.name}: {', '.join(unknown)}; available: {', '.join(sorted(records))}")
    try:
        return {source_id: contract.validate_record(records[source_id]) for source_id in wanted}
    except contract.ScenarioContractError as exc:
        raise ScriptError(f"{path.name}: {exc}") from exc


def control_prompt(path: Path = TEST_INPUTS_FILE) -> str:
    """The training-format prompt of held-out record C0027, built as training builds it."""
    try:
        with path.open(encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
        record = next(item for item in records if item.get("source_id") == CONTROL_ID)
    except (OSError, ValueError, StopIteration) as exc:
        raise ScriptError(f"cannot find {CONTROL_ID} in {path}: {exc}") from exc
    return contract.check_prompt(contract._prompt_generator().prompt_format.build_prompt(record))


def build_cases(wanted: list[str]) -> list[dict[str, Any]]:
    """Every generation to make: each path in each format, then the control."""
    cases = []
    for source_id, record in load_sample_records(wanted).items():
        for prompt_format in contract.PROMPT_VERSIONS:
            cases.append({
                "format": prompt_format,
                "path": source_id,
                "record": record,
                "prompt_version": contract.prompt_version_for(prompt_format),
                "prompt": contract.build_prompt(record, prompt_format),
            })
    cases.append({
        "format": CONTROL_FORMAT,
        "path": CONTROL_ID,
        "record": None,
        "prompt_version": contract.prompt_version_for(contract.TRAINING),
        "prompt": control_prompt(),
    })
    return cases


# -- The Space -----------------------------------------------------------------

def hf_token() -> str | None:
    """The token from HF_TOKEN or `hf auth login`, as huggingface_hub resolves it."""
    try:
        from huggingface_hub import get_token
    except ImportError as exc:
        raise ScriptError("huggingface_hub is not installed: pip install huggingface_hub") from exc
    return get_token()


def gradio_client(space_id: str, token: str | None):
    """A gradio_client.Client for the Space. The token is passed, never shown."""
    try:
        from gradio_client import Client
    except ImportError as exc:
        raise ScriptError("gradio_client is not installed: pip install gradio_client") from exc
    return Client(space_id, token=token, verbose=False)


def describe(error: BaseException, token: str | None) -> str:
    """One line about an error, with the token removed in case a library echoed it."""
    text = f"{type(error).__name__}: {str(error).strip()}" if str(error).strip() else type(error).__name__
    text = text.splitlines()[0]
    if token:
        text = text.replace(token, "***")
    text = re.sub(r"hf_[A-Za-z0-9]{8,}", "hf_***", text)
    return text[:500]


def check_metadata(metadata: Any, expected: dict[str, Any]) -> None:
    """The Space must carry exactly the revisions asked for, before any GPU call."""
    if not isinstance(metadata, dict):
        raise ScriptError(f"/metadata returned {type(metadata).__name__}, not an object")
    problems = [
        f"{field}: Space has {metadata.get(field)!r}, asked for {expected[field]!r}"
        for field in contract.PROVENANCE_FIELDS
        if metadata.get(field) != expected[field]
    ]
    if problems:
        raise ScriptError("the Space does not match the pinned provenance:\n  " + "\n  ".join(problems))


# -- Running -------------------------------------------------------------------

def summarise(case: dict[str, Any], response: Any, provenance: dict[str, Any]) -> dict[str, Any]:
    """The case's result row: validation, parsed sections and the metrics shown."""
    result = {
        "format": case["format"],
        "path": case["path"],
        "prompt_version": case["prompt_version"],
        "prompt": case["prompt"],
        "response": response,
        "valid": False,
        "error": None,
    }
    try:
        contract.validate_result(response, provenance)
    except contract.ScenarioContractError as exc:
        result["error"] = f"rejected: {exc}"
        return result
    sections = contract.parse_sections(response["text"])
    result.update(
        valid=True,
        sections=sections,
        missing=sections["missing"],
        preamble=sections["preamble"] is not None,
    )
    return result


def run_cases(
    cases: list[dict[str, Any]],
    client: Any,
    provenance: dict[str, Any],
    timeout: float,
    token: str | None,
    log: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    """Generate every case in order. A call that fails stops the run (a quota or
    Space problem would fail the rest too); results so far are kept."""
    max_new_tokens = provenance["generation_config"]["max_new_tokens"]
    results = []
    for number, case in enumerate(cases, 1):
        log(f"[{number}/{len(cases)}] {case['format']} {case['path']} ...")
        try:
            response = client.submit(case["prompt"], max_new_tokens, api_name=GENERATE_API).result(timeout=timeout)
        except Exception as exc:
            message = describe(exc, token)
            log(f"    failed: {message}")
            results.append({
                "format": case["format"], "path": case["path"], "prompt_version": case["prompt_version"],
                "prompt": case["prompt"], "response": None, "valid": False, "error": f"call failed: {message}",
            })
            log("Stopping: the remaining calls would likely fail the same way and spend quota.")
            break
        results.append(summarise(case, response, provenance))
        if not results[-1]["valid"]:
            log(f"    {results[-1]['error']}")
    return results


# -- Report --------------------------------------------------------------------

COLUMNS = (
    ("format", 18), ("path", 6), ("prompt tok", 10), ("new tok", 7), ("finish", 6),
    ("seconds", 7), ("missing", 12), ("preamble", 8),
)


def _missing_label(missing: list[str]) -> str:
    names = {"natural_language": "NL", "mathematical": "MATH", "attack_graph": "GRAPH"}
    return ",".join(names[item] for item in missing) or "none"


def table_row(result: dict[str, Any]) -> list[str]:
    response = result["response"]
    if not result["valid"]:
        return [result["format"], result["path"], "-", "-", "-", "-", "invalid", "-"]
    return [
        result["format"],
        result["path"],
        str(response.get("prompt_tokens", "?")),
        str(response["new_tokens"]),
        response["finish_reason"],
        f"{response['seconds']:.1f}",
        _missing_label(result["missing"]),
        "yes" if result["preamble"] else "no",
    ]


def snippet(result: dict[str, Any]) -> str:
    if not result["valid"]:
        return result["error"] or "no result"
    text = " ".join(result["response"]["text"].split())
    return text[:SNIPPET_CHARS] + ("..." if len(text) > SNIPPET_CHARS else "")


def format_report(results: list[dict[str, Any]]) -> str:
    """A compact table, then the first characters of each output."""
    widths = [width for _, width in COLUMNS]
    header = "  ".join(name.ljust(width) for name, width in COLUMNS)
    lines = [header, "  ".join("-" * width for width in widths)]
    for result in results:
        row = table_row(result)
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())
    lines.append("")
    for result in results:
        lines.append(f"{result['format']} {result['path']}: {snippet(result)}")
    return "\n".join(lines)


def write_results(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# -- Import --------------------------------------------------------------------

def import_results(
    results: list[dict[str, Any]], provenance: dict[str, Any], cache_dir: Path, log: Callable[[str], None] = print
) -> dict[str, int]:
    """Merge every valid sample-path result into the cache as source "live".

    The control is never imported: its prompt belongs to no app path.
    """
    counts: dict[str, int] = {}
    for result in results:
        if result["path"] == CONTROL_ID or not result["valid"]:
            continue
        entry = contract.make_cache_entry(
            prompt=result["prompt"],
            provenance=provenance,
            response=result["response"],
            source="live",
            prompt_version=result["prompt_version"],
        )
        status = cache.merge_entry(cache_dir, entry)
        counts[status] = counts.get(status, 0) + 1
        log(f"  {result['format']} {result['path']}: {status} ({entry['cache_key'][:12]})")
    return counts


# -- Main ----------------------------------------------------------------------

def main(
    argv: list[str] | None = None,
    *,
    client_factory: Callable[[str, str | None], Any] | None = None,
    token: str | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        provenance = contract.make_provenance(
            model_revision=args.base_revision,
            adapter_repo=args.adapter_repo,
            adapter_revision=args.adapter_revision,
            loading_recipe=args.loading_recipe,
            max_new_tokens=args.max_new_tokens,
        )
    except contract.ScenarioContractError as exc:
        raise ScriptError(str(exc)) from exc
    if not contract.is_repo_id(args.space_id):
        raise ScriptError("--space-id must look like OWNER/NAME")

    cases = build_cases(args.paths)
    if token is None:
        token = hf_token()
    if not token:
        raise ScriptError("no Hugging Face token: set HF_TOKEN or run `hf auth login`")

    print(f"WARNING: this makes {len(cases)} generations on {args.space_id}, each spending ZeroGPU quota "
          f"({len(args.paths)} path(s) x {len(contract.PROMPT_VERSIONS)} formats + 1 control).")
    if not args.yes:
        try:
            input("Press Enter to continue, Ctrl-C to stop. ")
        except (EOFError, KeyboardInterrupt):
            raise ScriptError("stopped before spending any quota") from None

    try:
        client = (client_factory or gradio_client)(args.space_id, token)
        metadata = client.predict(api_name=METADATA_API)
    except ScriptError:
        raise
    except Exception as exc:
        raise ScriptError(f"cannot reach {args.space_id}: {describe(exc, token)}") from exc
    check_metadata(metadata, provenance)
    print(f"Space {args.space_id} carries the pinned revisions; "
          f"context {metadata.get('context_tokens', '?')} tokens, prompt versions "
          f"{metadata.get('prompt_versions', '?')}.")

    results = run_cases(cases, client, provenance, args.timeout, token)
    close = getattr(client, "close", None)
    if close is not None:
        try:
            close()
        except Exception:
            pass

    print()
    print(format_report(results))

    output = args.output or DEFAULT_OUTPUT_DIR / (re.sub(r"[^0-9A-Za-z]", "", contract.utc_now()[:19]) + ".json")
    write_results(output, {
        "created_at": contract.utc_now(),
        "space_id": args.space_id,
        "provenance": provenance,
        "metadata": metadata,
        "results": results,
    })
    print(f"\nFull outputs written to {output}")

    if args.import_results:
        print("Importing valid results into the app cache:")
        counts = import_results(results, provenance, args.cache_dir)
        print("  " + (", ".join(f"{status} {n}" for status, n in sorted(counts.items())) or "nothing to import"))

    failed = [result for result in results if not result["valid"]]
    stopped_early = len(results) < len(cases)
    return 1 if failed or stopped_early else 0


if __name__ == "__main__":
    run(main)
