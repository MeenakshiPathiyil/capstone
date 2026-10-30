"""Import a pre-generation JSONL file into the local scenario cache.

Each line (scenario_contract.make_result_line) carries the analysis id, path
id, seven-key record and a full cache entry. A line is imported only if:

  - the entry validates: its cache key recomputes from the request provenance,
    and the response's model, adapter, revisions, recipe and generation
    config match that request;
  - its prompt version is a known one and its prompt is exactly what
    build_prompt() makes from the record in that version's format;
  - its source is "pregenerated";
  - when the analysis is saved locally, the path is selected there with the
    same record.

Valid entries merge atomically into app/.cache/scenarios/<cache_key>.json; a
valid entry already stored under the key is never replaced by different
content. Imported entries are linked to their analysis path unless that path
already shows another entry. Exit status 1 if any line was rejected.

    python -m app.scripts.import_scenarios results.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.api import scenario_cache as cache
from app.api import scenario_contract as contract
from app.scripts._common import DEFAULT_CACHE_DIR, ScriptError, exported_records, load_analysis, run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.import_scenarios",
        description="Validate a pre-generation JSONL file and merge it into the local scenario cache.")
    parser.add_argument("jsonl", type=Path, help="result file written by pregenerate_kaggle.ipynb")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
                        help="app cache root (default: CAPSTONE_CACHE_DIR or app/.cache)")
    parser.add_argument("--dry-run", action="store_true", help="validate only, write nothing")
    return parser


def check_line(line: object) -> dict:
    """The line's entry if every check passes, else ScenarioContractError."""
    if not isinstance(line, dict):
        raise contract.ScenarioContractError("line is not a JSON object")
    if line.get("line_version") != contract.RESULT_LINE_VERSION:
        raise contract.ScenarioContractError(f"unsupported line_version {line.get('line_version')!r}")
    for field in ("analysis_id", "source_id", "record", "entry"):
        if field not in line:
            raise contract.ScenarioContractError(f"line is missing {field}")
    record = contract.validate_record(line["record"])
    if record["source_id"] != line["source_id"]:
        raise contract.ScenarioContractError("record source_id differs from the line's source_id")
    entry = contract.validate_cache_entry(line["entry"])
    if entry["source"] != "pregenerated":
        raise contract.ScenarioContractError(f"source is {entry['source']!r}; imports must be pregenerated")
    request = entry["request"]
    prompt_format = contract.prompt_format_for_version(request["prompt_version"])
    if request["prompt"] != contract.build_prompt(record, prompt_format):
        raise contract.ScenarioContractError(
            f"prompt is not the one build_prompt() makes for this record in the {prompt_format} format")
    return entry


def import_file(path: Path, cache_dir: Path, dry_run: bool = False) -> dict[str, int]:
    """Import every valid line; print one status line each and return the counts."""
    counts: dict[str, int] = {}
    analyses: dict[str, dict | None] = {}

    def count(status: str) -> None:
        counts[status] = counts.get(status, 0) + 1

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ScriptError(f"cannot read {path}: {exc}") from exc

    for number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        label = f"line {number}"
        try:
            line = json.loads(raw)
            entry = check_line(line)
            label = f"line {number} {line['source_id']} {entry['cache_key'][:12]}"
            analysis_id = line["analysis_id"]
            if analysis_id not in analyses:
                analyses[analysis_id] = load_analysis(cache_dir, analysis_id)
            analysis = analyses[analysis_id]
            if analysis is not None and exported_records(analysis).get(line["source_id"]) != line["record"]:
                raise contract.ScenarioContractError(
                    f"{line['source_id']} is not a selected path with this record in analysis {analysis_id}")
        except (json.JSONDecodeError, contract.ScenarioContractError, ScriptError) as exc:
            print(f"{label}: rejected: {exc}")
            count("rejected")
            continue

        if dry_run:
            print(f"{label}: valid")
            count("valid")
            continue
        status = cache.merge_entry(cache_dir, entry)
        count(status)
        if analysis is None:
            print(f"{label}: {status}; analysis {analysis_id} not saved here, not linked")
            continue
        link_status = cache.link(cache_dir, analysis_id, line["source_id"], entry["cache_key"])
        print(f"{label}: {status}, link {link_status}")
    return counts


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    counts = import_file(args.jsonl, args.cache_dir, args.dry_run)
    summary = ", ".join(f"{status} {n}" for status, n in sorted(counts.items())) or "no lines"
    print(f"Summary: {summary}")
    return 1 if counts.get("rejected") else 0


if __name__ == "__main__":
    run(main)
