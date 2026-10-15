"""Measure the pipeline against a labelled corpus of real CloudFormation.

Pipeline:

corpus manifest.csv          file -> label (errors | good)
        |
parse each template          the stage-0 parser, on real input
        |
rule engine + privesc        findings per template
        |
graph + path finding         edges and attack paths per template
        |
recall / false positive      printed, and returned for a test to assert on

THEORY (why a benchmark and not more unit tests):
Every other test in this repo asks "does this rule fire on the fixture written for
it". That answers whether the code does what we said, and says nothing about
whether what we said covers reality. A rule set can pass 44 unit tests and still
miss 97% of real misconfigured templates, which is exactly what this benchmark
found the first time it ran: 3% recall on 234 known-bad templates, against a 4%
false positive rate on 361 known-good ones — a detector that flagged good
templates slightly *more* often than bad ones.

So this is the one measurement that can embarrass the rule set, and it exists to
be re-run after every change to it. `--baseline` writes the current numbers to
output/benchmark_baseline.json; a later run prints the delta against them, so
"this change improved recall by 9 points" is a number rather than a belief.

THEORY (why recall is the headline and precision is not):
The corpus labels a template `errors` when a scanner found *any* misconfiguration
in it, and those scanners check hundreds of conditions we do not implement. So a
template we fail to flag is a genuine miss, but a `good` template we do flag is
not necessarily a false positive — it may hold a real weakness no per-resource
scanner looks for, which is the entire point of an attack-graph tool. Recall is
therefore read as a lower bound on coverage, and the `good` rate is reported as
"flagged" rather than "wrong". Read it as a rate to keep an eye on, not to drive
to zero.

WHAT THIS DOES NOT MEASURE:
Whether a finding is *correct*. A rule that fired for the wrong reason counts the
same as one that fired for the right one. Only the unit tests check that, which is
why both exist.

Usage (from the repo root):
    python3 -m runner.benchmark
    python3 -m runner.benchmark --limit 300
    python3 -m runner.benchmark --baseline
    python3 -m runner.benchmark --corpus /path/to/corpus
"""

import argparse
import contextlib
import csv
import io
import json
import signal
import sys
from pathlib import Path

from engine.connection_builder import (
    build_capability_edges,
    build_connections,
    build_escalation_edges
)
from attack_path.path_finder import find_attack_paths
from security_state_graph.state_graph import SecurityStateGraph, evaluate_findings
from models.cloud_resource import CloudResource
from models.infra_model import InfraModel
from parser.infra_parser import (
    extract_semantic_properties,
    flatten_properties,
    load_cloudformation_template
)


BASE_DIR = Path(__file__).resolve().parent.parent

RULES_PATH = BASE_DIR / "data" / "security_rules.yaml"
BASELINE_PATH = BASE_DIR / "output" / "benchmark_baseline.json"

DEFAULT_CORPUS = Path.home() / "Downloads" / "cfn_semantic_corpus_2000"

MANIFEST = "manifest.csv"

# The label the corpus gives a template a scanner found something in.
ERROR_LABEL = "errors"
GOOD_LABEL = "good"

# Path search is exponential in the worst case. A template this large is not a
# demonstration candidate anyway, so it is counted and skipped rather than
# allowed to stall the run.
MAX_RESOURCES_FOR_PATHS = 45

# Seconds one template's path search may take before it is abandoned. Reported,
# so a rising count is visible rather than silently changing the totals.
PATH_SEARCH_TIMEOUT = 8


class SearchTimeout(Exception):
    """The path search on one template exceeded PATH_SEARCH_TIMEOUT."""


def _on_alarm(signum, frame):
    raise SearchTimeout()


# Installed at import rather than inside run().
#
# evaluate_template() is a public function that arms an alarm, so a caller using
# it directly — a test, or a script scoring one template — would otherwise arm a
# signal with its default disposition, and the process would be killed after
# PATH_SEARCH_TIMEOUT instead of the timeout being caught and reported.
#
# signal.signal only works on the main thread of the main interpreter, so this is
# guarded: importing the module from a worker thread should not raise.
try:
    signal.signal(signal.SIGALRM, _on_alarm)
except ValueError:  # pragma: no cover - not the main thread
    pass


def normalize_template(data):
    """A parsed template as the normalized resource dicts the pipeline reads."""

    resources = []

    for name, body in (data.get("Resources") or {}).items():

        if not isinstance(body, dict) or "Type" not in body:
            continue

        raw = body.get("Properties") or {}

        if not isinstance(raw, dict):
            raw = {}

        try:
            semantic = extract_semantic_properties(flatten_properties(raw), body["Type"])
        except Exception:
            continue

        resources.append({
            "id": name,
            "type": body["Type"],
            "raw_properties": raw,
            "semantic_properties": semantic
        })

    return resources


def evaluate_template(resources, rules_path=RULES_PATH):
    """Findings, edge count and attack paths for one template's resources."""

    # build_infra_from_resources rather than assembling the model here: it also
    # projects the abstract attributes the ruleset is written against. Built by
    # hand, this function reported zero findings for every rule that reads the
    # projection — the two ingress rules and all three bucket rules — across 441
    # templates, while the rules reading raw properties kept working. A benchmark
    # that silently measures half the ruleset is worse than no benchmark.
    from main import build_infra_from_resources

    # -----------------------------

    # The parser and the builders both print warnings on odd input, and a corpus
    # run would emit thousands. Silenced here and nowhere else.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):

        infra = build_infra_from_resources(resources)

        findings = evaluate_findings(infra, rules_path)
        state_graph = SecurityStateGraph(infra, findings)

    edges = sum(
        len(resource.connections)
        for resource in infra.all_resources()
    )

    # -----------------------------

    paths = []
    timed_out = False

    if len(resources) <= MAX_RESOURCES_FOR_PATHS:

        try:
            signal.alarm(PATH_SEARCH_TIMEOUT)

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                paths = find_attack_paths(state_graph)

            signal.alarm(0)

        except SearchTimeout:
            timed_out = True

        finally:
            signal.alarm(0)

    return {
        "findings": findings,
        "edges": edges,
        "paths": paths,
        "timed_out": timed_out
    }


def run(corpus=DEFAULT_CORPUS, limit=None, rules_path=RULES_PATH):
    """Evaluate every template in the corpus. Returns the summary dict."""

    corpus = Path(corpus)
    manifest = corpus / MANIFEST

    if not manifest.exists():
        raise FileNotFoundError("No %s in %s" % (MANIFEST, corpus))

    rows = list(csv.DictReader(open(manifest)))

    if limit:
        rows = rows[:limit]

    counts = {
        "templates": len(rows),
        "parsed": 0,
        "parse_failed": 0,
        "no_resources": 0,
        "path_timeouts": 0,
        "resources": 0,
        "findings": 0,
        "privesc_findings": 0,
        "edges": 0,
        "paths": 0
    }

    by_label = {
        ERROR_LABEL: {"total": 0, "flagged": 0},
        GOOD_LABEL: {"total": 0, "flagged": 0}
    }

    rule_hits = {}
    with_paths = []

    for row in rows:

        path = corpus / row["file"]

        if not path.exists():
            continue

        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                data = load_cloudformation_template(str(path))
        except Exception:
            counts["parse_failed"] += 1
            continue

        if not isinstance(data, dict) or not isinstance(data.get("Resources"), dict):
            counts["no_resources"] += 1
            continue

        resources = normalize_template(data)

        if not resources:
            counts["no_resources"] += 1
            continue

        counts["parsed"] += 1
        counts["resources"] += len(resources)

        try:
            result = evaluate_template(resources, rules_path)
        except Exception:
            continue

        findings = result["findings"]

        counts["findings"] += len(findings)
        counts["edges"] += result["edges"]
        counts["paths"] += len(result["paths"])

        counts["privesc_findings"] += sum(
            1
            for finding in findings
            if str(finding.get("rule_id", "")).startswith("PRIVESC")
        )

        if result["timed_out"]:
            counts["path_timeouts"] += 1

        for finding in findings:
            key = finding.get("rule_id")
            rule_hits[key] = rule_hits.get(key, 0) + 1

        label = row.get("label")

        if label in by_label:
            by_label[label]["total"] += 1

            if findings:
                by_label[label]["flagged"] += 1

        if result["paths"]:
            with_paths.append({
                "file": row["file"],
                "label": label,
                "resources": len(resources),
                "paths": len(result["paths"]),
                "objectives": sorted({
                    path_record["objective"]
                    for path_record in result["paths"]
                })
            })

    return {
        "counts": counts,
        "by_label": by_label,
        "recall": rate(by_label[ERROR_LABEL]),
        "good_flagged": rate(by_label[GOOD_LABEL]),
        "rule_hits": rule_hits,
        "templates_with_paths": with_paths
    }


def rate(bucket):
    """Flagged over total, as a percentage, guarding an empty bucket."""

    if not bucket["total"]:
        return 0.0

    return round(100.0 * bucket["flagged"] / bucket["total"], 1)


def load_baseline(path=BASELINE_PATH):
    """The stored baseline, or None when there is not one yet."""

    if not Path(path).exists():
        return None

    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def save_baseline(summary, path=BASELINE_PATH):
    """Store the headline numbers for a later run to compare against."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)

    Path(path).write_text(
        json.dumps(
            {
                "recall": summary["recall"],
                "good_flagged": summary["good_flagged"],
                "counts": summary["counts"]
            },
            indent=2,
            sort_keys=True
        ) + "\n"
    )


def delta(now, before):
    """A signed change, or an empty string when there is nothing to compare."""

    if before is None:
        return ""

    change = round(now - before, 1)

    if change == 0:
        return "  (no change)"

    return "  (%+.1f)" % change


def report(summary, baseline=None):
    """Print the summary, against the baseline when there is one."""

    counts = summary["counts"]
    errors = summary["by_label"][ERROR_LABEL]
    good = summary["by_label"][GOOD_LABEL]

    print("CORPUS: %d templates" % counts["templates"])
    print("  parsed                 %d" % counts["parsed"])
    print("  parse failures         %d" % counts["parse_failed"])
    print("  no usable resources    %d" % counts["no_resources"])

    if counts["path_timeouts"]:
        print("  path search abandoned  %d" % counts["path_timeouts"])

    print()
    print("  resources              %d" % counts["resources"])
    print("  rule + privesc findings %d  (%d escalation)"
          % (counts["findings"], counts["privesc_findings"]))
    print("  edges                  %d" % counts["edges"])
    print("  attack paths           %d" % counts["paths"])

    print()

    before_recall = baseline["recall"] if baseline else None
    before_good = baseline["good_flagged"] if baseline else None

    print("  RECALL on known-bad    %5.1f%%  (%d of %d)%s"
          % (summary["recall"], errors["flagged"], errors["total"],
             delta(summary["recall"], before_recall)))

    print("  flagged among 'good'   %5.1f%%  (%d of %d)%s"
          % (summary["good_flagged"], good["flagged"], good["total"],
             delta(summary["good_flagged"], before_good)))

    if summary["rule_hits"]:
        print()
        print("  findings by rule:")

        for key, value in sorted(summary["rule_hits"].items(), key=lambda item: -item[1]):
            print("    %-32s %d" % (key, value))

    if summary["templates_with_paths"]:
        print()
        print("  templates yielding an attack path: %d"
              % len(summary["templates_with_paths"]))

        for entry in summary["templates_with_paths"][:15]:
            print("    %-52s %2d paths  %s"
                  % (entry["file"], entry["paths"], ", ".join(entry["objectives"])))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Measure rule coverage against a labelled CloudFormation corpus"
    )

    parser.add_argument(
        "--corpus",
        default=str(DEFAULT_CORPUS),
        help="Corpus directory containing manifest.csv (default: %(default)s)"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Evaluate only the first N templates, for a quick check"
    )

    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Store this run's numbers as the baseline to compare future runs against"
    )

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    summary = run(corpus=args.corpus, limit=args.limit)

    report(summary, load_baseline())

    if args.baseline:
        save_baseline(summary)
        print()
        print("Baseline written to %s" % BASELINE_PATH)

    return 0


if __name__ == "__main__":
    sys.exit(main())
