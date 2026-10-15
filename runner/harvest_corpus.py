"""Rebuild the CloudFormation test corpora from their public sources.

Pipeline:

git clone --depth 1 each source repo
        |
walk for *.yml / *.yaml / *.template / *.json
        |
keep the ones that parse and have a Resources section
        |
drop anything whose sha1 is already in the reference corpus
        |
label, score by attack-chain ingredients, write a manifest
        |
a corpus directory runner/benchmark.py can read

THEORY (why this exists rather than a ZIP of templates):
The benchmark is only meaningful against real templates, and there are ~2,400 of
them. Shipping that as a blob makes the measurement unreproducible by anyone who
did not receive the blob, and it goes stale silently. Every source here is a
public repository, so the corpus is derivable, and a reviewer can check that the
input was not curated to flatter the result — which is the whole point of
measuring against data we did not write.

THEORY (why the labels here are weaker than the reference corpus's):
cfn_semantic_corpus_2000 labels a template `errors` because a scanner (KICS,
Checkov, cfn_nag) flagged it, which is an external judgement. This script has no
scanner, so it infers: a template from a vulnerable-by-design repository, or one
whose path contains `positive` / `fail` / `insecure`, is `errors`. That is good
enough to sort demonstration candidates and NOT good enough to quote a recall
figure from. Recall should be quoted against the reference corpus only.

A caveat the numbers depend on: a template is labelled for the single check its
fixture was written to exercise, not for everything wrong with it. So "recall"
measures how much of KICS's check set we have reimplemented, not how good the
tool is. See the README.

Usage:
    python3 -m runner.harvest_corpus --clone-dir /tmp/cfn_repos --out ~/Downloads/cfn_corpus_extra
    python3 -m runner.harvest_corpus --list
"""

import argparse
import contextlib
import csv
import hashlib
import io
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


# ── Sources ──────────────────────────────────────────────────────────────────

# The reference corpus, cfn_semantic_corpus_2000, was built from these. Listed so
# the provenance of the measurement everything is quoted against is in the repo
# rather than in a README beside a ZIP.
REFERENCE_CORPUS_SOURCES = [
    "Checkmarx/kics",
    "bridgecrewio/checkov",
    "stelligent/cfn_nag",
    "awslabs/aws-cloudformation-templates",
    "widdix/aws-cf-templates",
    "aws-cloudformation/cfn-lint",
    "awsdocs/aws-doc-sdk-examples",
    "aws-quickstart/quickstart-examples",
    "awslabs/aws-config-rules",
    "awslabs/aws-deployment-framework",
    "aws-samples/serverless-patterns"
]

# What this script clones. Chosen for two things the reference corpus is thin on:
# deliberately-vulnerable templates, and full-stack architectures where an attack
# chain can actually exist.
HARVEST_SOURCES = [
    # Vulnerable by design — the only reliably-bad templates available.
    "bridgecrewio/cfngoat",
    "aquasecurity/cfsec",

    # Full-stack reference architectures: load balancer + compute + IAM + data,
    # which is the shape a chain needs.
    "stelligent/cloudformation_templates",
    "aws-samples/ecs-refarch-cloudformation",
    "aws-samples/aws-refarch-wordpress",
    "aws-samples/aws-service-catalog-reference-architectures",
    "thinegan/cloudformation-project1",
    "thinegan/cloudformation-project2",
    "widdix/aws-cf-templates",
    "awslabs/aws-cloudformation-templates",

    # Scanner fixtures, for breadth.
    "aquasecurity/trivy",
    "tenable/terrascan",
    "voquis/aws-cloudformation-templates"
]

DEFAULT_CLONE_DIR = Path("/tmp/cfn_repos")
DEFAULT_OUT = Path.home() / "Downloads" / "cfn_corpus_extra"
DEFAULT_REFERENCE = Path.home() / "Downloads" / "cfn_semantic_corpus_2000"

SUFFIXES = {".yml", ".yaml", ".template", ".json"}

VULNERABLE_REPOS = {"bridgecrewio_cfngoat", "aquasecurity_cfsec"}
POSITIVE_MARKERS = ("positive", "fail", "insecure", "bad", "vulnerable")

MANIFEST_FIELDS = [
    "file", "label", "source", "resource_count",
    "semantic_categories", "has_open_ingress", "sha1_12", "origin_repo_path"
]


# ── The four ingredients an attack chain needs ───────────────────────────────

EXPOSED = {
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::CloudFront::Distribution",
    "AWS::ApiGateway::RestApi",
    "AWS::ApiGatewayV2::Api"
}
INGRESS = {"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"}
COMPUTE = {
    "AWS::EC2::Instance",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::AutoScaling::LaunchConfiguration",
    "AWS::EC2::LaunchTemplate",
    "AWS::ECS::Service",
    "AWS::Lambda::Function"
}
IDENTITY = {
    "AWS::IAM::Role",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::User"
}
DATA = {
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::DynamoDB::Table",
    "AWS::EFS::FileSystem",
    "AWS::SecretsManager::Secret",
    "AWS::KMS::Key",
    "AWS::Redshift::Cluster"
}

KEY_TYPES = EXPOSED | INGRESS | COMPUTE | IDENTITY | DATA


class Loader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation's !Ref / !GetAtt short forms."""


def _tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)

    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)

    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)

    return None


Loader.add_multi_constructor("!", _tag)


def clone_all(repos, clone_dir):
    """Shallow-clone each repo. Returns the ones that succeeded."""

    clone_dir = Path(clone_dir)
    clone_dir.mkdir(parents=True, exist_ok=True)

    cloned = []

    for repo in repos:

        name = repo.replace("/", "_")
        target = clone_dir / name

        if target.exists():
            cloned.append(target)
            print("  have   %s" % repo)
            continue

        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet",
             "https://github.com/%s.git" % repo, str(target)],
            capture_output=True
        )

        if result.returncode == 0:
            cloned.append(target)
            print("  cloned %s" % repo)
        else:
            print("  FAILED %s" % repo)

    return cloned


def reference_hashes(reference):
    """The sha1 prefixes already in the reference corpus, so nothing duplicates."""

    manifest = Path(reference) / "manifest.csv"

    if not manifest.exists():
        print("  (no reference corpus at %s — nothing will be deduplicated)" % reference)
        return set()

    with open(manifest) as handle:
        return {row["sha1_12"] for row in csv.DictReader(handle)}


def label_for(path):
    """`errors` when the provenance says the template is meant to be bad."""

    text = str(path).lower()

    if any(repo in text for repo in VULNERABLE_REPOS):
        return "errors"

    if any(marker in text for marker in POSITIVE_MARKERS):
        return "errors"

    return "good"


def read_template(path):
    """(types, resource_count) for a CloudFormation template, or None."""

    try:
        raw = path.read_bytes()
    except Exception:
        return None

    try:
        with contextlib.redirect_stderr(io.StringIO()):
            data = yaml.load(raw.decode("utf-8", "replace"), Loader=Loader)
    except Exception:
        return None

    if not isinstance(data, dict) or not isinstance(data.get("Resources"), dict):
        return None

    types = {
        body["Type"]
        for body in data["Resources"].values()
        if isinstance(body, dict) and isinstance(body.get("Type"), str)
    }

    if not types:
        return None

    return types, len(data["Resources"]), hashlib.sha1(raw).hexdigest()[:12]


def chain_score(types):
    """How many of the four chain ingredients a template has. 4 is a candidate."""

    return sum([
        bool(types & EXPOSED) or bool(types & INGRESS),
        bool(types & COMPUTE),
        bool(types & IDENTITY),
        bool(types & DATA)
    ])


def harvest(cloned, seen):
    """Every new, parseable template across the clones, best candidates first."""

    found = {}

    for root in cloned:

        for path in root.rglob("*"):

            if path.suffix.lower() not in SUFFIXES or ".git" in path.parts:
                continue

            parsed = read_template(path)

            if parsed is None:
                continue

            types, count, sha = parsed

            if sha in seen or sha in found:
                continue

            found[sha] = {
                "path": path,
                "sha1_12": sha,
                "label": label_for(path),
                "resources": count,
                "score": chain_score(types),
                "key_types": sorted(types & KEY_TYPES),
                "repo": root.name
            }

    return sorted(
        found.values(),
        key=lambda entry: (-entry["score"], -entry["resources"])
    )


def write_corpus(entries, out):
    """Copy the templates into a corpus directory with a benchmark manifest."""

    out = Path(out)

    if out.exists():
        shutil.rmtree(out)

    (out / "errors").mkdir(parents=True)
    (out / "good").mkdir(parents=True)

    rows = []

    for index, entry in enumerate(entries, 1):

        name = "%s/%s_%04d_%s%s" % (
            entry["label"],
            entry["label"],
            index,
            entry["path"].stem[:48].replace(" ", "_"),
            entry["path"].suffix
        )

        shutil.copyfile(entry["path"], out / name)

        rows.append({
            "file": name,
            "label": entry["label"],
            "source": entry["repo"],
            "resource_count": entry["resources"],
            "semantic_categories": ";".join(
                item.replace("AWS::", "") for item in entry["key_types"]
            ),
            "has_open_ingress": "",
            "sha1_12": entry["sha1_12"],
            "origin_repo_path": str(entry["path"])
        })

    with open(out / "manifest.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    return rows


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Rebuild the CloudFormation test corpus from public repos"
    )

    parser.add_argument("--clone-dir", default=str(DEFAULT_CLONE_DIR),
                        help="Where to clone the source repos (default: %(default)s)")

    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="Corpus directory to write (default: %(default)s)")

    parser.add_argument("--reference", default=str(DEFAULT_REFERENCE),
                        help="Reference corpus to deduplicate against (default: %(default)s)")

    parser.add_argument("--list", action="store_true",
                        help="Print the source repositories and exit")

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.list:
        print("Reference corpus (cfn_semantic_corpus_2000) was built from:")

        for repo in REFERENCE_CORPUS_SOURCES:
            print("  https://github.com/%s" % repo)

        print()
        print("This script clones:")

        for repo in HARVEST_SOURCES:
            print("  https://github.com/%s" % repo)

        return 0

    print("Cloning %d repositories into %s" % (len(HARVEST_SOURCES), args.clone_dir))
    cloned = clone_all(HARVEST_SOURCES, args.clone_dir)

    print()
    print("Deduplicating against %s" % args.reference)
    seen = reference_hashes(args.reference)

    print()
    entries = harvest(cloned, seen)

    print("Found %d new templates" % len(entries))

    for want in (4, 3):
        print("  %d/4 chain ingredients: %d"
              % (want, sum(1 for entry in entries if entry["score"] == want)))

    print()
    print("Top candidates:")

    for entry in [item for item in entries if item["score"] == 4][:10]:
        print("  %-6s %3d res  %s"
              % (entry["label"], entry["resources"], entry["path"].name))

    rows = write_corpus(entries, args.out)

    print()
    print("Wrote %d templates to %s" % (len(rows), args.out))
    print("Measure with: python3 -m runner.benchmark --corpus %s" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
