"""Analyses: from uploaded bytes to a saved, validated Analysis.

Two halves, split by process:

  child (app/api/worker.py)   parse the template, run runner.graph_runner.analyze,
                              project the result into the Analysis shape and the
                              two graph views, compute fix impact. Pure: no file
                              is written.
  parent (the API process)    validate the request, own the single worker slot,
                              validate what the child returned against the
                              schemas, and publish it atomically to the store.
"""

import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import uuid
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path as FilePath

import yaml

from app.api import schemas
from app.api.config import REPO_ROOT, Settings, make_private_dir
from app.api.graph import attack_view, state_view
from app.api.remediations import load_remediations, remediation_for
from app.api.worker import JobError, Worker


# Bump when the saved analysis.json shape changes. A saved analysis with another
# version is re-run from its stored input on read and rewritten.
SCHEMA_VERSION = 1

ACCEPTED_EXTENSIONS = [".yaml", ".yml", ".json", ".template"]

MAX_INDUSTRY_LENGTH = 200

RECURSION_MESSAGE = "The template nests too deeply or uses recursive aliases."

EXPANSION_MESSAGE = "The template expands to too much data (YAML aliases)."

# A mapping or list nested deeper than this is refused. Real templates stay
# under 20 levels; the YAML parser itself gives up near 250.
MAX_NESTING_DEPTH = 100

# Nodes in the document with every alias counted as often as it is used. A
# 2 MiB template of plain data stays far below this; a handful of fan-out
# aliases would reach billions.
MAX_EXPANDED_NODES = 200_000

# Fix impact is refused for an analysis the current code would rank differently.
OLDER_ANALYSER_MESSAGE = (
    "This analysis was produced by an older analyser; upload the template "
    "again for fix estimates."
)

# Fixed text for an unexpected failure. The details go to the log, not the client.
UNEXPECTED_MESSAGE = "The analysis failed unexpectedly."

SAMPLES = {
    "cloudformation5": {
        "name": "Three-tier web application",
        "description": "sample_yamls/cloudformation5.yml: public load balancer and "
                       "instances, an over-permissive role, a public bucket and a "
                       "database.",
        "kind": "single",
        "path": REPO_ROOT / "sample_yamls" / "cloudformation5.yml"
    },
    "nested": {
        "name": "Nested stacks",
        "description": "tests/fixtures/nested/parent.yaml: an attack chain split "
                       "across three child templates, found only once they are "
                       "merged.",
        "kind": "nested",
        "path": REPO_ROOT / "tests" / "fixtures" / "nested" / "parent.yaml"
    }
}

# The industries of the scenario generator's training data
# (scenario_generation/visualize_dataset.py), the default first. Suggestions
# only: the field is free text.
INDUSTRIES = [
    "Information technology service activities (ISIC J62)",
    "Information technology service activities (ISIC 6311)",
    "Information and communication (ISIC J)",
    "Financial and insurance activities (ISIC K)",
    "Human health and social work (ISIC Q)",
    "Public administration and defence (ISIC O)",
    "Electricity, gas, steam and AC supply (ISIC D)",
    "Education (ISIC P)",
    "Manufacturing (ISIC C)"
]

SEVERITIES = ["critical", "high", "medium", "low", "unknown"]

# Privilege findings the escalation catalogue does not name. See
# engine/privesc_detector.broad_grant_findings.
BROAD_GRANTS = {
    "WILDCARD_ADMIN_VIA_ATTACHED_POLICY": (
        "Administrator access through an attached policy",
        "An attached IAM policy grants every action on every resource to this "
        "principal."
    ),
    "BROAD_SERVICE_WILDCARD_GRANT": (
        "Service-wide wildcard grant",
        "This principal holds a <service>:* grant. The escalation catalogue "
        "names no single method for it, but it is still an escalation."
    )
}

RHINO_URL = "https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation"

# What a wildcard in an IAM Action means. The one reference for the broad grants.
IAM_ACTION_DOCS_URL = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html"
)

STACK_TYPE = "AWS::CloudFormation::Stack"

SAM_TYPE_PREFIX = "AWS::Serverless::"
FOR_EACH_PREFIX = "Fn::ForEach::"
TRANSFORM_KEY = "Fn::Transform"

MAX_ERROR_LENGTH = 300

log = logging.getLogger(__name__)


class InputError(Exception):
    """A request the analysis cannot be run on. Reported, never retried."""

    def __init__(self, detail, status=422):
        super().__init__(detail)
        self.detail = detail
        self.status = status


# ==============================================================================
# CHILD SIDE: input
# ==============================================================================

def decode_upload(data):
    """Uploaded bytes as text. UTF-8, with or without a byte order mark."""

    try:
        return data.decode("utf-8-sig")

    except UnicodeDecodeError:
        raise InputError("The file is not UTF-8 text.") from None


def load_template(text):
    """Parse YAML (or JSON) with the parser's CloudFormation tag support."""

    from parser.infra_parser import CloudFormationLoader

    try:
        return yaml.load(text, Loader=CloudFormationLoader)

    except RecursionError:
        raise InputError(RECURSION_MESSAGE) from None

    except ValueError:
        # The YAML constructors raise it for a number with thousands of digits
        # and for a date that does not exist.
        raise InputError(
            "The file holds a value that cannot be read, such as a number with "
            "too many digits or a date that does not exist."
        ) from None

    except yaml.YAMLError as error:

        problem = getattr(error, "problem", None) or "syntax error"
        mark = getattr(error, "problem_mark", None)

        where = (
            " (line %d, column %d)" % (mark.line + 1, mark.column + 1)
            if mark is not None else ""
        )

        raise InputError("The file is not valid YAML: %s%s." % (problem, where)) from None


def children(node):
    """The mappings and lists directly inside a mapping or list."""

    items = node.values() if isinstance(node, dict) else node

    return [item for item in items if isinstance(item, (dict, list))]


def check_structure(template):
    """Raise InputError when the loaded document nests or expands too far.

    Iterative, so it cannot hit the recursion limit it guards against. An alias
    is one shared object, so both measures key on id(): a node is walked again
    only when reached deeper than before, and its expanded size is computed
    once. A recursive alias is never finished, it only gets deeper, so it
    fails the depth check.
    """

    deepest = {}
    stack = [(template, 1)]

    while stack:

        node, depth = stack.pop()

        if not isinstance(node, (dict, list)):
            continue

        if depth > MAX_NESTING_DEPTH:
            raise InputError(RECURSION_MESSAGE)

        if deepest.get(id(node), 0) >= depth:
            continue

        deepest[id(node)] = depth

        stack.extend((child, depth + 1) for child in children(node))

    if not isinstance(template, (dict, list)):
        return

    # Acyclic from here on: expanded size, children before parents.
    sizes = {}
    stack = [template]

    while stack:

        node = stack[-1]

        if id(node) in sizes:
            stack.pop()
            continue

        pending = [child for child in children(node) if id(child) not in sizes]

        if pending:
            stack.extend(pending)
            continue

        items = node.values() if isinstance(node, dict) else node

        size = 1 + sum(
            sizes[id(item)] if isinstance(item, (dict, list)) else 1
            for item in items
        )

        if size > MAX_EXPANDED_NODES:
            raise InputError(EXPANSION_MESSAGE)

        sizes[id(node)] = size
        stack.pop()


def check_template(template, max_resources):
    """Raise InputError unless `template` has the shape the normalizer reads.

    Checked before parser.infra_parser.validate_template, which assumes the
    shape and would raise an AttributeError on, say, a list of resources.
    """

    check_structure(template)

    if not isinstance(template, dict):
        raise InputError(
            "This is not a CloudFormation template: the top level must be a mapping."
        )

    if "Resources" not in template:
        raise InputError("The template has no Resources section.")

    resources = template["Resources"]

    if not isinstance(resources, dict):
        raise InputError("Resources must be a mapping of logical ids to resources.")

    if len(resources) > max_resources:
        raise InputError(
            "The template declares %d resources; the limit is %d."
            % (len(resources), max_resources)
        )

    for name, body in resources.items():

        if not isinstance(name, str) or not name:
            raise InputError("Every resource needs a text logical id.")

        if name.startswith(FOR_EACH_PREFIX):
            raise InputError(
                "Fn::ForEach (AWS::LanguageExtensions) is not supported yet; "
                "expand the loop before uploading."
            )

        if name == TRANSFORM_KEY:
            raise InputError(
                "Fn::Transform directly under Resources (a macro or "
                "AWS::Include) is not supported; expand it before uploading."
            )

        if not isinstance(body, dict):
            raise InputError("Resource %s must be a mapping." % name)

        resource_type = body.get("Type")

        if not isinstance(resource_type, str) or not resource_type.strip():
            raise InputError("Resource %s needs a nonempty Type." % name)

        # `Properties:` with nothing after it is an empty block, not an error.
        if body.get("Properties") is None:
            body["Properties"] = {}

        if not isinstance(body["Properties"], dict):
            raise InputError("Properties of %s must be a mapping." % name)

        # The normalizer builds property names from these keys and assumes
        # text. Deeper keys are only ever formatted into a name, so they pass.
        for key in body["Properties"]:
            if not isinstance(key, str):
                raise InputError(
                    "Properties of %s has the key %s, which is not text. Put "
                    "quotes around it." % (name, repr(key)[:40])
                )

    return template


def json_key(key):
    """A mapping key as json.dumps would write it."""

    if isinstance(key, bool):
        return "true" if key else "false"

    if key is None:
        return "null"

    return str(key)


def jsonable(value):
    """`value` with every YAML-only type turned into JSON.

    The CLI reads normalized resources back from JSON, so making them JSON here
    keeps an upload and the CLI analysing the same data. Dates become ISO text,
    non-finite floats and anything else unknown become text. A PortRange (the
    attribute layer's ports) becomes its number, or {"from", "to"} for a range.
    """

    if isinstance(value, dict):
        return {json_key(key): jsonable(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]

    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)

    if isinstance(value, (date, datetime)):
        return value.isoformat()

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    from processing.attributes import PortRange

    if isinstance(value, PortRange):
        if value.low == value.high:
            return value.low

        return {"from": value.low, "to": value.high}

    return str(value)


def nested_stack_warnings(template):
    """One warning per nested stack an upload names. Uploads never fetch URLs."""

    return [
        {
            "kind": "nested_skipped",
            "message": "Nested stack %s was not fetched. Uploaded templates are "
                       "analysed alone, so its resources are not in this "
                       "analysis." % name
        }
        for name, body in template["Resources"].items()
        if body.get("Type") == STACK_TYPE
    ]


def transform_name(item):
    """The name of one Transform entry: text, or the Name of {Name, Parameters}."""

    if isinstance(item, dict):
        item = item.get("Name")

    return item.strip()[:100] if isinstance(item, str) and item.strip() else None


def transform_names(template):
    """Every transform or macro the template names, once each, in order.

    The top-level Transform (text, a list, or a {Name} mapping) and any
    Fn::Transform inside a resource.
    """

    declared = template.get("Transform")

    names = [
        transform_name(item)
        for item in (declared if isinstance(declared, list) else [declared])
    ]

    seen = set()
    stack = [template["Resources"]]

    while stack:

        node = stack.pop()

        if id(node) in seen:
            continue

        seen.add(id(node))

        if isinstance(node, dict) and TRANSFORM_KEY in node:
            names.append(transform_name(node[TRANSFORM_KEY]) or TRANSFORM_KEY)

        stack.extend(reversed(children(node)))

    # SAM resources without the Transform line would not deploy, but they are
    # just as unexpanded.
    if not any(names) and any(
        isinstance(body, dict) and str(body.get("Type")).startswith(SAM_TYPE_PREFIX)
        for body in template["Resources"].values()
    ):
        names.append("AWS::Serverless-2016-10-31")

    return list(dict.fromkeys(name for name in names if name))


def transform_warnings(template):
    """One warning per transform or macro: its output is never expanded."""

    return [
        {
            "kind": "transform_unexpanded",
            "message": "This template uses the transform %s. Transforms and "
                       "macros are not expanded, so resources they generate "
                       "are not analysed." % name
        }
        for name in transform_names(template)
    ]


def relative_to_repo(path):
    """A bundled path as text relative to the repo root, never absolute."""

    try:
        return FilePath(path).resolve().relative_to(REPO_ROOT).as_posix()

    except ValueError:
        return FilePath(path).name


def records_from_text(text, max_resources):
    """(records, warnings) for one uploaded template."""

    from parser.infra_parser import normalize, validate_template

    template = check_template(load_template(text), max_resources)

    records = jsonable(normalize(validate_template(template)))

    return records, transform_warnings(template) + nested_stack_warnings(template)


def nested_report_warnings(nested_report):
    """One warning per nested stack the merge skipped."""

    return [
        {
            "kind": "nested_skipped",
            "message": "Nested stack %s was skipped: %s." % (
                entry["stack"], entry["reason"]
            )
        }
        for entry in nested_report["skipped"]
    ]


def records_from_nested_sample(path, max_resources):
    """(records, warnings, nested_report) for the bundled nested sample."""

    from parser.nested import parse_merged

    records, report = parse_merged(path)

    if len(records) > max_resources:
        raise InputError(
            "The merged template declares %d resources; the limit is %d."
            % (len(records), max_resources)
        )

    nested_report = {
        "merged": [
            {
                "stack": entry["stack"],
                "template": relative_to_repo(entry["template"]),
                "resources": entry["resources"]
            }
            for entry in report["merged"]
        ],
        "skipped": [
            {
                "stack": str(entry.get("stack")),
                "reason": str(entry.get("reason")),
                "url": entry.get("url") if isinstance(entry.get("url"), str) else None
            }
            for entry in report["skipped"]
        ]
    }

    return jsonable(records), nested_report_warnings(nested_report), nested_report


def records_from_source(source, max_resources):
    """(records, warnings, nested_report) for one of the three kinds of source.

    upload   {"kind": "upload", "text"}: a template's text. Also what a saved
             upload, or a saved single-file sample, is re-run from.
    records  {"kind": "records", "records", "nested_report"}: the normalized
             resources a nested sample merged to. Its children are read once,
             at creation; after that the analysis re-runs from this.
    sample   {"kind": "sample", "sample_id"}: a bundled sample, read from the
             repo. Only a new analysis uses it.
    """

    if source["kind"] == "upload":
        records, warnings = records_from_text(source["text"], max_resources)
        return records, warnings, None

    if source["kind"] == "records":

        if len(source["records"]) > max_resources:
            raise InputError(
                "The merged template declares %d resources; the limit is %d."
                % (len(source["records"]), max_resources)
            )

        return (
            source["records"],
            nested_report_warnings(source["nested_report"]),
            source["nested_report"]
        )

    sample = SAMPLES.get(source.get("sample_id"))

    if sample is None:
        raise InputError("Unknown sample %r." % source.get("sample_id"), status=404)

    if sample["kind"] == "nested":
        return records_from_nested_sample(sample["path"], max_resources)

    records, warnings = records_from_text(
        decode_upload(sample["path"].read_bytes()),
        max_resources
    )

    return records, warnings, None


# ==============================================================================
# CHILD SIDE: projection
# ==============================================================================

def known_severity(severity):
    """A severity the contract allows; anything else is "unknown"."""

    severity = str(severity).lower() if severity is not None else "unknown"

    return severity if severity in SEVERITIES else "unknown"


def rule_catalog(rules_path):
    """(rules by id, privesc methods by id), read once per job."""

    from engine.privesc_detector import load_methods
    from engine.rule_engine import RuleEngine

    rules = {
        rule["id"]: rule
        for rule in RuleEngine(rules_path).rules
        if isinstance(rule, dict) and rule.get("id")
    }

    methods = {
        method["id"]: method
        for method in load_methods()
        if method.get("id")
    }

    return rules, methods


def one_line(text):
    """Folded YAML text as one line."""

    return " ".join(str(text or "").split())


def rule_info(finding, resource_type, rules, methods, remediations):
    """The RuleInfo for one finding: rule metadata plus its remediation."""

    from engine.attack_catalog import resolve

    rule_id = finding["rule_id"]
    source_id = finding.get("source_id") or rule_id

    rule = rules.get(rule_id)

    if rule is not None:

        state = rule.get("state")

        display_name = (
            state.get("display_name") or state.get("id")
            if isinstance(state, dict) else state
        )

        techniques = [
            {"id": str(item["id"]), "name": str(item.get("name") or "")}
            for item in rule.get("attack_techniques") or []
            if isinstance(item, dict) and item.get("id")
        ]

        references = [
            {
                "source": str(item.get("source") or ""),
                "id": str(item.get("id") or ""),
                "url": str(item.get("url") or "")
            }
            for item in rule.get("references") or []
            if isinstance(item, dict) and item.get("url")
        ]

        summary = one_line(rule.get("summary"))

    elif rule_id in methods:

        method = methods[rule_id]

        display_name = method.get("method") or rule_id

        summary = "Privilege escalation: holds %s, which escalates to %s." % (
            ", ".join(method.get("requires") or []),
            str(method.get("escalates_to") or "").replace("_", " ")
        )

        techniques = resolve(method.get("techniques") or [])

        references = [{"source": "rhino_security_labs", "id": rule_id, "url": RHINO_URL}]

    else:

        display_name, summary = BROAD_GRANTS.get(
            rule_id,
            (str(finding.get("state") or rule_id).replace("_", " ").capitalize(), "")
        )

        techniques = []

        references = (
            [{"source": "aws_iam", "id": rule_id, "url": IAM_ACTION_DOCS_URL}]
            if rule_id in BROAD_GRANTS else []
        )

    return {
        "rule_id": rule_id,
        "source_id": source_id,
        "display_name": str(display_name or rule_id),
        "summary": summary,
        "attack_techniques": techniques,
        "references": references,
        "remediation": remediation_for(
            remediations,
            rule_id,
            source_id,
            resource_type,
            is_method=rule is None
        )
    }


def assign_finding_ids(state_graph):
    """(resource, rule_id) -> finding id, in node then join order.

    `resource::rule_id`, which is unique on every template seen so far. A repeat
    gets a `#2` suffix rather than silently sharing an id.
    """

    ids = {}
    taken = set()

    for resource_id in sorted(state_graph.nodes):

        for finding in state_graph.states_of(resource_id):

            key = (resource_id, finding["rule_id"])

            if key in ids:
                continue

            identifier = "%s::%s" % key
            suffix = 2

            while identifier in taken:
                identifier = "%s::%s#%d" % (key[0], key[1], suffix)
                suffix = suffix + 1

            taken.add(identifier)
            ids[key] = identifier

    return ids


def project_step(step):
    """One describe_path step as the Step model."""

    from engine.attack_catalog import technique_name

    technique = step.get("technique")

    return {
        "source": step["source"],
        "target": step["target"],
        "category": step.get("category"),
        "relation": step.get("relation"),
        "action_id": step.get("action_id"),
        "action": str(step.get("action") or step.get("action_id") or ""),
        "tactic": step.get("tactic"),
        "technique": technique,
        # The ATT&CK matrix's name (data/attack_techniques.yaml), null when unknown.
        "technique_name": (technique_name(technique) or None) if technique else None,
        "precondition": list(step.get("precondition") or []),
        "precondition_options": list(step.get("precondition_options") or []),
        "postcondition": list(step.get("postcondition") or []),
        "required_permissions": [
            str(item) for item in step.get("required_permissions") or []
        ],
        "required_capabilities": jsonable(step.get("required_capabilities") or []),
        "evidence": [
            {"key": str(key), "value": jsonable(value)}
            for key, value in (step.get("input") or {}).items()
            if key not in ("target", "source")
        ],
        "output": jsonable(step.get("output") or {}),
        "fallback": bool(step.get("fallback"))
    }


def chain_groups(paths):
    """One group number per distinct hop chain, numbered from 1 in rank order."""

    groups = {}

    for path in paths:
        groups.setdefault(tuple(path["hops"]), len(groups) + 1)

    return groups


def project_risk(risk):
    """One contextual risk assessment as the PathRisk model. Its path_id and
    target repeat the path's source_id and target_id, so they are dropped."""

    return {
        key: value for key, value in risk.items() if key not in ("path_id", "target")
    }


def project_paths(result, finding_ids):
    """Every ranked path as the Path model, AP ids by overall rank."""

    from attack_path.exporter import source_id_for
    from attack_path.scoring import score_breakdown

    # The export numbers the selected paths from 1 and the steps number every
    # path from 1. They agree only because selection keeps a ranked prefix.
    if result.selected != result.paths[:len(result.selected)]:
        raise RuntimeError("selected paths are not a prefix of the ranked paths")

    groups = chain_groups(result.paths)

    projected = []

    for rank, path in enumerate(result.paths, 1):

        exported = rank <= len(result.selected)

        record = result.records[rank - 1] if exported else None

        if record is not None and record["source_id"] != source_id_for(rank):
            raise RuntimeError("export record %s is out of rank order" % rank)

        risk = result.risk[rank - 1]

        if risk["path_id"] != source_id_for(rank) or risk["target"] != path["target_id"]:
            raise RuntimeError("risk assessment %s is out of rank order" % rank)

        path_finding_ids = []

        for finding in path["states"]:

            identifier = finding_ids.get((finding["resource"], finding["rule_id"]))

            if identifier and identifier not in path_finding_ids:
                path_finding_ids.append(identifier)

        projected.append({
            "source_id": source_id_for(rank),
            "rank": rank,
            "exported": exported,
            "entry_id": path["entry_id"],
            "target_id": path["target_id"],
            "hops": list(path["hops"]),
            "length": path["length"],
            "public_entry": bool(path["public_entry"]),
            "objective": str(path.get("objective") or ""),
            "objective_name": str(
                path.get("objective_name") or path.get("objective") or ""
            ),
            "objective_techniques": [
                str(item) for item in path.get("objective_techniques") or []
            ],
            "score": path["score"],
            "attack_level": path["attack_level"],
            "breakdown": score_breakdown(path),
            "chain_group": groups[tuple(path["hops"])],
            "steps": [project_step(step) for step in path["steps"]],
            "finding_ids": path_finding_ids,
            "export": dict(record) if record is not None else None,
            "risk": project_risk(risk)
        })

    return projected


def analysis_warnings(result):
    """Rule errors, orphan findings and the attack graph's bounds, as Warnings."""

    from attack_path.path_finder import MAX_DEPTH
    from security_state_graph.attack_graph import ATTACKER_NODE_ID

    warnings = []

    for error in result.evaluation_errors:
        warnings.append({
            "kind": "rule_error",
            "message": "Rule %s could not be evaluated on %s: %s" % (
                error["rule_id"],
                error["resource"],
                str(error["error"])[:MAX_ERROR_LENGTH]
            )
        })

    for finding in result.state_graph.orphan_findings:
        warnings.append({
            "kind": "orphan_finding",
            "message": "Finding %s names %s, which is not in the template, and "
                       "was not used." % (finding.get("rule_id"), finding.get("resource"))
        })

    if result.attack_graph.truncated:
        warnings.append({
            "kind": "graph_truncated",
            "message": "The attack graph reached its state limit and is "
                       "incomplete. Paths through states beyond it are missing."
        })

    at_limit = [
        node
        for node in result.attack_graph.nodes.values()
        if node["id"] != ATTACKER_NODE_ID
        and node["depth"] >= result.attack_graph.max_depth
    ]

    if at_limit:
        warnings.append({
            "kind": "depth_limit",
            "message": "Paths are searched to %d hops. %d attacker state(s) sit "
                       "at that limit, so longer routes through them are not "
                       "reported." % (MAX_DEPTH, len(at_limit))
        })

    return warnings


def project_analysis(result, warnings, nested_report, rules_path):
    """The pipeline result as the Analysis body, minus the parent's provenance."""

    from security_state_graph.semantics import finding_severity

    graph = result.state_graph.to_dict()

    rules, methods = rule_catalog(rules_path)
    remediations = load_remediations()

    finding_ids = assign_finding_ids(result.state_graph)

    paths = project_paths(result, finding_ids)

    # finding id -> AP ids of the ranked paths carrying it
    on_paths = {}

    for path in paths:
        for identifier in path["finding_ids"]:
            on_paths.setdefault(identifier, []).append(path["source_id"])

    # -----------------------------

    resources = []
    findings = []
    seen = set()

    for node in graph["nodes"]:

        stored = result.state_graph.node(node["id"])

        node_findings = []

        for finding in result.state_graph.states_of(node["id"]):

            identifier = finding_ids[(node["id"], finding["rule_id"])]

            if identifier in seen:
                continue

            seen.add(identifier)
            node_findings.append(identifier)

            findings.append({
                "id": identifier,
                "resource": node["id"],
                "resource_type": node["type"],
                "rule_id": finding["rule_id"],
                "source_id": finding.get("source_id") or finding["rule_id"],
                "state": str(finding.get("state") or ""),
                "semantic": finding.get("semantic"),
                "severity": known_severity(finding_severity(finding)),
                "rule": rule_info(finding, node["type"], rules, methods, remediations),
                "on_paths": on_paths.get(identifier, [])
            })

        resources.append({
            "id": node["id"],
            "type": node["type"],
            "max_severity": (
                known_severity(node["max_severity"])
                if node["max_severity"] is not None else None
            ),
            "is_entry": node["is_entry"],
            "entry_reason": node["entry_reason"],
            "findings": node_findings,
            "attributes": jsonable(stored.get("attributes") or {}),
            "raw_properties": jsonable(stored.get("raw_properties") or {}),
            "connections": [
                {
                    "target": str(connection.get("target")),
                    "type": str(connection.get("type")),
                    "relation": connection.get("relation")
                }
                for connection in node["connections"]
            ]
        })

    # -----------------------------

    by_severity = {severity: 0 for severity in SEVERITIES}

    for finding in findings:
        by_severity[finding["severity"]] += 1

    by_level = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM")}

    for path in paths:
        by_level[path["attack_level"]] += 1

    summary = {
        "resources": graph["summary"]["resources"],
        "edges": graph["summary"]["edges"],
        "findings": graph["summary"]["findings"],
        "findings_by_severity": by_severity,
        "paths": len(paths),
        "paths_exported": len(result.selected),
        "paths_by_level": by_level,
        "entry_points": graph["summary"]["entry_points"],
        "top_score": paths[0]["score"] if paths else None
    }

    return {
        "summary": summary,
        "resources": resources,
        "findings": findings,
        "paths": paths,
        "top_fixes": [],
        "warnings": list(warnings) + analysis_warnings(result),
        "nested_report": nested_report
    }


def run_pipeline_on(records, industry, min_level):
    """runner.graph_runner.analyze over normalized records."""

    from main import build_infra_from_resources
    from runner.graph_runner import analyze

    return analyze(
        build_infra_from_resources(records),
        industry=industry,
        min_level=min_level
    )


def analysis_job(payload):
    """Child job: the Analysis body, both graph views and the normalized records."""

    from runner.graph_runner import RULES_PATH

    records, warnings, nested_report = records_from_source(
        payload["source"],
        payload["max_resources"]
    )

    result = run_pipeline_on(records, payload["industry"], payload["min_level"])

    return {
        "analysis": project_analysis(result, warnings, nested_report, RULES_PATH),
        "graphs": {
            "state": state_view(result.state_graph, result.paths),
            "attack": attack_view(result.state_graph, result.attack_graph, result.paths)
        },
        "normalized": records
    }


# ==============================================================================
# CHILD SIDE: fix impact
# ==============================================================================

def path_identity(path):
    """What makes two selected paths the same attack, independent of rank."""

    return (tuple(path["hops"]), path["objective"] or "")


def fixes_job(payload):
    """Child job: suppress each candidate finding in turn and re-select paths.

    Candidates are the findings on the top `scope_top` selected paths (every
    selected path when null). Selected path sets are compared by hops and
    objective, never by AP id, because ranks shift when a path drops out.
    """

    from attack_path.exporter import source_id_for
    from attack_path.path_finder import find_attack_paths
    from attack_path.scoring import select_high_risk
    from security_state_graph.semantics import finding_severity, severity_weight
    from security_state_graph.state_graph import SecurityStateGraph

    records, _, _ = records_from_source(payload["source"], payload["max_resources"])

    min_level = payload["min_level"]
    scope_top = payload["scope_top"]

    result = run_pipeline_on(records, payload["industry"], min_level)

    # The saved analysis is what the user is looking at, and the answer's AP ids
    # are its ids. If this code ranks the same input differently, the saved
    # ids no longer mean the same paths.
    ranked = [path_identity(path) for path in result.paths]

    if ranked != [(tuple(hops), objective or "") for hops, objective in payload["saved_paths"]]:
        raise InputError(OLDER_ANALYSER_MESSAGE, status=409)

    finding_ids = assign_finding_ids(result.state_graph)

    baseline = [path_identity(path) for path in result.selected]
    baseline_set = set(baseline)

    ap_ids = {
        identity: source_id_for(rank)
        for rank, identity in enumerate(baseline, 1)
    }

    scope = result.selected if scope_top is None else result.selected[:scope_top]

    # -----------------------------

    candidates = []
    severities = {}

    for path in scope:
        for finding in path["states"]:

            key = (finding["resource"], finding["rule_id"])

            if key not in candidates:
                candidates.append(key)
                severities[key] = finding_severity(finding)

    results = []
    weights = {}

    for key in candidates:

        reduced = [
            finding
            for finding in result.findings
            if (finding["resource"], finding["rule_id"]) != key
        ]

        selected = select_high_risk(
            find_attack_paths(SecurityStateGraph(result.infra, reduced)),
            min_level
        )

        after = [path_identity(path) for path in selected]
        after_set = set(after)

        removed = [identity for identity in baseline if identity not in after_set]
        added = [identity for identity in after if identity not in baseline_set]

        weights[finding_ids[key]] = severity_weight(severities[key])

        results.append({
            "finding_id": finding_ids[key],
            "selected_paths_removed": len(removed),
            "selected_paths_remaining": len(baseline) - len(removed),
            "selected_paths_added": len(added),
            "baseline_selected_paths": len(baseline),
            "removed_ids": [ap_ids[identity] for identity in removed],
            "added_paths": [
                {"hops": list(hops), "objective": objective}
                for hops, objective in added
            ],
            "scope_top": scope_top
        })

    # Most selected paths removed first, then the worse finding, then stable.
    results.sort(key=lambda item: (
        -item["selected_paths_removed"],
        -weights[item["finding_id"]],
        item["finding_id"]
    ))

    return {"candidate_count": len(candidates), "results": results}


# ==============================================================================
# PARENT SIDE
# ==============================================================================

@lru_cache(maxsize=1)
def analyser_commit():
    """The repo commit the analyser runs from, "+dirty" with tracked edits."""

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=5, check=True
        ).stdout.strip()

        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=5, check=True
        ).stdout.strip()

    except (OSError, subprocess.SubprocessError):
        return "unknown"

    return commit + ("+dirty" if dirty else "") if commit else "unknown"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def is_text_source(source):
    """True for a source whose stored input file is the template's text.

    An upload, and a bundled single-file sample. The nested sample is the one
    source that is several files.
    """

    return (
        source["kind"] == "upload"
        or SAMPLES[source["sample_id"]]["kind"] == "single"
    )


# C0 controls except tab, DEL, and the bidirectional overrides and isolates,
# none of which belong in text that is later printed, drawn or put in a header.
UNSAFE_CHARACTERS = re.compile("[\x00-\x08\x0a-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def printable(text):
    """`text` without control and bidirectional override characters."""

    return UNSAFE_CHARACTERS.sub("", text or "")


def clean_industry(industry):
    """Stripped, required, at most MAX_INDUSTRY_LENGTH characters."""

    industry = printable(industry).strip()

    if not industry:
        raise JobError(422, "Industry is required.")

    if len(industry) > MAX_INDUSTRY_LENGTH:
        raise JobError(
            422, "Industry is at most %d characters." % MAX_INDUSTRY_LENGTH
        )

    return industry


def display_name(filename):
    """An uploaded filename as display text only: its last component, capped."""

    name = printable(filename).replace("\\", "/").rsplit("/", 1)[-1].strip()

    return name[:255] or "template"


def extension_of(filename):
    suffix = FilePath(display_name(filename)).suffix.lower()
    return suffix if suffix in ACCEPTED_EXTENSIONS else None


def parse_top(top):
    """The `top` query value: a positive integer, or None for "all"."""

    if top == "all":
        return None

    try:
        value = int(top)

    except (TypeError, ValueError):
        value = 0

    if value < 1:
        raise JobError(422, "top must be a positive integer or \"all\".")

    return value


class UnknownAnalysis(JobError):

    def __init__(self):
        super().__init__(404, "Analysis not found.")


class AnalysisStore:
    """Saved analyses, one directory per analysis id.

    <root>/<uuid>/
        manifest.json             provenance and the options to re-run
        input<ext>                the uploaded bytes
        normalized_resources.json
        analysis.json
        graph_state.json, graph_attack.json
        fixes-top-<n|all>.json    fix impact, written once computed

    Ids are canonical UUIDs, checked before any path is built, so no request
    can name a file outside the root.
    """

    def __init__(self, root):
        self.root = FilePath(root)

    def directory(self, analysis_id):

        try:
            canonical = str(uuid.UUID(str(analysis_id)))

        except ValueError:
            raise UnknownAnalysis() from None

        if canonical != analysis_id:
            raise UnknownAnalysis()

        return self.root / canonical

    def exists(self, analysis_id):
        return self.directory(analysis_id).is_dir()

    def publish(self, analysis_id, files):
        """Write every file into a sibling temp directory, then rename it in."""

        destination = self.directory(analysis_id)

        make_private_dir(self.root)

        staging = self.root / (".tmp-%s" % analysis_id)

        try:
            staging.mkdir(mode=0o700)

            for name, data in files.items():
                (staging / name).write_bytes(data)

            os.rename(staging, destination)

        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def read_bytes(self, analysis_id, name):
        return (self.directory(analysis_id) / name).read_bytes()

    def read_json(self, analysis_id, name):
        return json.loads(self.read_bytes(analysis_id, name))

    def replace_json(self, analysis_id, name, value):
        """Write one file atomically: a temp file, then os.replace."""

        target = self.directory(analysis_id) / name
        temporary = target.with_name(".%s.%s.tmp" % (name, uuid.uuid4().hex))

        try:
            temporary.write_bytes(dump(value))
            os.replace(temporary, target)

        finally:
            if temporary.exists():
                temporary.unlink()


def dump(value):
    return json.dumps(value, indent=1, ensure_ascii=False).encode("utf-8")


def validated(model, value):
    """`value` checked against `model`, as plain JSON-ready data."""

    return model.model_validate(value).model_dump(mode="json")


class AnalysisService:
    """Every analysis operation the routes need, over one store and one worker."""

    def __init__(self, settings: Settings, worker: Worker):
        self.settings = settings
        self.worker = worker
        self.store = AnalysisStore(settings.analyses_dir)

    # -----------------------------

    async def _run(self, kind, payload, timeout, admit=None):
        """The job's result. admit (a rate limit) is called only when the job
        can start, so a busy worker's 503 costs the client nothing. Nothing
        awaits between the check and the worker taking its slot."""

        if admit is not None and not self.worker.busy:
            admit()

        return await self.worker.run(kind, payload, timeout)

    def _commit(self):
        """ANALYSER_COMMIT when set, else the commit read from git."""

        return self.settings.analyser_commit or analyser_commit()

    async def _analyse(self, source, industry, min_level, admit=None):

        return await self._run(
            "analysis",
            {
                "source": source,
                "industry": industry,
                "min_level": min_level,
                "max_resources": self.settings.max_resources
            },
            self.settings.analysis_timeout_s,
            admit
        )

    def _assemble(self, manifest, body):
        """The child's body plus the manifest's provenance, validated.

        Whatever goes wrong here is a bug, not the client's input: it is logged
        and reported as a fixed message, never as the exception's text.
        """

        try:
            return self._assembled(manifest, body)

        except Exception:
            log.exception("Assembling analysis %s failed.", manifest.get("id"))
            raise JobError(500, UNEXPECTED_MESSAGE) from None

    def _assembled(self, manifest, body):

        analysis = dict(body["analysis"])

        analysis.update({
            "id": manifest["id"],
            "created_at": manifest["created_at"],
            "input_name": manifest["input_name"],
            "input_sha256": manifest["input_sha256"],
            "industry": manifest["industry"],
            "min_level": manifest["min_level"],
            "analyser_commit": self._commit(),
            "schema_version": SCHEMA_VERSION
        })

        return (
            validated(schemas.Analysis, analysis),
            {
                view: validated(schemas.GraphView, graph)
                for view, graph in body["graphs"].items()
            }
        )

    async def _create(self, source, input_name, input_bytes, input_ext, industry,
                      min_level, extra_manifest=None, admit=None):

        industry = clean_industry(industry)

        # A template is analysed from the very bytes that are stored with it.
        body = await self._analyse(
            {"kind": "upload", "text": decode_upload_or_422(input_bytes)}
            if is_text_source(source) else source,
            industry,
            min_level,
            admit
        )

        analysis_id = str(uuid.uuid4())

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "id": analysis_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "input_name": input_name,
            "input_sha256": sha256(input_bytes),
            "input_file": "input" + input_ext,
            "source": source,
            "industry": industry,
            "min_level": min_level,
            "analyser_commit": self._commit()
        }

        manifest.update(extra_manifest or {})

        # What a nested sample merged to, so it re-runs without its children.
        if body["analysis"]["nested_report"] is not None:
            manifest["nested_report"] = body["analysis"]["nested_report"]

        analysis, graphs = self._assemble(manifest, body)

        self.store.publish(analysis_id, {
            "manifest.json": dump(manifest),
            manifest["input_file"]: input_bytes,
            "normalized_resources.json": dump(body["normalized"]),
            "analysis.json": dump(analysis),
            "graph_state.json": dump(graphs["state"]),
            "graph_attack.json": dump(graphs["attack"])
        })

        return analysis

    async def create_from_upload(self, filename, data, industry, min_level, admit=None):

        extension = extension_of(filename)

        if extension is None:
            raise JobError(
                415,
                "Upload a CloudFormation template ending in %s."
                % ", ".join(ACCEPTED_EXTENSIONS)
            )

        if len(data) > self.settings.max_upload_bytes:
            raise JobError(
                413,
                "The file is larger than the %d byte limit."
                % self.settings.max_upload_bytes
            )

        return await self._create(
            {"kind": "upload"},
            display_name(filename),
            data,
            extension,
            industry,
            min_level,
            admit=admit
        )

    async def create_from_sample(self, sample_id, industry, min_level, admit=None):

        sample = SAMPLES.get(sample_id)

        if sample is None:
            raise JobError(404, "Unknown sample %r." % sample_id)

        path = sample["path"]

        extra = {}

        if sample["kind"] == "nested":
            # Provenance for every bundled file the merge can read.
            extra["nested_inputs"] = [
                {"template": relative_to_repo(child), "sha256": sha256(child.read_bytes())}
                for child in sorted(path.parent.iterdir())
                if child.suffix.lower() in ACCEPTED_EXTENSIONS
            ]

        return await self._create(
            {"kind": "sample", "sample_id": sample_id},
            path.name,
            path.read_bytes(),
            path.suffix.lower(),
            industry,
            min_level,
            extra,
            admit
        )

    # -----------------------------

    def _manifest(self, analysis_id):

        if not self.store.exists(analysis_id):
            raise UnknownAnalysis()

        try:
            return self.store.read_json(analysis_id, "manifest.json")

        except (OSError, ValueError):
            raise JobError(
                409, "Saved analysis %s is unreadable." % analysis_id
            ) from None

    def _stored_source(self, analysis_id, manifest):
        """The source to re-run, read back from the store. Never the repo."""

        try:

            if is_text_source(manifest["source"]):
                return {
                    "kind": "upload",
                    "text": decode_upload_or_422(
                        self.store.read_bytes(analysis_id, manifest["input_file"])
                    )
                }

            return {
                "kind": "records",
                "records": self.store.read_json(
                    analysis_id, "normalized_resources.json"
                ),
                "nested_report": manifest["nested_report"]
            }

        except (OSError, ValueError, KeyError):
            raise JobError(
                409, "Saved analysis %s has no readable input." % analysis_id
            ) from None

    async def _rebuild(self, analysis_id, manifest):
        """Re-run a saved analysis from its stored input and rewrite it."""

        source = self._stored_source(analysis_id, manifest)

        body = await self._analyse(source, manifest["industry"], manifest["min_level"])

        analysis, graphs = self._assemble(manifest, body)

        self.store.replace_json(analysis_id, "graph_state.json", graphs["state"])
        self.store.replace_json(analysis_id, "graph_attack.json", graphs["attack"])
        self.store.replace_json(analysis_id, "analysis.json", analysis)

        return analysis, graphs

    async def get(self, analysis_id):
        """The saved Analysis. Re-run only when its schema version is not current."""

        manifest = self._manifest(analysis_id)

        try:
            saved = self.store.read_json(analysis_id, "analysis.json")

            if saved.get("schema_version") == SCHEMA_VERSION:
                return validated(schemas.Analysis, saved)

        except (OSError, ValueError):
            pass

        analysis, _ = await self._rebuild(analysis_id, manifest)

        return analysis

    async def graph(self, analysis_id, view):

        analysis = await self.get(analysis_id)

        try:
            return validated(
                schemas.GraphView,
                self.store.read_json(analysis_id, "graph_%s.json" % view)
            )

        except (OSError, ValueError):
            pass

        _, graphs = await self._rebuild(analysis_id, self._manifest(analysis["id"]))

        return graphs[view]

    # -----------------------------

    def _scope(self, analysis, top):
        """The normalized scope: None, "every selected path", for "all", for a
        count that reaches the selected count, and for any count when no path
        is selected. One scope, one saved file."""

        scope_top = parse_top(top)

        if scope_top is not None and scope_top >= analysis["summary"]["paths_exported"]:
            return None

        return scope_top

    @staticmethod
    def _fixes_file(scope_top):
        return "fixes-top-%s.json" % ("all" if scope_top is None else scope_top)

    async def cached_fixes(self, analysis_id, top):
        """The saved FixImpactResult for this scope, or None."""

        analysis = await self.get(analysis_id)

        name = self._fixes_file(self._scope(analysis, top))

        try:
            return validated(
                schemas.FixImpactResult, self.store.read_json(analysis_id, name)
            )

        except (OSError, ValueError):
            return None

    async def compute_fixes(self, analysis_id, top, admit=None):
        """Fix impact for this scope, computed in the worker unless saved."""

        cached = await self.cached_fixes(analysis_id, top)

        if cached is not None:
            return cached

        analysis = await self.get(analysis_id)
        manifest = self._manifest(analysis_id)

        scope_top = self._scope(analysis, top)

        body = await self._run(
            "fixes",
            {
                "source": self._stored_source(analysis_id, manifest),
                "industry": manifest["industry"],
                "min_level": manifest["min_level"],
                "max_resources": self.settings.max_resources,
                "scope_top": scope_top,
                "saved_paths": [
                    [path["hops"], path["objective"]] for path in analysis["paths"]
                ]
            },
            self.settings.impact_timeout_s,
            admit
        )

        result = validated(schemas.FixImpactResult, {
            "analysis_id": analysis_id,
            "scope_top": scope_top,
            "candidate_count": body["candidate_count"],
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "results": body["results"]
        })

        self.store.replace_json(analysis_id, self._fixes_file(scope_top), result)

        return result


def decode_upload_or_422(data):
    """decode_upload for the parent, raising the HTTP-facing error."""

    try:
        return decode_upload(data)

    except InputError as error:
        raise JobError(error.status, error.detail) from None
