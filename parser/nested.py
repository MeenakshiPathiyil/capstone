"""Merge a nested-stack architecture into one set of normalized resources.

Pipeline:

parent template
        |
find AWS::CloudFormation::Stack resources
        |
resolve TemplateURL -> a local file under the repo root
        |
parse the child, prefixing every id with the stack's logical name
        |
rewrite the child's references: its own ids get the prefix, its parameter
names get whatever the parent passed in
        |
one flat list of records, as if the account had been written in one file

THEORY (why this is worth building):
Production infrastructure is not one template. The reference architectures on
GitHub put the VPC in one file, the load balancer in another, the compute in a
third and the database in a fourth, joined by AWS::CloudFormation::Stack. Analysed
one file at a time, none of them contains an attack chain — the front door is in
one file and the data is in another — so a scanner that reads single templates
cannot see the thing an attack graph exists to find. Of 24 templates harvested
from two reference-architecture repos, zero had all four chain ingredients, and
that was the reason.

THEORY (the three things that have to be resolved):
Merging is not concatenation. Three references have to survive it.

  1. `TemplateURL` is an S3 URL, not a path:
     "https://s3.amazonaws.com/bucket/infrastructure/vpc.yaml". The bucket is
     wherever the templates were published, which tells us nothing, but the *path
     suffix* — "infrastructure/vpc.yaml" — is the repository layout. So the URL is
     matched against files under a root by longest suffix.

  2. Logical ids are only unique within a template. Two children can both declare
     "SecurityGroup". So every child id gains its stack's name as a prefix, and
     the child's own internal references are rewritten to match — otherwise
     merging breaks the very edges the child had.

  3. Children talk to each other through the parent, not directly:
        parent: SecurityGroup: !GetAtt SecurityGroups.Outputs.LoadBalancerSG
        child:  Parameters: SecurityGroup   ...   !Ref SecurityGroup
     So a parameter name inside the child has to be substituted with what the
     parent passed, and a `!GetAtt Child.Outputs.Name` has to be resolved through
     that child's Outputs block to the resource it names. Without step 3 the
     children merge as disconnected islands, which looks like success and finds
     nothing.

WHAT THIS DOES NOT DO:
  * No S3 fetching. A TemplateURL with no counterpart on disk is skipped and
    counted, never guessed at.
  * `Fn::Sub`, `Fn::Join` and friends inside a TemplateURL are not evaluated, so a
    computed URL will not resolve.
  * An output whose Value is a computed expression rather than a plain `!Ref`
    resolves to nothing. `!GetAtt X.Outputs.Y` where Y is built by Fn::Join is
    the common case here, and it is dropped rather than approximated.
  * Nothing is invented for a missing child. A skipped stack leaves the parent's
    Stack resource in place as an ordinary node, which is honest: the graph then
    shows a boundary it could not cross.
"""

from pathlib import Path

from parser.infra_parser import (
    extract_semantic_properties,
    flatten_properties,
    load_cloudformation_template,
    normalize,
    validate_template
)


STACK_TYPE = "AWS::CloudFormation::Stack"

TEMPLATE_URL = "TemplateURL"
PARAMETERS = "Parameters"
OUTPUTS = "Outputs"
RESOURCES = "Resources"
VALUE = "Value"

# The separator between a stack's name and a child's logical id. A dot, because
# CloudFormation ids are alphanumeric, so it cannot collide with a real one.
PREFIX_SEPARATOR = "."

# "VPC.Outputs.PublicSubnets" — the shape !GetAtt collapses to once the loader has
# turned the short form into a scalar.
OUTPUTS_MARKER = PREFIX_SEPARATOR + OUTPUTS + PREFIX_SEPARATOR

SUFFIXES = (".yaml", ".yml", ".json", ".template")

# Depth guard. Nested stacks nest, and a template that includes itself would
# otherwise recurse until the interpreter gives up.
MAX_DEPTH = 5


def index_templates(root):
    """Every template under `root`, indexed by its path relative to it.

    Built once per merge and consulted per TemplateURL, because a reference
    architecture resolves a dozen URLs against the same tree.
    """

    root = Path(root)
    index = {}

    for path in root.rglob("*"):

        if path.suffix.lower() not in SUFFIXES:
            continue

        if ".git" in path.parts:
            continue

        index[path.relative_to(root).as_posix()] = path

    return index


def resolve_template_url(url, index):
    """The local file a TemplateURL refers to, by longest matching path suffix.

    The bucket and region in the URL describe where the templates were published,
    which is not where they are being read from. The tail of the path is the
    repository layout, so the longest suffix that matches a known file wins —
    longest, so "infrastructure/vpc.yaml" is preferred over a stray "vpc.yaml"
    somewhere else in the tree.
    """

    if not isinstance(url, str):
        return None

    tail = url.split("://")[-1]
    parts = [part for part in tail.split("/") if part]

    for start in range(len(parts)):

        candidate = "/".join(parts[start:])

        if candidate in index:
            return index[candidate]

    return None


def output_target(child_template, output_name):
    """What a child's named Output resolves to, or None.

    Only a plain `!Ref` is resolved. An output built with Fn::Join or Fn::Sub is
    returned as None rather than approximated — a wrong edge is worse than a
    missing one, and graph/connection_builder is where the honest-fallback
    argument for that is written down.
    """

    outputs = child_template.get(OUTPUTS)

    if not isinstance(outputs, dict):
        return None

    entry = outputs.get(output_name)

    if not isinstance(entry, dict):
        return None

    value = entry.get(VALUE)

    return value if isinstance(value, str) else None


def prefixed(prefix, resource_id):
    """A child id under its stack's namespace."""

    return "%s%s%s" % (prefix, PREFIX_SEPARATOR, resource_id) if prefix else resource_id


def rewrite_value(value, rename):
    """One property value with any id it names rewritten, recursively."""

    if isinstance(value, str):
        return rename.get(value, value)

    if isinstance(value, list):
        return [rewrite_value(item, rename) for item in value]

    if isinstance(value, dict):
        return {key: rewrite_value(item, rename) for key, item in value.items()}

    return value


def rewrite_records(records, rename):
    """Records with every reference remapped, and semantics recomputed.

    Semantics are recomputed rather than remapped because they are keyed on
    flattened property paths, and a rewritten value can change what a path means —
    a parameter name that becomes a real resource id is the whole point of the
    substitution.
    """

    rewritten = []

    for record in records:

        raw = rewrite_value(record["raw_properties"], rename)

        rewritten.append({
            "id": record["id"],
            "type": record["type"],
            "raw_properties": raw,
            "semantic_properties": extract_semantic_properties(
                flatten_properties(raw),
                record["type"]
            )
        })

    return rewritten


def parse_merged(path, root=None, follow_stacks=True):
    """A template and everything it nests, as one flat list of records.

    Returns (records, report). The report names every stack that could not be
    resolved, because a silently skipped child is a silently missing attack path.
    """

    path = Path(path)
    root = Path(root) if root else path.parent

    index = index_templates(root)
    report = {"merged": [], "skipped": []}

    records = _merge(path, "", index, report, follow_stacks, 0, set())

    return records, report


def _merge(path, prefix, index, report, follow_stacks, depth, seen):
    """Recursive worker. `seen` holds resolved paths, so a cycle terminates."""

    resolved = Path(path).resolve()

    if resolved in seen or depth > MAX_DEPTH:
        report["skipped"].append({
            "stack": prefix or str(path),
            "reason": "cycle" if resolved in seen else "max depth"
        })
        return []

    seen = seen | {resolved}

    template = validate_template(load_cloudformation_template(str(path)))

    # -----------------------------

    own = normalize(template)

    local_ids = {record["id"] for record in own}

    rename = {
        resource_id: prefixed(prefix, resource_id)
        for resource_id in local_ids
    }

    for record in own:
        record["id"] = rename[record["id"]]

    own = rewrite_records(own, rename)

    if not follow_stacks:
        return own

    # -----------------------------

    merged = list(own)

    for stack_id, body in (template.get(RESOURCES) or {}).items():

        if not isinstance(body, dict) or body.get("Type") != STACK_TYPE:
            continue

        properties = body.get("Properties") or {}

        child_path = resolve_template_url(properties.get(TEMPLATE_URL), index)

        if child_path is None:
            report["skipped"].append({
                "stack": prefixed(prefix, stack_id),
                "reason": "TemplateURL not found on disk",
                "url": properties.get(TEMPLATE_URL)
            })
            continue

        child_prefix = prefixed(prefix, stack_id)

        child_records = _merge(
            child_path, child_prefix, index, report, follow_stacks, depth + 1, seen
        )

        if not child_records:
            continue

        # -----------------------------

        # What the parent passed in, resolved to ids in the merged namespace. This
        # is step 3 of the docstring: without it the child is an island.
        substitutions = _parameter_substitutions(
            properties.get(PARAMETERS) or {},
            prefix,
            template,
            index
        )

        merged.extend(rewrite_records(child_records, substitutions))

        report["merged"].append({
            "stack": child_prefix,
            "template": str(child_path),
            "resources": len(child_records)
        })

    return merged


def _parameter_substitutions(passed, prefix, parent_template, index):
    """child parameter name -> the merged id the parent passed for it."""

    substitutions = {}

    parent_ids = set(parent_template.get(RESOURCES) or {})

    for name, value in passed.items():

        if not isinstance(value, str):
            continue

        # !GetAtt SiblingStack.Outputs.Thing — resolve through the sibling's
        # Outputs to the resource it actually names.
        if OUTPUTS_MARKER in value:

            sibling_id, _, output_name = value.partition(OUTPUTS_MARKER)

            sibling = (parent_template.get(RESOURCES) or {}).get(sibling_id)

            if not isinstance(sibling, dict):
                continue

            sibling_url = (sibling.get("Properties") or {}).get(TEMPLATE_URL)
            sibling_path = resolve_template_url(sibling_url, index)

            if sibling_path is None:
                continue

            sibling_template = load_cloudformation_template(str(sibling_path))

            target = output_target(sibling_template, output_name)

            if target is None:
                continue

            substitutions[name] = prefixed(
                prefixed(prefix, sibling_id), target
            )

            continue

        # !Ref SomeParentResource
        if value in parent_ids:
            substitutions[name] = prefixed(prefix, value)

    return substitutions
