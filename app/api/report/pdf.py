"""Build the security assessment PDF from a saved Analysis.

    context = build_context(analysis, fix_impact, top, scenarios_by_path)
    pdf = render_pdf(context)

build_context is pure: it reads only its arguments and the repository's static
catalogs (scoring constants, objectives, technique names), so the same inputs
always describe the same report. It never computes fix impact and never asks
the model for a scenario; the caller passes in whatever is already cached.

render_pdf autoescapes every value (template names, evidence and generated text
are all untrusted) and renders with a URL fetcher that can only read files from
the packaged static directory, so nothing in a report can make WeasyPrint fetch
a remote URL or read another local file.

Native libraries: WeasyPrint needs Pango, which Homebrew installs under
/opt/homebrew/lib (Apple silicon) or /usr/local/lib (Intel). Homebrew's own
Python searches those directories already; other macOS Pythons (python.org,
uv-managed) do not, and plain `import weasyprint` fails there unless
DYLD_FALLBACK_LIBRARY_PATH names them. weasyprint() below adds the existing
Homebrew directories to that variable in os.environ before the first import.
That works in-process because cffi resolves bare library names through
ctypes.util.find_library, which reads os.environ on every call, so uvicorn
needs no environment set up by hand.
"""

import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import jinja2
import markupsafe


REPORT_DIR = Path(__file__).resolve().parent
STATIC_DIR = REPORT_DIR / "static"
TEMPLATES_DIR = REPORT_DIR / "templates"
STYLESHEET = STATIC_DIR / "report.css"

TITLE = "Attack Path Assessment"

SEVERITIES = ["critical", "high", "medium", "low", "unknown"]

# Attack levels are drawn in the colour of the matching finding severity.
LEVEL_STYLE = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium"}

# The exact wording plan section 5.4 fixes for the impact numbers.
IMPACT_LABEL = (
    "Paths no longer at or above the selected risk level after suppressing "
    "this finding."
)

IMPACT_ABSENT = "Impact estimates not included"

REFERENCE_SOURCES = {"aws_config": "AWS Config"}

# Evidence keys renamed for the reader. "evidence" lists the rule source ids of
# the findings that make the step possible.
EVIDENCE_KEYS = {"evidence": "findings"}

# Content width of an A4 page with 18 mm margins, and the slot an arrow takes
# in a chain diagram, in millimetres.
CONTENT_WIDTH_MM = 174.0
ARROW_MM = 5.0

# Boxes per chain row: one row up to this many hops, then two balanced rows.
# Short chains keep boxes at a readable width instead of stretching them.
CHAIN_ROW_MAX = 5

# Most paths detailed in one report. Rendering cost grows faster than the path
# count (78 paths took 10 s, 820 took 100 s), so a larger scope is cut here and
# the report says so; the app has every path.
MAX_REPORT_PATHS = 50
BOX_MAX_MM = 44.0

# How the contextual risk model reached a path's target, in the report's words.
REACHABILITY = {
    "direct": "direct",
    "via_path": "via path",
    "post_compromise": "after compromise"
}

# The three sections a generated scenario has, in order, as the report titles them.
SCENARIO_SECTIONS = {
    "natural_language": "Natural language",
    "mathematical": "Mathematical expression",
    "attack_graph": "Attack graph"
}

HOMEBREW_LIBRARY_DIRS = ["/opt/homebrew/lib", "/usr/local/lib"]

MIME_TYPES = {
    ".css": "text/css",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".svg": "image/svg+xml",
    ".png": "image/png"
}


# ==============================================================================
# WeasyPrint, loaded lazily
# ==============================================================================

def add_homebrew_library_path():
    """On macOS, let ctypes find Homebrew's Pango (see the module docstring)."""

    if sys.platform != "darwin":
        return

    current = [
        part for part in os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "").split(":")
        if part
    ]

    extra = [
        directory for directory in HOMEBREW_LIBRARY_DIRS
        if directory not in current and Path(directory).is_dir()
    ]

    if extra:
        os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(current + extra)


def weasyprint():
    """The weasyprint module. ImportError or OSError when it cannot load."""

    add_homebrew_library_path()

    import weasyprint as module

    return module


@lru_cache(maxsize=1)
def probe():
    """(available, reason): can this process render a PDF? Cached per process.

    Importing is not enough: a broken Pango install imports and then fails on
    the first layout, so the probe renders one tiny page.
    """

    try:
        module = weasyprint()

    except ImportError:
        return False, "WeasyPrint is not installed."

    except OSError as error:
        return False, "WeasyPrint cannot load its system libraries (%s)." % error

    try:
        module.HTML(string="<p>probe</p>").write_pdf()

    except Exception as error:  # noqa: BLE001 - any failure means unavailable
        return False, "WeasyPrint cannot render a page (%s)." % type(error).__name__

    return True, None


# ==============================================================================
# Formatting helpers
# ==============================================================================

def parse_time(value):
    """A datetime from the ISO text a saved Analysis holds, or a datetime."""

    if isinstance(value, datetime):
        moment = value
    else:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    return moment.astimezone(timezone.utc)


def long_date(moment):
    return "%d %s" % (moment.day, moment.strftime("%B %Y"))


def short_date(moment):
    return "%d %s" % (moment.day, moment.strftime("%b %Y"))


def timestamp(moment):
    return "%s, %s UTC" % (long_date(moment), moment.strftime("%H:%M"))


def number(value, places=2):
    """A float without trailing zeros past what it needs: 56.04, 30, 0.5."""

    if value is None:
        return ""

    text = ("%%.%df" % places) % float(value)

    return text.rstrip("0").rstrip(".") if "." in text else text


def plural(count, singular, many=None):
    return "%d %s" % (count, singular if count == 1 else (many or singular + "s"))


def type_label(resource_type):
    """AWS::EC2::Instance -> EC2 Instance."""

    parts = str(resource_type or "").split("::")

    if parts and parts[0] == "AWS":
        parts = parts[1:]

    return " ".join(parts) or "Unknown type"


def humanize(key):
    return str(key).replace("_", " ")


def source_label(source):
    """aws_config -> AWS Config; anything else title-cased from its id."""

    return REFERENCE_SOURCES.get(source) or humanize(source).title()


BREAK_POINTS = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[_./:,(=-])")

# A run longer than MAX_UNBROKEN with no natural break point (a hash, a long
# lowercase name) gets a hint every HINT_EVERY characters, so no id can
# overflow its box. Ordinary words are never split.
MAX_UNBROKEN = 16
HINT_EVERY = 8


def breakable(text):
    """Escaped text with <wbr> at camelCase and punctuation boundaries.

    Long ids then wrap at a word boundary (OverPermissive|InstanceProfile)
    instead of mid-word. The CSS sets overflow-wrap: normal on these, because
    WeasyPrint ignores the hints and splits mid-word under break-word.
    """

    parts = []

    for part in BREAK_POINTS.split(str(text)):

        if len(part) <= MAX_UNBROKEN:
            parts.append(part)
            continue

        parts.extend(
            part[index:index + HINT_EVERY] for index in range(0, len(part), HINT_EVERY)
        )

    return markupsafe.Markup("<wbr>").join(markupsafe.escape(part) for part in parts)


# Ids longer than this get word-boundary break hints in running text.
SOFT_ID_LENGTH = 32

# The running footer shows at most this many characters of the template name.
FOOTER_NAME_LENGTH = 48


def soft_id(text):
    """An id in running text: left whole unless it is too long for a line."""

    text = str(text)

    return breakable(text) if len(text) > SOFT_ID_LENGTH else text


def shortened(text, limit=FOOTER_NAME_LENGTH):
    """Keep the start and the end (usually the extension) of a long name."""

    text = str(text)

    if len(text) <= limit:
        return text

    tail = limit // 3

    return text[:limit - tail - 1] + "\u2026" + text[-tail:]


def slug(text, limit=60):
    """Lowercase ASCII words joined by "-", for a download filename."""

    ascii_text = (
        unicodedata.normalize("NFKD", str(text or ""))
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )

    words = re.findall(r"[a-z0-9]+", ascii_text)

    return "-".join(words)[:limit].strip("-")


def report_filename(analysis):
    """attack-path-assessment-<template>-<analysis date>.pdf, ASCII only."""

    stem = Path(str(analysis.get("input_name") or "")).stem

    date = parse_time(analysis["created_at"]).strftime("%Y-%m-%d")

    return "attack-path-assessment-%s-%s.pdf" % (slug(stem) or "template", date)


def chips(value):
    """An evidence value as a list of short strings."""

    if isinstance(value, dict):
        return ["%s: %s" % (humanize(key), item) for key, item in value.items()]

    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]

    if isinstance(value, bool):
        return ["yes" if value else "no"]

    if value is None or value == "":
        return []

    return [str(value)]


# ==============================================================================
# Scope
# ==============================================================================

def normalize_top(top, selected):
    """(scope_top, requested label). scope_top None means every selected path.

    Accepts an int, None or "all", or the query text. A count that reaches the
    selected count, or any count when nothing is selected, is the "all" scope,
    the same normalization as AnalysisService._scope, so that one scope has one
    saved fix-impact result.
    """

    if top is None or top == "all":
        return None, "all"

    value = int(top)

    if value < 1:
        raise ValueError("top must be a positive integer or \"all\"")

    if value >= selected:
        return None, "all"

    return value, str(value)


def impact_matches(fix_impact, analysis, scope_top):
    """Only an impact result for this analysis and this exact scope is used."""

    return bool(
        fix_impact
        and fix_impact.get("analysis_id") == analysis["id"]
        and fix_impact.get("scope_top") == scope_top
    )


# ==============================================================================
# Context
# ==============================================================================

def severity_styles():
    from attack_path.renderer import SEVERITY_STYLES

    return SEVERITY_STYLES


def scoring_constants():
    """The numbers the method section quotes, read from the scoring code."""

    from attack_path.path_finder import MAX_DEPTH, load_objectives
    from attack_path.scoring import (
        CRITICAL_SCORE_THRESHOLD,
        HIGH_SCORE_THRESHOLD,
        LENGTH_DAMPING_PER_HOP,
        PUBLIC_ENTRY_BOOST
    )
    from security_state_graph.semantics import (
        DEFAULT_SEVERITY_WEIGHT,
        SEVERITY_WEIGHTS
    )

    weights = [
        {"severity": severity, "weight": number(SEVERITY_WEIGHTS[severity], 1)}
        for severity in ["critical", "high", "medium", "low"]
        if severity in SEVERITY_WEIGHTS
    ]

    weights.append({"severity": "unknown", "weight": number(DEFAULT_SEVERITY_WEIGHT, 1)})

    return {
        "weights": weights,
        "objectives": [
            {
                "name": objective["name"],
                "weight": number(objective.get("base_weight") or 0.0, 1)
            }
            for objective in load_objectives()
        ],
        "damping": number(LENGTH_DAMPING_PER_HOP),
        "boost": number(PUBLIC_ENTRY_BOOST),
        "critical": number(CRITICAL_SCORE_THRESHOLD),
        "high": number(HIGH_SCORE_THRESHOLD),
        "max_depth": MAX_DEPTH
    }


def risk_constants():
    """The contextual risk model's numbers the method section quotes, read from
    risk_scoring/. They are module-private there, so this is the one place that
    reaches in."""

    from risk_scoring.graph_model.resource_metadata import CriticalityLevel
    from risk_scoring.multipliers.reach_multiplier import ReachabilityClass
    from risk_scoring.scoring import exposure_score, impact_score, path_ease, risk_scorer

    exposure = exposure_score._EXPOSURE_SCORE_BY_REACHABILITY
    base = impact_score._CRITICALITY_BASE

    return {
        "impact_exponent": number(risk_scorer._IMPACT_EXPONENT),
        "exposure_exponent": number(risk_scorer._EXPOSURE_EXPONENT),
        "ease_exponent": number(risk_scorer._PATH_EASE_EXPONENT),
        "base_unknown": number(impact_score._UNKNOWN_CRITICALITY_BASE),
        "base_high": number(base[CriticalityLevel.HIGH]),
        "base_medium": number(base[CriticalityLevel.MEDIUM]),
        "base_low": number(base[CriticalityLevel.LOW]),
        "sensitive_bonus": number(impact_score._SENSITIVE_DATA_BONUS),
        "production_bonus": number(impact_score._PRODUCTION_BONUS),
        "blast_bonus": number(impact_score._MAX_BLAST_RADIUS_BONUS),
        "direct": number(exposure[ReachabilityClass.DIRECT]),
        "via_path": number(exposure[ReachabilityClass.VIA_PATH]),
        "post_compromise": number(exposure[ReachabilityClass.POST_COMPROMISE]),
        "decay": number(path_ease._PATH_EASE_DECAY)
    }


def risk_tags(risk):
    """The target's tag-derived metadata in a few words, known values only."""

    parts = []

    if risk["environment"]:
        parts.append("environment %s" % risk["environment"])

    if risk["asset_criticality"]:
        parts.append("%s criticality" % risk["asset_criticality"])

    if risk["sensitive_data"] is not None:
        parts.append("sensitive data" if risk["sensitive_data"] else "no sensitive data")

    return "target tagged %s" % ", ".join(parts) if parts else "target not tagged"


def risk_block(risk, ranks):
    """A path's contextual risk for its one-line summary, or None without one.
    `ranks` is how many distinct ranks the analysis has."""

    if not risk:
        return None

    return {
        "score": number(risk["score"]),
        "rank": risk["rank"],
        "ranks": ranks,
        "impact": number(risk["impact"]),
        "exposure": number(risk["exposure"]),
        "path_ease": number(risk["path_ease"]),
        "reachability": REACHABILITY.get(risk["reachability"], humanize(risk["reachability"])),
        "tags": risk_tags(risk)
    }


def technique_name(technique_id):
    from engine.attack_catalog import technique_name as lookup

    try:
        return lookup(technique_id) if technique_id else ""

    except (OSError, ValueError, KeyError):
        return ""


def strip(counts, order, style_of, total=None):
    """Segments for a proportional bar plus its legend."""

    total = total if total is not None else sum(counts.get(key, 0) for key in order)

    return [
        {
            "key": key,
            "label": key,
            "count": counts.get(key, 0),
            "style": style_of(key),
            "pct": number(100.0 * counts.get(key, 0) / total, 3) if total else "0"
        }
        for key in order
    ]


ENTRY_REASON = re.compile(r"(\S+) \(([^(),]+), (\w+)\)")


def entry_reasons(resource, findings_by_id):
    """Why a resource is an entry point, as finding names where possible."""

    text = resource.get("entry_reason") or ""

    names = []

    for rule_id, _state, _severity in ENTRY_REASON.findall(text):

        finding = findings_by_id.get("%s::%s" % (resource["id"], rule_id))

        name = finding["rule"]["display_name"] if finding else rule_id

        if name not in names:
            names.append(name)

    if names:
        return names

    return [text.split(":", 1)[-1].strip() or text] if text else []


def finding_row(finding, selected_ids):
    rule = finding["rule"]

    return {
        "id": finding["id"],
        "resource": finding["resource"],
        "resource_type": type_label(finding["resource_type"]),
        "severity": finding["severity"],
        "name": rule["display_name"],
        "summary": rule["summary"],
        "rule_id": finding["rule_id"],
        "paths": len(finding["on_paths"]),
        "selected_path_ids": [p for p in finding["on_paths"] if p in selected_ids],
        "references": [
            {
                "source": source_label(reference["source"]),
                "id": reference["id"],
                "url": reference["url"]
            }
            for reference in rule["references"]
        ],
        "remediation": rule.get("remediation")
    }


def guidance_groups(rows):
    """Findings grouped by severity, then by identical remediation guidance."""

    groups = []

    for severity in SEVERITIES:

        checks = {}

        for row in rows:

            if row["severity"] != severity:
                continue

            remediation = row["remediation"] or {}

            key = (row["name"], remediation.get("fix"), remediation.get("snippet"))

            check = checks.setdefault(key, {
                "name": row["name"],
                "summary": row["summary"],
                "remediation": row["remediation"],
                "resources": [],
                "path_ids": set()
            })

            if row["resource"] not in check["resources"]:
                check["resources"].append(row["resource"])

            # Distinct paths: one path can cross two resources with this finding.
            check["path_ids"].update(row["selected_path_ids"])

        for check in checks.values():
            check["selected_paths"] = len(check.pop("path_ids"))

        if checks:
            groups.append({
                "severity": severity,
                "checks": sorted(
                    checks.values(),
                    key=lambda check: (-check["selected_paths"], check["name"])
                )
            })

    return groups


def step_row(index, step):
    technique = step.get("technique")

    requires = list(step.get("precondition") or [])

    return {
        "n": index,
        "source": step["source"],
        "target": step["target"],
        "action": step["action"],
        "tactic": step.get("tactic") or "",
        "technique": technique or "",
        "technique_name": technique_name(technique),
        "requires": requires,
        "alternatives": [
            option for option in step.get("precondition_options") or []
            if option not in requires
        ],
        "grants": list(step.get("postcondition") or []),
        "permissions": list(step.get("required_permissions") or []),
        "evidence": [
            {
                "key": EVIDENCE_KEYS.get(item["key"], humanize(item["key"])),
                "chips": chips(item["value"])
            }
            for item in step.get("evidence") or []
            if chips(item["value"])
        ],
        "fallback": bool(step.get("fallback"))
    }


def scenario_block(scenario):
    """The cached scenario's sections, with honest notes for what is missing."""

    if not scenario:
        return None

    sections_data = scenario.get("sections") or {}

    sections = []

    for field, title in SCENARIO_SECTIONS.items():

        text = sections_data.get(field)

        if text is None:
            note = "%s section not generated." % title

            if scenario.get("reached_token_cap"):
                note = note + (
                    " Generation stopped at the %d-token limit before reaching it."
                    % scenario.get("max_new_tokens", 0)
                )

            sections.append({"title": title, "text": None, "note": note})

        elif not text.strip():
            sections.append({
                "title": title, "text": None, "note": "%s section is empty." % title
            })

        else:
            sections.append({"title": title, "text": text, "note": None})

    generated = scenario.get("generated_at")

    return {
        "preamble": sections_data.get("preamble"),
        "sections": sections,
        "source": "pre-generated" if scenario.get("source") == "pregenerated" else "live",
        "model": "%s @ %s" % (
            scenario.get("model_id", "?"), str(scenario.get("model_revision", ""))[:12]
        ),
        "adapter": "%s @ %s" % (
            scenario.get("adapter_repo", "?"), str(scenario.get("adapter_revision", ""))[:12]
        ),
        "recipe": scenario.get("loading_recipe", ""),
        "prompt_version": scenario.get("prompt_version", ""),
        "tokens": "%s of %s" % (
            scenario.get("new_tokens", "?"), scenario.get("max_new_tokens", "?")
        ),
        "finish_reason": scenario.get("finish_reason", ""),
        "generated": short_date(parse_time(generated)) if generated else ""
    }


def path_block(path, resources_by_id, routes, scenario, risk_ranks=0):
    breakdown = path["breakdown"]

    hops = []

    for index, hop in enumerate(path["hops"]):

        resource = resources_by_id.get(hop) or {}

        severity = resource.get("max_severity") or "clean"

        hops.append({
            "id": hop,
            "type": type_label(resource.get("type")),
            "severity": severity,
            "severity_label": "no findings" if severity == "clean" else severity,
            "findings": len(resource.get("findings") or []),
            "entry": index == 0
        })

    # Every box has the same width. A wrapped row starts with an arrow, so the
    # width leaves room for one arrow per box.
    per_row = len(hops) if len(hops) <= CHAIN_ROW_MAX else -(-len(hops) // 2)

    box_mm = min(BOX_MAX_MM, (CONTENT_WIDTH_MM - per_row * ARROW_MM) / max(per_row, 1))

    same_route = [
        other for other in routes.get(path["chain_group"], [])
        if other != path["source_id"]
    ]

    return {
        "source_id": path["source_id"],
        "rank": path["rank"],
        "level": path["attack_level"],
        "level_style": LEVEL_STYLE[path["attack_level"]],
        "score": number(path["score"]),
        "objective": path["objective_name"],
        "objective_techniques": [
            {"id": technique, "name": technique_name(technique)}
            for technique in path["objective_techniques"]
        ],
        "entry_id": path["entry_id"],
        "target_id": path["target_id"],
        "public_entry": path["public_entry"],
        "length": path["length"],
        "hops": hops,
        # Rounded down, so rounding never pushes a box onto the next row.
        "box_mm": "%.1f" % (int(box_mm * 10) / 10.0 - 0.2),
        "breakdown": {
            "severity_total": number(breakdown["severity_total"]),
            "objective_weight": number(breakdown["objective_weight"]),
            "hops": breakdown["hops"],
            "length_factor": number(breakdown["length_factor"], 3),
            "public_entry": breakdown["public_entry"],
            "boost": number(breakdown["boost"]),
            "score": number(breakdown["score"]),
            "threshold_high": number(breakdown["threshold_high"]),
            "threshold_critical": number(breakdown["threshold_critical"])
        },
        "risk": risk_block(path.get("risk"), risk_ranks),
        "findings": len(path["finding_ids"]),
        "steps": [step_row(index + 1, step) for index, step in enumerate(path["steps"])],
        "same_route": same_route,
        "scenario": scenario_block(scenario)
    }


def impact_row(result, findings_by_id, selected_ids):
    finding = findings_by_id.get(result["finding_id"])

    row = finding_row(finding, selected_ids) if finding else {
        "id": result["finding_id"],
        "resource": result["finding_id"].split("::", 1)[0],
        "resource_type": "",
        "severity": "unknown",
        "name": result["finding_id"],
        "summary": "",
        "rule_id": "",
        "paths": 0,
        "selected_path_ids": [],
        "references": [],
        "remediation": None
    }

    row.update({
        "removed": result["selected_paths_removed"],
        "remaining": result["selected_paths_remaining"],
        "added": result["selected_paths_added"],
        "baseline": result["baseline_selected_paths"],
        "removed_ids": result["removed_ids"]
    })

    return row


def build_context(analysis, fix_impact, top, scenarios_by_path, generated_at=None):
    """Everything the template prints, computed once from saved data.

    analysis           a saved Analysis, as JSON-ready data
    fix_impact         a cached FixImpactResult for this scope, or None. A
                       result for another analysis or scope is ignored.
    top                how many selected paths to include: an int, or None or
                       "all" for every selected path. A count of at least the
                       selected count is "all".
    scenarios_by_path  {AP id: cached Scenario}; paths without one get no
                       scenario block.
    generated_at       when the report was produced (default: now, UTC)
    """

    summary = analysis["summary"]
    styles = severity_styles()

    findings_by_id = {finding["id"]: finding for finding in analysis["findings"]}
    resources_by_id = {resource["id"]: resource for resource in analysis["resources"]}

    selected_paths = [path for path in analysis["paths"] if path["exported"]]
    selected_ids = {path["source_id"] for path in selected_paths}

    selected = len(selected_paths)

    scope_top, requested = normalize_top(top, selected)

    in_scope = selected_paths if scope_top is None else selected_paths[:scope_top]
    included = in_scope[:MAX_REPORT_PATHS]

    analysed = parse_time(analysis["created_at"])
    generated = parse_time(generated_at or datetime.now(timezone.utc))

    min_level = analysis["min_level"]

    # -- impact ---------------------------------------------------------------

    impact = None

    if selected and impact_matches(fix_impact, analysis, scope_top):

        rows = [
            impact_row(result, findings_by_id, selected_ids)
            for result in fix_impact["results"]
        ]

        impact = {
            "rows": rows,
            "effective": [row for row in rows if row["removed"] or row["added"]],
            "candidate_count": fix_impact["candidate_count"],
            "scope": (
                "every selected path" if fix_impact["scope_top"] is None
                else "the top %s" % plural(fix_impact["scope_top"], "selected path")
            ),
            "computed": short_date(parse_time(fix_impact["computed_at"]))
        }

    impact_ids = {row["id"] for row in impact["rows"]} if impact else set()

    all_rows = [finding_row(finding, selected_ids) for finding in analysis["findings"]]

    # -- paths -----------------------------------------------------------------

    routes = {}

    for path in analysis["paths"]:
        if path["exported"]:
            routes.setdefault(path["chain_group"], []).append(path["source_id"])

    scenarios_by_path = scenarios_by_path or {}

    # Contextual risk ranks are dense, so the lowest is the number of distinct
    # ranks. Analyses saved before the model have none.
    risk_ranks = max(
        (path["risk"]["rank"] for path in analysis["paths"] if path.get("risk")),
        default=0
    )

    paths = [
        path_block(
            path,
            resources_by_id,
            routes,
            scenarios_by_path.get(path["source_id"]),
            risk_ranks
        )
        for path in included
    ]

    headline = [
        {
            "source_id": path["source_id"],
            "objective": path["objective_name"],
            "hops": path["hops"],
            "level": path["attack_level"],
            "level_style": LEVEL_STYLE[path["attack_level"]],
            "score": number(path["score"])
        }
        for path in selected_paths[:3]
    ]

    # -- inventory -------------------------------------------------------------

    by_type = {}

    for resource in analysis["resources"]:
        by_type[resource["type"]] = by_type.get(resource["type"], 0) + 1

    entry_points = [
        {
            "id": resource["id"],
            "type": type_label(resource["type"]),
            "severity": resource.get("max_severity") or "clean",
            "reasons": entry_reasons(resource, findings_by_id)
        }
        for resource in analysis["resources"]
        if resource["is_entry"]
    ]

    # -- sections --------------------------------------------------------------

    sections = [
        {"id": "summary", "title": "Executive summary"},
        {"id": "method", "title": "Scope, method and assumptions"},
        {"id": "inventory", "title": "Resource inventory"},
        {"id": "remediation", "title": "Prioritised remediation"}
    ]

    if paths:
        sections.append({"id": "paths", "title": "Attack paths"})

    sections.append({"id": "findings", "title": "All findings"})

    for index, section in enumerate(sections):
        section["number"] = index + 1

    numbers = {section["id"]: section["number"] for section in sections}

    return {
        "title": TITLE,
        "styles": styles,
        "levels": list(LEVEL_STYLE),
        "level_style": LEVEL_STYLE,
        "severities": SEVERITIES,
        "impact_label": IMPACT_LABEL,
        "impact_absent": IMPACT_ABSENT,
        "sections": sections,
        "numbers": numbers,
        "analysis": {
            "id": analysis["id"],
            "template": analysis["input_name"],
            "template_short": shortened(analysis["input_name"]),
            "sha256": analysis["input_sha256"],
            "industry": analysis["industry"],
            "min_level": min_level,
            "commit": analysis["analyser_commit"],
            "analysed": timestamp(analysed),
            "date": short_date(analysed),
            "generated": timestamp(generated)
        },
        "summary": summary,
        "finding_strip": strip(
            summary["findings_by_severity"], SEVERITIES, lambda key: key
        ),
        "level_strip": strip(
            summary["paths_by_level"], list(LEVEL_STYLE), lambda key: LEVEL_STYLE[key]
        ),
        "scope": {
            "requested": requested,
            "top": scope_top,
            "selected": selected,
            "included": len(paths),
            "label": (
                "No selected paths" if not selected
                else "All %s" % plural(selected, "selected path") if len(paths) == selected
                else "Top %d of %d selected paths" % (len(paths), selected)
            ),
            "cap_note": (
                "Showing the top %d of %d selected paths; see the app for the rest."
                % (len(paths), selected)
                if len(in_scope) > len(paths) else None
            )
        },
        "headline": headline,
        "impact": impact,
        "scoring": scoring_constants(),
        "risk_model": risk_constants() if risk_ranks else None,
        "warnings": analysis.get("warnings") or [],
        "nested": analysis.get("nested_report"),
        "inventory": {
            "by_type": sorted(
                [
                    {"type": resource_type, "label": type_label(resource_type), "count": count}
                    for resource_type, count in by_type.items()
                ],
                key=lambda row: (-row["count"], row["type"])
            ),
            "entry_points": entry_points
        },
        "prioritised": impact["rows"] if impact else [],
        "guidance": guidance_groups(
            [row for row in all_rows if row["id"] not in impact_ids]
        ),
        "paths": paths,
        "scenario_count": len([path for path in paths if path["scenario"]]),
        "findings": [
            {
                "severity": severity,
                "rows": sorted(
                    [row for row in all_rows if row["severity"] == severity],
                    key=lambda row: (row["resource"], row["name"])
                )
            }
            for severity in SEVERITIES
            if any(row["severity"] == severity for row in all_rows)
        ]
    }


# ==============================================================================
# Rendering
# ==============================================================================

@lru_cache(maxsize=1)
def environment():
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True
    )

    env.filters["plural"] = plural
    env.filters["breakable"] = breakable
    env.filters["soft_id"] = soft_id

    return env


def render_html(context):
    """The report as an HTML string (autoescaped)."""

    return environment().get_template("report.html.j2").render(**context)


def static_fetcher_class(module):
    """A URLFetcher that serves files under STATIC_DIR and refuses the rest."""

    root = STATIC_DIR.resolve()

    class StaticOnlyFetcher(module.urls.URLFetcher):

        def fetch(self, url, headers=None):

            if not url.startswith("file:"):
                raise ValueError("Report assets must be packaged files: %s" % url)

            from urllib.request import url2pathname

            path = Path(url2pathname(url.split("?", 1)[0].split("#", 1)[0][len("file:"):]))

            resolved = path.resolve()

            if not resolved.is_relative_to(root) or not resolved.is_file():
                raise ValueError("Not a packaged report asset: %s" % url)

            mime = MIME_TYPES.get(resolved.suffix.lower(), "application/octet-stream")

            return module.urls.URLFetcherResponse(
                resolved.as_uri(), resolved.read_bytes(), {"Content-Type": mime}
            )

    return StaticOnlyFetcher


def render_pdf(context):
    """PDF bytes for a build_context() result. Blocking; run it in a thread."""

    module = weasyprint()

    from weasyprint.text.fonts import FontConfiguration

    fetcher = static_fetcher_class(module)(allowed_protocols=["file"])

    fonts = FontConfiguration()

    base_url = STATIC_DIR.resolve().as_uri() + "/"

    stylesheet = module.CSS(
        string=STYLESHEET.read_text(encoding="utf-8"),
        base_url=base_url,
        url_fetcher=fetcher,
        font_config=fonts
    )

    document = module.HTML(
        string=render_html(context),
        base_url=base_url,
        url_fetcher=fetcher
    )

    return document.write_pdf(stylesheets=[stylesheet], font_config=fonts)
