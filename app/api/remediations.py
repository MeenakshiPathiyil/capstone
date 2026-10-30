"""Load data/remediations.yaml and find the entry for one finding.

The catalog is keyed by rule `source_id` (one fix per check, shared by the
resource types it covers) and by privilege escalation method id. An absent file,
an unreadable file or a partial entry is not an error here: the finding is still
reported, with `remediation: null`.
"""

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]

REMEDIATIONS_PATH = REPO_ROOT / "data" / "remediations.yaml"


def load_remediations(path=REMEDIATIONS_PATH):
    """{"rules": {source_id: entry}, "methods": {method_id: entry}}, never raising."""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)

    except (OSError, yaml.YAMLError):
        return {"rules": {}, "methods": {}}

    if not isinstance(data, dict):
        return {"rules": {}, "methods": {}}

    return {
        section: {
            str(key): entry
            for key, entry in (data.get(section) or {}).items()
            if isinstance(entry, dict)
        }
        if isinstance(data.get(section), dict) else {}
        for section in ("rules", "methods")
    }


def remediation_for(catalog, rule_id, source_id, resource_type, is_method):
    """The Remediation fields for one finding, or None when there is no usable entry.

    `by_resource_type` replaces the snippet for one CloudFormation type, because
    the same check is fixed under a different property path on each type.
    """

    if is_method:
        entry = catalog["methods"].get(rule_id)

    else:
        entry = catalog["rules"].get(source_id)

    if not entry:
        return None

    fix = entry.get("fix")
    url = entry.get("url")

    if not isinstance(fix, str) or not fix.strip():
        return None

    if not isinstance(url, str) or not url.strip():
        return None

    snippet = entry.get("snippet")

    override = (entry.get("by_resource_type") or {})

    if isinstance(override, dict) and isinstance(override.get(resource_type), dict):
        snippet = override[resource_type].get("snippet", snippet)

    return {
        "fix": " ".join(fix.split()),
        "snippet": snippet if isinstance(snippet, str) and snippet.strip() else None,
        "url": url.strip()
    }
