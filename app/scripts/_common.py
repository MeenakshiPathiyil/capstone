"""Paths and helpers shared by the scenario deployment and cache scripts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCRIPTS_DIR = Path(__file__).resolve().parent
APP_DIR = SCRIPTS_DIR.parent
REPO_ROOT = APP_DIR.parent
MODEL_SPACE_DIR = APP_DIR / "model_space"
CONTRACT_FILE = APP_DIR / "api" / "scenario_contract.py"

# Same default and override as app/api/config.py Settings.cache_dir.
DEFAULT_CACHE_DIR = Path(os.environ.get("CAPSTONE_CACHE_DIR") or APP_DIR / ".cache")

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class ScriptError(RuntimeError):
    """A failure reported to the user as one line, without a traceback."""


def run(main) -> None:
    """Call main(), turning ScriptError into a message and exit status 1."""
    try:
        sys.exit(main())
    except ScriptError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analysis_file(cache_dir: Path, analysis_id: str) -> Path:
    """app/.cache/analyses/<uuid>/analysis.json for a validated UUID."""
    if not _UUID_RE.fullmatch(analysis_id):
        raise ScriptError(f"not an analysis id (lowercase UUID): {analysis_id!r}")
    return Path(cache_dir) / "analyses" / analysis_id / "analysis.json"


def load_analysis(cache_dir: Path, analysis_id: str) -> dict[str, Any] | None:
    """The saved analysis as plain JSON, None when it is not in this cache."""
    path = analysis_file(cache_dir, analysis_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScriptError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("paths"), list):
        raise ScriptError(f"{path} is not a saved analysis (no paths list)")
    return data


def exported_records(analysis: dict[str, Any]) -> dict[str, dict[str, str]]:
    """{source_id: seven-key export record} for the analysis's selected paths."""
    records = {}
    for path in analysis["paths"]:
        if isinstance(path, dict) and path.get("exported") and isinstance(path.get("export"), dict):
            records[path["source_id"]] = path["export"]
    return records


def hf_api():
    """An HfApi using the token from HF_TOKEN or `hf auth login`, checked once.

    The token is never read, printed or passed here; huggingface_hub resolves
    it itself.
    """
    try:
        from huggingface_hub import HfApi
    except ImportError as exc:
        raise ScriptError("huggingface_hub is not installed: pip install huggingface_hub") from exc
    api = HfApi()
    try:
        user = api.whoami()
    except Exception as exc:
        raise ScriptError(
            "not logged in to Hugging Face: set HF_TOKEN or run `hf auth login` "
            f"({type(exc).__name__})") from exc
    print(f"Hugging Face account: {user.get('name', '?')}")
    return api
