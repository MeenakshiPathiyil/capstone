"""The local scenario cache: one validated result per file, plus path links.

Layout under the cache root (app/.cache by default):

    scenarios/<cache_key>.json            one cache entry (scenario_contract)
    scenarios/links/<analysis_id>.json    {"paths": {source_id: cache_key}}

Entries are immutable once valid: the first accepted result for a key wins and
is never overwritten by different content. Links say which entry an analysis
path shows, so a cached scenario stays readable after the live model
configuration (and so the key a new request would use) has changed.

Every write goes to a temporary file in the same directory and is moved into
place with os.replace, under an exclusive lock file so the API and
import_scenarios.py can merge into the same cache. Read failures raise
CacheError; nothing here makes up a scenario.

Standard library only, apart from the shared contract.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterator

from app.api import scenario_contract as contract
from app.api.config import make_private_dir

try:
    import fcntl
except ImportError:  # Windows: the lock degrades to atomic replaces only.
    fcntl = None


LINKS_VERSION = 1
_ANALYSIS_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class CacheError(RuntimeError):
    """A cache file that exists but cannot be read or does not validate."""


def scenarios_dir(cache_root: Path) -> Path:
    return Path(cache_root) / "scenarios"


def entry_path(cache_root: Path, key: str) -> Path:
    if not contract.is_cache_key(key):
        raise ValueError(f"not a cache key: {key!r}")
    return scenarios_dir(cache_root) / f"{key}.json"


def links_path(cache_root: Path, analysis_id: str) -> Path:
    if not isinstance(analysis_id, str) or not _ANALYSIS_ID_RE.fullmatch(analysis_id):
        raise ValueError(f"not an analysis id: {analysis_id!r}")
    return scenarios_dir(cache_root) / "links" / f"{analysis_id}.json"


@contextlib.contextmanager
def locked(cache_root: Path) -> Iterator[None]:
    """Exclusive inter-process lock for read-modify-write on the cache."""
    directory = scenarios_dir(cache_root)
    make_private_dir(directory)
    with open(directory / ".lock", "a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write_json_atomic(path: Path, value: Any) -> None:
    """Write JSON to a sibling temporary file, fsync it and replace path."""
    make_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CacheError(f"cannot read {path.name}: {exc}") from exc


def read_entry(cache_root: Path, key: str) -> dict[str, Any] | None:
    """The validated entry for key, None if absent, CacheError if unusable."""
    path = entry_path(cache_root, key)
    if not path.exists():
        return None
    entry = _read_json(path)
    try:
        contract.validate_cache_entry(entry)
    except contract.ScenarioContractError as exc:
        raise CacheError(f"invalid cache entry {path.name}: {exc}") from exc
    if entry["cache_key"] != key:
        raise CacheError(f"cache entry {path.name} holds key {entry['cache_key']}")
    return entry


def entry_matches(entry: dict[str, Any], record: dict[str, str]) -> bool:
    """True when entry was generated from exactly this export record's prompt.

    A link names a cache key; the record behind a path can change when the
    analysis is rebuilt, and then the linked scenario is about another path.
    The prompt is rebuilt in the format the entry's own prompt_version names, so
    entries of every known format keep matching; an unknown version never does.
    """
    try:
        prompt_format = contract.prompt_format_for_version(entry["request"]["prompt_version"])
        return entry["request"]["prompt"] == contract.build_prompt(record, prompt_format)
    except contract.ScenarioContractError:
        return False


def merge_entry(cache_root: Path, entry: dict[str, Any]) -> str:
    """Store a validated entry unless a valid one already holds its key.

    Returns "created", "unchanged" (identical entry already stored),
    "kept_existing" (a valid entry with different content is kept: the first
    accepted result for a key wins) or "replaced_invalid" (an unreadable or
    invalid file was replaced).
    """
    contract.validate_cache_entry(entry)
    key = entry["cache_key"]
    with locked(cache_root):
        try:
            existing = read_entry(cache_root, key)
        except CacheError:
            write_json_atomic(entry_path(cache_root, key), entry)
            return "replaced_invalid"
        if existing is None:
            write_json_atomic(entry_path(cache_root, key), entry)
            return "created"
        if contract.canonical_json(existing) == contract.canonical_json(entry):
            return "unchanged"
        return "kept_existing"


def read_links(cache_root: Path, analysis_id: str) -> dict[str, str]:
    """{source_id: cache_key} for an analysis, {} when none were recorded."""
    path = links_path(cache_root, analysis_id)
    if not path.exists():
        return {}
    data = _read_json(path)
    if (not isinstance(data, dict) or data.get("schema_version") != LINKS_VERSION
            or not isinstance(data.get("paths"), dict)
            or not all(isinstance(k, str) and contract.is_cache_key(v) for k, v in data["paths"].items())):
        raise CacheError(f"invalid links file {path.name}")
    return dict(data["paths"])


def link(cache_root: Path, analysis_id: str, source_id: str, key: str, *, replace: bool = False) -> str:
    """Record that an analysis path shows the entry for key.

    Returns "linked", "unchanged" or "kept_existing" (the path already shows a
    different entry and replace is false). The API passes replace=True after a
    new live generation; an import never takes over an existing link.
    """
    if not contract.is_cache_key(key):
        raise ValueError(f"not a cache key: {key!r}")
    path = links_path(cache_root, analysis_id)
    with locked(cache_root):
        paths = read_links(cache_root, analysis_id)
        current = paths.get(source_id)
        if current == key:
            return "unchanged"
        if current is not None and not replace:
            return "kept_existing"
        paths[source_id] = key
        write_json_atomic(path, {
            "schema_version": LINKS_VERSION,
            "analysis_id": analysis_id,
            "paths": paths,
        })
        return "linked"
