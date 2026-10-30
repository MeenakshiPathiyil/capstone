"""The scenario generation contract shared by the API, the model Space and Kaggle.

One definition of what a scenario request is and what a valid answer looks
like: the prompt, the generation settings, the cache identity, the Space
response and the section parser. The API, app/model_space/app.py and
app/scripts/pregenerate_kaggle.ipynb all use this file; the deploy and export
scripts copy it next to the code that needs it instead of keeping a second
source in git.

It must stay importable with the standard library alone. torch, transformers
and gradio never appear here, and the prompt builder in scenario_generation/ is
imported only inside build_prompt(), so the Space and the Kaggle notebook can
import this module without the repository checked out.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any


# -- Identity of the evaluated model -------------------------------------------

BASE_MODEL_ID = "mistralai/Mistral-7B-Instruct-v0.3"

# The evaluated loading recipe: 4-bit NF4 with double quantisation, compute
# dtype bf16 when the GPU supports it and fp16 otherwise, LoRA adapter attached
# and never merged (scenario_generation/fine_tuning/run_inference.py
# load_models). Any other recipe gets its own name, so its outputs get their
# own cache keys and labels.
NF4_UNMERGED = "nf4-dq-unmerged"
LOADING_RECIPES = {
    NF4_UNMERGED: "4-bit NF4, double quant, bf16/fp16 compute by GPU support, LoRA unmerged",
}

# Two prompt formats the adapter can be served with. Each has its own version
# string, which is part of every cache key and stored with every cache entry,
# so results of one format are never served as the other's.
#
#   structured-p1  the team's structured prompt: STRUCTURED_PROMPTS[0] (P1)
#                  through prompt_generator.format_model_input. Five facts
#                  lines, OBJECTIVE and a PROMPT FOCUS block. The default.
#   training       what the adapter was trained on: prompt_format.build_prompt
#                  over SYSTEM_INSTRUCTION and the five facts lines (no
#                  OBJECTIVE, no PROMPT FOCUS), token for token.
#
# Bump a version whenever the text its format produces changes; the pinned
# prompt digests in app/api/tests/test_scenario_contract.py fail until it is
# bumped. A cache entry is read with the format its own prompt_version names.
PROMPT_TEMPLATE_ID = "P1"
STRUCTURED_P1 = "structured-p1"
TRAINING = "training"
PROMPT_VERSIONS = {
    STRUCTURED_P1: "P1.v1",
    TRAINING: "training.v1",
}
DEFAULT_PROMPT_FORMAT = STRUCTURED_P1
PROMPT_VERSION = PROMPT_VERSIONS[DEFAULT_PROMPT_FORMAT]

# Version of the cache-key payload, the stored cache entry and the JSONL line
# the Kaggle notebook writes. Changing any of their shapes bumps the number.
KEY_VERSION = 1
CACHE_ENTRY_VERSION = 1
RESULT_LINE_VERSION = 1

SOURCES = ("live", "pregenerated")
FINISH_REASONS = ("eos", "length", "other")


# -- Generation settings -------------------------------------------------------

# prompt_generator.generate_text: 1200 new tokens, sampling at temperature 0.7,
# top_p 0.9, repetition penalty 1.05, stop on EOS.
MAX_NEW_TOKENS = 1200
TEMPERATURE = 0.7
TOP_P = 0.9
REPETITION_PENALTY = 1.05

# A cheap bound checked before tokenising. Real prompts are about 2,500
# characters; the Space also checks the token count against the model context.
MAX_PROMPT_CHARS = 16_000


def generation_settings(max_new_tokens: int = MAX_NEW_TOKENS) -> dict[str, Any]:
    """The generation config for one request; part of the cache identity."""
    return {
        "max_new_tokens": check_max_new_tokens(max_new_tokens),
        "do_sample": True,
        "temperature": TEMPERATURE,
        "top_p": TOP_P,
        "repetition_penalty": REPETITION_PENALTY,
        # Tokenizer behaviour, as in run_inference.py: the prompt carries its
        # own <s>, generation stops on the tokenizer's EOS id, pad falls back
        # to EOS when the tokenizer has none, the KV cache is on, and only the
        # new tokens are decoded, without special tokens, then stripped.
        "prompt_add_special_tokens": False,
        "eos_token_id": "tokenizer.eos_token_id",
        "pad_token_id": "tokenizer.pad_token_id, eos when unset",
        "use_cache": True,
        "decode": "new tokens only, skip_special_tokens, strip",
    }


def generate_kwargs(settings: dict[str, Any], eos_token_id: int, pad_token_id: int) -> dict[str, Any]:
    """model.generate() keyword arguments for a generation_settings() dict."""
    kwargs = {
        "max_new_tokens": settings["max_new_tokens"],
        "do_sample": settings["do_sample"],
        "repetition_penalty": settings["repetition_penalty"],
        "eos_token_id": eos_token_id,
        "pad_token_id": pad_token_id,
        "use_cache": settings["use_cache"],
    }
    if settings["do_sample"]:
        kwargs["temperature"] = settings["temperature"]
        kwargs["top_p"] = settings["top_p"]
    return kwargs


# -- Errors --------------------------------------------------------------------

class ScenarioContractError(ValueError):
    """A request, Space response or cache entry that breaks this contract."""


# -- Argument checks -----------------------------------------------------------

_SHA_RE = re.compile(r"[0-9a-f]{40}")
_REPO_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*")
_CACHE_KEY_RE = re.compile(r"[0-9a-f]{64}")


def is_commit_sha(value: Any) -> bool:
    """True for a full 40-character lowercase hex commit id."""
    return isinstance(value, str) and bool(_SHA_RE.fullmatch(value))


def is_repo_id(value: Any) -> bool:
    """True for an OWNER/NAME Hugging Face repo id."""
    return isinstance(value, str) and bool(_REPO_ID_RE.fullmatch(value))


def is_cache_key(value: Any) -> bool:
    return isinstance(value, str) and bool(_CACHE_KEY_RE.fullmatch(value))


def check_max_new_tokens(value: Any) -> int:
    """The token cap as an int in 1..MAX_NEW_TOKENS, or ScenarioContractError."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScenarioContractError(
            f"max_new_tokens must be an integer, got {type(value).__name__}")
    if not 1 <= value <= MAX_NEW_TOKENS:
        raise ScenarioContractError(
            f"max_new_tokens must be between 1 and {MAX_NEW_TOKENS}, got {value}")
    return value


def check_prompt(prompt: Any) -> str:
    """A non-empty prompt string within MAX_PROMPT_CHARS."""
    if not isinstance(prompt, str):
        raise ScenarioContractError(f"prompt must be a string, got {type(prompt).__name__}")
    if not prompt.strip():
        raise ScenarioContractError("prompt is empty")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ScenarioContractError(
            f"prompt is {len(prompt)} characters; the limit is {MAX_PROMPT_CHARS}")
    return prompt


# -- Prompt --------------------------------------------------------------------

def _prompt_generator():
    """scenario_generation.prompt_generator, imported on first use.

    It is stdlib-only, but it lives in the repository, which the Space and the
    Kaggle notebook do not have; they receive finished prompts instead.
    """
    from scenario_generation import prompt_generator

    return prompt_generator


def record_keys() -> tuple[str, ...]:
    """The seven export keys the prompt template reads."""
    return tuple(_prompt_generator().ATTACK_PATH_KEYS)


def validate_record(record: Any) -> dict[str, str]:
    """A seven-key export record with string values, unchanged."""
    keys = record_keys()
    if not isinstance(record, dict):
        raise ScenarioContractError(f"record must be an object, got {type(record).__name__}")
    missing = [key for key in keys if key not in record]
    extra = sorted(set(record) - set(keys))
    if missing or extra:
        raise ScenarioContractError(
            f"record must have exactly the keys {', '.join(keys)}"
            + (f"; missing {', '.join(missing)}" if missing else "")
            + (f"; unexpected {', '.join(extra)}" if extra else ""))
    not_strings = [key for key in keys if not isinstance(record[key], str)]
    if not_strings:
        raise ScenarioContractError(f"record values must be strings: {', '.join(not_strings)}")
    return record


def check_prompt_format(prompt_format: Any) -> str:
    """A known prompt format name, or ScenarioContractError."""
    if not isinstance(prompt_format, str) or prompt_format not in PROMPT_VERSIONS:
        raise ScenarioContractError(
            f"prompt format must be one of {', '.join(PROMPT_VERSIONS)}, got {prompt_format!r}")
    return prompt_format


def prompt_version_for(prompt_format: str) -> str:
    """The prompt_version string of a prompt format."""
    return PROMPT_VERSIONS[check_prompt_format(prompt_format)]


def prompt_format_for_version(prompt_version: Any) -> str:
    """The prompt format a prompt_version names, or ScenarioContractError."""
    for name, version in PROMPT_VERSIONS.items():
        if version == prompt_version:
            return name
    raise ScenarioContractError(
        f"unknown prompt_version {prompt_version!r}; known: {', '.join(PROMPT_VERSIONS.values())}")


def training_input(record: dict[str, str]) -> str:
    """The five facts lines of the training data's `input` field for a record.

    The objective is not among them: the adapter never saw it in training.
    """
    return (
        f"SOURCE: {record['source_name']} ({record['source_id']})\n"
        f"INDUSTRY: {record['industry']}\n"
        f"ATTACK LEVEL: {record['attack_level']}\n"
        f"TECHNIQUES: {record['techniques']}\n"
        f"SURFACES: {record['surfaces']}"
    )


def build_prompt(record: dict[str, str], prompt_format: str = DEFAULT_PROMPT_FORMAT) -> str:
    """The exact prompt for one export record in the named format."""
    check_prompt_format(prompt_format)
    validate_record(record)
    generator = _prompt_generator()
    if prompt_format == TRAINING:
        # The module prompt_generator itself builds with, which is the one
        # training imports.
        return check_prompt(generator.prompt_format.build_prompt({
            "instruction": generator.SYSTEM_INSTRUCTION,
            "input": training_input(record),
        }))
    template = generator.STRUCTURED_PROMPTS[0]
    if template["prompt_id"] != PROMPT_TEMPLATE_ID:
        raise ScenarioContractError(
            f"STRUCTURED_PROMPTS[0] is {template['prompt_id']}, expected {PROMPT_TEMPLATE_ID}; "
            f"update PROMPT_TEMPLATE_ID and bump PROMPT_VERSIONS[{STRUCTURED_P1!r}]")
    return check_prompt(generator.format_model_input(template, record))


# -- Provenance and cache identity ---------------------------------------------

PROVENANCE_FIELDS = (
    "model_id",
    "model_revision",
    "adapter_repo",
    "adapter_revision",
    "loading_recipe",
    "generation_config",
)


def make_provenance(
    *,
    model_revision: str,
    adapter_repo: str,
    adapter_revision: str,
    loading_recipe: str = NF4_UNMERGED,
    max_new_tokens: int = MAX_NEW_TOKENS,
) -> dict[str, Any]:
    """The model side of a request: what must produce the text, pinned."""
    provenance = {
        "model_id": BASE_MODEL_ID,
        "model_revision": model_revision,
        "adapter_repo": adapter_repo,
        "adapter_revision": adapter_revision,
        "loading_recipe": loading_recipe,
        "generation_config": generation_settings(max_new_tokens),
    }
    return validate_provenance(provenance)


def validate_provenance(provenance: Any) -> dict[str, Any]:
    """A provenance dict with pinned revisions and a known recipe, unchanged."""
    if not isinstance(provenance, dict):
        raise ScenarioContractError("provenance must be an object")
    missing = [field for field in PROVENANCE_FIELDS if field not in provenance]
    if missing:
        raise ScenarioContractError(f"provenance is missing {', '.join(missing)}")
    problems = []
    if provenance["model_id"] != BASE_MODEL_ID:
        problems.append(f"model_id must be {BASE_MODEL_ID}, got {provenance['model_id']!r}")
    for field in ("model_revision", "adapter_revision"):
        if not is_commit_sha(provenance[field]):
            problems.append(f"{field} must be a full 40-character commit SHA, got {provenance[field]!r}")
    if not is_repo_id(provenance["adapter_repo"]):
        problems.append(f"adapter_repo must look like owner/name, got {provenance['adapter_repo']!r}")
    if provenance["loading_recipe"] not in LOADING_RECIPES:
        problems.append(
            f"loading_recipe {provenance['loading_recipe']!r} is not one of {', '.join(LOADING_RECIPES)}")
    config = provenance["generation_config"]
    if not isinstance(config, dict):
        problems.append("generation_config must be an object")
    else:
        try:
            expected = generation_settings(config.get("max_new_tokens"))
        except ScenarioContractError as exc:
            problems.append(f"generation_config: {exc}")
        else:
            if config != expected:
                problems.append("generation_config differs from this contract's generation_settings()")
    if problems:
        raise ScenarioContractError("; ".join(problems))
    return provenance


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8, no NaN."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def cache_key(prompt: str, provenance: dict[str, Any], prompt_version: str = PROMPT_VERSION) -> str:
    """SHA-256 over the exact prompt, prompt version and full model provenance."""
    payload = {
        "key_version": KEY_VERSION,
        "prompt": check_prompt(prompt),
        "prompt_version": prompt_version,
        **{field: provenance[field] for field in PROVENANCE_FIELDS},
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# -- Space response ------------------------------------------------------------

RESPONSE_FIELDS = (
    "text",
    "new_tokens",
    "max_new_tokens",
    "hit_eos",
    "finish_reason",
    "seconds",
    *PROVENANCE_FIELDS,
)


def finish_reason_for(new_tokens: int, max_new_tokens: int, hit_eos: bool) -> str:
    if hit_eos:
        return "eos"
    if new_tokens >= max_new_tokens:
        return "length"
    return "other"


def reached_token_cap(new_tokens: int, max_new_tokens: int, hit_eos: bool) -> bool:
    """Confirmed truncation by the token cap. Missing headers alone never are."""
    return new_tokens >= max_new_tokens and not hit_eos


def build_response(
    *,
    text: str,
    new_tokens: int,
    hit_eos: bool,
    seconds: float,
    provenance: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The /generate response for one finished generation."""
    max_new_tokens = provenance["generation_config"]["max_new_tokens"]
    response = {
        "text": text,
        "new_tokens": new_tokens,
        "max_new_tokens": max_new_tokens,
        "hit_eos": hit_eos,
        "finish_reason": finish_reason_for(new_tokens, max_new_tokens, hit_eos),
        "seconds": round(seconds, 3),
        **{field: provenance[field] for field in PROVENANCE_FIELDS},
    }
    if extra:
        response.update({key: value for key, value in extra.items() if key not in response})
    return response


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_result(response: Any, expected_provenance: dict[str, Any]) -> dict[str, Any]:
    """The Space response if it is well formed and produced by what was requested.

    A response whose model, adapter, revisions, recipe or generation config
    differs from expected_provenance is rejected, never relabelled. Extra
    informational fields (runtime, prompt_tokens) pass through unchanged.
    """
    if not isinstance(response, dict):
        raise ScenarioContractError(f"response must be an object, got {type(response).__name__}")
    missing = [field for field in RESPONSE_FIELDS if field not in response]
    if missing:
        raise ScenarioContractError(f"response is missing {', '.join(missing)}")

    problems = []
    if not isinstance(response["text"], str):
        problems.append("text must be a string")
    if not _is_int(response["new_tokens"]) or response["new_tokens"] < 0:
        problems.append("new_tokens must be a non-negative integer")
    if not _is_int(response["max_new_tokens"]):
        problems.append("max_new_tokens must be an integer")
    if not isinstance(response["hit_eos"], bool):
        problems.append("hit_eos must be a boolean")
    if response["finish_reason"] not in FINISH_REASONS:
        problems.append(f"finish_reason must be one of {', '.join(FINISH_REASONS)}")
    seconds = response["seconds"]
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds < 0:
        problems.append("seconds must be a non-negative number")
    if problems:
        raise ScenarioContractError("malformed response: " + "; ".join(problems))

    mismatched = [
        f"{field} is {response[field]!r}, requested {expected_provenance[field]!r}"
        for field in PROVENANCE_FIELDS
        if response[field] != expected_provenance[field]
    ]
    if mismatched:
        raise ScenarioContractError("provenance mismatch: " + "; ".join(mismatched))

    if response["max_new_tokens"] != expected_provenance["generation_config"]["max_new_tokens"]:
        raise ScenarioContractError("max_new_tokens differs from the requested generation_config")
    if response["new_tokens"] > response["max_new_tokens"]:
        raise ScenarioContractError("new_tokens exceeds max_new_tokens")
    expected_reason = finish_reason_for(response["new_tokens"], response["max_new_tokens"], response["hit_eos"])
    if response["finish_reason"] != expected_reason:
        raise ScenarioContractError(
            f"finish_reason {response['finish_reason']!r} contradicts hit_eos/new_tokens "
            f"(expected {expected_reason!r})")
    return response


# -- Section parsing -----------------------------------------------------------

# The header grammar of scenario_generation/evaluation/manual_eval_metrics.py
# (SECTIONS_ORDERED and NL_TEXT_RE / MATH_TEXT_RE / GRAPH_TEXT_RE): literal,
# case-sensitive headers anywhere in the text, first occurrence wins. The
# evaluator is not imported because the Space and Kaggle do not ship it; the
# tests pin both the headers and the extracted text to the evaluator's.
SECTION_HEADERS = (
    ("natural_language", "[NATURAL LANGUAGE]"),
    ("mathematical", "[MATHEMATICAL EXPRESSION]"),
    ("attack_graph", "[ATTACK GRAPH]"),
)
_HEADER_RE = re.compile("|".join(re.escape(header) for _, header in SECTION_HEADERS))


def parse_sections(text: str) -> dict[str, Any]:
    """Split generated text into its three sections, a preamble and what is missing.

    Each section runs from the first occurrence of its header to the next
    header of any kind, or the end. For output with each header once and in
    order this is exactly what the evaluator's regexes extract; with a header
    missing or repeated it stops a section at the next header instead of
    swallowing the following sections. Text before the first header is the
    preamble and is never relabelled as the natural-language section. A
    present but empty section is "", a missing one is None and is listed in
    "missing" by field name. Missing sections say nothing about token-cap
    truncation; see reached_token_cap().
    """
    matches = list(_HEADER_RE.finditer(text))
    first = {}
    for index, match in enumerate(matches):
        first.setdefault(match.group(0), index)

    sections: dict[str, Any] = {}
    for field, header in SECTION_HEADERS:
        index = first.get(header)
        if index is None:
            sections[field] = None
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[field] = text[matches[index].end():end].strip()

    preamble = (text[:matches[0].start()] if matches else text).strip()
    sections["preamble"] = preamble or None
    sections["missing"] = [field for field, _ in SECTION_HEADERS if sections[field] is None]
    return sections


# -- Cache entries -------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ScenarioContractError("generated_at must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScenarioContractError(f"generated_at is not ISO 8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ScenarioContractError("generated_at must carry a UTC offset")
    return parsed


def make_cache_entry(
    *,
    prompt: str,
    provenance: dict[str, Any],
    response: dict[str, Any],
    source: str,
    generated_at: str | None = None,
    prompt_version: str = PROMPT_VERSION,
) -> dict[str, Any]:
    """One validated cache entry, stored as app/.cache/scenarios/<cache_key>.json."""
    entry = {
        "schema_version": CACHE_ENTRY_VERSION,
        "cache_key": cache_key(prompt, provenance, prompt_version),
        "source": source,
        "generated_at": generated_at or utc_now(),
        "request": {
            "prompt": prompt,
            "prompt_version": prompt_version,
            **{field: provenance[field] for field in PROVENANCE_FIELDS},
        },
        "response": response,
    }
    return validate_cache_entry(entry)


def validate_cache_entry(entry: Any) -> dict[str, Any]:
    """A cache entry whose key, request provenance and response all agree."""
    if not isinstance(entry, dict):
        raise ScenarioContractError("cache entry must be an object")
    if entry.get("schema_version") != CACHE_ENTRY_VERSION:
        raise ScenarioContractError(
            f"unsupported cache entry schema_version {entry.get('schema_version')!r}")
    for field in ("cache_key", "source", "generated_at", "request", "response"):
        if field not in entry:
            raise ScenarioContractError(f"cache entry is missing {field}")
    if entry["source"] not in SOURCES:
        raise ScenarioContractError(f"source must be one of {', '.join(SOURCES)}")
    _parse_utc(entry["generated_at"])
    request = entry["request"]
    if not isinstance(request, dict) or "prompt" not in request or "prompt_version" not in request:
        raise ScenarioContractError("cache entry request must hold prompt and prompt_version")
    provenance = validate_provenance({field: request.get(field) for field in PROVENANCE_FIELDS})
    expected_key = cache_key(request["prompt"], provenance, request["prompt_version"])
    if entry["cache_key"] != expected_key:
        raise ScenarioContractError(
            f"cache_key {entry['cache_key']!r} does not match its request (expected {expected_key})")
    validate_result(entry["response"], provenance)
    return entry


def scenario_payload(entry: dict[str, Any]) -> dict[str, Any]:
    """The API's Scenario fields for a validated cache entry."""
    response = entry["response"]
    request = entry["request"]
    return {
        "cache_key": entry["cache_key"],
        "source": entry["source"],
        "text": response["text"],
        "sections": parse_sections(response["text"]),
        "reached_token_cap": reached_token_cap(
            response["new_tokens"], response["max_new_tokens"], response["hit_eos"]),
        "hit_eos": response["hit_eos"],
        "new_tokens": response["new_tokens"],
        "max_new_tokens": response["max_new_tokens"],
        "finish_reason": response["finish_reason"],
        "seconds": response["seconds"],
        "model_id": response["model_id"],
        "model_revision": response["model_revision"],
        "adapter_repo": response["adapter_repo"],
        "adapter_revision": response["adapter_revision"],
        "loading_recipe": response["loading_recipe"],
        "prompt_version": request["prompt_version"],
        "generation_config": response["generation_config"],
        "generated_at": entry["generated_at"],
    }


# -- Pre-generation result lines -----------------------------------------------

def make_result_line(
    *, analysis_id: str, source_id: str, record: dict[str, str], entry: dict[str, Any]
) -> dict[str, Any]:
    """One JSONL line of a pre-generation result file."""
    return {
        "line_version": RESULT_LINE_VERSION,
        "analysis_id": analysis_id,
        "source_id": source_id,
        "record": record,
        "entry": entry,
    }
