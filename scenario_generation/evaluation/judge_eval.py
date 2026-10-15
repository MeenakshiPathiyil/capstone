"""judge_eval.py"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Shared canonical modules from fine_tuning/ (dependency-free — they import fine
# with no ML stack installed). Same import shim as evaluate.py / make_test_inputs.py.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fine_tuning"))
import prompt_format  # noqa: E402
import data_split  # noqa: E402


# ── Constants ─────────────────────────────────────────────────────────────────

JUDGE_MODEL = "gemini-2.5-flash-lite"

MAX_NEW_TOKENS = 1280        # matches evaluate.py / run_inference.py
MAX_INPUT_TOKENS = 2048      # matches finetuning.MAX_SEQ_LEN

GEMINI_CALL_DELAY = 3        # seconds between judge calls, to stay off the 429 path
GEMINI_MAX_RETRIES = 6
GEMINI_RETRY_BASE_SECONDS = 5
GEMINI_RETRY_MAX_SECONDS = 60

# The rubric criteria, in report order. "total" is always the computed sum.
SCORE_KEYS = ("level_of_detail", "technical_accuracy", "realism", "creativity")


# ── Logging helpers — makes a 20-minute run readable ──────────────────────────

def _ts() -> str:
    """Return a short timestamp like [08:42:01] for every log line."""
    return datetime.now().strftime("[%H:%M:%S]")


def log(msg: str) -> None:
    """Standard info message."""
    print(f"{_ts()} [INFO]  {msg}", flush=True)


def log_ok(msg: str) -> None:
    """Success message."""
    print(f"{_ts()} [ OK ]  {msg}", flush=True)


def log_warn(msg: str) -> None:
    """Warning — something is off but we can continue."""
    print(f"{_ts()} [WARN]  {msg}", flush=True)


def log_err(msg: str) -> None:
    """Error — something failed."""
    print(f"{_ts()} [ERR!]  {msg}", flush=True)


def log_section(title: str) -> None:
    """Print a big separator so sections are findable in long output."""
    bar = "=" * 60
    print(f"\n{bar}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{bar}", flush=True)


def log_output_preview(label: str, text: str, max_chars: int = 300) -> None:
    """Print the first max_chars characters of a generated output, so you can see at"""
    preview = text[:max_chars].replace("\n", " ").strip()
    if len(text) > max_chars:
        preview += f"... [{len(text)} chars total]"
    print(f"{_ts()} [TEXT]  {label}: {preview}", flush=True)


def log_scores(label: str, scores: dict) -> None:
    """Pretty-print a score dict so each criterion is on its own line."""
    print(f"{_ts()} [SCORE] {label}:", flush=True)
    print(f"           detail={scores['level_of_detail']:>2}  "
          f"accuracy={scores['technical_accuracy']:>2}  "
          f"realism={scores['realism']:>2}  "
          f"creativity={scores['creativity']:>2}  "
          f"-> TOTAL={scores['total']:>2}", flush=True)


# ── API key helpers ───────────────────────────────────────────────────────────

def normalize_api_key(value) -> Optional[str]:
    """Strip quotes/whitespace; treat an unexpanded {PLACEHOLDER} as missing."""
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'")
    if not cleaned:
        return None
    if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", cleaned):
        return None
    return cleaned


def resolve_api_key(cli_key) -> Optional[str]:
    """CLI flag wins, then GOOGLE_API_KEY, then GEMINI_API_KEY."""
    key = normalize_api_key(cli_key)
    if key:
        log("API key source: --gemini_key argument")
        return key
    key = normalize_api_key(os.getenv("GOOGLE_API_KEY"))
    if key:
        log("API key source: GOOGLE_API_KEY environment variable")
        return key
    key = normalize_api_key(os.getenv("GEMINI_API_KEY"))
    if key:
        log("API key source: GEMINI_API_KEY environment variable")
        return key
    return None


def mask_api_key(key: str) -> str:
    """Never log a whole key — the logs get pasted into the report."""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"


# ── Gemini client + auth ──────────────────────────────────────────────────────

def build_judge_client(api_key: str):
    """Build the Gemini client from an explicit key."""
    from google import genai

    saved_google = os.environ.pop("GOOGLE_API_KEY", None)
    saved_gemini = os.environ.pop("GEMINI_API_KEY", None)
    try:
        return genai.Client(api_key=api_key)
    finally:
        if saved_google is not None:
            os.environ["GOOGLE_API_KEY"] = saved_google
        if saved_gemini is not None:
            os.environ["GEMINI_API_KEY"] = saved_gemini


def is_retryable_gemini_error(exc: Exception) -> bool:
    """True for transient rate-limit / unavailable errors worth backing off on."""
    msg = str(exc).upper()
    retry_tokens = [
        "503",
        "UNAVAILABLE",
        "429",
        "RESOURCE_EXHAUSTED",
        "RATE LIMIT",
        "TOO MANY REQUESTS",
    ]
    return any(token in msg for token in retry_tokens)


def gemini_generate_with_retry(client, model: str, contents: str, call_label: str):
    """Call Gemini with exponential backoff; returns (response, elapsed_seconds)."""
    last_error = None
    for attempt in range(1, GEMINI_MAX_RETRIES + 1):
        try:
            t0 = time.time()
            response = client.models.generate_content(model=model, contents=contents)
            return response, time.time() - t0
        except Exception as e:
            last_error = e
            if not is_retryable_gemini_error(e) or attempt == GEMINI_MAX_RETRIES:
                raise

            wait_s = min(GEMINI_RETRY_BASE_SECONDS * (2 ** (attempt - 1)),
                         GEMINI_RETRY_MAX_SECONDS)
            log_warn(
                f"  [gemini] {call_label} failed (attempt {attempt}/{GEMINI_MAX_RETRIES}) "
                f"with retryable error: {e}. Waiting {wait_s}s then retrying..."
            )
            time.sleep(wait_s)

    # Not reachable (the loop either returns or raises), but keeps analysers happy.
    if last_error is not None:
        raise last_error


def preflight_judge_auth(client) -> None:
    """Ping the judge model before loading 7B of weights."""
    log(f"Sending auth precheck ping to model: {JUDGE_MODEL}")
    try:
        response, elapsed = gemini_generate_with_retry(
            client=client,
            model=JUDGE_MODEL,
            contents="Reply with exactly: ok",
            call_label="auth precheck",
        )
        if not response or not getattr(response, "text", None):
            raise ValueError("Empty response during Gemini auth precheck")
        log_ok(f"Auth precheck passed in {elapsed:.1f}s — model replied: "
               f"'{response.text.strip()}'")
    except Exception as e:
        msg = str(e)
        if "API_KEY_INVALID" in msg or "API Key not found" in msg:
            raise RuntimeError(
                "Gemini API key was rejected. Make sure GOOGLE_API_KEY is a valid "
                "AI Studio key, not a restricted Cloud key."
            ) from e
        if "404" in msg or "not found" in msg.lower():
            raise RuntimeError(
                f"Model '{JUDGE_MODEL}' not found. Check the exact name with "
                f"client.models.list(). Original error: {msg}"
            ) from e
        raise


# ── Held-out test set (resolved through the ONE shared split) ─────────────────

def resolve_test_records(data_path, test_inputs_path, test_size: int = 10,
                         val_frac: float = 0.15, seed: int = 42) -> list:
    """Return the held-out records to judge."""
    data_path = Path(data_path)
    test_path = Path(test_inputs_path)

    if data_path.exists():
        split = data_split.ensure_test_inputs(
            data_path, test_path,
            test_size=test_size, val_frac=val_frac, seed=seed,
        )
        test_ids = data_split.ids_of(split["test"])
        pool_ids = data_split.ids_of(split["train"]) | data_split.ids_of(split["val"])
        if not test_ids.isdisjoint(pool_ids):
            raise ValueError(
                "Held-out test set overlaps the train/val pool — refusing to "
                "judge the fine-tune on data it was trained on."
            )
        return split["test"]

    if test_path.exists():
        records = data_split.read_test_inputs(test_path)
        if not records:
            raise ValueError(f"No valid test input entries found in {test_path}")
        return records

    raise FileNotFoundError(
        f"Neither the dataset ({data_path}) nor the held-out artifact "
        f"({test_path}) exists. Run: python evaluation/make_test_inputs.py"
    )


def record_source_id(record: dict, idx: int) -> str:
    """Stable label for one record, agreeing with data_split.source_id."""
    return (record.get("source_id")
            or (record.get("_meta") or {}).get("source_id")
            or f"entry_{idx:02d}")


# ── Prompt + local model generation ───────────────────────────────────────────

def build_eval_prompt(record: dict, tokenizer) -> str:
    """Return the generation prompt for ``record`` — the canonical one, byte for byte."""
    return prompt_format.build_chat(record, tokenizer, for_training=False)


def build_bnb_config():
    """4-bit NF4 quantization config — identical to evaluate.py's."""
    import torch
    from transformers import BitsAndBytesConfig

    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )


def load_judged_models(base_model_name: str, adapter_path):
    """Load the 4-bit base model once and attach the LoRA adapter to it."""
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    log(f"Loading {base_model_name} in 4-bit quantization (NF4)...")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        quantization_config=build_bnb_config(),
        device_map="auto",
    )
    log_ok(f"Base model loaded in {time.time() - t0:.1f}s")
    log(f"Device map: {getattr(model, 'hf_device_map', 'N/A')}")

    tokenizer = AutoTokenizer.from_pretrained(base_model_name)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        log_warn("pad_token was None — set to eos_token")
    tokenizer.padding_side = "right"
    log_ok("Tokenizer loaded")

    log(f"Attaching LoRA adapter from: {adapter_path}")
    t0 = time.time()
    model = PeftModel.from_pretrained(model, str(adapter_path))
    model.eval()
    log_ok(f"Adapter attached in {time.time() - t0:.1f}s")
    return model, tokenizer


def generate_text(model, tokenizer, record: dict, label: str = "model") -> str:
    """Run the local model on one record and return only the newly generated text."""
    import torch

    prompt = build_eval_prompt(record, tokenizer)
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True,
                       max_length=MAX_INPUT_TOKENS,
                       add_special_tokens=False).to(model.device)
    n = inputs["input_ids"].shape[1]
    log(f"  [{label}] Generating... input tokens={n}, max_new_tokens={MAX_NEW_TOKENS}")

    t0 = time.time()
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            repetition_penalty=1.05,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.pad_token_id,
        )
    elapsed = time.time() - t0

    new_tokens = output_ids.shape[1] - n
    tok_per_sec = new_tokens / elapsed if elapsed > 0 else 0
    log_ok(f"  [{label}] Done — {new_tokens} new tokens in {elapsed:.1f}s "
           f"({tok_per_sec:.1f} tok/s)")

    return tokenizer.decode(output_ids[0][n:], skip_special_tokens=True).strip()


def generate_pair(model, tokenizer, record: dict) -> tuple:
    """Return (base_output, finetuned_output) for one record from the single model."""
    log("  Generating from BASE model (adapter disabled)...")
    with model.disable_adapter():
        base_output = generate_text(model, tokenizer, record, label="base")
    log_output_preview("BASE output", base_output)

    log("  Generating from FINE-TUNED model...")
    tuned_output = generate_text(model, tokenizer, record, label="ft")
    log_output_preview("FINE-TUNED output", tuned_output)
    return base_output, tuned_output


# ── Gemini judge + score parsing ──────────────────────────────────────────────

def extract_json_block(text: str) -> Optional[str]:
    """Pull the JSON object out of a judge reply, or return None."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        return match.group(0)
    return None


def failed_scores(reason: str) -> dict:
    """A zeroed score dict carrying why it failed."""
    scores = {key: 0 for key in SCORE_KEYS}
    scores["total"] = 0
    scores["parse_error"] = reason
    return scores


def is_scored(scores: dict) -> bool:
    """True when this dict holds real judge scores (not a parse failure)."""
    return "parse_error" not in scores


def parse_score_json(text: str) -> dict:
    """Parse a judge reply into {criterion: int, ..., "total": int}."""
    raw_json = extract_json_block(text)
    if raw_json is None:
        return failed_scores(f"no JSON object in judge reply: {(text or '')[:120]!r}")

    try:
        data = json.loads(raw_json.replace("'", '"'))
    except json.JSONDecodeError as e:
        return failed_scores(f"judge reply is not valid JSON ({e})")
    if not isinstance(data, dict):
        return failed_scores(f"judge reply JSON is a {type(data).__name__}, not an object")

    scores = {}
    for key in SCORE_KEYS:
        if key not in data:
            return failed_scores(f"missing key {key!r} in score JSON")
        try:
            scores[key] = int(data[key])
        except (TypeError, ValueError):
            return failed_scores(f"non-numeric value for {key!r}: {data[key]!r}")

    computed_total = sum(scores[key] for key in SCORE_KEYS)
    try:
        reported_total = int(data.get("total", computed_total))
    except (TypeError, ValueError):
        reported_total = computed_total
    if reported_total != computed_total:
        log_warn(f"Judge total mismatch: reported={reported_total}, "
                 f"computed={computed_total}. Using the computed sum.")
    scores["total"] = computed_total
    return scores


def build_rubric_prompt(scenario_text: str) -> str:
    """The judge prompt: fixed rubric, JSON-only reply, no reference answer."""
    return (
        "Score this cyber attack scenario on 4 criteria, each 1-10.\n"
        "Return ONLY valid JSON with this exact structure, no explanation, no markdown:\n"
        '{"level_of_detail": <int 1-10>, '
        '"technical_accuracy": <int 1-10>, '
        '"realism": <int 1-10>, '
        '"creativity": <int 1-10>, '
        '"total": <sum of above>}\n'
        f"Scenario to score:\n{scenario_text}"
    )


def judge_scenario(client, scenario_text: str, label: str = "output") -> dict:
    """Ask Gemini to score one scenario. Logs the raw reply so a formatting problem"""
    log(f"  [gemini] Judging: {label} (scenario length: {len(scenario_text)} chars)")

    response, elapsed = gemini_generate_with_retry(
        client=client,
        model=JUDGE_MODEL,
        contents=build_rubric_prompt(scenario_text),
        call_label=f"judge {label}",
    )

    if not response or not getattr(response, "text", None):
        return failed_scores("empty response from Gemini judge")

    log_ok(f"  [gemini] Response received in {elapsed:.1f}s")
    raw = response.text.strip()
    log(f"  [gemini] Raw response: {raw[:200]}")
    return parse_score_json(raw)


def judge_scenario_safe(client, scenario_text: str, label: str) -> dict:
    """judge_scenario, but a transport failure degrades this entry only."""
    try:
        return judge_scenario(client, scenario_text, label=label)
    except Exception as e:
        log_err(f"  [gemini] judge call failed for {label}: {e}")
        return failed_scores(f"judge call failed: {e}")


# ── Results table ─────────────────────────────────────────────────────────────

def print_table(per_entry: list, base_avg: float, tuned_avg: float,
                improvement: float) -> None:
    """Per-entry totals, then the averages and the overall improvement."""
    log_section("FINAL RESULTS")
    header = (f"{'source_id':<16}{'base_total':>12}{'finetuned_total':>18}"
              f"{'delta':>10}{'winner':>12}")
    print(header)
    print("-" * len(header))
    for row in per_entry:
        sid = row["source_id"]
        b = row["base_scores"]["total"]
        t = row["finetuned_scores"]["total"]
        d = t - b
        winner = "fine-tuned" if d > 0 else ("base" if d < 0 else "tie")
        print(f"{sid:<16}{b:>12}{t:>18}{d:>10}{winner:>12}")
    print("-" * len(header))
    print(f"{'AVERAGE':<16}{base_avg:>12.2f}{tuned_avg:>18.2f}"
          f"{(tuned_avg - base_avg):>10.2f}")
    improvement_label = f"+{improvement:.2f}%" if improvement >= 0 else f"{improvement:.2f}%"
    print(f"\n[OK] Overall improvement: {improvement_label}")


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score base vs fine-tuned scenarios with a Gemini judge")
    parser.add_argument("--base_model", required=True,
                        help="Base model path or HF name (e.g. mistralai/Mistral-7B-Instruct-v0.3)")
    parser.add_argument("--adapter_path", required=True,
                        help="Path to the LoRA adapter output folder (e.g. fine_tuning/output)")
    parser.add_argument("--test_inputs", required=True,
                        help="Path to the shared held-out split artifact (evaluation/test_inputs.jsonl)")
    parser.add_argument("--out", required=True,
                        help="Path to save the judge scores JSON (e.g. evaluation/judge_scores.json)")
    parser.add_argument("--gemini_key", "--google_api_key", dest="gemini_key", default=None,
                        help="Gemini API key; falls back to GOOGLE_API_KEY / GEMINI_API_KEY / .env")
    parser.add_argument("--data", default="dataset/training_data.jsonl",
                        help="Full dataset JSONL the held-out split is derived from "
                             "(default: dataset/training_data.jsonl)")
    parser.add_argument("--test_size", type=int, default=10,
                        help="Number of held-out records to judge (default: 10)")
    parser.add_argument("--val_frac", type=float, default=0.15,
                        help="Validation fraction of the train pool, as used in training (default: 0.15)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Split seed; must match the training run (default: 42)")
    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    try:
        log_section("STARTUP")
        run_start = time.time()

        dotenv_path = Path(__file__).resolve().parents[1] / ".env"
        if dotenv_path.exists():
            try:
                from dotenv import load_dotenv
            except ImportError:
                log_warn("python-dotenv not installed — skipping .env "
                         "(pip install -r evaluation/requirements_eval.txt)")
            else:
                load_dotenv(dotenv_path=dotenv_path, override=False)
                log(f"Loaded .env from: {dotenv_path}")

        api_key = resolve_api_key(args.gemini_key)
        if not api_key:
            log_err("Gemini API key missing. Use --gemini_key or set GOOGLE_API_KEY.")
            sys.exit(1)

        log(f"API key: {mask_api_key(api_key)} (len={len(api_key)})")
        log(f"Judge model: {JUDGE_MODEL}")
        log(f"Gemini call delay: {GEMINI_CALL_DELAY}s between requests")
        log(f"Max new tokens: {MAX_NEW_TOKENS}")
        log(f"Base model: {args.base_model}")
        log(f"Adapter path: {args.adapter_path}")
        log(f"Dataset: {args.data}")
        log(f"Test inputs: {args.test_inputs}")
        log(f"Output path: {args.out}")

        adapter_path = Path(args.adapter_path)
        out_path = Path(args.out)

        if not adapter_path.exists():
            log_err(f"Adapter path not found: {adapter_path}")
            sys.exit(1)

        # ── Resolve the held-out set ────────────────
        log_section("RESOLVING HELD-OUT TEST SET")
        entries = resolve_test_records(
            args.data, args.test_inputs,
            test_size=args.test_size, val_frac=args.val_frac, seed=args.seed,
        )
        log_ok(f"{len(entries)} held-out entries (seed={args.seed}), "
               "disjoint from the train/val pool")
        for i, entry in enumerate(entries, start=1):
            log(f"  Entry {i:>2}: source_id={record_source_id(entry, i)!r}, "
                f"instruction_len={len(entry.get('instruction', ''))} chars, "
                f"input_len={len(entry.get('input', ''))} chars")

        # ── Gemini auth check (before loading 7B) ───
        log_section("GEMINI AUTH CHECK")
        judge_client = build_judge_client(api_key)
        preflight_judge_auth(judge_client)

        # ── Load the model + adapter ────────────────
        log_section("LOADING MODEL + ADAPTER")
        model, tokenizer = load_judged_models(args.base_model, adapter_path)

        adapter_files = sorted(p for p in adapter_path.iterdir())
        log(f"Adapter directory contents ({len(adapter_files)} items):")
        for f in adapter_files:
            if f.is_file():
                log(f"  {f.name:<40} {f.stat().st_size / 1e6:>8.2f} MB")
            else:
                log(f"  {f.name}/ (dir)")

        # ── Main evaluation loop ────────────────────
        log_section("EVALUATION LOOP")
        log(f"Processing {len(entries)} entries.")
        log(f"Estimated Gemini calls: {len(entries) * 2} (2 per entry)")

        per_entry = []
        unscored = []
        base_totals = []
        tuned_totals = []

        for idx, entry in enumerate(entries, start=1):
            source_id = record_source_id(entry, idx)
            instruction = entry.get("instruction", "")
            input_text = entry.get("input", "")

            print(flush=True)
            log(f"Entry {idx}/{len(entries)}: {source_id} {'─' * 35}")

            if not instruction or not input_text:
                log_warn(f"Skipping {source_id}: missing instruction or input field")
                unscored.append({"source_id": source_id,
                                 "reason": "missing instruction or input field"})
                continue

            t_gen = time.time()
            base_output, tuned_output = generate_pair(model, tokenizer, entry)
            log(f"  Both generations done in {time.time() - t_gen:.1f}s total")

            log("  Asking Gemini to judge BASE output...")
            base_scores = judge_scenario_safe(judge_client, base_output,
                                              label=f"{source_id}/base")
            log_scores("BASE scores", base_scores)
            log(f"  [gemini] Waiting {GEMINI_CALL_DELAY}s before next judge call...")
            time.sleep(GEMINI_CALL_DELAY)

            log("  Asking Gemini to judge FINE-TUNED output...")
            tuned_scores = judge_scenario_safe(judge_client, tuned_output,
                                               label=f"{source_id}/ft")
            log_scores("FINE-TUNED scores", tuned_scores)
            log(f"  [gemini] Waiting {GEMINI_CALL_DELAY}s before next entry...")
            time.sleep(GEMINI_CALL_DELAY)

            if not is_scored(base_scores) or not is_scored(tuned_scores):
                reason = base_scores.get("parse_error") or tuned_scores.get("parse_error")
                log_warn(f"  {source_id} left out of the averages: {reason}")
                unscored.append({"source_id": source_id, "reason": reason})
                continue

            delta = tuned_scores["total"] - base_scores["total"]
            if delta > 0:
                log_ok(f"  Fine-tuned WINS this entry by {delta} points")
            elif delta < 0:
                log_warn(f"  Base model wins this entry by {abs(delta)} points")
            else:
                log("  TIE for this entry")

            base_totals.append(base_scores["total"])
            tuned_totals.append(tuned_scores["total"])
            per_entry.append({
                "source_id": source_id,
                "base_scores": base_scores,
                "finetuned_scores": tuned_scores,
                "base_output": base_output,
                "finetuned_output": tuned_output,
            })

        # ── Final results ───────────────────────────
        if not per_entry:
            log_err("No entries were successfully evaluated. Check your test inputs.")
            sys.exit(1)

        base_avg = sum(base_totals) / len(base_totals)
        tuned_avg = sum(tuned_totals) / len(tuned_totals)
        improvement_pct = ((tuned_avg - base_avg) / base_avg * 100.0) if base_avg else 0.0

        result = {
            "summary": {
                "judge_model": JUDGE_MODEL,
                "entries_scored": len(per_entry),
                "entries_unscored": len(unscored),
                "base_model_avg": round(base_avg, 3),
                "finetuned_model_avg": round(tuned_avg, 3),
                "improvement_pct": round(improvement_pct, 3),
            },
            "per_entry": [
                {
                    "source_id": item["source_id"],
                    "base_scores": item["base_scores"],
                    "finetuned_scores": item["finetuned_scores"],
                }
                for item in per_entry
            ],
            "unscored": unscored,
        }

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        print_table(per_entry, base_avg, tuned_avg, improvement_pct)
        if unscored:
            log_warn(f"{len(unscored)} entries were not scored (see 'unscored' in {out_path})")

        log_ok(f"Saved judge results to: {out_path}")
        log_ok(f"Total run time: {(time.time() - run_start) / 60:.1f} minutes")

    except KeyboardInterrupt:
        print("\n[!] Evaluation interrupted by user")
        sys.exit(130)
    except Exception as e:
        log_err(f"Evaluation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
