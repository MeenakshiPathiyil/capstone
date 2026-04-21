"""Compare base vs fine-tuned scenario generation using Gemini as a judge."""

import argparse
import json
import os
import re
import sys
import time
import textwrap
from datetime import datetime
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

try:
    from dotenv import load_dotenv
except ImportError:
    print("[!] python-dotenv not installed. Run:")
    print("    pip install python-dotenv")
    sys.exit(1)

try:
    from google import genai
except ImportError:
    print("[!] google-genai not installed. Run:")
    print("    pip install google-genai")
    sys.exit(1)


JUDGE_MODEL = "gemini-2.5-flash-lite"
MAX_NEW_TOKENS = 1200
GEMINI_CALL_DELAY = 3   # seconds to wait between each Gemini API call to avoid 429/rate-limit errors


# ─────────────────────────────────────────────
#  Logging helpers — makes output easy to read
# ─────────────────────────────────────────────

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
    """Print a big separator so you can easily find sections in long output."""
    bar = "=" * 60
    print(f"\n{bar}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{bar}", flush=True)


def log_output_preview(label: str, text: str, max_chars: int = 300) -> None:
    """
    Print the first max_chars characters of a generated output so you can
    see at a glance what the model actually produced without flooding the log.
    """
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


# ─────────────────────────────────────────────
#  API key helpers
# ─────────────────────────────────────────────

def normalize_api_key(value) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'")
    if not cleaned:
        return None
    if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", cleaned):
        return None
    return cleaned


def resolve_api_key(cli_key) -> str | None:
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
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"


# ─────────────────────────────────────────────
#  Gemini client + auth
# ─────────────────────────────────────────────

def build_judge_client(api_key: str):
    saved_google = os.environ.pop("GOOGLE_API_KEY", None)
    saved_gemini = os.environ.pop("GEMINI_API_KEY", None)
    try:
        return genai.Client(api_key=api_key)
    finally:
        if saved_google is not None:
            os.environ["GOOGLE_API_KEY"] = saved_google
        if saved_gemini is not None:
            os.environ["GEMINI_API_KEY"] = saved_gemini


def preflight_judge_auth(client) -> None:
    log(f"Sending auth precheck ping to model: {JUDGE_MODEL}")
    try:
        t0 = time.time()
        response = client.models.generate_content(
            model=JUDGE_MODEL,
            contents="Reply with exactly: ok",
        )
        elapsed = time.time() - t0
        if not response or not getattr(response, "text", None):
            raise ValueError("Empty response during Gemini auth precheck")
        log_ok(f"Auth precheck passed in {elapsed:.1f}s — model replied: '{response.text.strip()}'")
    except Exception as e:
        msg = str(e)
        if "API_KEY_INVALID" in msg or "API Key not found" in msg:
            raise RuntimeError(
                "Gemini API key was rejected. Make sure GOOGLE_API_KEY is a valid "
                "AI Studio key, not a restricted Cloud key."
            ) from e
        if "404" in msg or "not found" in msg.lower():
            raise RuntimeError(
                f"Model '{JUDGE_MODEL}' not found. Check the exact name with client.models.list(). "
                f"Original error: {msg}"
            ) from e
        raise


# ─────────────────────────────────────────────
#  Argument parsing
# ─────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate base vs fine-tuned model quality")
    parser.add_argument("--base_model", required=True)
    parser.add_argument("--adapter_path", required=True)
    parser.add_argument("--test_inputs", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--gemini_key", "--google_api_key", dest="gemini_key", default=None)
    return parser.parse_args()


def build_bnb_config() -> BitsAndBytesConfig:
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )


# ─────────────────────────────────────────────
#  Data loading
# ─────────────────────────────────────────────

def load_test_inputs(path: Path) -> list[dict]:
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                log_warn(f"Skipping malformed JSON at line {line_num}")
    if not entries:
        raise ValueError("No valid test input entries found")
    return entries


def format_prompt(instruction: str, input_text: str) -> str:
    return f"[INST] {instruction}\n\n{input_text} [/INST]"


# ─────────────────────────────────────────────
#  Local model generation
# ─────────────────────────────────────────────

def generate_text(model, tokenizer, prompt: str, label: str = "model") -> str:
    """
    Run the local model and return only the newly generated text.
    Logs token counts and generation time so you can see exactly how long
    each forward pass is taking and how many tokens were produced.
    """
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048).to(model.device)
    input_token_count = inputs["input_ids"].shape[1]
    log(f"  [{label}] Generating... input tokens={input_token_count}, max_new_tokens={MAX_NEW_TOKENS}")

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

    total_tokens = output_ids.shape[1]
    new_tokens = total_tokens - input_token_count
    tok_per_sec = new_tokens / elapsed if elapsed > 0 else 0
    log_ok(f"  [{label}] Done — {new_tokens} new tokens in {elapsed:.1f}s ({tok_per_sec:.1f} tok/s)")

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    if decoded.startswith(prompt):
        return decoded[len(prompt):].strip()
    return decoded.strip()


# ─────────────────────────────────────────────
#  Gemini judge
# ─────────────────────────────────────────────

def extract_json_block(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        return match.group(0)
    raise ValueError(f"No JSON object found in Gemini response. Raw text:\n{text[:400]}")


def parse_score_json(text: str) -> dict:
    raw_json = extract_json_block(text)
    raw_json = raw_json.replace("'", '"')
    data = json.loads(raw_json)
    required = ["level_of_detail", "technical_accuracy", "realism", "creativity", "total"]
    for key in required:
        if key not in data:
            raise ValueError(f"Missing key in score JSON: '{key}'")
        if not isinstance(data[key], int):
            data[key] = int(data[key])
    expected_total = (
        data["level_of_detail"] + data["technical_accuracy"]
        + data["realism"] + data["creativity"]
    )
    if data["total"] != expected_total:
        log_warn(f"Gemini total mismatch: reported={data['total']}, computed={expected_total}. Auto-correcting.")
        data["total"] = expected_total
    return data


def judge_scenario(client, scenario_text: str, label: str = "output") -> dict:
    """
    Ask Gemini to score a scenario. Logs the raw response so you can see
    exactly what Gemini sent back.
    """
    rubric_prompt = (
        "Score this cyber attack scenario on 4 criteria, each 1-10.\n"
        "Return ONLY valid JSON with this exact structure, no explanation, no markdown:\n"
        '{"level_of_detail": <int 1-10>, '
        '"technical_accuracy": <int 1-10>, '
        '"realism": <int 1-10>, '
        '"creativity": <int 1-10>, '
        '"total": <sum of above>}\n'
        f"Scenario to score:\n{scenario_text}"
    )

    log(f"  [gemini] Judging: {label} (scenario length: {len(scenario_text)} chars)")

    t0 = time.time()
    response = client.models.generate_content(model=JUDGE_MODEL, contents=rubric_prompt)
    elapsed = time.time() - t0

    if not response or not getattr(response, "text", None):
        raise ValueError("Empty response from Gemini judge")

    log_ok(f"  [gemini] Response received in {elapsed:.1f}s")

    # Log the raw Gemini response — useful to catch formatting issues
    raw = response.text.strip()
    log(f"  [gemini] Raw response: {raw[:200]}")

    scores = parse_score_json(raw)
    return scores


# ─────────────────────────────────────────────
#  Results table
# ─────────────────────────────────────────────

def print_table(per_entry: list[dict], base_avg: float, tuned_avg: float, improvement: float) -> None:
    log_section("FINAL RESULTS")
    header = f"{'source_id':<16}{'base_total':>12}{'finetuned_total':>18}{'delta':>10}{'winner':>12}"
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
    print(f"{'AVERAGE':<16}{base_avg:>12.2f}{tuned_avg:>18.2f}{(tuned_avg - base_avg):>10.2f}")
    improvement_label = f"+{improvement:.2f}%" if improvement >= 0 else f"{improvement:.2f}%"
    print(f"\n[OK] Overall improvement: {improvement_label}")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    try:
        log_section("STARTUP")
        run_start = time.time()

        dotenv_path = Path(__file__).resolve().parents[1] / ".env"
        if dotenv_path.exists():
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
        log(f"Test inputs: {args.test_inputs}")
        log(f"Output path: {args.out}")

        test_inputs_path = Path(args.test_inputs)
        adapter_path = Path(args.adapter_path)
        out_path = Path(args.out)

        if not test_inputs_path.exists():
            log_err(f"Test input file not found: {test_inputs_path}")
            sys.exit(1)
        if not adapter_path.exists():
            log_err(f"Adapter path not found: {adapter_path}")
            sys.exit(1)

        # ── Load test data ──────────────────────────
        log_section("LOADING TEST INPUTS")
        entries = load_test_inputs(test_inputs_path)
        log_ok(f"Loaded {len(entries)} entries from {test_inputs_path}")
        for i, e in enumerate(entries, 1):
            sid = e.get("source_id") or f"entry_{i:02d}"
            log(f"  Entry {i:>2}: source_id={sid!r}, "
                f"instruction_len={len(e.get('instruction',''))} chars, "
                f"input_len={len(e.get('input',''))} chars")

        # ── Load base model ─────────────────────────
        log_section("LOADING BASE MODEL")
        log(f"Loading {args.base_model} in 4-bit quantization (NF4)...")
        t0 = time.time()
        bnb_config = build_bnb_config()
        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
        base_model.eval()
        log_ok(f"Base model loaded in {time.time() - t0:.1f}s")
        log(f"Device map: {getattr(base_model, 'hf_device_map', 'N/A')}")

        tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
            log_warn("pad_token was None — set to eos_token")
        tokenizer.padding_side = "right"
        log_ok("Tokenizer loaded")

        # ── Load fine-tuned adapter ─────────────────
        log_section("LOADING FINE-TUNED ADAPTER")
        log(f"Loading LoRA adapter from: {adapter_path}")
        t0 = time.time()
        finetuned_model = PeftModel.from_pretrained(base_model, str(adapter_path))
        finetuned_model.eval()
        log_ok(f"Fine-tuned adapter loaded in {time.time() - t0:.1f}s")

        adapter_files = list(adapter_path.iterdir())
        log(f"Adapter directory contents ({len(adapter_files)} items):")
        for f in sorted(adapter_files):
            if f.is_file():
                size_mb = f.stat().st_size / 1e6
                log(f"  {f.name:<40} {size_mb:>8.2f} MB")
            else:
                log(f"  {f.name}/ (dir)")

        # ── Auth check ──────────────────────────────
        log_section("GEMINI AUTH CHECK")
        judge_client = build_judge_client(api_key)
        preflight_judge_auth(judge_client)

        # ── Main evaluation loop ────────────────────
        log_section("EVALUATION LOOP")
        log(f"Processing {len(entries)} entries.")
        log(f"Estimated Gemini calls: {len(entries) * 2} (2 per entry x {len(entries)} entries)")

        per_entry = []
        base_totals = []
        tuned_totals = []

        for idx, entry in enumerate(entries, start=1):
            source_id = (
                entry.get("source_id")
                or entry.get("_meta", {}).get("source_id")
                or f"entry_{idx:02d}"
            )
            instruction = entry.get("instruction", "")
            input_text = entry.get("input", "")

            print(flush=True)
            log(f"Entry {idx}/{len(entries)}: {source_id} {'─' * 35}")

            if not instruction or not input_text:
                log_warn(f"Skipping {source_id}: missing instruction or input field")
                continue

            prompt = format_prompt(instruction, input_text)
            log(f"  Prompt built — total length: {len(prompt)} chars")

            # Generate from base model
            log("  Generating from BASE model...")
            t_gen = time.time()
            base_output = generate_text(base_model, tokenizer, prompt, label="base")
            log_output_preview("BASE output", base_output)

            # Generate from fine-tuned model
            log("  Generating from FINE-TUNED model...")
            tuned_output = generate_text(finetuned_model, tokenizer, prompt, label="ft")
            log_output_preview("FINE-TUNED output", tuned_output)
            log(f"  Both generations done in {time.time() - t_gen:.1f}s total")

            # Judge base output
            log("  Asking Gemini to judge BASE output...")
            base_scores = judge_scenario(judge_client, base_output, label=f"{source_id}/base")
            log_scores("BASE scores", base_scores)
            log(f"  [gemini] Waiting {GEMINI_CALL_DELAY}s before next judge call...")
            time.sleep(GEMINI_CALL_DELAY)

            # Judge fine-tuned output
            log("  Asking Gemini to judge FINE-TUNED output...")
            tuned_scores = judge_scenario(judge_client, tuned_output, label=f"{source_id}/ft")
            log_scores("FINE-TUNED scores", tuned_scores)
            log(f"  [gemini] Waiting {GEMINI_CALL_DELAY}s before next entry...")
            time.sleep(GEMINI_CALL_DELAY)

            # Per-entry comparison
            delta = tuned_scores["total"] - base_scores["total"]
            if delta > 0:
                log_ok(f"  Fine-tuned WINS this entry by {delta} points")
            elif delta < 0:
                log_warn(f"  Base model wins this entry by {abs(delta)} points")
            else:
                log(f"  TIE for this entry")

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
        }

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        print_table(per_entry, base_avg, tuned_avg, improvement_pct)

        total_elapsed = time.time() - run_start
        log_ok(f"Saved evaluation results to: {out_path}")
        log_ok(f"Total run time: {total_elapsed / 60:.1f} minutes")

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