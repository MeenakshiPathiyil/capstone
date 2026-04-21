"""Compare base vs fine-tuned scenario generation using Gemini as a judge."""

import argparse
import json
import os
import re
import sys
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


JUDGE_MODEL = "gemini-2.5-flash-lite"   # ✅ FIXED: was "gemini-2.5-flash", now using lite version
MAX_NEW_TOKENS = 1200


def normalize_api_key(value: str | None) -> str | None:
    """Clean key values and ignore empty/unexpanded placeholder inputs."""
    if value is None:
        return None

    cleaned = value.strip().strip('"').strip("'")
    if not cleaned:
        return None

    # Common notebook placeholder when shell interpolation did not occur.
    if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", cleaned):
        return None

    return cleaned


def resolve_api_key(cli_key: str | None) -> str | None:
    key = normalize_api_key(cli_key)
    if key:
        return key

    key = normalize_api_key(os.getenv("GOOGLE_API_KEY"))
    if key:
        return key

    key = normalize_api_key(os.getenv("GEMINI_API_KEY"))
    if key:
        return key

    return None


def mask_api_key(key: str) -> str:
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"


def build_judge_client(api_key: str):
    """Create Gemini client using explicit key and avoid env-precedence surprises."""
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
    """Validate Gemini auth before the expensive generation/evaluation loop."""
    print(f"[+] Running Gemini auth precheck with model: {JUDGE_MODEL}")  # ✅ FIXED: shows which model is being tested
    try:
        response = client.models.generate_content(
            model=JUDGE_MODEL,   # ✅ FIXED: was hardcoded, now uses the JUDGE_MODEL constant
            contents="Reply with exactly: ok",
        )
        if not response or not getattr(response, "text", None):
            raise ValueError("Empty response during Gemini auth precheck")
        print(f"[+] Auth precheck passed. Model responded: {response.text.strip()}")  # ✅ FIXED: confirm success
    except Exception as e:
        msg = str(e)
        if "API_KEY_INVALID" in msg or "API Key not found" in msg:
            raise RuntimeError(
                "Gemini API key was rejected. Ensure GOOGLE_API_KEY is an AI Studio Gemini key "
                "(not a restricted/non-Gemini key), and verify key restrictions in Google Cloud."
            ) from e
        if "404" in msg or "not found" in msg.lower():          # ✅ FIXED: catch wrong model name errors clearly
            raise RuntimeError(
                f"Model '{JUDGE_MODEL}' not found. Check available models with client.models.list(). "
                f"Original error: {msg}"
            ) from e
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate base vs fine-tuned model quality")
    parser.add_argument("--base_model", required=True, help="Base model path or HF name")
    parser.add_argument("--adapter_path", required=True, help="Path to LoRA adapter output folder")
    parser.add_argument("--test_inputs", required=True, help="Path to test input JSONL (10 entries)")
    parser.add_argument("--out", required=True, help="Path to save evaluation_results.json")
    parser.add_argument(
        "--gemini_key",
        "--google_api_key",
        dest="gemini_key",
        default=None,
        help="Gemini API key (optional if set in GOOGLE_API_KEY or GEMINI_API_KEY)",
    )
    return parser.parse_args()


def build_bnb_config() -> BitsAndBytesConfig:
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )


def load_test_inputs(path: Path) -> list[dict]:
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                print("[!] Skipping malformed JSON line in test inputs")
    if not entries:
        raise ValueError("No valid test input entries found")
    return entries


def format_prompt(instruction: str, input_text: str) -> str:
    return f"[INST] {instruction}\n\n{input_text} [/INST]"   # ✅ FIXED: was escaped \\n, now real newline


def generate_text(model, tokenizer, prompt: str) -> str:
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048).to(model.device)
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

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    if decoded.startswith(prompt):
        return decoded[len(prompt):].strip()
    return decoded.strip()


def extract_json_block(text: str) -> str:
    text = text.strip()

    # ✅ FIXED: strip markdown code fences that Gemini sometimes wraps around JSON
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

    if text.startswith("{") and text.endswith("}"):
        return text

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        return match.group(0)

    raise ValueError(f"No JSON object found in Gemini response. Raw text was:\n{text[:300]}")  # ✅ FIXED: show what was returned to help debug


def parse_score_json(text: str) -> dict:
    raw_json = extract_json_block(text)

    # ✅ FIXED: Gemini sometimes uses single quotes instead of double quotes in JSON
    raw_json = raw_json.replace("'", '"')

    data = json.loads(raw_json)

    required = [
        "level_of_detail",
        "technical_accuracy",
        "realism",
        "creativity",
        "total",
    ]
    for key in required:
        if key not in data:
            raise ValueError(f"Missing key in score JSON: {key}")
        if not isinstance(data[key], int):
            data[key] = int(data[key])   # ✅ FIXED: auto-convert float scores to int instead of crashing

    expected_total = (
        data["level_of_detail"]
        + data["technical_accuracy"]
        + data["realism"]
        + data["creativity"]
    )
    if data["total"] != expected_total:
        data["total"] = expected_total

    return data


def judge_scenario(client, scenario_text: str) -> dict:
    rubric_prompt = (
        "Score this cyber attack scenario on 4 criteria, each 1-10.\n"   # ✅ FIXED: real newline, not \\n
        "Return ONLY valid JSON with this exact structure, no explanation, no markdown:\n"  # ✅ FIXED: explicit instruction to avoid markdown
        '{"level_of_detail": <int 1-10>, '   # ✅ FIXED: show JSON with double quotes so model follows suit
        '"technical_accuracy": <int 1-10>, '
        '"realism": <int 1-10>, '
        '"creativity": <int 1-10>, '
        '"total": <sum of above>}\n'
        f"Scenario to score:\n{scenario_text}"
    )

    response = client.models.generate_content(
        model=JUDGE_MODEL,
        contents=rubric_prompt,
    )
    if not response or not getattr(response, "text", None):
        raise ValueError("Empty response from Gemini judge")

    return parse_score_json(response.text)


def print_table(per_entry: list[dict], base_avg: float, tuned_avg: float, improvement: float) -> None:
    print("\n[+] Score comparison per entry")
    header = f"{'source_id':<16}{'base_total':>12}{'finetuned_total':>18}{'delta':>10}"
    print(header)
    print("-" * len(header))

    for row in per_entry:
        sid = row["source_id"]
        b = row["base_scores"]["total"]
        t = row["finetuned_scores"]["total"]
        d = t - b
        print(f"{sid:<16}{b:>12}{t:>18}{d:>10}")

    print("-" * len(header))
    print(f"{'AVERAGE':<16}{base_avg:>12.2f}{tuned_avg:>18.2f}{(tuned_avg - base_avg):>10.2f}")
    print(f"[✓] Overall improvement: {improvement:.2f}%")


def main() -> None:
    args = parse_args()

    try:
        dotenv_path = Path(__file__).resolve().parents[1] / ".env"
        if dotenv_path.exists():
            load_dotenv(dotenv_path=dotenv_path, override=False)

        api_key = resolve_api_key(args.gemini_key)
        if not api_key:
            print(
                "[!] Gemini API key missing. Use --gemini_key/--google_api_key "
                "or set GOOGLE_API_KEY (or GEMINI_API_KEY) in .env"
            )
            sys.exit(1)
        print(f"[+] Resolved Gemini API key: {mask_api_key(api_key)} (len={len(api_key)})")
        print(f"[+] Judge model: {JUDGE_MODEL}")   # ✅ FIXED: print which model will be used, helpful for debugging

        test_inputs_path = Path(args.test_inputs)
        adapter_path = Path(args.adapter_path)
        out_path = Path(args.out)

        if not test_inputs_path.exists():
            print(f"[!] Test input file not found: {test_inputs_path}")
            sys.exit(1)
        if not adapter_path.exists():
            print(f"[!] Adapter path not found: {adapter_path}")
            sys.exit(1)

        print("[+] Loading test inputs")
        entries = load_test_inputs(test_inputs_path)
        print(f"[+] Loaded {len(entries)} entries")

        print(f"[+] Loading base model in 4-bit: {args.base_model}")
        bnb_config = build_bnb_config()

        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
        base_model.eval()

        tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        tokenizer.padding_side = "right"

        print(f"[+] Loading fine-tuned adapter from: {adapter_path}")
        finetuned_model = PeftModel.from_pretrained(base_model, str(adapter_path))
        finetuned_model.eval()

        print("[+] Initializing Gemini judge client")
        judge_client = build_judge_client(api_key)
        preflight_judge_auth(judge_client)

        per_entry = []
        base_totals = []
        tuned_totals = []

        for idx, entry in enumerate(entries, start=1):
            source_id = entry.get("source_id") or entry.get("_meta", {}).get("source_id") or f"entry_{idx:02d}"
            instruction = entry.get("instruction", "")
            input_text = entry.get("input", "")

            if not instruction or not input_text:
                print(f"[!] Skipping {source_id}: missing instruction/input")
                continue

            print(f"[+] ({idx}/{len(entries)}) Generating for {source_id}")
            prompt = format_prompt(instruction, input_text)

            base_output = generate_text(base_model, tokenizer, prompt)
            tuned_output = generate_text(finetuned_model, tokenizer, prompt)

            base_scores = judge_scenario(judge_client, base_output)
            tuned_scores = judge_scenario(judge_client, tuned_output)

            base_totals.append(base_scores["total"])
            tuned_totals.append(tuned_scores["total"])

            per_entry.append(
                {
                    "source_id": source_id,
                    "base_scores": base_scores,
                    "finetuned_scores": tuned_scores,
                    "base_output": base_output,
                    "finetuned_output": tuned_output,
                }
            )

        if not per_entry:
            print("[!] No entries were successfully evaluated")
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
        print(f"[✓] Saved evaluation results to: {out_path}")

    except KeyboardInterrupt:
        print("\n[!] Evaluation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Evaluation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()