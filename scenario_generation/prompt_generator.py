"""
prompt_generator.py
--------------------
MVP Prompt Generator for the Scenario Generation Module.

Pipeline:
  1. A PromptGenerator selects from 4 structured cybersec prompts.
  2. Each prompt + a dummy attack path is sent to the fine-tuned Mistral-7B
     (LoRA adapter stored in fine_tuning/output/).
  3. The generated tri-modal scenario (Natural Language + Math + Attack Graph)
     is printed to terminal and saved as both .csv and .txt.

Usage (run from scenario_generation/):
    python prompt_generator.py
    python prompt_generator.py --base_model mistralai/Mistral-7B-Instruct-v0.3 \\
                               --adapter_path fine_tuning/output \\
                               --output_prefix results/prompt_gen_output

Future extension:
    Replace STRUCTURED_PROMPTS with a fine-tuned prompt-generation LLM that
    derives context-aware prompts directly from scored attack paths.

Requirements:
    pip install torch transformers peft bitsandbytes accelerate
"""

import argparse
import csv
import gc
import os
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

BASE_MODEL_DEFAULT  = "mistralai/Mistral-7B-Instruct-v0.3"
ADAPTER_PATH_DEFAULT = "fine_tuning/output"
MAX_NEW_TOKENS       = 1200


# ─────────────────────────────────────────────────────────────────────────────
# The System Instruction — mirrors exactly what the model was trained on.
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = (
    "You are a senior cybersecurity red team expert specializing in cloud infrastructure attacks.\n"
    "Your task is to generate detailed, technically accurate cyber attack scenarios in a strict tri-modal format.\n\n"
    "CRITICAL FORMATTING RULES — follow these exactly or the output will be rejected:\n"
    "1. Your response MUST start immediately with the line: [NATURAL LANGUAGE]\n"
    "2. Do NOT use markdown. No **, no ##, no *, no backticks, no bold, no headers.\n"
    "3. The three section headers must appear EXACTLY as plain text on their own line:\n"
    "   [NATURAL LANGUAGE]\n"
    "   [MATHEMATICAL EXPRESSION]\n"
    "   [ATTACK GRAPH]\n"
    "4. Never skip a section. Never add a preamble before [NATURAL LANGUAGE]. Never add closing remarks after [ATTACK GRAPH].\n"
    "5. Use real MITRE ATT&CK technique IDs exactly as provided.\n"
    "6. The mathematical expression must follow G = (N, S, V, P, FS) notation exactly.\n"
    "7. The attack graph must list numbered stages with plain text arrows (->)."
)


# ─────────────────────────────────────────────────────────────────────────────
# Structured Prompt Library
# Each entry is a dict with:
#   "prompt_id"   : human-readable ID
#   "focus"       : short label for what angle this prompt emphasises
#   "user_context": the context block appended to the attack path, guiding tone
# ─────────────────────────────────────────────────────────────────────────────

STRUCTURED_PROMPTS = [
    {
        "prompt_id": "P1",
        "focus": "Full Tri-Modal Scenario (Standard)",
        "user_context": (
            "Generate a complete tri-modal cyber attack scenario for the attack path above.\n"
            "Produce all three sections in order:\n"
            "  [NATURAL LANGUAGE]  — A step-by-step narrative: initial access, lateral movement, "
            "privilege escalation, data exfiltration/impact. Reference each MITRE technique ID inline.\n"
            "  [MATHEMATICAL EXPRESSION] — Graph notation: N (nodes), S (security weaknesses), "
            "V (techniques), P (paths), FS (final state), using G = (N, S, V, P, FS).\n"
            "  [ATTACK GRAPH] — Numbered stages with plain-text arrows (->)."
        ),
    },
    {
        "prompt_id": "P2",
        "focus": "Cloud-Centric IAM Abuse Focus",
        "user_context": (
            "Generate a tri-modal cyber attack scenario with a deep focus on cloud IAM misconfigurations.\n"
            "In [NATURAL LANGUAGE]: emphasise how the attacker abuses IAM roles, service accounts, "
            "metadata APIs, and cloud-native privilege escalation to move from initial access to full "
            "cloud environment compromise. Reference each MITRE technique ID inline.\n"
            "In [MATHEMATICAL EXPRESSION]: model IAM roles as explicit nodes and misconfigurations as "
            "security weaknesses in the G = (N, S, V, P, FS) notation.\n"
            "In [ATTACK GRAPH]: trace each stage from endpoint to cloud control plane to final impact."
        ),
    },
    {
        "prompt_id": "P3",
        "focus": "Stealth & Persistence — APT-Style",
        "user_context": (
            "Generate a tri-modal cyber attack scenario modelled on a long-dwell APT campaign.\n"
            "In [NATURAL LANGUAGE]: emphasise how the attacker maintains stealth over weeks — "
            "slow credential harvesting, living-off-the-land techniques, log tampering, and "
            "establishing persistent backdoors — before achieving final objectives. "
            "Reference each MITRE technique ID inline.\n"
            "In [MATHEMATICAL EXPRESSION]: highlight persistence nodes and defense-evasion "
            "weaknesses within the G = (N, S, V, P, FS) notation.\n"
            "In [ATTACK GRAPH]: show the full kill chain from initial compromise through "
            "persistence, discovery, lateral movement, and final impact."
        ),
    },
    {
        "prompt_id": "P4",
        "focus": "Impact-Oriented — Ransomware / Data Exfiltration",
        "user_context": (
            "Generate a tri-modal cyber attack scenario focused on the impact phase: "
            "large-scale data exfiltration or ransomware deployment against cloud-hosted assets.\n"
            "In [NATURAL LANGUAGE]: describe initial access and lateral movement concisely, "
            "then provide rich detail on the data staging, encryption, exfiltration mechanism, "
            "and business impact (regulatory fines, reputational damage, service disruption). "
            "Reference each MITRE technique ID inline.\n"
            "In [MATHEMATICAL EXPRESSION]: include egress nodes and final-state nodes "
            "in the G = (N, S, V, P, FS) notation.\n"
            "In [ATTACK GRAPH]: ensure the final stage explicitly names the impact "
            "(e.g., Ransomware Deployment, Data Breach, Service Disruption)."
        ),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Dummy Attack Path — a realistic MITRE-based path used for MVP testing.
# In the real system this comes from the scored graph-path ranking module.
# ─────────────────────────────────────────────────────────────────────────────

DUMMY_ATTACK_PATH = {
    "source_id"    : "DUMMY-MVP-001",
    "source_name"  : "MVP Test Campaign",
    "industry"     : "Financial and insurance activities (ISIC K)",
    "attack_level" : "HIGH",
    "techniques"   : (
        "T1190 - Exploit Public-Facing Application, "
        "T1078 - Valid Accounts, "
        "T1098.001 - Additional Cloud Credentials, "
        "T1567.002 - Exfiltration to Cloud Storage, "
        "T1486 - Data Encrypted for Impact"
    ),
    "surfaces"     : (
        "Internet-facing services / user endpoints, "
        "Internal network / cloud metadata services, "
        "OS / IAM permission model, "
        "Data egress points / cloud APIs"
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_bnb_config() -> BitsAndBytesConfig:
    """4-bit QLoRA quantisation — same config used during fine-tuning."""
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )


def format_model_input(prompt_entry: dict, attack_path: dict) -> str:
    """
    Build the [INST] ... [/INST] prompt that the model expects.
    The 'input' block mirrors the training data format exactly.
    """
    input_block = (
        f"SOURCE: {attack_path['source_name']} ({attack_path['source_id']})\n"
        f"INDUSTRY: {attack_path['industry']}\n"
        f"ATTACK LEVEL: {attack_path['attack_level']}\n"
        f"TECHNIQUES: {attack_path['techniques']}\n"
        f"SURFACES: {attack_path['surfaces']}\n\n"
        f"PROMPT FOCUS: {prompt_entry['focus']}\n"
        f"{prompt_entry['user_context']}"
    )
    return f"[INST] {SYSTEM_INSTRUCTION}\n\n{input_block} [/INST]"


def generate_text(model, tokenizer, prompt: str) -> str:
    """Run greedy/sampling generation and strip the echoed prompt prefix."""
    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=2048,
    ).to(model.device)

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
    # Strip the prompt prefix that some tokeniser setups echo back
    if decoded.startswith(prompt):
        return decoded[len(prompt):].strip()
    # Fallback: strip everything before [NATURAL LANGUAGE]
    marker = "[NATURAL LANGUAGE]"
    if marker in decoded:
        return decoded[decoded.index(marker):].strip()
    return decoded.strip()


def cleanup_memory(model=None, tokenizer=None):
    if model is not None:
        del model
    if tokenizer is not None:
        del tokenizer
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def save_results_csv(results: list[dict], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["prompt_id", "focus", "attack_path_id", "industry",
                  "attack_level", "techniques", "surfaces",
                  "full_prompt", "generated_scenario"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"[✓] CSV saved  → {path}")


def save_results_txt(results: list[dict], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    sep = "=" * 80
    with path.open("w", encoding="utf-8") as f:
        f.write("PROMPT GENERATOR MVP — SCENARIO GENERATION OUTPUT\n")
        f.write(f"{sep}\n\n")
        for r in results:
            f.write(f"PROMPT ID    : {r['prompt_id']}\n")
            f.write(f"FOCUS        : {r['focus']}\n")
            f.write(f"ATTACK PATH  : {r['attack_path_id']} | {r['industry']} | LEVEL: {r['attack_level']}\n")
            f.write(f"TECHNIQUES   : {r['techniques']}\n")
            f.write(f"SURFACES     : {r['surfaces']}\n")
            f.write(f"\n--- GENERATED SCENARIO ---\n\n")
            f.write(r["generated_scenario"])
            f.write(f"\n\n{sep}\n\n")
    print(f"[✓] TXT saved  → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prompt Generator MVP — cybersec scenario generation via fine-tuned Mistral-7B"
    )
    parser.add_argument(
        "--base_model",
        default=BASE_MODEL_DEFAULT,
        help=f"Base HuggingFace model name or local path (default: {BASE_MODEL_DEFAULT})",
    )
    parser.add_argument(
        "--adapter_path",
        default=ADAPTER_PATH_DEFAULT,
        help=f"Path to LoRA adapter directory (default: {ADAPTER_PATH_DEFAULT})",
    )
    parser.add_argument(
        "--output_prefix",
        default="results/prompt_gen_output",
        help="Output file prefix — produces <prefix>.csv and <prefix>.txt (default: results/prompt_gen_output)",
    )
    parser.add_argument(
        "--prompt_ids",
        nargs="+",
        default=None,
        help="Run only specific prompt IDs, e.g. --prompt_ids P1 P3  (default: all)",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    adapter_path  = Path(args.adapter_path)
    output_csv    = Path(f"{args.output_prefix}.csv")
    output_txt    = Path(f"{args.output_prefix}.txt")

    # Filter prompt list if --prompt_ids was specified
    prompts_to_run = STRUCTURED_PROMPTS
    if args.prompt_ids:
        ids = set(args.prompt_ids)
        prompts_to_run = [p for p in STRUCTURED_PROMPTS if p["prompt_id"] in ids]
        if not prompts_to_run:
            print(f"[!] None of the requested prompt IDs {args.prompt_ids} matched. "
                  f"Available: {[p['prompt_id'] for p in STRUCTURED_PROMPTS]}")
            sys.exit(1)

    print()
    print("=" * 70)
    print("  PROMPT GENERATOR MVP — Intelligent Cloud Security Testing")
    print("  Synthetic Cyber Attack Scenario Generation")
    print("=" * 70)
    print(f"  Base model   : {args.base_model}")
    print(f"  Adapter path : {adapter_path}")
    print(f"  Output CSV   : {output_csv}")
    print(f"  Output TXT   : {output_txt}")
    print(f"  Prompts      : {[p['prompt_id'] for p in prompts_to_run]}")
    print("=" * 70)
    print()

    if not adapter_path.exists():
        print(f"[!] Adapter path not found: {adapter_path}")
        print("    Run this script from the scenario_generation/ directory.")
        sys.exit(1)

    if not torch.cuda.is_available():
        print("[!] WARNING: No GPU detected. Generation will be very slow on CPU.")

    # ── Load model ────────────────────────────────────────────────────────────
    print("[*] Loading base model in 4-bit (QLoRA)…")
    bnb_config = build_bnb_config()

    try:
        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            quantization_config=bnb_config,
            device_map="auto",
        )
    except Exception as e:
        print(f"[!] Failed to load base model: {e}")
        sys.exit(1)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    print(f"[*] Loading LoRA adapter from: {adapter_path}")
    try:
        finetuned_model = PeftModel.from_pretrained(base_model, str(adapter_path))
    except Exception as e:
        print(f"[!] Failed to load LoRA adapter: {e}")
        cleanup_memory(base_model, tokenizer)
        sys.exit(1)
    finetuned_model.eval()
    print("[✓] Model ready.\n")

    # ── Generation loop ───────────────────────────────────────────────────────
    results = []

    for i, prompt_entry in enumerate(prompts_to_run, 1):
        pid    = prompt_entry["prompt_id"]
        focus  = prompt_entry["focus"]

        print(f"{'─'*70}")
        print(f"[{i}/{len(prompts_to_run)}] Running Prompt {pid}: {focus}")
        print(f"{'─'*70}")

        full_prompt = format_model_input(prompt_entry, DUMMY_ATTACK_PATH)

        print("[*] Generating scenario…")
        scenario = generate_text(finetuned_model, tokenizer, full_prompt)

        # ── Terminal preview ──────────────────────────────────────────────────
        print("\n┌── GENERATED SCENARIO (preview first 600 chars) ──────────────┐")
        preview = scenario[:600] + ("\n  …[truncated]" if len(scenario) > 600 else "")
        for line in preview.splitlines():
            print(f"│  {line}")
        print("└──────────────────────────────────────────────────────────────┘\n")

        results.append({
            "prompt_id"          : pid,
            "focus"              : focus,
            "attack_path_id"     : DUMMY_ATTACK_PATH["source_id"],
            "industry"           : DUMMY_ATTACK_PATH["industry"],
            "attack_level"       : DUMMY_ATTACK_PATH["attack_level"],
            "techniques"         : DUMMY_ATTACK_PATH["techniques"],
            "surfaces"           : DUMMY_ATTACK_PATH["surfaces"],
            "full_prompt"        : full_prompt,
            "generated_scenario" : scenario,
        })

    # ── Cleanup ───────────────────────────────────────────────────────────────
    print("[*] Unloading model and clearing GPU cache…")
    cleanup_memory(finetuned_model, tokenizer)

    # ── Save outputs ──────────────────────────────────────────────────────────
    print("\n=== SAVING RESULTS ===")
    save_results_csv(results, output_csv)
    save_results_txt(results, output_txt)

    print("\n[✓] Done. Review the outputs in the files above.")
    print("    Compare these against baseline Mistral-7B using evaluation/evaluate.py")


if __name__ == "__main__":
    main()
