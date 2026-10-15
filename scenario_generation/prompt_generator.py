"""prompt_generator.py"""

import argparse
import csv
import gc
import json
import sys
from pathlib import Path

# The prompt builder training uses, so generation sees the trained format.
sys.path.insert(0, str(Path(__file__).resolve().parent / "fine_tuning"))
import prompt_format  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────

BASE_MODEL_DEFAULT  = "mistralai/Mistral-7B-Instruct-v0.3"
ADAPTER_PATH_DEFAULT = "fine_tuning/output"
MAX_NEW_TOKENS       = 1200


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

ATTACK_PATH_KEYS = (
    "source_id",
    "source_name",
    "industry",
    "attack_level",
    "techniques",
    "surfaces",

    # Added with the exporter's objectives layer. The same hops are a different
    # scenario depending on what the attacker does at the end — reading a
    # database, encrypting it, or flooding it — and this is the only field that
    # says which. Without it the model would write a data-theft narrative for a
    # ransomware path.
    "objective",
)


def load_attack_paths(path: Path) -> list:
    """Load ranked attack paths from the exported JSON list, worst first."""
    if not path.exists():
        raise FileNotFoundError(
            f"attack paths file not found: {path}\n"
            "    Generate it in the infrastructure repo with:\n"
            "        python3 -m runner.graph_runner\n"
            "    then pass its output/attack_paths.json via --attack_paths."
        )

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a JSON list of attack paths, got "
            f"{type(data).__name__}"
        )

    if not data:
        raise ValueError(
            f"{path}: the export contains no attack paths. The graph found "
            "nothing exploitable — check the findings and edges upstream "
            "before generating scenarios."
        )

    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {i} is not a JSON object")
        missing = [key for key in ATTACK_PATH_KEYS if key not in entry]
        if missing:
            raise ValueError(
                f"{path}: entry {i} is missing required key(s) "
                f"{', '.join(missing)} — the prompt template reads all of "
                f"{', '.join(ATTACK_PATH_KEYS)}. Re-run the exporter."
            )

    return data


# ─────────────────────────────────────────────────────────────────────────────

def build_bnb_config():
    """4-bit QLoRA quantisation — same config used during fine-tuning."""
    import torch
    from transformers import BitsAndBytesConfig

    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )


def build_input_block(prompt_entry: dict, attack_path: dict) -> str:
    """Build the record's ``input`` block — the facts half of the prompt."""
    return (
        f"SOURCE: {attack_path['source_name']} ({attack_path['source_id']})\n"
        f"INDUSTRY: {attack_path['industry']}\n"
        f"ATTACK LEVEL: {attack_path['attack_level']}\n"
        f"TECHNIQUES: {attack_path['techniques']}\n"
        f"SURFACES: {attack_path['surfaces']}\n"
        f"OBJECTIVE: {attack_path['objective']}\n\n"
        f"PROMPT FOCUS: {prompt_entry['focus']}\n"
        f"{prompt_entry['user_context']}"
    )


def format_model_input(prompt_entry: dict, attack_path: dict) -> str:
    """The generation prompt for one (prompt, attack path) pair, in the trained format."""
    record = {
        "instruction": SYSTEM_INSTRUCTION,
        "input": build_input_block(prompt_entry, attack_path),
    }
    return prompt_format.build_prompt(record)


def generate_text(model, tokenizer, prompt_entry: dict, attack_path: dict) -> str:
    """Generate one scenario and return only the newly generated text."""
    import torch

    prompt = format_model_input(prompt_entry, attack_path)
    inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False).to(model.device)
    n = inputs["input_ids"].shape[1]

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

    return tokenizer.decode(output_ids[0][n:], skip_special_tokens=True).strip()


def cleanup_memory(model=None, tokenizer=None):
    import torch

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
        f.write("PROMPT GENERATOR — SCENARIO GENERATION OUTPUT\n")
        f.write(f"{sep}\n\n")
        for r in results:
            f.write(f"PROMPT ID    : {r['prompt_id']}\n")
            f.write(f"FOCUS        : {r['focus']}\n")
            f.write(f"ATTACK PATH  : {r['attack_path_id']} | {r['industry']} | LEVEL: {r['attack_level']}\n")
            f.write(f"TECHNIQUES   : {r['techniques']}\n")
            f.write(f"SURFACES     : {r['surfaces']}\n")
            f.write("\n--- GENERATED SCENARIO ---\n\n")
            f.write(r["generated_scenario"])
            f.write(f"\n\n{sep}\n\n")
    print(f"[✓] TXT saved  → {path}")


# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prompt Generator — tri-modal scenario generation over ranked attack paths via fine-tuned Mistral-7B"
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
        "--attack_paths",
        required=True,
        help="Path to the ranked attack paths exported by the infrastructure repo's "
             "runner/graph_runner.py (output/attack_paths.json) — a JSON list whose entries "
             "carry source_id, source_name, industry, attack_level, techniques, surfaces. "
             "Every prompt is run against every path in the file",
    )
    parser.add_argument(
        "--prompt_ids",
        nargs="+",
        default=None,
        help="Run only specific prompt IDs, e.g. --prompt_ids P1 P3  (default: all)",
    )
    parser.add_argument(
        "--path_ids",
        nargs="+",
        default=None,
        help="Run only specific attack-path source IDs, e.g. --path_ids AP-001 AP-002 "
             "(default: all paths in the file)",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    adapter_path  = Path(args.adapter_path)
    attack_paths_path = Path(args.attack_paths)
    output_csv    = Path(f"{args.output_prefix}.csv")
    output_txt    = Path(f"{args.output_prefix}.txt")

    # ── Attack paths, before anything expensive happens ───────────────────────
    try:
        attack_paths = load_attack_paths(attack_paths_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"[!] Could not load attack paths: {e}")
        sys.exit(1)

    if args.path_ids:
        wanted = set(args.path_ids)
        attack_paths = [p for p in attack_paths if p["source_id"] in wanted]
        if not attack_paths:
            print(f"[!] None of the requested path IDs {args.path_ids} matched "
                  f"{attack_paths_path}.")
            sys.exit(1)

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
    print("  PROMPT GENERATOR — Intelligent Cloud Security Testing")
    print("  Synthetic Cyber Attack Scenario Generation")
    print("=" * 70)
    print(f"  Base model   : {args.base_model}")
    print(f"  Adapter path : {adapter_path}")
    print(f"  Attack paths : {attack_paths_path} ({len(attack_paths)} paths)")
    print(f"  Output CSV   : {output_csv}")
    print(f"  Output TXT   : {output_txt}")
    print(f"  Prompts      : {[p['prompt_id'] for p in prompts_to_run]}")
    print(f"  Paths        : {[p['source_id'] for p in attack_paths]}")
    print(f"  Generations  : {len(prompts_to_run) * len(attack_paths)}")
    print("=" * 70)
    print()

    if not adapter_path.exists():
        print(f"[!] Adapter path not found: {adapter_path}")
        print("    Run this script from the scenario_generation/ directory.")
        sys.exit(1)

    # ── Load model ────────────────────────────────────────────────────────────
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if not torch.cuda.is_available():
        print("[!] WARNING: No GPU detected. Generation will be very slow on CPU.")

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
    total = len(prompts_to_run) * len(attack_paths)
    i = 0

    for attack_path in attack_paths:
        for prompt_entry in prompts_to_run:
            i += 1
            pid    = prompt_entry["prompt_id"]
            focus  = prompt_entry["focus"]

            print(f"{'─'*70}")
            print(f"[{i}/{total}] Path {attack_path['source_id']} "
                  f"({attack_path['attack_level']}) × Prompt {pid}: {focus}")
            print(f"    {attack_path['source_name']}")
            print(f"{'─'*70}")

            # Recorded for the CSV. generate_text() rebuilds it through the same
            full_prompt = format_model_input(prompt_entry, attack_path)

            print("[*] Generating scenario…")
            scenario = generate_text(
                finetuned_model, tokenizer, prompt_entry, attack_path)

            # ── Terminal preview ──────────────────────────────────────────────
            print("\n┌── GENERATED SCENARIO (preview first 600 chars) ──────────────┐")
            preview = scenario[:600] + ("\n  …[truncated]" if len(scenario) > 600 else "")
            for line in preview.splitlines():
                print(f"│  {line}")
            print("└──────────────────────────────────────────────────────────────┘\n")

            results.append({
                "prompt_id"          : pid,
                "focus"              : focus,
                "attack_path_id"     : attack_path["source_id"],
                "industry"           : attack_path["industry"],
                "attack_level"       : attack_path["attack_level"],
                "techniques"         : attack_path["techniques"],
                "surfaces"           : attack_path["surfaces"],
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
