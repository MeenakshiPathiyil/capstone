# ============================================================
# COLAB PROMPT GENERATOR — Baseline vs Fine-Tuned Comparison
# Intelligent Cloud Security Testing
# Synthetic Cyber Attack Scenario Generation
# ============================================================
#
# FILES TO UPLOAD TO COLAB  (all from fine_tuning/output/):
# ─────────────────────────────────────────────────────────────────
#   1. adapter_config.json          (~1 KB)   — LoRA config
#   2. adapter_model.safetensors    (~27 MB)  — LoRA weights  ← the important one
#   3. tokenizer.json               (~3.6 MB) — tokenizer vocab
#   4. tokenizer_config.json        (~1 KB)   — tokenizer settings
#   5. chat_template.jinja          (~4 KB)   — chat format template
#
#   Total: ~31 MB    |    Base model downloads automatically from HuggingFace.
# ─────────────────────────────────────────────────────────────────
#
# SETUP STEPS:
#   1. Open Google Colab → Runtime → Change runtime type → T4 GPU
#   2. Copy each CELL block (inside triple-quotes) into a Colab code cell.
#   3. Run cells in order: Cell 1 → 2 → 3 → 4 → 5
# ============================================================


# ╔══════════════════════════════════════════════════════════════╗
# ║  CELL 1 — Install dependencies                               ║
# ╚══════════════════════════════════════════════════════════════╝
"""
!pip install -q \
    torch>=2.1.0 \
    transformers>=4.40.0 \
    peft>=0.10.0 \
    bitsandbytes>=0.43.0 \
    accelerate>=0.28.0

import torch
print("CUDA available:", torch.cuda.is_available())
if torch.cuda.is_available():
    print("GPU:", torch.cuda.get_device_name(0))
    print("VRAM:", round(torch.cuda.get_device_properties(0).total_memory / 1e9, 1), "GB")
"""


# ╔══════════════════════════════════════════════════════════════╗
# ║  CELL 2 — Upload the 5 adapter files                         ║
# ║  Select all 5 files at once in the upload dialog:            ║
# ║    adapter_config.json                                        ║
# ║    adapter_model.safetensors                                  ║
# ║    tokenizer.json                                             ║
# ║    tokenizer_config.json                                      ║
# ║    chat_template.jinja                                        ║
# ╚══════════════════════════════════════════════════════════════╝
"""
from google.colab import files
import os

ADAPTER_DIR = "fine_tuning/output"
os.makedirs(ADAPTER_DIR, exist_ok=True)

REQUIRED_FILES = [
    "adapter_config.json",
    "adapter_model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "chat_template.jinja",
]

print("Upload dialog opening — select all 5 files at once (Ctrl+click / Cmd+click):")
uploaded = files.upload()

# Move uploaded files into the adapter directory
for fname, data in uploaded.items():
    dest = os.path.join(ADAPTER_DIR, fname)
    with open(dest, "wb") as f:
        f.write(data)
    print(f"  ✓ {fname}  ({len(data):,} bytes)  →  {dest}")

# Verify all required files are present
missing = [f for f in REQUIRED_FILES if not os.path.exists(os.path.join(ADAPTER_DIR, f))]
if missing:
    print(f"\n[!] Missing files — please re-upload: {missing}")
else:
    print(f"\n[✓] All {len(REQUIRED_FILES)} required files present in {ADAPTER_DIR}. Run Cell 3.")
"""


# ╔══════════════════════════════════════════════════════════════╗
# ║  CELL 3 — Shared config, prompts, and helpers               ║
# ╚══════════════════════════════════════════════════════════════╝
"""
import gc, csv, torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

# ── Config ────────────────────────────────────────────────────
BASE_MODEL   = "mistralai/Mistral-7B-Instruct-v0.3"
ADAPTER_PATH = "fine_tuning/output"
MAX_NEW_TOKENS = 1200

OUTPUT_CSV   = "prompt_gen_comparison.csv"
OUTPUT_TXT   = "prompt_gen_comparison.txt"

# ── System instruction — matches training data exactly ────────
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

# ── 4 Structured Prompts ──────────────────────────────────────
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

# ── Dummy Attack Path ─────────────────────────────────────────
# In the real pipeline this comes from the scored graph-path ranking module.
DUMMY_ATTACK_PATH = {
    "source_id"   : "DUMMY-MVP-001",
    "source_name" : "MVP Test Campaign",
    "industry"    : "Financial and insurance activities (ISIC K)",
    "attack_level": "HIGH",
    "techniques"  : (
        "T1190 - Exploit Public-Facing Application, "
        "T1078 - Valid Accounts, "
        "T1098.001 - Additional Cloud Credentials, "
        "T1567.002 - Exfiltration to Cloud Storage, "
        "T1486 - Data Encrypted for Impact"
    ),
    "surfaces"    : (
        "Internet-facing services / user endpoints, "
        "Internal network / cloud metadata services, "
        "OS / IAM permission model, "
        "Data egress points / cloud APIs"
    ),
}

# ── Helpers ───────────────────────────────────────────────────
def build_bnb_config():
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )

def format_model_input(prompt_entry, attack_path):
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

def generate_text(model, tokenizer, prompt):
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
    marker = "[NATURAL LANGUAGE]"
    if marker in decoded:
        return decoded[decoded.index(marker):].strip()
    return decoded.strip()

def cleanup(model=None, tokenizer=None):
    if model    is not None: del model
    if tokenizer is not None: del tokenizer
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    print("[✓] Memory cleared.\n")

print("[✓] Config and helpers loaded. Run Cell 4 next.")
"""


# ╔══════════════════════════════════════════════════════════════╗
# ║  CELL 4 — Generate: Baseline then Fine-Tuned                 ║
# ║  (runs both phases sequentially to stay within T4 VRAM)      ║
# ╚══════════════════════════════════════════════════════════════╝
"""
results = []   # will hold one dict per (prompt × model)

# ══ PHASE 1: BASELINE (base Mistral-7B, no adapter) ══════════
print("=" * 60)
print("  PHASE 1 — BASELINE Mistral-7B (no fine-tuning)")
print("=" * 60)
print("[*] Loading base model in 4-bit…")

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=build_bnb_config(),
    device_map="auto",
)
base_model.eval()

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"
print("[✓] Base model loaded.\n")

for i, prompt_entry in enumerate(STRUCTURED_PROMPTS, 1):
    pid   = prompt_entry["prompt_id"]
    focus = prompt_entry["focus"]
    print(f"[{i}/4] Baseline — Prompt {pid}: {focus}")
    full_prompt = format_model_input(prompt_entry, DUMMY_ATTACK_PATH)
    scenario    = generate_text(base_model, tokenizer, full_prompt)
    print("  Preview:", scenario[:300].replace("\n", " "), "…\n")
    results.append({
        "model"              : "baseline",
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

print("[*] Unloading baseline model…")
cleanup(base_model, tokenizer)

# ══ PHASE 2: FINE-TUNED (base + LoRA adapter) ════════════════
print("=" * 60)
print("  PHASE 2 — FINE-TUNED Mistral-7B (LoRA adapter)")
print("=" * 60)
print("[*] Loading base model in 4-bit…")

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=build_bnb_config(),
    device_map="auto",
)
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

print(f"[*] Attaching LoRA adapter from {ADAPTER_PATH}…")
finetuned_model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
finetuned_model.eval()
print("[✓] Fine-tuned model loaded.\n")

for i, prompt_entry in enumerate(STRUCTURED_PROMPTS, 1):
    pid   = prompt_entry["prompt_id"]
    focus = prompt_entry["focus"]
    print(f"[{i}/4] Fine-tuned — Prompt {pid}: {focus}")
    full_prompt = format_model_input(prompt_entry, DUMMY_ATTACK_PATH)
    scenario    = generate_text(finetuned_model, tokenizer, full_prompt)
    print("  Preview:", scenario[:300].replace("\n", " "), "…\n")
    results.append({
        "model"              : "finetuned",
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

print("[*] Unloading fine-tuned model…")
cleanup(finetuned_model, tokenizer)

# ══ SAVE CSV ══════════════════════════════════════════════════
fieldnames = ["model","prompt_id","focus","attack_path_id","industry",
              "attack_level","techniques","surfaces","full_prompt","generated_scenario"]
with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        writer.writerow(r)
print(f"[✓] CSV saved → {OUTPUT_CSV}")

# ══ SAVE TXT (side-by-side per prompt) ═══════════════════════
sep1 = "=" * 80
sep2 = "-" * 80

baseline_results  = {r["prompt_id"]: r for r in results if r["model"] == "baseline"}
finetuned_results = {r["prompt_id"]: r for r in results if r["model"] == "finetuned"}

with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
    f.write("PROMPT GENERATOR MVP — BASELINE vs FINE-TUNED COMPARISON\n")
    f.write(f"{sep1}\n\n")

    for prompt_entry in STRUCTURED_PROMPTS:
        pid   = prompt_entry["prompt_id"]
        focus = prompt_entry["focus"]
        ap    = DUMMY_ATTACK_PATH

        f.write(f"PROMPT {pid}: {focus}\n")
        f.write(f"Attack Path  : {ap['source_id']} | {ap['industry']} | {ap['attack_level']}\n")
        f.write(f"Techniques   : {ap['techniques']}\n")
        f.write(f"\n{'▶ BASELINE OUTPUT (Mistral-7B, no fine-tuning)':^80}\n{sep2}\n")
        f.write(baseline_results[pid]["generated_scenario"])
        f.write(f"\n\n{'▶ FINE-TUNED OUTPUT (Mistral-7B + LoRA adapter)':^80}\n{sep2}\n")
        f.write(finetuned_results[pid]["generated_scenario"])
        f.write(f"\n\n{sep1}\n\n")

print(f"[✓] TXT saved → {OUTPUT_TXT}")
print("\n[✓] All done! Run Cell 5 to download output files.")
"""


# ╔══════════════════════════════════════════════════════════════╗
# ║  CELL 5 — Download output files                              ║
# ╚══════════════════════════════════════════════════════════════╝
"""
from google.colab import files
files.download("prompt_gen_comparison.csv")
files.download("prompt_gen_comparison.txt")
"""
