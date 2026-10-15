"""
create_notebook.py
------------------
Run this script once locally to generate colab_prompt_gen.ipynb.

    python create_notebook.py

Then upload colab_prompt_gen.ipynb to Google Colab.
"""
import json
from pathlib import Path

# ── Cell sources ──────────────────────────────────────────────────────────────

MD_INTRO = """# Prompt Generator MVP — Baseline vs Fine-Tuned
**Intelligent Cloud Security Testing | Synthetic Cyber Attack Scenario Generation**

---

## ⚠️ Setup (BEFORE running any cell)
1. **Accelerator → GPU T4 x2** (already set if you opened this notebook with T4 x2)
2. Confirm the **finetuned** dataset is attached under **Input** (it should show `/kaggle/input/finetuned/`)
3. Run cells **in order: 1 → 2 → 3 → 4 → 5 → 6 → 7**

> The base model `mistralai/Mistral-7B-Instruct-v0.3` (~14 GB) downloads automatically from HuggingFace.
> Adapter files are loaded directly from `/kaggle/input/finetuned/` — no manual upload needed.

**Outputs** (saved to `/kaggle/working/`):
- `prompt_gen_comparison.csv`
- `prompt_gen_comparison.txt`

Download them from the **Output** tab on the right after the notebook finishes.
"""

CELL1 = """# Cell 1 — MUST run first after every session restart
# Sets PYTORCH_ALLOC_CONF before CUDA initialises — prevents OOM fragmentation
import os
os.environ['PYTORCH_ALLOC_CONF'] = 'expandable_segments:True'

import torch
print('CUDA available:', torch.cuda.is_available())
if torch.cuda.is_available():
    n_gpus = torch.cuda.device_count()
    print(f'GPUs found: {n_gpus}')
    for i in range(n_gpus):
        free, total = torch.cuda.mem_get_info(i)
        print(f'  GPU {i}: {torch.cuda.get_device_name(i)} | Free: {free/1e9:.2f} GB / {total/1e9:.2f} GB')
    free0 = torch.cuda.mem_get_info(0)[0] / 1e9
    if free0 < 10:
        print('WARNING: GPU 0 has less than 10 GB free. Consider restarting the session.')
    else:
        print('OK: Ready. Mistral-7B 4-bit needs ~4.5 GB VRAM per GPU.')
else:
    print('ERROR: No GPU detected. Enable GPU T4 x2 in Kaggle accelerator settings.')
"""

CELL2 = """# Cell 2 — Install dependencies
!pip install -q transformers>=4.40.0 peft>=0.10.0 bitsandbytes>=0.43.0 accelerate>=0.28.0
print('Done.')
"""

CELL3 = """# Cell 3 — Auto-discover adapter files inside /kaggle/input/
import os

REQUIRED_FILES = [
    'adapter_config.json',
    'adapter_model.safetensors',
    'tokenizer.json',
    'tokenizer_config.json',
    'chat_template.jinja',
]

# ── Step 1: Show full /kaggle/input/ tree (for debugging) ──────────────────
print('=== /kaggle/input/ directory tree ===')
for root, dirs, files in os.walk('/kaggle/input'):
    depth = root.replace('/kaggle/input', '').count(os.sep)
    indent = '  ' * depth
    print(f'{indent}{os.path.basename(root)}/')
    for f in files:
        print(f'{indent}  {f}')
print()

# ── Step 2: Auto-locate the directory that contains all required files ─────
def find_adapter_dir(base='/kaggle/input'):
    # Walk base and return the first dir that contains all REQUIRED_FILES
    for root, dirs, files in os.walk(base):
        if all(f in files for f in REQUIRED_FILES):
            return root
    return None

ADAPTER_DIR = find_adapter_dir()

if ADAPTER_DIR is None:
    print('ERROR: Could not find a directory containing all 5 adapter files.')
    print('Make sure the "finetuned" dataset is attached under Input.')
else:
    print(f'Found adapter files at: {ADAPTER_DIR}')
    for fname in REQUIRED_FILES:
        fpath = os.path.join(ADAPTER_DIR, fname)
        sz = os.path.getsize(fpath)
        print(f'  OK  {fname}  ({sz:,} bytes)')
    # Persist the resolved path so Cell 4 can read it
    with open('/kaggle/working/.adapter_dir', 'w') as _f:
        _f.write(ADAPTER_DIR)
    print()
    print('All 5 adapter files found. Run Cell 4.')
"""

CELL4 = """# Cell 4 — Config, prompts, and helper functions
import gc, csv, time, torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

BASE_MODEL   = 'mistralai/Mistral-7B-Instruct-v0.3'
OUTPUT_DIR   = '/kaggle/working'

# Read adapter path discovered by Cell 3
_adapter_ptr = '/kaggle/working/.adapter_dir'
if os.path.exists(_adapter_ptr):
    with open(_adapter_ptr) as _f:
        ADAPTER_PATH = _f.read().strip()
    print(f'Adapter path: {ADAPTER_PATH}')
else:
    ADAPTER_PATH = '/kaggle/input/finetuned'   # fallback
    print(f'WARNING: .adapter_dir not found, using fallback: {ADAPTER_PATH}')
MAX_NEW_TOKENS = 1200
OUTPUT_CSV     = os.path.join(OUTPUT_DIR, 'prompt_gen_comparison.csv')
OUTPUT_TXT     = os.path.join(OUTPUT_DIR, 'prompt_gen_comparison.txt')

# Mirrors the training data instruction format exactly
SYSTEM_INSTRUCTION = '''You are a senior cybersecurity red team expert specializing in cloud infrastructure attacks.
Your task is to generate detailed, technically accurate cyber attack scenarios in a strict tri-modal format.

CRITICAL FORMATTING RULES:
1. Your response MUST start immediately with the line: [NATURAL LANGUAGE]
2. Do NOT use markdown. No **, no ##, no *, no backticks, no bold, no headers.
3. The three section headers must appear EXACTLY as plain text on their own line:
   [NATURAL LANGUAGE]
   [MATHEMATICAL EXPRESSION]
   [ATTACK GRAPH]
4. Never skip a section. Never add a preamble before [NATURAL LANGUAGE].
5. Use real MITRE ATT&CK technique IDs exactly as provided.
6. The mathematical expression must follow G = (N, S, V, P, FS) notation exactly.
7. The attack graph must list numbered stages with plain text arrows (->) .'''

STRUCTURED_PROMPTS = [
    {
        'prompt_id': 'P1',
        'focus': 'Full Tri-Modal Scenario (Standard)',
        'user_context': '''Generate a complete tri-modal cyber attack scenario for the attack path above.
Produce all three sections:
  [NATURAL LANGUAGE]  - Step-by-step narrative referencing each MITRE technique ID inline.
  [MATHEMATICAL EXPRESSION] - G = (N, S, V, P, FS) notation.
  [ATTACK GRAPH] - Numbered stages with plain-text arrows (->) .'''
    },
    {
        'prompt_id': 'P2',
        'focus': 'Cloud-Centric IAM Abuse',
        'user_context': '''Generate a tri-modal scenario focused on cloud IAM misconfigurations.
In [NATURAL LANGUAGE]: detail IAM role abuse, service account compromise, and metadata API exploitation.
Reference each MITRE technique ID inline.
In [MATHEMATICAL EXPRESSION]: model IAM roles as explicit nodes in G = (N, S, V, P, FS).
In [ATTACK GRAPH]: trace each stage from endpoint to cloud control plane to final impact.'''
    },
    {
        'prompt_id': 'P3',
        'focus': 'Stealth and Persistence (APT-Style)',
        'user_context': '''Generate a tri-modal scenario modelled on a long-dwell APT campaign.
In [NATURAL LANGUAGE]: describe slow credential harvesting, living-off-the-land techniques,
log tampering, and persistent backdoors. Reference each MITRE technique ID inline.
In [MATHEMATICAL EXPRESSION]: highlight persistence nodes in G = (N, S, V, P, FS).
In [ATTACK GRAPH]: full kill chain from initial compromise to final impact.'''
    },
    {
        'prompt_id': 'P4',
        'focus': 'Impact - Ransomware / Data Exfiltration',
        'user_context': '''Generate a tri-modal scenario focused on the impact phase.
In [NATURAL LANGUAGE]: brief initial access, then rich detail on data staging,
encryption, exfiltration, and business impact. Reference each MITRE technique ID inline.
In [MATHEMATICAL EXPRESSION]: include egress nodes in G = (N, S, V, P, FS).
In [ATTACK GRAPH]: name the final stage explicitly (e.g. Ransomware Deployment, Data Breach).'''
    },
]

# Dummy attack path — replace with real scored paths once graph module is complete
DUMMY_ATTACK_PATH = {
    'source_id'   : 'DUMMY-MVP-001',
    'source_name' : 'MVP Test Campaign',
    'industry'    : 'Financial and insurance activities (ISIC K)',
    'attack_level': 'HIGH',
    'techniques'  : (
        'T1190 - Exploit Public-Facing Application, '
        'T1078 - Valid Accounts, '
        'T1098.001 - Additional Cloud Credentials, '
        'T1567.002 - Exfiltration to Cloud Storage, '
        'T1486 - Data Encrypted for Impact'
    ),
    'surfaces': (
        'Internet-facing services / user endpoints, '
        'Internal network / cloud metadata services, '
        'OS / IAM permission model, '
        'Data egress points / cloud APIs'
    ),
}

def build_bnb():
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type='nf4',
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )

def format_prompt(p, ap):
    sid, sname = ap['source_id'], ap['source_name']
    ind, lvl   = ap['industry'], ap['attack_level']
    tech, surf = ap['techniques'], ap['surfaces']
    foc, ctx   = p['focus'], p['user_context']
    block = f'''SOURCE: {sname} ({sid})
INDUSTRY: {ind}
ATTACK LEVEL: {lvl}
TECHNIQUES: {tech}
SURFACES: {surf}

PROMPT FOCUS: {foc}
{ctx}'''
    return f'[INST] {SYSTEM_INSTRUCTION}\\n\\n{block} [/INST]'

def gen(model, tokenizer, prompt):
    # Decode only new tokens — fixes the baseline echo bug
    inputs = tokenizer(
        prompt, return_tensors='pt', truncation=True, max_length=2048
    ).to(model.device)
    n = inputs['input_ids'].shape[1]
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            repetition_penalty=1.05,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.pad_token_id,
        )
    return tokenizer.decode(out[0][n:], skip_special_tokens=True).strip()

def cleanup(model=None, tok=None):
    if model is not None: del model
    if tok   is not None: del tok
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.synchronize()
        torch.cuda.empty_cache()
    time.sleep(3)
    free = torch.cuda.mem_get_info()[0] / 1e9 if torch.cuda.is_available() else 0
    print(f'Cleared. GPU free: {free:.2f} GB')
    print()

def load_base():
    m = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, quantization_config=build_bnb(), device_map='auto'
    )
    t = AutoTokenizer.from_pretrained(BASE_MODEL)
    if t.pad_token is None:
        t.pad_token = t.eos_token
    t.padding_side = 'right'
    return m, t

print('Config loaded. Run Cell 5 to start generation.')
"""

CELL5 = """# Cell 5 — Generate: Baseline then Fine-Tuned (~15-20 min on T4)
results = []

# ── Phase 1: Baseline ────────────────────────────────────────
print('=' * 60)
print('PHASE 1 - BASELINE Mistral-7B (no fine-tuning)')
print('=' * 60)
model, tok = load_base()
model.eval()
print('Base model loaded.')
print()

for i, p in enumerate(STRUCTURED_PROMPTS, 1):
    pid, focus = p['prompt_id'], p['focus']
    print(f'[{i}/4] Baseline {pid}: {focus}')
    prompt   = format_prompt(p, DUMMY_ATTACK_PATH)
    scenario = gen(model, tok, prompt)
    print(f'  Preview: {scenario[:180].replace(chr(10), " ")} ...')
    print()
    results.append({
        'model': 'baseline', 'prompt_id': pid, 'focus': focus,
        'attack_path_id': DUMMY_ATTACK_PATH['source_id'],
        'industry'      : DUMMY_ATTACK_PATH['industry'],
        'attack_level'  : DUMMY_ATTACK_PATH['attack_level'],
        'techniques'    : DUMMY_ATTACK_PATH['techniques'],
        'surfaces'      : DUMMY_ATTACK_PATH['surfaces'],
        'full_prompt'   : prompt,
        'generated_scenario': scenario,
    })

print('Unloading baseline model...')
cleanup(model, tok)

# ── Phase 2: Fine-tuned ──────────────────────────────────────
print('=' * 60)
print('PHASE 2 - FINE-TUNED Mistral-7B (LoRA adapter)')
print('=' * 60)
model, tok = load_base()
print(f'Attaching LoRA adapter from {ADAPTER_PATH}...')
ft_model = PeftModel.from_pretrained(model, ADAPTER_PATH)
ft_model.eval()
print('Fine-tuned model ready.')
print()

for i, p in enumerate(STRUCTURED_PROMPTS, 1):
    pid, focus = p['prompt_id'], p['focus']
    print(f'[{i}/4] Fine-tuned {pid}: {focus}')
    prompt   = format_prompt(p, DUMMY_ATTACK_PATH)
    scenario = gen(ft_model, tok, prompt)
    print(f'  Preview: {scenario[:180].replace(chr(10), " ")} ...')
    print()
    results.append({
        'model': 'finetuned', 'prompt_id': pid, 'focus': focus,
        'attack_path_id': DUMMY_ATTACK_PATH['source_id'],
        'industry'      : DUMMY_ATTACK_PATH['industry'],
        'attack_level'  : DUMMY_ATTACK_PATH['attack_level'],
        'techniques'    : DUMMY_ATTACK_PATH['techniques'],
        'surfaces'      : DUMMY_ATTACK_PATH['surfaces'],
        'full_prompt'   : prompt,
        'generated_scenario': scenario,
    })

print('Unloading fine-tuned model...')
cleanup(ft_model, tok)

# ── Save CSV ─────────────────────────────────────────────────
fields = [
    'model', 'prompt_id', 'focus', 'attack_path_id', 'industry',
    'attack_level', 'techniques', 'surfaces', 'full_prompt', 'generated_scenario',
]
with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in results:
        w.writerow({k: r.get(k, '') for k in fields})
print(f'CSV saved: {OUTPUT_CSV}')

# ── Save TXT (side-by-side comparison) ───────────────────────
NL  = chr(10)
SEP = '=' * 80
DIV = '-' * 80
base_r = {r['prompt_id']: r for r in results if r['model'] == 'baseline'}
ft_r   = {r['prompt_id']: r for r in results if r['model'] == 'finetuned'}

with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
    f.write('PROMPT GENERATOR MVP - BASELINE vs FINE-TUNED COMPARISON' + NL)
    f.write(SEP + NL + NL)
    for p in STRUCTURED_PROMPTS:
        pid, focus = p['prompt_id'], p['focus']
        src  = DUMMY_ATTACK_PATH['source_id']
        ind  = DUMMY_ATTACK_PATH['industry']
        lvl  = DUMMY_ATTACK_PATH['attack_level']
        tech = DUMMY_ATTACK_PATH['techniques']
        f.write(f'PROMPT {pid}: {focus}' + NL)
        f.write(f'Path      : {src} | {ind} | {lvl}' + NL)
        f.write(f'Techniques: {tech}' + NL + NL)
        f.write('BASELINE OUTPUT (Mistral-7B, no fine-tuning)' + NL)
        f.write(DIV + NL)
        f.write(base_r[pid]['generated_scenario'] + NL + NL)
        f.write('FINE-TUNED OUTPUT (Mistral-7B + LoRA adapter)' + NL)
        f.write(DIV + NL)
        f.write(ft_r[pid]['generated_scenario'] + NL + NL)
        f.write(SEP + NL + NL)

print(f'TXT saved: {OUTPUT_TXT}')
print()
print('Done! Run Cell 6 to evaluate outputs.')
"""

CELL7 = """
# Cell 6 — Automated Evaluation (Reference-Free, No LLM Judge)
# Metrics:
#   1. Structural Compliance  — are all 3 sections present and in order?
#   2. MITRE Technique Recall — % of input technique IDs found in output
#   3. Format Specifics       — G-notation, -> arrows, numbered stages, no markdown
#   4. Lexical Diversity      — Distinct-1, Distinct-2, Type-Token Ratio (TTR)
#   5. BERTScore              — semantic similarity shift (baseline vs fine-tuned)

import os, re, csv
from collections import Counter

!pip install -q bert-score
from bert_score import score as bert_score

OUTPUT_DIR = '/kaggle/working'
CSV_PATH   = os.path.join(OUTPUT_DIR, 'prompt_gen_comparison.csv')
EVAL_CSV   = os.path.join(OUTPUT_DIR, 'eval_results.csv')

SECTIONS = ['[NATURAL LANGUAGE]', '[MATHEMATICAL EXPRESSION]', '[ATTACK GRAPH]']
MITRE_RE  = re.compile(r'T\d{4}(?:\.\d{3})?')
G_RE      = re.compile(r'G\s*=\s*\(\s*N')
ARROW_RE  = re.compile(r'->')
STAGE_RE  = re.compile(r'^\d+[.)\s]', re.MULTILINE)
MD_RE     = re.compile(r'(\*\*|^##|^#\s)', re.MULTILINE)

# ── Load CSV ──
rows = []
with open(CSV_PATH, newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        rows.append(r)
print(f'Loaded {len(rows)} rows from {CSV_PATH}')

baseline_rows = [r for r in rows if r['model'] == 'baseline']
ft_rows       = [r for r in rows if r['model'] == 'finetuned']

# ── Helper functions ──

def structural_score(text):
    found = [s for s in SECTIONS if s in text]
    return len(found), (found == SECTIONS)

def mitre_recall(text, technique_str):
    input_ids = set(MITRE_RE.findall(technique_str))
    if not input_ids:
        return 1.0
    return round(len(input_ids & set(MITRE_RE.findall(text))) / len(input_ids), 4)

def format_checks(text):
    return (bool(G_RE.search(text)),
            len(ARROW_RE.findall(text)),
            len(STAGE_RE.findall(text)),
            len(MD_RE.findall(text)))

def lexical_diversity(text):
    tokens = re.findall(r'\b\w+\b', text.lower())
    if len(tokens) < 2:
        return 0.0, 0.0, 0.0
    bigrams = [f'{tokens[i]}_{tokens[i+1]}' for i in range(len(tokens)-1)]
    d1  = round(len(set(tokens))  / len(tokens), 4)
    d2  = round(len(set(bigrams)) / len(bigrams), 4) if bigrams else 0.0
    ttr = round(len(set(tokens))  / len(tokens), 4)
    return d1, d2, ttr

# ── Per-row metrics ──
eval_rows = []
for row in rows:
    text    = row['generated_scenario']
    n_secs, ordered          = structural_score(text)
    g_ok, arrows, stg, md   = format_checks(text)
    d1, d2, ttr              = lexical_diversity(text)
    eval_rows.append({
        'model'             : row['model'],
        'prompt_id'         : row['prompt_id'],
        'focus'             : row['focus'],
        'sections_found'    : n_secs,
        'sections_in_order' : int(ordered),
        'mitre_recall'      : mitre_recall(text, row['techniques']),
        'g_notation_ok'     : int(g_ok),
        'arrow_count'       : arrows,
        'numbered_stages'   : stg,
        'markdown_hits'     : md,
        'distinct_1'        : d1,
        'distinct_2'        : d2,
        'ttr'               : ttr,
        'word_count'        : len(text.split()),
        'bert_P'            : '',
        'bert_R'            : '',
        'bert_F1'           : '',
    })

# ── BERTScore: fine-tuned vs baseline per prompt (no reference needed) ──
print('\\nComputing BERTScore (fine-tuned vs baseline) ...')
base_texts = [r['generated_scenario'] for r in baseline_rows]
ft_texts   = [r['generated_scenario'] for r in ft_rows]
if base_texts and ft_texts and len(base_texts) == len(ft_texts):
    P, R, F1 = bert_score(ft_texts, base_texts, lang='en', verbose=False)
    for i, (p, r, f) in enumerate(zip(P.tolist(), R.tolist(), F1.tolist())):
        pid = ft_rows[i]['prompt_id']
        for ev in eval_rows:
            if ev['prompt_id'] == pid:
                ev['bert_P']  = round(p, 4)
                ev['bert_R']  = round(r, 4)
                ev['bert_F1'] = round(f, 4)
    print('BERTScore done.')
else:
    print('Skipping BERTScore (row count mismatch).')

# ── Print summary table ──
METRICS = ['sections_found','sections_in_order','mitre_recall','g_notation_ok',
           'arrow_count','numbered_stages','markdown_hits','distinct_1',
           'distinct_2','ttr','word_count','bert_F1']

print()
print(f'{"model":>12} {"prompt_id":>10}', end='')
for m in METRICS:
    print(f' {m:>18}', end='')
print()
for ev in eval_rows:
    print(f'{ev["model"]:>12} {ev["prompt_id"]:>10}', end='')
    for m in METRICS:
        print(f' {str(ev.get(m,"")):>18}', end='')
    print()

# ── Aggregate averages ──
def avg(lst): return round(sum(float(x) for x in lst if x != '') / len(lst), 4) if lst else 0

print()
for model_name in ('baseline', 'finetuned'):
    subset = [e for e in eval_rows if e['model'] == model_name]
    if not subset: continue
    print(f'--- {model_name.upper()} AVERAGES ---')
    for m in METRICS:
        vals = [e[m] for e in subset if e.get(m) != '']
        print(f'  {m:<22}: {avg(vals)}')
    print()

# ── Save eval CSV ──
fields = ['model','prompt_id','focus'] + METRICS + ['bert_P','bert_R']
with open(EVAL_CSV, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for ev in eval_rows:
        w.writerow({k: ev.get(k,'') for k in fields})

print(f'Eval CSV saved: {EVAL_CSV}')
print('Run Cell 7 to confirm all output files.')
"""

CELL6 = """# Cell 7 (final) — Confirm output files
import os

OUTPUT_DIR = '/kaggle/working'
filenames  = [
    'prompt_gen_comparison.csv',
    'prompt_gen_comparison.txt',
    'eval_results.csv',
]

print('Output files:')
for fname in filenames:
    fpath = os.path.join(OUTPUT_DIR, fname)
    if os.path.exists(fpath):
        sz = os.path.getsize(fpath)
        print(f'  \u2714 {fpath}  ({sz:,} bytes)')
    else:
        print(f'  \u2718 {fpath}  NOT FOUND')

print()
print('Download them from the Output tab on the right panel of this Kaggle notebook.')
"""

# ── Notebook assembly ──────────────────────────────────────────────────────────

def md_cell(source, cell_id):
    return {"cell_type": "markdown", "id": cell_id, "metadata": {}, "source": source}

def code_cell(source, cell_id):
    return {"cell_type": "code", "execution_count": None, "id": cell_id,
            "metadata": {}, "outputs": [], "source": source}

notebook = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kaggle": {
            "accelerator": "nvidiaTeslaT4",
            "dataSources": [{"sourceType": "datasetVersion", "sourceId": "finetuned"}],
            "isGpuEnabled": True,
            "isInternetEnabled": True
        },
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.10.12"},
    },
    "cells": [
        md_cell(MD_INTRO,  "md-intro-001"),
        code_cell(CELL1,   "code-gpu-002"),
        code_cell(CELL2,   "code-install-003"),
        code_cell(CELL3,   "code-files-004"),
        code_cell(CELL4,   "code-config-005"),
        code_cell(CELL5,   "code-gen-006"),
        code_cell(CELL7,   "code-eval-007"),
        code_cell(CELL6,   "code-dl-008"),
    ],
}

out = Path("kaggle_prompt_gen.ipynb")
with out.open("w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=1, ensure_ascii=False)

print(f"Created: {out.resolve()}")
print("Upload kaggle_prompt_gen.ipynb to Kaggle and run the cells in order.")
print("Make sure the 'finetuned' dataset is attached under Input before running.")
