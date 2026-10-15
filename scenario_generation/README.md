# Scenario Generation Module

End-to-end pipeline for generating **tri-modal cyber attack scenarios** from MITRE
ATT&CK STIX data, fine-tuning a QLoRA adapter on `mistralai/Mistral-7B-Instruct-v0.3`,
and evaluating base vs fine-tuned output quality.

> **Pipeline repair (see [`fine_tuning/CHANGES.md`](fine_tuning/CHANGES.md)).**
> The QLoRA pipeline was repaired for correctness and train/inference parity:
> one shared prompt builder, EOS-terminated targets, 2048-token sequences,
> true 4-bit precision (bf16/fp16 auto), completion-only loss masking, a real
> eval/early-stopping loop, and a single deterministic held-out split. The
> sections below describe the **repaired** behaviour.

```
STIX (ATT&CK)  ─▶  parse_stix.py  ─▶  generate_outputs.py  ─▶  training_data.jsonl
                                                                     │
                       ┌─────────────────────────────────────────────┤
                       ▼                                              ▼
            data_split → test_inputs.jsonl              fine_tune.py (QLoRA)  ─▶  output/ (adapter)
            (held-out, unseen)                                        │
                       │                                              ▼
                       └───▶ run_inference.py / evaluate.py / judge_eval.py / manual_eval_metrics.py
                                                                      │
   infra repo: graph/exporter.py  ─▶  output/attack_paths.json  ─▶  prompt_generator.py
                                          (real ranked paths)         --attack_paths
```

The left half is trained on ATT&CK campaigns; the right half is pointed at a real
account. The two meet in `prompt_generator.py`, which reads the ranked attack
paths the infrastructure repo exports and generates one tri-modal scenario per
prompt per path — see [section 6](#6--scenario-generation-over-real-attack-paths).

---

## Repository Layout
```
scenario_generation/
├── dataset/
│   ├── raw/                        ← enterprise-attack-18.1.json (gitignored, download manually)
│   ├── inputs/                     ← parse_stix.py output: training_inputs.jsonl (gitignored)
│   └── training_data.jsonl         ← 81 tri-modal training records (gitignored)
├── dataset_pipeline/
│   ├── parse_stix.py               ← STIX bundle → structured input JSONs
│   ├── generate_outputs.py         ← structured inputs → tri-modal records via Claude API
│   └── requirements.txt
├── fine_tuning/
│   ├── prompt_format.py            ← ★ canonical prompt builder (shared by train + inference)
│   ├── data_split.py               ← ★ deterministic train/val/test split (keyed on _meta.source_id)
│   ├── finetuning.py               ← QLoRA training logic (+ --check_data / --smoke / self-test / --merge)
│   ├── fine_tune.py                ← thin launcher (imports finetuning.main)
│   ├── run_inference.py            ← ★ importable inference (canonical prompt, decode-only-new)
│   ├── requirements_finetune.txt   ← pinned to the verified stack (see below)
│   ├── CHANGES.md                  ← what the repair fixed and why (+ Colab A100/T4 guide)
│   └── output/
│       ├── adapter_config.json     ← LoRA config of the shipped adapter
│       ├── tokenizer_config.json   ← Mistral-7B tokenizer config
│       ├── chat_template.jinja     ← Mistral chat template
│       └── README.md               ← auto-generated model card (records the training stack)
├── evaluation/
│   ├── make_test_inputs.py         ← writes the held-out test_inputs.jsonl (uses data_split)
│   ├── test_inputs.jsonl           ← ★ the shared held-out split artifact (gitignored)
│   ├── evaluate.py                 ← base vs fine-tuned generations → manual review worksheet
│                                     (lazy ML imports: imports on a laptop)
│   ├── judge_eval.py               ← ★ automated Gemini-judge scores (canonical prompt, lazy imports)
│   ├── requirements_eval.txt       ← judge-only deps (google-genai, python-dotenv)
│   └── manual_eval_metrics.py      ← reference-free structural metrics (no LLM judge)
├── prompt_generator.py             ← ★ scenario generation over the real ranked attack paths
│                                     (`--attack_paths`; the DUMMY_ATTACK_PATH is gone)
├── tests/                          ← ★ pytest suite (prompt parity, score parsing, split
│   └── fixtures/attack_paths.json     disjointness, attack-path contract) + a committed
│                                      real export from the infrastructure repo
├── pytest.ini                      ← pythonpath so `import judge_eval` / `prompt_format` resolve
├── create_notebook.py              ← regenerates all three notebooks from the .py sources
│                                     (the .py files are the source of truth)
├── colab_finetune_setup.ipynb      ← ★ Colab: ships + runs fine_tune.py (generated)
├── finetune_output_test.ipynb      ← ★ Colab: ships + runs run_inference.py (generated)
└── kaggle_prompt_gen.ipynb         ← ★ Kaggle: baseline vs fine-tuned comparison + metrics
                                      (generated; replaces the old hand-written
                                       colab_prompt_generator.py)

★ = added / central to the repaired pipeline.
```

---

## 1 — Dataset Pipeline

Install dependencies:
```bash
pip install -r dataset_pipeline/requirements.txt
```

Download the ATT&CK STIX bundle (~50MB, gitignored):
```bash
curl -L -o dataset/raw/enterprise-attack-18.1.json \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.1.json"
```

Parse STIX into structured inputs (→ `dataset/inputs/training_inputs.jsonl`):
```bash
python dataset_pipeline/parse_stix.py \
  --stix dataset/raw/enterprise-attack-18.1.json \
  --out  dataset/inputs/
```

Generate tri-modal training records via the Claude API (→ `dataset/training_data.jsonl`):
```bash
export ANTHROPIC_API_KEY=your_key_here
python dataset_pipeline/generate_outputs.py \
  --inputs dataset/inputs/training_inputs.jsonl \
  --out    dataset/training_data.jsonl \
  --limit  80 \
  --model  claude-haiku-4-5-20251001
```
Result: **81 records** with fields `instruction` / `input` / `output` / `_meta`
(the `_meta.source_id`, e.g. `C0027`, is the stable id used by the split).

---

## 2 — Fine-Tuning (QLoRA)

**What QLoRA does:** loads Mistral-7B in 4-bit (~4-5GB VRAM), attaches small LoRA
adapter matrices, and trains only those (≈0.2% of parameters) — runnable on a free
Colab T4. The repaired pipeline trains true QLoRA: 4-bit NF4 base, bf16/fp16
compute matched to the trainer's mixed precision, completion-only loss, and
EOS-terminated targets so the model learns to stop.

Install:
```bash
pip install -r fine_tuning/requirements_finetune.txt
```

### Offline probes (no GPU / no ML stack required)
```bash
# Data + prompt-parity probe: asserts the inference prompt is a prefix of the
# training text, prints token-length stats, flags truncation at --max_seq_len,
# and checks the train/test split is disjoint. Creates evaluation/test_inputs.jsonl.
python fine_tuning/fine_tune.py --check_data --data dataset/training_data.jsonl

# CUDA-guarded 3-step end-to-end run. No-op with a clear message when there's no GPU.
python fine_tuning/fine_tune.py --smoke --out /tmp/smoke
```

### Train (locally or on Colab — same script)
```bash
python fine_tuning/fine_tune.py \
  --data dataset/training_data.jsonl \
  --out  fine_tuning/output \
  --test_inputs evaluation/test_inputs.jsonl
```
The script auto-creates the held-out split (if missing), trains on the complement,
runs eval each epoch with early stopping + best-checkpoint selection, then runs a
post-training self-test (generates one held-out sample and asserts the three
headers appear in order and EOS is hit).

**Precision is auto-selected:** `torch.cuda.is_bf16_supported()` → bf16 compute +
`bf16=True` on A100; otherwise fp16 compute + `fp16=True` on T4. See
[`fine_tuning/CHANGES.md`](fine_tuning/CHANGES.md) for the per-device Colab guide.

### Useful flags (all have sensible defaults)
| Flag | Default | Notes |
|---|---|---|
| `--epochs` `--lr` | `3` `2e-4` | training length / learning rate |
| `--r` `--alpha` `--lora_dropout` | `16` `32` `0.05` | LoRA capacity |
| `--target_modules` | `all` | `all` (all linear), `attn` (attention-only), or a comma list |
| `--max_seq_len` | `2048` | examples are ≤~1,574 tokens; <2048 truncates some (`--check_data` reports how many) |
| `--batch_size` `--grad_accum` | `1` `4` | effective batch = 4 |
| `--test_size` `--val_frac` `--seed` | `10` `0.15` `42` | held-out test count / val fraction / seed |
| `--merge` | off | also save a merged fp16 model under `output/merged` (needs ~14-16GB) |
| `--trust_remote_code` | off | unnecessary for Mistral |

### The shipped adapter
The adapter currently referenced in `output/` was produced by the **pre-repair**
run (attention-only LoRA, no completion masking, fp32 compute, 64/17 split; see
`output/README.md` for the exact stack). Re-train with the repaired pipeline to get
the corrected behaviour (all-linear LoRA by default, completion-only loss,
EOS-terminated targets, 60/11/10 split). The `*.safetensors` weights are gitignored.

### Run in Colab
Open `colab_finetune_setup.ipynb` (repo root — `create_notebook.py` writes all
three notebooks next to itself): it checks the GPU, installs the
pinned requirements, **ships the fixed `.py` modules into the runtime**, has you
upload `training_data.jsonl`, runs `fine_tune.py`, and downloads
`finetuned_adapters.zip` + `test_inputs.jsonl`. No training logic lives in the
notebook — it runs the repaired script, so the fixes always apply. Always download
the adapter before ending the session (Colab storage is ephemeral).

---

## 3 — Held-Out Split (single source of truth)

`fine_tuning/data_split.py` produces one deterministic split (seed 42), keyed on
`_meta.source_id`, persisted to `evaluation/test_inputs.jsonl`. Training, inference,
and evaluation all read this same artifact, so the held-out test set is provably
**unseen** (train ∩ test = ∅, asserted by `--check_data`).

Create/regenerate it explicitly (the trainer also auto-creates it):
```bash
python evaluation/make_test_inputs.py            # writes evaluation/test_inputs.jsonl
python evaluation/make_test_inputs.py --force    # regenerate
```
Each line carries `idx`, `source_id`, `instruction`, `input`, and the reference
`output` (used for comparison, never fed to the model).

---

## 4 — Inference

Generate scenarios for the held-out test inputs with the fine-tuned adapter:
```bash
python fine_tuning/run_inference.py \
  --adapter fine_tuning/output \
  --test_inputs evaluation/test_inputs.jsonl \
  --out fine_tuning/output/inference_results.txt \
  --samples 3
```
Uses the **canonical prompt** (`prompt_format.build_chat`, identical to training),
sets eos/pad ids so the model stops, and decodes **only the new tokens** (no echoed
prompt). Add `--compare` for side-by-side base vs fine-tuned output, or
`--greedy` for deterministic decoding (defaults: sampling, temp 0.7, top_p 0.9,
repetition_penalty 1.1, `max_new_tokens` 1280). `--smoke` runs a one-sample
self-test (no-op without a GPU). `finetune_output_test.ipynb` (repo root) is the
Colab wrapper: it *ships* this script into the runtime and calls it, so the
notebook cannot hold a prompt of its own.

---

## 5 — Evaluation

Two complementary tracks over the **same held-out split**:

* **Structural metrics** (steps 1-2) are **reference-free and deterministic** —
  no LLM judge — because each metric directly tests a rule the model was trained
  on (section headers in order, MITRE recall/precision, exact
  `G = (N, S, V, P, FS)` notation, `->` arrows, numbered stages, no markdown,
  lexical diversity, truncation).
* **The Gemini judge** (step 3, `judge_eval.py`) adds the qualitative axis those
  metrics cannot see — level of detail, technical accuracy, realism, creativity.
  It needs an API key and is sampled, so it is reported alongside the
  deterministic metrics, never instead of them.

1. **Produce base vs fine-tuned outputs.** On Kaggle, `kaggle_prompt_gen.ipynb`
   generates `prompt_gen_comparison.txt` over the held-out inputs. Locally,
   `evaluate.py` writes a side-by-side **manual review worksheet**:
   ```bash
   python evaluation/evaluate.py \
     --base_model   mistralai/Mistral-7B-Instruct-v0.3 \
     --adapter_path fine_tuning/output \
     --test_inputs  evaluation/test_inputs.jsonl \
     --out_json     evaluation/eval_outputs.json \
     --out_md       evaluation/manual_eval.md
   ```
2. **Score the comparison** with the structural metrics:
   ```bash
   python evaluation/manual_eval_metrics.py --txt prompt_gen_comparison.txt --csv
   ```
   Outputs `eval_report.md` (baseline vs fine-tuned table + per-prompt breakdown)
   and `eval_results.csv`.
3. **Score with the Gemini judge** (automated, 4 criteria x 1-10, base vs
   fine-tuned on every held-out record):
   ```bash
   pip install -r evaluation/requirements_eval.txt
   export GOOGLE_API_KEY=your_ai_studio_key      # or --gemini_key, or .env
   python evaluation/judge_eval.py \
     --base_model   mistralai/Mistral-7B-Instruct-v0.3 \
     --adapter_path fine_tuning/output \
     --test_inputs  evaluation/test_inputs.jsonl \
     --out          evaluation/judge_scores.json
   ```
   Both generations use the **canonical prompt** (`prompt_format.build_chat`,
   `add_special_tokens=False` so BOS is not doubled), the records come from
   `data_split` (disjointness asserted before the first API call), and the base
   pass runs with the adapter disabled so "base" really is the base model. Writes
   per-entry + average scores and prints the comparison table; an unparseable
   judge reply drops that entry (`unscored`) instead of failing the run.

---

## 6 — Scenario Generation over Real Attack Paths

This is the deliverable: `prompt_generator.py` combines every structured prompt in
its library with every **real** ranked attack path and generates a tri-modal
scenario for each pair.

```bash
python3 prompt_generator.py \
  --attack_paths ../../capstone-feature-infra-model/output/attack_paths.json
```

`--attack_paths` is **required**. The paths come from the other half of the
project: the infrastructure repo builds the security state graph, ranks the
exploitable routes, and exports one record per path.

```bash
# in the infrastructure repo — one command, writes output/attack_paths.json
cd ../../capstone-feature-infra-model
python3 -m runner.graph_runner
```

### It used to be a hardcoded dummy

`prompt_generator.py` carried a `DUMMY_ATTACK_PATH` constant, so every run
produced four scenarios about the same invented campaign — the model was never
conditioned on an account at all, and the "generated from infrastructure" claim
was only true of the format. That constant is gone; the paths are loaded, and
validated, from the export.

### The contract

> **Note on technique ids.** These come from the
> [ATT&CK Cloud/IaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
> and are validated against it in the other repo. Two ids the ruleset used to
> emit — `T1133` (External Remote Services) and `T1567.002` (Exfiltration to
> Cloud Storage) — are *not* in the IaaS matrix, so the model had been receiving
> technique ids outside the matrix we cite. They are now `T1021`/`T1078` and
> `T1537` respectively.

Each entry in `attack_paths.json` carries exactly seven keys, checked at load time
against `ATTACK_PATH_KEYS` **before the model is loaded** — a missing key would
otherwise be a `KeyError` raised inside an f-string with 7B of weights already on
the GPU:

| Key | Example |
|---|---|
| `source_id` | `AP-001` — rank order, zero-padded |
| `source_name` | `OpenSecurityGroup -> PublicEC2Instance -> OverPermissiveRole -> PublicRDS` |
| `industry` | `Information technology service activities (ISIC J62)` |
| `attack_level` | `CRITICAL` / `HIGH` / `MEDIUM` |
| `techniques` | `T1190 - Exploit Public-Facing Application, T1078.004 - Valid Accounts: Cloud Accounts, ...` (kill-chain order, ATT&CK IaaS matrix) |
| `surfaces` | `Internet-facing services / user endpoints, Application runtime environment, ...` |
| `objective` | `Ransomware or destruction` / `Data theft` / `Denial of service` / `Identity takeover` / `Resource hijacking` |

`objective` is the newest key and the one that changes what the model should
write. The same hops are a data-theft scenario or a ransomware scenario depending
on what the attacker does on arrival, and nothing else in the record distinguishes
them — the exporter emits one path per objective, so two records can share every
hop and differ only here.

The three failure modes a teammate will actually hit are each reported as
themselves: the file has not been copied over from the other repo, the export ran
before the graph found any paths, or the export is from an older revision that
wrote different keys.

### Flags

| Flag | Default | Notes |
|---|---|---|
| `--attack_paths` | *required* | the exported JSON list; every prompt runs against every path |
| `--base_model` | `mistralai/Mistral-7B-Instruct-v0.3` | base HF model name or local path |
| `--adapter_path` | `fine_tuning/output` | LoRA adapter directory |
| `--output_prefix` | `results/prompt_gen_output` | produces `<prefix>.csv` and `<prefix>.txt` |
| `--prompt_ids` | all | e.g. `--prompt_ids P1 P3` |
| `--path_ids` | all | e.g. `--path_ids AP-001 AP-002` |

Prompting goes through `prompt_format.build_chat` — the same canonical builder
training used. This file used to build its own
`f"[INST] {...}\n\n{...} [/INST]"`, with an extra space before the marker and no
BOS, which is the same one-space bug that made the Gemini judge under-score the
fine-tune. The heavy imports (torch, transformers, peft) are **lazy**, so
`--help`, the attack-path loader and the prompt builder all work — and are
tested — on a machine with no ML stack installed.

---

## Tests
```bash
python3 -m pytest -q          # 94 tests, run from scenario_generation/
```
Offline and dependency-free (stdlib + pytest, Python 3.9): the eval prompt and the
`prompt_generator.py` prompt are both byte-identical to the training prompt,
judge-score parsing survives fenced and malformed replies, the held-out split is
disjoint from training, and the seven-key attack-path contract is pinned against a
committed real export (`tests/fixtures/attack_paths.json`) with one prompt
asserted per exported path.

**Two guards whose scope is derived rather than listed**, because both were
previously defeated by a file sitting outside them rather than by a wrong
assertion:

* *No hand-rolled prompts.* Nothing outside `prompt_format.py` may build an
  `[INST]` string. The scan covers every `.py` under `evaluation/` and
  `fine_tuning/`, **every script at the repo root**, and **every `.ipynb`** —
  notebooks are JSON, so a `*.py` glob could not see the two stale ones that held
  live drifted templates. A notebook may only contain the markers inside a
  verbatim copy of a repository module it ships into its runtime, and that copy is
  asserted **byte-identical to the file on disk**, so a notebook that has drifted
  from the source of truth fails. The coverage test asserts an exact file set: a
  subset check can never fail because a file dropped out of the scan.
* *Imports are cheap.* Every module under `evaluation/` and `fine_tuning/` and
  every root-level script is exec'd in a fresh interpreter and asserted to pull in
  none of torch / transformers / peft / trl / datasets / bitsandbytes / accelerate
  / google-genai. `evaluation/evaluate.py` used to import three of them at module
  scope, and this sentence in the README was the only thing asserting otherwise.
  (`visualize_dataset.py` is exempt for matplotlib alone — it is a plotting
  utility, and matplotlib is not the ML stack.)

---

## Output Format

Each record's `output` is exactly three plain-text sections (no markdown), in order
(the full rules live in every record's `instruction`):

```
[NATURAL LANGUAGE]
Readable attack narrative; references each MITRE technique ID inline, e.g. (T1190).

[MATHEMATICAL EXPRESSION]
N  = {n1: Employee Endpoint, n2: Web Application Server, ...}   # nodes
S  = {s1: Deserialization Vulnerability, ...}                   # states / weaknesses
V  = {v1: T1087.003 - Phishing, ...}                            # techniques (ATT&CK IDs)
P  = {p1: n1 -> n2, p2: n2 -> n3, ...}                          # transitions
FS = {Data Exfiltration and Ransom Demand}                      # final state / objective
G = (N, S, V, P, FS)

[ATTACK GRAPH]
Stage 1 (Initial Access): Employee Endpoint [T1087.003] -> Web Application Server
Stage 2 (Exploitation):   Web Application Server [T1190] -> Cloud Metadata Service
...
```

---

## Requirements / target stack

Fine-tuning is pinned (`fine_tuning/requirements_finetune.txt`) to the stack that
produced the shipped adapter (`output/README.md`): **Transformers 5.x · TRL 0.29.x
· PEFT 0.18.x · datasets 4.x · torch ≥2.4 · bitsandbytes 0.47–0.49 · accelerate
≥1.1**, Python 3.12. The code branches on the TRL/transformers API differences
(`max_length` vs `max_seq_length`, `processing_class` vs `tokenizer`, the
completion-only collator), so nearby versions also work.

## Regenerating the notebooks

The notebooks are generated from the `.py` sources (the source of truth) — never
edit them by hand:
```bash
python create_notebook.py    # rewrites the 3 notebooks, embedding the fixed modules
```
All three land **next to `create_notebook.py`**, at the repository root. There is
deliberately no copy under `fine_tuning/`: two stale forks lived there for months,
the README pointed at them, and they trained and inferred with a prompt no
`.py` file in the repository emitted. `tests/test_no_hand_rolled_prompts.py`
asserts the shipped module copies inside each notebook are byte-identical to the
files on disk, so a notebook that has not been regenerated after a change to
`prompt_format.py` fails the suite instead of quietly running the old prompt.

## Known notes
- Dataset/adapter files (`training_data.jsonl`, `inputs/`, `raw/`, `*.safetensors`,
  `test_inputs.jsonl`) are gitignored — run the pipeline scripts to reproduce them.
- 81 records is a small dataset; `eval_loss` is noisy (the trainer warns about this).
- Colab storage is ephemeral — download the adapter zip before ending the session.
- `attack_paths.json` is produced by the *other* repository and is not tracked here;
  `tests/fixtures/attack_paths.json` is a committed copy of a real export, used only
  to pin the contract offline. Regenerate the live one with
  `python3 -m runner.graph_runner` in `capstone-feature-infra-model/`.
- Three files were **deleted** as pre-repair duplicates, each of which carried its
  own drifted `[INST]` template while the guard could not see it:
  `colab_prompt_generator.py` (a hand-maintained cell-script superseded by the
  generated `kaggle_prompt_gen.ipynb`, and the last holder of the dummy attack
  path), and `fine_tuning/colab_finetune_setup.ipynb` +
  `fine_tuning/finetune_output_test.ipynb` (stale forks of the notebooks
  `create_notebook.py` generates at the repo root). The guard now scans every
  root-level script and every notebook, and asserts the deleted paths stay gone —
  see `tests/test_no_hand_rolled_prompts.py`. Recover them from git history if
  the pre-repair text is ever needed as evidence.
- Items verified offline vs. on-Colab-only are listed at the end of
  [`fine_tuning/CHANGES.md`](fine_tuning/CHANGES.md).
