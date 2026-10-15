# Scenario generation

Stage 4 of the project. Turns each ranked attack path from the graph pipeline into
a **tri-modal cyber attack scenario** (narrative, `G = (N, S, V, P, FS)`
expression, staged attack graph), using a QLoRA fine-tune of
`mistralai/Mistral-7B-Instruct-v0.3`, and evaluates the result.

```
ATT&CK STIX ─▶ dataset_pipeline/ ─▶ dataset/training_data.jsonl (81 records)
                                          │
                       ┌──────────────────┴───────────────────┐
                       ▼                                      ▼
     data_split: 17 held-out records              fine_tuning/ (QLoRA) ─▶ adapter
     evaluation/test_inputs.jsonl                             │
                       └──────▶ run_inference / evaluate / judge_eval ◀──┘

../output/attack_paths.json ─▶ evaluation/inputs/attack_paths.json ─▶ prompt_generator.py
     (graph pipeline)               (committed snapshot)              compare_models.py
```

## The adapter, and the format it was trained on

The adapter (`fine_tuning/output/`, r=16, alpha=32, attention-only) came from the
original Colab notebook. Three facts about that run shape everything here:

- **Prompt.** It trained on `<s>[INST] {instruction}\n\n{input} [/INST]\n{output}</s>`.
  The space before `[/INST]` and the newline after it are not Mistral's chat
  template. `fine_tuning/prompt_format.py` reproduces this text, token for token,
  and every training and inference path uses it.
- **Held-out records.** It trained on 64 of the 81 records. The other 17 are
  frozen in `fine_tuning/data_split.py` and committed as
  `evaluation/test_inputs.jsonl`. Evaluation refuses a test file holding any other
  record.
- **Truncation.** TRL's default 1024-token limit cut every training example, so
  the adapter saw only about the first 600 tokens of each answer and never an
  ending. Expect long outputs that stop at the token cap.

The weights (`adapter_model.safetensors`, about 27 MB) are shared outside git;
put them in `fine_tuning/output/`. The full story is in
[`fine_tuning/CHANGES.md`](fine_tuning/CHANGES.md).

## Layout

```
scenario_generation/
├── dataset/training_data.jsonl     81 records: instruction, input, output, _meta
├── dataset_pipeline/               STIX → structured inputs → records (Gemini)
├── fine_tuning/
│   ├── prompt_format.py            the trained prompt, shared by every path
│   ├── data_split.py               the 17 held-out records; train/val from the rest
│   ├── finetuning.py, fine_tune.py QLoRA training (--check_data, --smoke, --merge)
│   ├── run_inference.py            generation for the held-out records
│   ├── requirements_finetune.txt   the ML stack, pinned to the adapter's versions
│   ├── CHANGES.md                  the pipeline repair and the October correction
│   └── output/                     adapter config and model card (weights not in git)
├── evaluation/
│   ├── test_inputs.jsonl           the 17 held-out records
│   ├── inputs/attack_paths.json    snapshot of the graph pipeline's export
│   ├── evaluate.py                 base vs fine-tuned → manual review worksheet
│   ├── judge_eval.py               base vs fine-tuned → Gemini judge scores
│   ├── manual_eval_metrics.py      reference-free format metrics
│   ├── compare_models.py           fine-tuned Mistral vs RedSage Qwen
│   └── make_test_inputs.py         rewrites test_inputs.jsonl from the split
├── prompt_generator.py             scenarios for the real attack paths
├── create_notebook.py              writes the five notebooks from the .py files
├── *.ipynb                         generated; never edit by hand
└── tests/
```

## 1. Dataset

```bash
pip install -r dataset_pipeline/requirements.txt
curl -L -o dataset/raw/enterprise-attack-18.1.json \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.1.json"
python dataset_pipeline/parse_stix.py --stix dataset/raw/enterprise-attack-18.1.json --out dataset/inputs/
export GEMINI_API_KEY=...
python dataset_pipeline/generate_outputs.py --inputs dataset/inputs/training_inputs.jsonl \
  --out dataset/training_data.jsonl --limit 80
```

`generate_outputs.py` defaults to `gemma-3-27b-it`. The committed
`training_data.jsonl` is the one the adapter was trained on; regenerating it
changes the data under the adapter.

## 2. Fine-tuning

```bash
pip install -r fine_tuning/requirements_finetune.txt
python fine_tuning/fine_tune.py --check_data      # split and token lengths, no GPU needed
python fine_tuning/fine_tune.py --smoke --out /tmp/smoke   # 3 steps; no-op without CUDA
python fine_tuning/fine_tune.py --data dataset/training_data.jsonl --out fine_tuning/output
```

Training tokenizes each example itself, with the loss on the answer only, and
refuses to start if any example would be truncated (`--max_seq_len`, default
2048; the longest example is 1,683 tokens). It evaluates on the validation split
each epoch, keeps the best checkpoint, then generates one held-out sample and
checks it has the three section headers in order and stops before the cap.
Precision is picked for the GPU: bf16 on A100, fp16 on T4.

| Flag | Default | |
|---|---|---|
| `--epochs` `--lr` | `3` `2e-4` | |
| `--r` `--alpha` `--lora_dropout` | `16` `32` `0.05` | |
| `--target_modules` | `all` | `attn` reproduces the shipped adapter's layers |
| `--max_seq_len` | `2048` | |
| `--batch_size` `--grad_accum` | `1` `4` | |
| `--val_frac` `--seed` | `0.15` `42` | the test set is fixed, see `data_split.py` |
| `--merge` | off | also save a merged fp16 model (needs ~16 GB) |

On Colab, `colab_finetune_setup.ipynb` does the same: it ships the `.py` files
into the runtime, asks for `training_data.jsonl`, trains and downloads
`finetuned_adapters.zip`.

## 3. Inference and evaluation

All of these read the 17 held-out records by default.

```bash
python fine_tuning/run_inference.py --adapter fine_tuning/output --samples 3 --compare
python evaluation/evaluate.py --base_model mistralai/Mistral-7B-Instruct-v0.3 \
  --adapter_path fine_tuning/output --out_json evaluation/eval_outputs.json \
  --out_md evaluation/manual_eval.md
pip install -r evaluation/requirements_eval.txt
export GOOGLE_API_KEY=...
python evaluation/judge_eval.py --base_model mistralai/Mistral-7B-Instruct-v0.3 \
  --adapter_path fine_tuning/output --out evaluation/judge_scores.json
python evaluation/manual_eval_metrics.py --txt prompt_gen_comparison.txt --csv
```

- **Format metrics** (`manual_eval_metrics.py`) are deterministic and need no
  model: section headers in order, MITRE recall and precision, exact
  `G = (N, S, V, P, FS)` notation, arrows, numbered stages, no markdown, lexical
  diversity, truncation.
- **The Gemini judge** (`judge_eval.py`, `gemini-2.5-flash-lite`) scores level of
  detail, technical accuracy, realism and creativity from 1 to 10. It generates
  the base output with the adapter disabled, so "base" really is the base model.

`eval_report.md`, `eval_results.csv` and `prompt_gen_comparison.txt` at this
folder's root are results from April, produced before the prompt and test set
were corrected. Treat them as history.

## 4. Scenarios for the real attack paths

```bash
python3 -m runner.graph_runner                       # from the repo root
python3 prompt_generator.py --attack_paths ../output/attack_paths.json
```

Every prompt in the library (P1 to P4) runs against every path. `--prompt_ids`
and `--path_ids` narrow it; outputs go to `results/`.

Each path carries exactly these seven string keys, checked before any model
loads:

| Key | Example |
|---|---|
| `source_id` | `AP-001` |
| `source_name` | `OpenSecurityGroup -> PublicEC2Instance -> OverPermissiveInstanceProfile -> OverPermissiveRole -> InsecureS3Bucket` |
| `industry` | `Information technology service activities (ISIC J62)` |
| `attack_level` | `CRITICAL` / `HIGH` |
| `techniques` | `T1190 - Exploit Public-Facing Application, T1078.004 - Valid Accounts: Cloud Accounts, ...` (kill-chain order) |
| `surfaces` | `Internet-facing services / user endpoints, ...` |
| `objective` | `Data theft` / `Ransomware or destruction` / `Denial of service` / `Identity takeover` / `Resource hijacking` |

The input block adds `OBJECTIVE:` and the prompt's focus to the five lines the
training records have (`SOURCE`, `INDUSTRY`, `ATTACK LEVEL`, `TECHNIQUES`,
`SURFACES`). The objective is information the model needs, but it is input the
adapter never saw.

## 5. Fine-tuned Mistral vs RedSage Qwen

`evaluation/compare_models.py` runs the fine-tuned Mistral and
`RISys-Lab/RedSage-Qwen3-8B-Ins` on the same five attack paths (`AP-001`,
`AP-003`, `AP-007`, `AP-014`, `AP-015`: both entry routes, the four objectives
the export contains, and the one short path). Each model gets the same request in its own format,
the same decoding settings and seed, and both are scored with the format metrics
and the Gemini judge. The judge key is required; `--no_judge` reports the format
metrics only.

On an Apple Silicon Mac (both models converted once to 4-bit MLX, about 28 GB of
downloads the first time):

```bash
python3.12 -m venv .venv && .venv/bin/pip install "mlx-lm==0.32.0"
export OPENROUTER_API_KEY=...        # or GOOGLE_API_KEY
.venv/bin/python evaluation/compare_models.py --backend mlx
```

On a GPU, open `colab_compare_models.ipynb` or `kaggle_compare_models.ipynb`.
Results land in `results/model_comparison/` (`report.md`, `side_by_side.txt`);
rerunning with the same `--out_dir` skips finished work.

When reading the results:

- The format metrics favour Mistral by construction: it was fine-tuned on this
  exact format. Compare domain knowledge on the judge's technical accuracy and
  realism.
- RedSage's chat template adds its own system prompt; that is the model's
  default and is left in.
- On MLX both models are 4-bit MLX rather than the NF4 the adapter was trained
  with: fair between the two, slightly different from training.

## Tests

```bash
python3 -m pytest -q         # from here, or from the repo root for every test
```

Python 3.9 with PyYAML and pytest; no ML stack. They pin the trained prompt, the
held-out split, judge-score parsing and the attack-path contract. Two guards
derive their scope instead of listing it:

- **No hand-rolled prompts.** Nothing outside `prompt_format.py` may build an
  `[INST]` string. The scan covers every `.py` here and every notebook; a notebook
  may only hold the markers inside a verbatim copy of a module it ships, and that
  copy must equal the file on disk.
- **Cheap imports.** Every module is imported in a fresh interpreter and must not
  pull in torch, transformers, peft, trl, datasets, bitsandbytes, accelerate or
  google-genai.

## Notebooks

```bash
python create_notebook.py
```

Writes all five notebooks from the `.py` sources. A test fails when a notebook's
copy of a module is out of date, so run this after changing any shipped module.
