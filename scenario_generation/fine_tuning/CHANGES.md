# QLoRA pipeline repair — what changed and why

This documents the correctness / train-vs-inference-parity repair of the QLoRA
fine-tuning pipeline for `mistralai/Mistral-7B-Instruct-v0.3`. The shipped adapter
produced off-format output that echoed the prompt, used emoji/markdown, and never
stopped. Each fix below states what was wrong, why it mattered, and what changed.

## A — Prompt parity (root cause)
**Wrong:** six different prompt builders existed (the manual `[INST] … [/INST]\n`
in training, three variants in the inference notebook, one in `evaluate.py`, one
in the Kaggle generator) and *none* matched what training saw. The model was
fine-tuned on one wrapper and prompted with another, so it parroted instructions
and drifted off-format. **Why it mattered:** an LLM only learns the mapping it was
shown; a different inference prompt is out-of-distribution. **Changed:** one
canonical builder `prompt_format.build_chat(record, tokenizer, for_training)`
imported by training *and* every inference path. It uses the record's full
`instruction` and `tokenizer.apply_chat_template` (with a byte-identical
dependency-free fallback). The inference prompt is, by construction, a strict
prefix of the training text (asserted by `assert_parity`).

## B — EOS / stopping
**Wrong:** training targets never ended with an EOS token, and `generate()` calls
didn't set `eos_token_id`/`pad_token_id`, so the model had no learned/looked-up
stop signal and ran to the token cap (truncated mid-sentence). **Changed:** the
chat template terminates every training target with EOS, and every `generate()`
call sets `eos_token_id` and `pad_token_id`.

## C — Sequence length
**Wrong:** `MAX_SEQ_LEN=2048` was defined but never passed to TRL, so the default
1024 truncated the `[ATTACK GRAPH]` ending of *every* example (estimated
1,183–1,574 tokens; 81/81 over 1024). **Changed:** the length is wired into
`SFTConfig` under the field name the installed TRL exposes (`max_length` or
`max_seq_length`). `--check_data` prints the configured length and the truncation
count (0 at 2048) and training aborts if anything still exceeds it.

## D — True QLoRA precision + k-bit prep
**Wrong:** `bnb_4bit_compute_dtype=torch.float32` + `bnb_4bit_quant_storage=
torch.float32` + `fp16=False/bf16=False` + a late `os.environ["ACCELERATE_MIXED_
PRECISION"]="fp16"` meant fp32 compute (not QLoRA) and a config that contradicted
itself; `prepare_model_for_kbit_training` was missing. **Changed:** compute dtype
auto-selects (bf16 on A100, fp16 on T4) and is **matched** to `SFTConfig`'s
`bf16`/`fp16`; `quant_storage` and the env line are removed; `prepare_model_for_
kbit_training(use_gradient_checkpointing=True)` runs after the 4-bit load and
before `get_peft_model`; gradient checkpointing uses `use_reentrant=False`.

## E — Loss masking (completion-only)
**Wrong:** the docstring claimed the prompt was masked, but no masking was set up —
loss was computed over the prompt too. **Changed:** `DataCollatorForCompletionOnlyLM`
with the `[/INST]` token ids computed **in context** (tokenizing a real sample and
diffing, not the raw string — the classic footgun that silently masks everything).
A label-masking check asserts labels are `-100` on the prompt and real ids on the
completion; the docstring now matches.

## F — Eval + model selection
**Wrong:** a validation split was created but never used. **Changed:**
`eval_strategy="epoch"`, `per_device_eval_batch_size=1`, `load_best_model_at_end=
True`, `metric_for_best_model="eval_loss"`, `greater_is_better=False`, and
`EarlyStoppingCallback(patience=2)`. Validation is guaranteed ≥1 record and the
code warns that 81 records make `eval_loss` noisy.

## G — Hyperparameter hygiene
**Changed:** `optim="paged_adamw_8bit"`; `target_modules` is configurable and now
defaults to **all** linear projections (q,k,v,o,gate,up,down) with `attn` as an
easy override; `set_seed(42)` plus `seed`/`data_seed` in `SFTConfig`;
`--trust_remote_code` flag (default False). Epochs, lr, r, alpha, lora_dropout,
max_seq_len, target_modules, base model, batch/accum, and split sizes are all
exposed via argparse with the previous values as defaults.

## H — Consistent "unseen" eval split
**Wrong:** `make_test_inputs.py` read a non-existent `dataset/inputs/training_
inputs.jsonl` and keyed on a top-level `source_id` the dataset didn't have, while
`finetuning.py` did its own random split — so the eval set wasn't guaranteed
unseen. **Changed:** one deterministic split (`data_split.py`, keyed on
`_meta.source_id`) is persisted to `evaluation/test_inputs.jsonl`; finetuning
trains on the complement, and `make_test_inputs.py`/`evaluate.py` read the same
artifact. `--check_data` asserts train ∩ test is empty.

## I — Inference notebook / script
**Wrong:** the notebook used a wrong/one-liner prompt, tiny `max_new_tokens` (300),
and decoded the full sequence then string-replaced the prompt (which failed,
echoing the prompt into saved output). **Changed:** inference logic moved to
`run_inference.py` (imported by the regenerated notebook); it uses the canonical
prompt, `max_new_tokens=1280` (1024–1536), sets eos/pad ids, and decodes **only
the new tokens** (`out[0][n:]`, `skip_special_tokens=True`).

## J — Cleanups
Module docstring header corrected to `finetuning.py`; the dead triple-quoted
string inside `train()` (demoted to a no-op by the `os.environ` line above it) is
gone; the step-count print now reports the true optimizer-step count
`ceil(len(train)/(bs*grad_accum))*epochs`; `BitsAndBytesConfig`/`SFTConfig`
indentation tidied.

## Extras (P1–P6)
- **`--check_data`** (P1): dependency-free probe — parity assert, token-length
  stats (real tokenizer if importable, else a labelled chars/4 estimate),
  truncation flag, masking check (when deps present), and the split intersection.
- **`--smoke`** (P2): CUDA-guarded `max_steps=3` train + one generation; a clear
  no-op with a message when there's no GPU.
- **Post-training self-test** (P3): generates one held-out sample and asserts the
  three headers appear in order and EOS is hit before the cap; exits non-zero on
  failure.
- **`--merge`** (P4): optional `merge_and_unload` into a fresh fp16 base saved
  under `output/merged` (off by default; needs ~14–16GB).
- **`requirements_finetune.txt`** (P6): pinned to the verified stack (Transformers
  5.x, TRL 0.29.x, PEFT 0.18.x, datasets 4.x, torch ≥2.4, bnb 0.47–0.49); code
  branches where the API differs.
- Notebooks are regenerated from the `.py` sources by `create_notebook.py`
  (source of truth); no training/inference/prompt logic is duplicated inline.

## How to run on Colab

Install: `pip install -r fine_tuning/requirements_finetune.txt`

### A100 (bf16)
`torch.cuda.is_bf16_supported()` is **True** → compute dtype `bfloat16`,
`SFTConfig(bf16=True, fp16=False)`. Recommended (defaults already fit):
```
python fine_tuning/fine_tune.py --data dataset/training_data.jsonl \
    --out fine_tuning/output --test_inputs evaluation/test_inputs.jsonl
```
A100 (40/80GB) comfortably fits all-linear LoRA at `max_seq_len 2048`; you may
raise `--batch_size`/`--r` for speed/capacity.

### T4 (fp16)
`torch.cuda.is_bf16_supported()` is **False** → compute dtype `float16`,
`SFTConfig(bf16=False, fp16=True)`. Same command. On a 15GB T4 keep
`--batch_size 1 --grad_accum 4`; if you hit OOM, use `--target_modules attn` or
lower `--max_seq_len` (note: <2048 truncates some examples — `--check_data` will
tell you how many).

Then evaluate (same held-out split):
```
python evaluation/evaluate.py --base_model mistralai/Mistral-7B-Instruct-v0.3 \
    --adapter_path fine_tuning/output --test_inputs evaluation/test_inputs.jsonl \
    --out_json evaluation/eval_outputs.json --out_md evaluation/manual_eval.md
```

## What could NOT be verified offline (verify on Colab)
This repair was validated with `py_compile`, the dependency-free `--check_data`,
and the GPU-less `--smoke` no-op only (this machine has no GPU and no ML stack).
Confirm on Colab: real-tokenizer token counts and the in-context `[/INST]` ids;
`DataCollatorForCompletionOnlyLM` masking on the real tokenizer and single
BOS/EOS after TRL's tokenization; bf16/fp16 auto-selection on real A100/T4; the
full train→eval_loss→best-checkpoint→self-test loop; and `--merge`.
