# QLoRA pipeline repair — what changed and why

This documents the correctness / train-vs-inference-parity repair of the QLoRA
fine-tuning pipeline for `mistralai/Mistral-7B-Instruct-v0.3`. The shipped adapter
produced off-format output that echoed the prompt, used emoji/markdown, and never
stopped. Each fix below states what was wrong, why it mattered, and what changed.

## October 2026: matched to the adapter we actually have

The adapter we have (the one in `output/`, r=16, alpha=32, q/k/v/o) was not
trained by this repair. It came from the original Colab notebook, which:

- trained on `[INST] {instruction}\n\n{input} [/INST]\n{output}`, with TRL 0.29.1
  adding `<s>` and appending `</s>`. Note the space before `[/INST]` and the
  newline after it.
- split the 81 records with `datasets`' `train_test_split(test_size=0.2,
  seed=42)`, training on 64 and holding out 17.
- set no `max_length`, so TRL's default of 1024 tokens applied. Every example is
  1,316 to 1,683 tokens, so all 81 were cut: the adapter saw about the first 600
  tokens of each answer and never an ending or a `</s>`. Expect it to run long.

The repair had moved every inference path to Mistral's chat template (no space,
no newline), so the adapter was being prompted with text it never saw, and its
"unseen" test set was 10 records that were all in the adapter's training data.
Both are now aligned with the adapter:

- `prompt_format.build_prompt` / `build_completion` produce the trained text.
  Checked against TRL 0.29.1 with the real tokenizer: token-identical for all 81
  records.
- `data_split.HELD_OUT_SOURCE_IDS` freezes the 17 held-out records, and
  `evaluation/test_inputs.jsonl` holds them. Validation for a retrain comes from
  the other 64.
- Section E's collator does not exist in TRL 0.29, so a retrain silently fell
  back to loss on the whole sequence. `finetuning.py` now tokenizes each example
  itself with a `completion_mask` and sets `completion_only_loss=True`. Checked
  end to end on CPU with TRL 0.29.1 and a tiny model: one `<s>`, a final `</s>`,
  the prompt masked, the answer carrying the loss.

Sections A, E and H below describe the repair as first written; where they
disagree with this section, this section is what the code does.

## A — Prompt parity (root cause)
**Wrong:** six different prompt builders existed (the manual `[INST] … [/INST]\n`
in training, three variants in the inference notebook, one in `evaluate.py`, one
in the Kaggle generator) and *none* matched what training saw. The model was
fine-tuned on one wrapper and prompted with another, so it parroted instructions
and drifted off-format. **Why it mattered:** an LLM only learns the mapping it was
shown; a different inference prompt is out-of-distribution. **Changed:** one
canonical builder in `prompt_format.py`, imported by training *and* every
inference path, using the record's full `instruction`. (It now produces the
adapter's trained format; see the October section above.)

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
loss was computed over the prompt too. **Changed:** each example is tokenized with a
`completion_mask` that is 0 on the prompt and 1 on the answer, and TRL is told
`completion_only_loss=True`. (The first version used
`DataCollatorForCompletionOnlyLM`, which TRL 0.29 no longer has.)

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
unseen. **Changed:** one split (`data_split.py`, keyed on `_meta.source_id`) whose test
set is the 17 records the shipped adapter never trained on, committed as
`evaluation/test_inputs.jsonl`. Training uses the other 64; evaluation refuses a
test file holding any record outside the 17.

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
- **`--check_data`** (P1): no model load. Prints the split, and with a tokenizer
  available, the token lengths, the masked prompt length, and how many examples
  would be truncated.
- **`--smoke`** (P2): CUDA-guarded `max_steps=3` train + one generation; a clear
  no-op with a message when there's no GPU.
- **Post-training self-test** (P3): generates one held-out sample and asserts the
  three headers appear in order and EOS is hit before the cap; exits non-zero on
  failure.
- **`--merge`** (P4): optional `merge_and_unload` into a fresh fp16 base saved
  under `output/merged` (off by default; needs ~14–16GB).
- **`requirements_finetune.txt`** (P6): pinned to the stack that trained the
  adapter (Transformers 5.x, TRL 0.29.x, PEFT 0.18.x, datasets 4.x, torch ≥2.4,
  bnb 0.47–0.49). The code is written against these versions.
- Notebooks are regenerated from the `.py` sources by `create_notebook.py`
  (source of truth); no training/inference/prompt logic is duplicated inline.

## How to run on Colab

Install: `pip install -r fine_tuning/requirements_finetune.txt`

### A100 (bf16)
`torch.cuda.is_bf16_supported()` is **True** → compute dtype `bfloat16`,
`SFTConfig(bf16=True, fp16=False)`. Recommended (defaults already fit):
```
python fine_tuning/fine_tune.py --data dataset/training_data.jsonl \
    --out fine_tuning/output
```
A100 (40/80GB) comfortably fits all-linear LoRA at `max_seq_len 2048`; you may
raise `--batch_size`/`--r` for speed/capacity.

### T4 (fp16)
`torch.cuda.is_bf16_supported()` is **False** → compute dtype `float16`,
`SFTConfig(bf16=False, fp16=True)`. Same command. On a 15GB T4 keep
`--batch_size 1 --grad_accum 4`; if you hit OOM, use `--target_modules attn` or
lower `--max_seq_len`. Training refuses to start if that would truncate any
example, since a cut example loses its ending and its `</s>`.

Then evaluate (same held-out split):
```
python evaluation/evaluate.py --base_model mistralai/Mistral-7B-Instruct-v0.3 \
    --adapter_path fine_tuning/output --test_inputs evaluation/test_inputs.jsonl \
    --out_json evaluation/eval_outputs.json --out_md evaluation/manual_eval.md
```

## What was verified, and what still needs a GPU
Verified on CPU with TRL 0.29.1, transformers 5.0.0 and the real tokenizer: the
prompt is token-identical to the adapter's training run for all 81 records; the
held-out ids match `datasets`' split; training masks the prompt, keeps one `<s>`
and a final `</s>`, and runs train, eval and best-checkpoint selection on a tiny
model. Still needs a GPU: 4-bit loading, bf16/fp16 auto-selection on A100/T4, the
post-training self-test on the real model, and `--merge`.
