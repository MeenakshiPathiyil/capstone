"""
run_inference.py
----------------
Load the QLoRA fine-tuned Mistral-7B adapter and generate tri-modal cyber attack
scenarios for the held-out test inputs.

This is the importable, testable home for inference logic — the notebook
(finetune_output_test.ipynb) just calls into here, so the inference prompt can
never drift from the training prompt: both use prompt_format.build_chat.

Key correctness properties (vs. the old notebook):
  * Uses the SHARED canonical prompt with the FULL instruction (not a one-liner).
  * Sets eos_token_id + pad_token_id on every generate() call so the model stops.
  * Decodes ONLY the newly generated tokens (out[0][n:]) — the saved text is the
    completion, never the echoed prompt.

Usage (run from scenario_generation/):
    python fine_tuning/run_inference.py \
        --adapter fine_tuning/output \
        --test_inputs evaluation/test_inputs.jsonl \
        --out fine_tuning/output/inference_results.txt
    python fine_tuning/run_inference.py --smoke      # CUDA-guarded no-op probe
"""

import argparse
import sys
from pathlib import Path

import prompt_format
import data_split


BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.3"
REQUIRED_HEADERS = ["[NATURAL LANGUAGE]", "[MATHEMATICAL EXPRESSION]", "[ATTACK GRAPH]"]


# ── Model loading ─────────────────────────────────────────────────────────────

def load_models(base, adapter, trust_remote_code=False, with_adapter=True):
    """Load the 4-bit base model and (optionally) attach the LoRA adapter."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel

    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    compute_dtype = torch.bfloat16 if bf16 else torch.float16
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=compute_dtype,
    )

    print(f"[+] Loading base model ({'bf16' if bf16 else 'fp16'} compute): {base}")
    model = AutoModelForCausalLM.from_pretrained(
        base, quantization_config=bnb_config, device_map="auto",
        trust_remote_code=trust_remote_code,
    )
    tokenizer = AutoTokenizer.from_pretrained(base, trust_remote_code=trust_remote_code)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if with_adapter:
        print(f"[+] Attaching adapter: {adapter}")
        model = PeftModel.from_pretrained(model, adapter)

    model.config.use_cache = True
    model.eval()
    return model, tokenizer


# ── Generation ────────────────────────────────────────────────────────────────

def generation_kwargs(tokenizer, max_new_tokens, do_sample, temperature, top_p, repetition_penalty):
    """Assemble generate() kwargs; sampling params only included when sampling."""
    kw = dict(
        max_new_tokens=max_new_tokens,
        eos_token_id=tokenizer.eos_token_id,   # fix B2: stop on EOS
        pad_token_id=tokenizer.pad_token_id,   # fix B2
        do_sample=do_sample,
        repetition_penalty=repetition_penalty,
    )
    if do_sample:
        kw["temperature"] = temperature
        kw["top_p"] = top_p
    return kw


def generate_one(model, tokenizer, record, gen_kwargs):
    """Generate the completion for one record; returns (text, new_token_ids)."""
    import torch

    # build_chat already embeds BOS, so tokenize with add_special_tokens=False.
    prompt = prompt_format.build_chat(record, tokenizer, for_training=False)
    inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False).to(model.device)
    n = inputs["input_ids"].shape[1]
    with torch.no_grad():
        out = model.generate(**inputs, **gen_kwargs)
    new_ids = out[0][n:]                                  # fix I2: only new tokens
    text = tokenizer.decode(new_ids, skip_special_tokens=True).strip()
    return text, new_ids.tolist()


def headers_in_order(text):
    pos = [text.find(h) for h in REQUIRED_HEADERS]
    return all(p >= 0 for p in pos) and pos == sorted(pos), pos


# ── Test-input loading ────────────────────────────────────────────────────────

def load_records(args):
    """Held-out test inputs by default; a single dataset index if --index given."""
    if args.index is not None:
        recs = data_split.load_records(args.data)
        return [dict(recs[args.index], source_id=data_split.source_id(recs[args.index], args.index))]
    return data_split.read_test_inputs(args.test_inputs)


# ── Main run ──────────────────────────────────────────────────────────────────

def run(args) -> int:
    records = load_records(args)
    if args.samples:
        records = records[: args.samples]
    print(f"[+] {len(records)} record(s) to generate")

    model, tokenizer = load_models(args.base, args.adapter, args.trust_remote_code, with_adapter=True)
    gk = generation_kwargs(tokenizer, args.max_new_tokens, args.do_sample,
                           args.temperature, args.top_p, args.repetition_penalty)

    base_model = None
    if args.compare:
        base_model, _ = load_models(args.base, args.adapter, args.trust_remote_code, with_adapter=False)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("TRI-MODAL CYBER ATTACK SCENARIO GENERATION\n")
        f.write("=" * 80 + "\n\n")
        for i, rec in enumerate(records, 1):
            sid = rec.get("source_id", f"#{i}")
            print(f"[+] ({i}/{len(records)}) {sid}")
            text, _ = generate_one(model, tokenizer, rec, gk)

            f.write("=" * 80 + "\n")
            f.write(f"SAMPLE {i}  (source_id: {sid})\n")
            f.write("-" * 80 + "\n\n")
            f.write("INPUT:\n" + rec.get("input", "") + "\n\n")
            if args.compare and base_model is not None:
                base_text, _ = generate_one(base_model, tokenizer, rec, gk)
                f.write("BASELINE OUTPUT:\n" + base_text + "\n\n")
                f.write("FINE-TUNED OUTPUT:\n" + text + "\n\n")
            else:
                f.write("OUTPUT:\n" + text + "\n\n")

    print(f"[✓] Saved to: {out_path}")
    return 0


def run_smoke(args) -> int:
    """CUDA-guarded one-sample self-test (fix I acceptance)."""
    try:
        import torch
    except ImportError:
        print("[smoke] PyTorch not installed — inference smoke is a NO-OP here.")
        print("        On Colab with a GPU it generates one held-out sample and")
        print("        checks all three headers appear in order and EOS is hit.")
        return 0
    if not torch.cuda.is_available():
        print("[smoke] No CUDA GPU — inference smoke is a NO-OP.")
        return 0

    records = data_split.read_test_inputs(args.test_inputs)
    model, tokenizer = load_models(args.base, args.adapter, args.trust_remote_code, with_adapter=True)
    gk = generation_kwargs(tokenizer, args.max_new_tokens, do_sample=False,
                           temperature=args.temperature, top_p=args.top_p,
                           repetition_penalty=args.repetition_penalty)
    text, new_ids = generate_one(model, tokenizer, records[0], gk)
    ok_headers, pos = headers_in_order(text)
    eos_hit = tokenizer.eos_token_id in new_ids
    print(f"[smoke] headers in order: {ok_headers} {pos}")
    print(f"[smoke] EOS before cap  : {eos_hit} ({len(new_ids)}/{args.max_new_tokens} tokens)")
    ok = ok_headers and eos_hit
    print(f"[smoke] RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def build_arg_parser():
    p = argparse.ArgumentParser(description="Run inference with the fine-tuned adapter")
    p.add_argument("--base", default=BASE_MODEL)
    p.add_argument("--adapter", default="fine_tuning/output",
                   help="Path to the saved LoRA adapter folder")
    p.add_argument("--test_inputs", default=data_split.DEFAULT_TEST_INPUTS,
                   help="Held-out test inputs JSONL")
    p.add_argument("--data", default="dataset/training_data.jsonl",
                   help="Dataset (only used with --index)")
    p.add_argument("--index", type=int, default=None,
                   help="Generate for a specific dataset index instead of the test set")
    p.add_argument("--samples", type=int, default=0, help="Limit number of samples (0 = all)")
    p.add_argument("--compare", action="store_true", help="Also generate base (no adapter) output")
    p.add_argument("--out", default="fine_tuning/output/inference_results.txt")
    p.add_argument("--trust_remote_code", action="store_true")

    # Generation controls (fix I3 defaults).
    p.add_argument("--max_new_tokens", type=int, default=1280, help="1024–1536 recommended")
    p.add_argument("--do_sample", action="store_true", default=True)
    p.add_argument("--greedy", dest="do_sample", action="store_false",
                   help="Disable sampling (deterministic)")
    p.add_argument("--temperature", type=float, default=0.7)
    p.add_argument("--top_p", type=float, default=0.9)
    p.add_argument("--repetition_penalty", type=float, default=1.1)
    p.add_argument("--smoke", action="store_true", help="CUDA-guarded one-sample self-test")
    return p


def main():
    args = build_arg_parser().parse_args()
    if args.smoke:
        sys.exit(run_smoke(args))
    sys.exit(run(args))


if __name__ == "__main__":
    main()
