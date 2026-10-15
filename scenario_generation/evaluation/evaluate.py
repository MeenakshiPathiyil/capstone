"""Generate base vs fine-tuned scenarios for manual evaluation."""

import argparse
import json
import os
import sys
import gc
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

MAX_NEW_TOKENS = 1200


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate base vs fine-tuned outputs for manual review")
    parser.add_argument("--base_model", required=True, help="Base model path or HF name (e.g. mistralai/Mistral-7B-Instruct-v0.3)")
    parser.add_argument("--adapter_path", required=True, help="Path to LoRA adapter output folder")
    parser.add_argument("--test_inputs", required=True, help="Path to test input JSONL (10 entries)")
    parser.add_argument("--out_json", required=True, help="Path to save intermediate evaluation_outputs.json")
    parser.add_argument("--out_md", required=True, help="Path to save the manual evaluation worksheet (.md)")
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
    return f"[INST] {instruction}\n\n{input_text} [/INST]"


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


def load_cache(cache_path: Path) -> dict:
    if cache_path.exists():
        with cache_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache_path: Path, data: dict):
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def generate_markdown_worksheet(cache: dict, test_inputs: list[dict], md_path: Path):
    print(f"[*] Generating formatting markdown report at {md_path}...")
    lines = []
    lines.append("# Manual Evaluation Worksheet")
    lines.append("Compare the Scenario Base generation and the Finetuned generation to determine qualitative improvements.\n")

    for entry in test_inputs:
        source_id = entry.get("source_id") or entry.get("_meta", {}).get("source_id") or "Unknown ID"
        if source_id not in cache:
            continue
            
        data = cache[source_id]
        input_text = entry.get("input", "")
        base_output = data.get("base_output", "*No Base Output Generated*")
        tuned_output = data.get("finetuned_output", "*No Tuned Output Generated*")

        lines.append(f"## Target Source ID: `{source_id}`")
        lines.append("\n**Input Structure Facts:**")
        lines.append("```json\n" + input_text + "\n```")
        
        lines.append("\n### Base Mistral-7B Output")
        lines.append(base_output)
        
        lines.append("\n### Finetuned Mistral-7B Output")
        lines.append(tuned_output)
        
        lines.append("\n---\n")
        
    with md_path.open('w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print("[✓] Markdown generation complete.")


def cleanup_memory(model=None, tokenizer=None):
    """Aggressively unloads models to circumvent OOM on constrained GPUs."""
    print("[*] Unloading model and clearing GPU cache...")
    if model is not None:
        del model
    if tokenizer is not None:
        del tokenizer
        
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    print("[✓] Memory cleared.\n")


def main() -> None:
    args = parse_args()
    
    test_inputs_path = Path(args.test_inputs)
    adapter_path = Path(args.adapter_path)
    out_json_path = Path(args.out_json)
    out_md_path = Path(args.out_md)

    if not test_inputs_path.exists():
        print(f"[!] Test input file not found: {test_inputs_path}")
        sys.exit(1)
        
    entries = load_test_inputs(test_inputs_path)
    cache = load_cache(out_json_path)

    base_needs_gen = [e for e in entries if ("base_output" not in cache.get(e.get("source_id") or e.get("_meta", {}).get("source_id", "NO_ID"), {}))]
    tuned_needs_gen = [e for e in entries if ("finetuned_output" not in cache.get(e.get("source_id") or e.get("_meta", {}).get("source_id", "NO_ID"), {}))]

    # Phase 1: Base Generation (Only if missing from cache)
    if base_needs_gen:
        print("\n=== PHASE 1: GENERATING BASE MODEL OUTPUTS ===")
        print(f"[*] Loading base model in 4-bit: {args.base_model}")
        bnb_config = build_bnb_config()

        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            quantization_config=bnb_config,
            device_map="auto",
        )
        base_model.eval()

        tokenizer = AutoTokenizer.from_pretrained(args.base_model)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        tokenizer.padding_side = "right"

        for idx, entry in enumerate(base_needs_gen, start=1):
            source_id = entry.get("source_id") or entry.get("_meta", {}).get("source_id")
            if not source_id: 
                continue
                
            print(f"[+] ({idx}/{len(base_needs_gen)}) Generating BASE output for {source_id}")
            prompt = format_prompt(entry.get("instruction", ""), entry.get("input", ""))
            
            output_text = generate_text(base_model, tokenizer, prompt)
            
            if source_id not in cache:
                cache[source_id] = {}
            cache[source_id]["base_output"] = output_text
            save_cache(out_json_path, cache)

        # Immediate Cleanup before Phase 2
        cleanup_memory(base_model, tokenizer)
    else:
        print("[✓] Phase 1 Skipped: Base memory already generated.")

    # Phase 2: Finetuned Generation
    if tuned_needs_gen:
        print("=== PHASE 2: GENERATING FINETUNED MODEL OUTPUTS ===")
        print(f"[*] Loading base model in 4-bit: {args.base_model}")
        bnb_config = build_bnb_config()
        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            quantization_config=bnb_config,
            device_map="auto",
        )
        
        tokenizer = AutoTokenizer.from_pretrained(args.base_model)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        tokenizer.padding_side = "right"

        print(f"[*] Loading fine-tuned adapter from: {adapter_path}")
        if not adapter_path.exists():
            print(f"[!] Adapter path not found: {adapter_path}")
            sys.exit(1)
            
        finetuned_model = PeftModel.from_pretrained(base_model, str(adapter_path))
        finetuned_model.eval()

        for idx, entry in enumerate(tuned_needs_gen, start=1):
            source_id = entry.get("source_id") or entry.get("_meta", {}).get("source_id")
            if not source_id: 
                continue
                
            print(f"[+] ({idx}/{len(tuned_needs_gen)}) Generating TUNED output for {source_id}")
            prompt = format_prompt(entry.get("instruction", ""), entry.get("input", ""))
            
            output_text = generate_text(finetuned_model, tokenizer, prompt)
            
            if source_id not in cache:
                cache[source_id] = {}
            cache[source_id]["finetuned_output"] = output_text
            save_cache(out_json_path, cache)

        cleanup_memory(finetuned_model, tokenizer)
        base_model = None # It's wrapped by Peft, so `del finetuned_model` del references it, but we can be explicit
        cleanup_memory(base_model)
    else:
        print("[✓] Phase 2 Skipped: Finetuned memory already generated.")

    # Phase 3: Reporting
    print("\n=== PHASE 3: WORKSHEET GENERATION ===")
    generate_markdown_worksheet(cache, entries, out_md_path)


if __name__ == "__main__":
    main()
