"""compare_models.py

Fine-tuned Mistral-7B against RedSage-Qwen3-8B on the same attack paths.

Both models get the same request for every (path, prompt) pair: Mistral in the
exact format its adapter was trained on, RedSage as the user turn of its own
chat template. Decoding settings and seed are the same, so the only thing that
changes between the two columns of the report is the model.

The models load one at a time, in 4-bit: bitsandbytes NF4 on an NVIDIA GPU,
or MLX on Apple Silicon, where both models are converted from their official
weights with the same settings and the adapter is translated to MLX's layout.
Every generation and every judge score is appended to disk as soon as it
exists, so a disconnected session picks up where it stopped when rerun with
the same --out_dir.

The judge is gemini-2.5-flash-lite with the rubric from judge_eval.py, called
through OpenRouter when OPENROUTER_API_KEY is set, otherwise through Gemini.

Run from scenario_generation/:
    python evaluation/compare_models.py --adapter_path fine_tuning/output
    python evaluation/compare_models.py --backend mlx      # on a Mac
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import prompt_generator as pg  # noqa: E402  (also puts fine_tuning/ on sys.path)
import prompt_format  # noqa: E402
import manual_eval_metrics as metrics  # noqa: E402
import judge_eval as judge  # noqa: E402


MISTRAL = "mistral_ft"
REDSAGE = "redsage"
LABELS = {MISTRAL: "Fine-tuned Mistral", REDSAGE: "RedSage Qwen"}

REDSAGE_DEFAULT = "RISys-Lab/RedSage-Qwen3-8B-Ins"
ATTACK_PATHS_DEFAULT = HERE / "inputs" / "attack_paths.json"

# Both entry routes, all four objectives, and the one two-hop path. The ranked
# top five would all start from the same security group.
SAMPLE_PATH_IDS = ["AP-001", "AP-003", "AP-007", "AP-014", "AP-015"]
SEED = 42

MLX_CACHE = Path.home() / ".cache" / "mlx-4bit"

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_JUDGE = "google/" + judge.JUDGE_MODEL

# Qwen3 templates can open a reasoning block. It is not part of the scenario,
# so it is dropped before scoring.
THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)


def job_key(model_key: str, path_id: str, prompt_id: str) -> str:
    return f"{model_key}|{path_id}|{prompt_id}"


def read_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def append_jsonl(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def build_record(prompt_entry: dict, attack_path: dict) -> dict:
    """The same instruction and input that prompt_generator.py sends."""
    return {
        "instruction": pg.SYSTEM_INSTRUCTION,
        "input": pg.build_input_block(prompt_entry, attack_path),
    }


def render_prompt(model_key: str, record: dict, tokenizer) -> str:
    """The same request for both models, each in the format it expects."""
    if model_key == MISTRAL:
        # The exact prompt the adapter was trained on.
        return prompt_format.build_prompt(record)

    return tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt_format.user_message(record)}],
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )


def load_model(model_key: str, args):
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model_id = args.mistral_base if model_key == MISTRAL else args.redsage_model
    print(f"[*] Loading {LABELS[model_key]} ({model_id}) in 4-bit")

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=pg.build_bnb_config(),
        device_map="auto",
    )
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if model_key == MISTRAL:
        from peft import PeftModel
        print(f"[*] Attaching LoRA adapter from {args.adapter_path}")
        model = PeftModel.from_pretrained(model, args.adapter_path)

    model.eval()
    return model, tokenizer


def generate(model, tokenizer, prompt: str) -> dict:
    """Same decoding settings as prompt_generator.py, seeded per call."""
    import torch

    torch.manual_seed(SEED)
    inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False).to(model.device)
    n = inputs["input_ids"].shape[1]

    started = time.time()
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=pg.MAX_NEW_TOKENS,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            repetition_penalty=1.05,
            pad_token_id=tokenizer.pad_token_id,
        )
    seconds = time.time() - started

    text = tokenizer.decode(output_ids[0][n:], skip_special_tokens=True)
    return {
        "output": THINK_RE.sub("", text).strip(),
        "prompt_tokens": n,
        "new_tokens": int(output_ids.shape[1] - n),
        "seconds": round(seconds, 1),
    }


def mlx_quantized(hf_id: str) -> str:
    """A 4-bit MLX copy of a Hugging Face model, converted on first use and cached."""
    path = MLX_CACHE / hf_id.replace("/", "--")
    if not path.exists():
        from mlx_lm import convert
        print(f"[*] Converting {hf_id} to 4-bit MLX in {path} (first run only)")
        convert(hf_id, mlx_path=str(path), quantize=True, q_bits=4, q_group_size=64)
    return str(path)


def mlx_adapter(peft_dir: str, out_dir: Path) -> str:
    """The PEFT LoRA adapter in MLX's layout.

    PEFT stores A as (r, in) and B as (out, r) and scales by alpha / r. MLX
    stores the transposes and takes the scale from its config.
    """
    import mlx.core as mx

    config = json.loads((Path(peft_dir) / "adapter_config.json").read_text())
    weights = mx.load(str(Path(peft_dir) / "adapter_model.safetensors"))

    converted = {}
    for name, value in weights.items():
        # base_model.model.model.layers.0.self_attn.q_proj.lora_A.weight
        module, kind = name[len("base_model.model."):].rsplit(".lora_", 1)
        converted[f"{module}.lora_{kind[0].lower()}"] = value.T

    modules = {tuple(name.rsplit(".lora_", 1)[0].split(".")) for name in converted}
    out_dir.mkdir(parents=True, exist_ok=True)
    mx.save_safetensors(str(out_dir / "adapters.safetensors"), converted)
    (out_dir / "adapter_config.json").write_text(json.dumps({
        "fine_tune_type": "lora",
        "num_layers": 1 + max(int(parts[2]) for parts in modules),
        "lora_parameters": {
            "rank": config["r"],
            "scale": config["lora_alpha"] / config["r"],
            "dropout": 0.0,
            "keys": sorted({".".join(parts[3:]) for parts in modules}),
        },
    }, indent=2))
    return str(out_dir)


def load_model_mlx(model_key: str, args):
    from mlx_lm import load

    if model_key == MISTRAL:
        print(f"[*] Loading {LABELS[MISTRAL]} with the adapter from {args.adapter_path}")
        adapter = mlx_adapter(args.adapter_path, Path(args.out_dir) / "mlx_adapter")
        return load(mlx_quantized(args.mistral_base), adapter_path=adapter)

    print(f"[*] Loading {LABELS[REDSAGE]}")
    return load(mlx_quantized(args.redsage_model))


def generate_mlx(model, tokenizer, prompt: str) -> dict:
    """Same decoding settings as the CUDA path."""
    import mlx.core as mx
    from mlx_lm import stream_generate
    from mlx_lm.sample_utils import make_logits_processors, make_sampler

    mx.random.seed(SEED)
    ids = tokenizer.encode(prompt, add_special_tokens=False)

    started = time.time()
    text, last = "", None
    for last in stream_generate(
        model, tokenizer, ids,
        max_tokens=pg.MAX_NEW_TOKENS,
        sampler=make_sampler(temp=0.7, top_p=0.9),
        logits_processors=make_logits_processors(repetition_penalty=1.05),
    ):
        text += last.text

    return {
        "output": THINK_RE.sub("", text).strip(),
        "prompt_tokens": len(ids),
        "new_tokens": last.generation_tokens,
        "seconds": round(time.time() - started, 1),
    }


def free_mlx(model, tokenizer) -> None:
    import gc
    import mlx.core as mx

    del model, tokenizer
    gc.collect()
    mx.clear_cache()


BACKENDS = {
    "cuda": (load_model, generate, pg.cleanup_memory),
    "mlx": (load_model_mlx, generate_mlx, free_mlx),
}


def run_model(model_key: str, jobs: list, args, outputs_path: Path, done: set) -> None:
    pending = [(p, q) for p, q in jobs
               if job_key(model_key, p["source_id"], q["prompt_id"]) not in done]
    if not pending:
        print(f"[=] {LABELS[model_key]}: all {len(jobs)} generations already on disk")
        return

    load, generate, free = BACKENDS[args.backend]
    model, tokenizer = load(model_key, args)
    model_id = args.mistral_base if model_key == MISTRAL else args.redsage_model

    for i, (attack_path, prompt_entry) in enumerate(pending, 1):
        print(f"[{LABELS[model_key]} {i}/{len(pending)}] "
              f"{attack_path['source_id']} x {prompt_entry['prompt_id']}")

        prompt = render_prompt(model_key, build_record(prompt_entry, attack_path), tokenizer)
        result = generate(model, tokenizer, prompt)
        print(f"    {result['new_tokens']} tokens in {result['seconds']}s")

        append_jsonl(outputs_path, {
            "model": model_key,
            "model_id": model_id,
            "path_id": attack_path["source_id"],
            "path_name": attack_path["source_name"],
            "attack_level": attack_path["attack_level"],
            "techniques": attack_path["techniques"],
            "prompt_id": prompt_entry["prompt_id"],
            "focus": prompt_entry["focus"],
            **result,
        })

    free(model, tokenizer)


def openrouter_reply(api_key: str, prompt: str) -> str:
    """One reply from the judge model, retried on rate limits and server errors."""
    body = json.dumps({
        "model": OPENROUTER_JUDGE,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    last = judge.GEMINI_MAX_RETRIES - 1

    for attempt in range(judge.GEMINI_MAX_RETRIES):
        request = urllib.request.Request(OPENROUTER_URL, data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.load(response)["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if (e.code != 429 and e.code < 500) or attempt == last:
                raise
        except urllib.error.URLError:
            if attempt == last:
                raise
        time.sleep(min(judge.GEMINI_RETRY_BASE_SECONDS * 2 ** attempt,
                       judge.GEMINI_RETRY_MAX_SECONDS))


def build_scorer(args):
    """The judge as a function of (scenario, label), checked before any model loads."""
    if args.no_judge:
        return None

    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    if openrouter_key:
        print(f"[*] Judge: {OPENROUTER_JUDGE} through OpenRouter")
        try:
            openrouter_reply(openrouter_key, "Reply with exactly: ok")
        except urllib.error.HTTPError as e:
            sys.exit(f"[!] OpenRouter refused the judge check ({e.code}): "
                     f"{e.read().decode('utf-8', 'replace')[:200]}")

        def score(text: str, label: str) -> dict:
            try:
                reply = openrouter_reply(openrouter_key, judge.build_rubric_prompt(text))
            except Exception as e:
                return judge.failed_scores(f"judge call failed for {label}: {e}")
            return judge.parse_score_json(reply)

        return score

    api_key = judge.resolve_api_key(args.gemini_key)
    if api_key:
        client = judge.build_judge_client(api_key)
        judge.preflight_judge_auth(client)
        return lambda text, label: judge.judge_scenario_safe(client, text, label)

    sys.exit("[!] No judge key found. Set OPENROUTER_API_KEY or GOOGLE_API_KEY, "
             "or pass --no_judge to report the format metrics only.")


def judge_all(rows: list, scores_path: Path, score) -> dict:
    """Judge scores per generation, keyed like the outputs file."""
    scores = {r["key"]: r["scores"] for r in read_jsonl(scores_path)}

    for row in rows:
        key = job_key(row["model"], row["path_id"], row["prompt_id"])
        if key in scores and judge.is_scored(scores[key]):
            continue

        result = score(row["output"], key)
        scores[key] = result
        append_jsonl(scores_path, {"key": key, "scores": result})
        time.sleep(judge.GEMINI_CALL_DELAY)

    return scores


def average(values: list) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def winner(name: str, a: float, b: float) -> str:
    if a == b:
        return "Tie"
    a_wins = a > b if name not in metrics.LOWER_IS_BETTER else a < b
    return LABELS[MISTRAL] if a_wins else LABELS[REDSAGE]


def write_report(rows: list, scores: dict, args, out_dir: Path) -> None:
    by_model = {MISTRAL: [], REDSAGE: []}
    for row in rows:
        by_model[row["model"]].append(row)

    measured = {
        key: [metrics.compute_metrics(r) for r in group]
        for key, group in by_model.items()
    }

    lines = [
        "# Fine-tuned Mistral vs RedSage Qwen",
        "",
        f"- Fine-tuned Mistral: `{args.mistral_base}` + adapter `{args.adapter_path}`",
        f"- RedSage Qwen: `{args.redsage_model}`",
        f"- Attack paths: `{args.attack_paths}`, "
        f"{len({r['path_id'] for r in rows})} paths, prompts "
        f"{sorted({r['prompt_id'] for r in rows})}",
        f"- Both in 4-bit ({'MLX, group size 64' if args.backend == 'mlx' else 'bitsandbytes NF4'}), "
        f"temperature 0.7, top_p 0.9, repetition penalty 1.05, max {pg.MAX_NEW_TOKENS} new tokens, seed {SEED}",
        "",
        "## Format and coverage metrics (averaged)",
        "",
        f"| Metric | {LABELS[MISTRAL]} | {LABELS[REDSAGE]} | Better |",
        "|---|---:|---:|:---:|",
    ]
    for name in metrics.NUMERIC_METRICS:
        a = average([getattr(m, name) for m in measured[MISTRAL]])
        b = average([getattr(m, name) for m in measured[REDSAGE]])
        lines.append(f"| `{name}` | {a} | {b} | {winner(name, a, b)} |")

    speed = {
        key: average([r["new_tokens"] / r["seconds"] for r in group if r["seconds"]])
        for key, group in by_model.items()
    }
    lines += [
        "",
        f"Generation speed: {LABELS[MISTRAL]} {speed[MISTRAL]} tok/s, "
        f"{LABELS[REDSAGE]} {speed[REDSAGE]} tok/s.",
    ]

    def judged(model_key, path_id, prompt_id):
        result = scores.get(job_key(model_key, path_id, prompt_id))
        return result if result and judge.is_scored(result) else None

    if scores:
        lines += ["", "## Gemini judge (1 to 10 per criterion)", "",
                  f"| Criterion | {LABELS[MISTRAL]} | {LABELS[REDSAGE]} |",
                  "|---|---:|---:|"]
        scored = {
            key: [s for s in (judged(key, r["path_id"], r["prompt_id"]) for r in group) if s]
            for key, group in by_model.items()
        }
        for criterion in judge.SCORE_KEYS + ("total",):
            a = average([s[criterion] for s in scored[MISTRAL]])
            b = average([s[criterion] for s in scored[REDSAGE]])
            lines.append(f"| {criterion} | {a} | {b} |")

        wins = {MISTRAL: 0, REDSAGE: 0, "tie": 0}
        lines += ["", "| Path | Prompt | Mistral total | RedSage total |",
                  "|---|---|---:|---:|"]
        for row in by_model[MISTRAL]:
            a = judged(MISTRAL, row["path_id"], row["prompt_id"])
            b = judged(REDSAGE, row["path_id"], row["prompt_id"])
            if not (a and b):
                continue
            wins[MISTRAL if a["total"] > b["total"] else REDSAGE if b["total"] > a["total"] else "tie"] += 1
            lines.append(f"| {row['path_id']} | {row['prompt_id']} | {a['total']} | {b['total']} |")
        lines += ["", f"Entries won: {LABELS[MISTRAL]} {wins[MISTRAL]}, "
                      f"{LABELS[REDSAGE]} {wins[REDSAGE]}, ties {wins['tie']}."]

    report = out_dir / "report.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n[OK] Report saved to {report}")


def write_side_by_side(rows: list, out_dir: Path) -> None:
    """Both outputs for each path, one after the other, for reading."""
    outputs = {job_key(r["model"], r["path_id"], r["prompt_id"]): r for r in rows}
    rule = "=" * 80
    blocks = []
    for row in rows:
        if row["model"] != MISTRAL:
            continue
        other = outputs.get(job_key(REDSAGE, row["path_id"], row["prompt_id"]))
        blocks.append(
            f"{rule}\n{row['path_id']} | {row['attack_level']} | {row['prompt_id']}: {row['focus']}\n"
            f"{row['path_name']}\nTechniques: {row['techniques']}\n{rule}\n\n"
            f"--- {LABELS[MISTRAL].upper()} ---\n\n{row['output']}\n\n"
            f"--- {LABELS[REDSAGE].upper()} ---\n\n{other['output'] if other else '(not generated)'}\n"
        )
    path = out_dir / "side_by_side.txt"
    path.write_text("\n".join(blocks), encoding="utf-8")
    print(f"[OK] Outputs saved to {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fine-tuned Mistral-7B vs RedSage-Qwen3-8B on the same attack paths")
    parser.add_argument("--attack_paths", default=str(ATTACK_PATHS_DEFAULT),
                        help="attack_paths.json exported by the infrastructure repo")
    parser.add_argument("--adapter_path", default=pg.ADAPTER_PATH_DEFAULT,
                        help="LoRA adapter folder or Hugging Face repo id")
    parser.add_argument("--mistral_base", default=pg.BASE_MODEL_DEFAULT)
    parser.add_argument("--redsage_model", default=REDSAGE_DEFAULT)
    parser.add_argument("--prompt_ids", nargs="+", default=["P1"],
                        help="Prompts from prompt_generator.py to run (default: P1)")
    parser.add_argument("--path_ids", nargs="+", default=SAMPLE_PATH_IDS,
                        help=f"Paths to run (default: {' '.join(SAMPLE_PATH_IDS)})")
    parser.add_argument("--all_paths", action="store_true",
                        help="Run every path in the file instead of --path_ids")
    parser.add_argument("--out_dir", default="results/model_comparison")
    parser.add_argument("--backend", choices=sorted(BACKENDS),
                        default="mlx" if sys.platform == "darwin" else "cuda",
                        help="cuda: bitsandbytes on an NVIDIA GPU. mlx: Apple Silicon")
    parser.add_argument("--gemini_key", default=None,
                        help="Gemini API key; falls back to GOOGLE_API_KEY / GEMINI_API_KEY")
    parser.add_argument("--no_judge", action="store_true",
                        help="Skip the judge and report format metrics only")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    attack_paths = pg.load_attack_paths(Path(args.attack_paths))
    if not args.all_paths:
        attack_paths = [p for p in attack_paths if p["source_id"] in set(args.path_ids)]
    prompts = [p for p in pg.STRUCTURED_PROMPTS if p["prompt_id"] in set(args.prompt_ids)]
    if not attack_paths or not prompts:
        sys.exit("[!] No paths or prompts selected. Check --path_ids and --prompt_ids.")

    jobs = [(p, q) for p in attack_paths for q in prompts]
    print(f"[*] {len(attack_paths)} paths x {len(prompts)} prompts x 2 models "
          f"= {2 * len(jobs)} generations")

    # Check the judge before spending half an hour on generation.
    score = build_scorer(args)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs_path = out_dir / "outputs.jsonl"

    for model_key in (MISTRAL, REDSAGE):
        done = {job_key(r["model"], r["path_id"], r["prompt_id"]) for r in read_jsonl(outputs_path)}
        run_model(model_key, jobs, args, outputs_path, done)

    wanted = {(p["source_id"], q["prompt_id"]) for p, q in jobs}
    rows = [r for r in read_jsonl(outputs_path) if (r["path_id"], r["prompt_id"]) in wanted]

    scores = judge_all(rows, out_dir / "judge_scores.jsonl", score) if score else {}

    write_side_by_side(rows, out_dir)
    write_report(rows, scores, args, out_dir)


if __name__ == "__main__":
    main()
