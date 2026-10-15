"""
create_notebook.py
-------------------
Regenerate every Colab/Kaggle notebook from the .py sources, which are the single
source of truth. The notebooks no longer re-implement training/inference/prompt
logic inline (that was how prompt drift crept back in). Instead each notebook
*ships* the fixed repo modules (prompt_format.py, data_split.py, finetuning.py,
run_inference.py, fine_tune.py) into the runtime and then runs them — so the
prompt and pipeline can never diverge from what training used.

    python create_notebook.py

Generates (next to this script):
    colab_finetune_setup.ipynb   - QLoRA training: runs fine_tune.py
    finetune_output_test.ipynb   - inference: runs run_inference.py on held-out
    kaggle_prompt_gen.ipynb      - baseline vs fine-tuned comparison + metrics
    kaggle_compare_models.ipynb  - fine-tuned Mistral vs RedSage Qwen, runs compare_models.py
    colab_compare_models.ipynb   - the same comparison for Colab
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent          # scenario_generation/
FT = HERE / "fine_tuning"
EVAL = HERE / "evaluation"
TEST_INPUTS = EVAL / "test_inputs.jsonl"


# ── helpers ─────────────────────────────────────────────────────────────────

def read(path) -> str:
    return Path(path).read_text(encoding="utf-8")


def pyliteral(text: str) -> str:
    """A valid Python string literal whose value is exactly `text`.

    Non-ASCII stays raw: json escapes an emoji as a surrogate pair, which Python
    reads back as two lone surrogates that write_text cannot encode.
    """
    return json.dumps(text, ensure_ascii=False)


def md_cell(source, cid):
    return {"cell_type": "markdown", "id": cid, "metadata": {}, "source": source}


def code_cell(source, cid):
    return {"cell_type": "code", "execution_count": None, "id": cid,
            "metadata": {}, "outputs": [], "source": source}


def ship_cell(files: dict, cid: str, note: str = ""):
    """A code cell that writes the given {filename: source} files to the cwd."""
    lines = ["# Ship the fixed repo modules into this runtime (source of truth)."]
    if note:
        lines.append(f"# {note}")
    lines.append("import pathlib")
    for name, src in files.items():
        lines.append(
            f"pathlib.Path({pyliteral(name)}).write_text({pyliteral(src)}, encoding='utf-8')"
        )
    lines.append("print('Wrote:', " + ", ".join(pyliteral(n) for n in files) + ")")
    return code_cell("\n".join(lines), cid)


def write_notebook(path: Path, cells: list, metadata: dict):
    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": metadata,
        "cells": cells,
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(notebook, f, indent=1, ensure_ascii=False)
    print(f"Created: {path.name}  ({path.stat().st_size:,} bytes)")


COLAB_META = {
    "accelerator": "GPU",
    "colab": {"provenance": []},
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python"},
}

KAGGLE_META = {
    "kaggle": {
        "accelerator": "nvidiaTeslaT4",
        "dataSources": [{"sourceType": "datasetVersion", "sourceId": "finetuned"}],
        "isGpuEnabled": True,
        "isInternetEnabled": True,
    },
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python"},
}

REQUIREMENTS = read(FT / "requirements_finetune.txt")


# ── 1) Training notebook (Colab) ───────────────────────────────────────────────

def build_training_notebook():
    files = {
        "prompt_format.py": read(FT / "prompt_format.py"),
        "data_split.py":    read(FT / "data_split.py"),
        "finetuning.py":    read(FT / "finetuning.py"),
        "fine_tune.py":     read(FT / "fine_tune.py"),
        "requirements_finetune.txt": REQUIREMENTS,
    }

    md_intro = (
        "# QLoRA Fine-Tuning (Colab)\n\n"
        "Fine-tunes `mistralai/Mistral-7B-Instruct-v0.3` on the tri-modal scenario "
        "dataset using the **fixed** pipeline (`fine_tune.py`). No training logic "
        "lives in this notebook — it ships the repo modules and runs the script, so "
        "the prompt/precision/masking fixes always apply.\n\n"
        "Steps: GPU check -> install -> ship code -> upload `training_data.jsonl` -> "
        "train -> download the adapter.\n\n"
        "**Precision is auto-selected:** bf16 on A100, fp16 on T4."
    )

    gpu_check = (
        "import torch\n"
        "print('CUDA available:', torch.cuda.is_available())\n"
        "if torch.cuda.is_available():\n"
        "    print('GPU:', torch.cuda.get_device_name(0))\n"
        "    print('bf16 supported (A100=True, T4=False):', torch.cuda.is_bf16_supported())\n"
        "else:\n"
        "    print('No GPU. Runtime -> Change runtime type -> T4 GPU')"
    )

    install = (
        "!pip install -q -r requirements_finetune.txt\n"
        "print('Installed fine-tuning requirements.')"
    )

    upload = (
        "from google.colab import files\n"
        "print('Upload training_data.jsonl')\n"
        "up = files.upload()\n"
        "import os; print('cwd files:', os.listdir('.'))"
    )

    run_train = (
        "# Runs the fixed QLoRA pipeline. The 17 held-out records listed in\n"
        "# data_split.py are never trained on, so evaluation stays honest.\n"
        "!python fine_tune.py --data training_data.jsonl --out ./output\n"
        "# Override examples:\n"
        "#   --target_modules attn   (attention-only LoRA)\n"
        "#   --epochs 5 --lr 1e-4 --r 32 --alpha 64\n"
        "#   --merge                 (also save a merged fp16 model; needs ~16GB)"
    )

    download = (
        "import shutil\n"
        "from google.colab import files\n"
        "shutil.make_archive('finetuned_adapters', 'zip', './output')\n"
        "files.download('finetuned_adapters.zip')"
    )

    cells = [
        md_cell(md_intro, "md-intro"),
        code_cell(gpu_check, "gpu-check"),
        code_cell(install, "install"),
        ship_cell(files, "ship-code", "These are the repaired pipeline files."),
        code_cell(upload, "upload-data"),
        code_cell(run_train, "run-train"),
        code_cell(download, "download"),
    ]
    write_notebook(HERE / "colab_finetune_setup.ipynb", cells, COLAB_META)


# ── 2) Inference test notebook (Colab) ─────────────────────────────────────────

def build_inference_notebook():
    files = {
        "prompt_format.py": read(FT / "prompt_format.py"),
        "data_split.py":    read(FT / "data_split.py"),
        "run_inference.py": read(FT / "run_inference.py"),
        "test_inputs.jsonl": read(TEST_INPUTS),
        "requirements_finetune.txt": REQUIREMENTS,
    }

    md_intro = (
        "# Inference Test — Fine-Tuned Scenario Generator (Colab)\n\n"
        "Generates tri-modal scenarios for the **held-out** test inputs using "
        "`run_inference.py`. All inference logic lives in that script and uses the "
        "**same** `prompt_format.build_prompt` as training, so the prompt cannot drift.\n\n"
        "It sets eos/pad ids (the model stops) and decodes **only the new tokens** "
        "(no echoed prompt). Upload your adapter folder into `./output` first."
    )

    install = "!pip install -q -r requirements_finetune.txt\nprint('Installed.')"

    upload = (
        "import os\n"
        "from google.colab import files\n"
        "os.makedirs('output', exist_ok=True)\n"
        "print('Upload the adapter files (adapter_model.safetensors, adapter_config.json,\\n"
        "tokenizer files, chat_template.jinja) — they will be moved into ./output')\n"
        "up = files.upload()\n"
        "for fn in up:\n"
        "    os.replace(fn, os.path.join('output', fn))\n"
        "print('output/:', os.listdir('output'))"
    )

    run_infer = (
        "# Decodes only the new tokens; MAX_NEW_TOKENS=1280 (in the 1024-1536 range).\n"
        "!python run_inference.py --adapter ./output --test_inputs ./test_inputs.jsonl --out ./inference_results.txt --samples 3\n"
        "# Add --compare to also generate the base (no-adapter) output side by side."
    )

    show = (
        "print(open('inference_results.txt', encoding='utf-8').read())"
    )

    cells = [
        md_cell(md_intro, "md-intro"),
        code_cell(install, "install"),
        ship_cell(files, "ship-code", "run_inference.py + shared modules + held-out inputs."),
        code_cell(upload, "upload-adapter"),
        code_cell(run_infer, "run-infer"),
        code_cell(show, "show-results"),
    ]
    write_notebook(HERE / "finetune_output_test.ipynb", cells, COLAB_META)


# ── 3) Baseline vs fine-tuned comparison (Kaggle) ──────────────────────────────

def build_comparison_notebook():
    files = {
        "prompt_format.py": read(FT / "prompt_format.py"),
        "test_inputs.jsonl": read(TEST_INPUTS),
    }

    md_intro = (
        "# Baseline vs Fine-Tuned — Scenario Generator (Kaggle)\n\n"
        "Compares base `Mistral-7B-Instruct-v0.3` against the LoRA fine-tune on the "
        "**real held-out** test inputs, using the **canonical** prompt "
        "(`prompt_format.build_prompt`, the format the adapter was trained on). Emits "
        "`prompt_gen_comparison.{csv,txt}` (the .txt is parseable by "
        "`manual_eval_metrics.py`) and a reference-free metrics table.\n\n"
        "Attach the **finetuned** adapter dataset under *Input* before running."
    )

    gpu = (
        "import torch, os\n"
        "os.environ['PYTORCH_ALLOC_CONF'] = 'expandable_segments:True'\n"
        "print('CUDA:', torch.cuda.is_available(),\n"
        "      '| bf16:', torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False)"
    )

    install = "!pip install -q -U transformers peft bitsandbytes accelerate\nprint('Done.')"

    discover = (
        "import os\n"
        "REQUIRED = ['adapter_config.json', 'adapter_model.safetensors']\n"
        "def find_adapter_dir(base='/kaggle/input'):\n"
        "    for root, _dirs, fs in os.walk(base):\n"
        "        if all(r in fs for r in REQUIRED):\n"
        "            return root\n"
        "    return None\n"
        "ADAPTER_DIR = find_adapter_dir()\n"
        "print('Adapter dir:', ADAPTER_DIR)\n"
        "assert ADAPTER_DIR, 'Attach the finetuned adapter dataset under Input.'"
    )

    config = (
        "import gc, csv, json, torch\n"
        "from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig\n"
        "from peft import PeftModel\n"
        "import prompt_format  # shipped above — same builder as training\n"
        "\n"
        "BASE_MODEL = 'mistralai/Mistral-7B-Instruct-v0.3'\n"
        "OUT = '/kaggle/working'\n"
        "MAX_NEW_TOKENS = 1280\n"
        "TXT = os.path.join(OUT, 'prompt_gen_comparison.txt')\n"
        "CSV = os.path.join(OUT, 'prompt_gen_comparison.csv')\n"
        "\n"
        "RECORDS = [json.loads(l) for l in open('test_inputs.jsonl', encoding='utf-8') if l.strip()]\n"
        "print(f'{len(RECORDS)} held-out records')\n"
        "\n"
        "import re\n"
        "TECH_RE = re.compile(r'TECHNIQUES:\\s*(.+)')\n"
        "def techniques_of(rec):\n"
        "    m = TECH_RE.search(rec.get('input', ''))\n"
        "    return m.group(1).strip() if m else ''\n"
        "\n"
        "def build_bnb():\n"
        "    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()\n"
        "    return BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',\n"
        "        bnb_4bit_use_double_quant=True,\n"
        "        bnb_4bit_compute_dtype=torch.bfloat16 if bf16 else torch.float16)\n"
        "\n"
        "def load_base():\n"
        "    m = AutoModelForCausalLM.from_pretrained(BASE_MODEL, quantization_config=build_bnb(),\n"
        "        device_map='auto')\n"
        "    t = AutoTokenizer.from_pretrained(BASE_MODEL)\n"
        "    if t.pad_token is None: t.pad_token = t.eos_token\n"
        "    m.config.use_cache = True; m.eval()\n"
        "    return m, t\n"
        "\n"
        "def gen(model, tok, rec):\n"
        "    # The trained prompt; decode only new tokens (no echoed prompt); stops on EOS.\n"
        "    prompt = prompt_format.build_prompt(rec)\n"
        "    inputs = tok(prompt, return_tensors='pt', add_special_tokens=False).to(model.device)\n"
        "    n = inputs['input_ids'].shape[1]\n"
        "    with torch.no_grad():\n"
        "        out = model.generate(**inputs, max_new_tokens=MAX_NEW_TOKENS, do_sample=True,\n"
        "            temperature=0.7, top_p=0.9, repetition_penalty=1.1,\n"
        "            eos_token_id=tok.eos_token_id, pad_token_id=tok.pad_token_id)\n"
        "    return tok.decode(out[0][n:], skip_special_tokens=True).strip()\n"
        "\n"
        "def cleanup(*objs):\n"
        "    for o in objs:\n"
        "        del o\n"
        "    gc.collect()\n"
        "    if torch.cuda.is_available(): torch.cuda.empty_cache()\n"
        "print('Config ready.')"
    )

    generate = (
        "results = []\n"
        "print('PHASE 1 - BASELINE'); model, tok = load_base()\n"
        "for i, rec in enumerate(RECORDS, 1):\n"
        "    print(f'  baseline {i}/{len(RECORDS)} {rec.get(\"source_id\")}')\n"
        "    results.append({'model': 'baseline', 'prompt_id': f'P{i}',\n"
        "        'source_id': rec.get('source_id', f'P{i}'),\n"
        "        'techniques': techniques_of(rec), 'output': gen(model, tok, rec)})\n"
        "cleanup(model)\n"
        "\n"
        "print('PHASE 2 - FINE-TUNED'); model, tok = load_base()\n"
        "ft = PeftModel.from_pretrained(model, ADAPTER_DIR); ft.eval()\n"
        "for i, rec in enumerate(RECORDS, 1):\n"
        "    print(f'  finetuned {i}/{len(RECORDS)} {rec.get(\"source_id\")}')\n"
        "    results.append({'model': 'finetuned', 'prompt_id': f'P{i}',\n"
        "        'source_id': rec.get('source_id', f'P{i}'),\n"
        "        'techniques': techniques_of(rec), 'output': gen(ft, tok, rec)})\n"
        "cleanup(ft, model)\n"
        "\n"
        "# CSV\n"
        "with open(CSV, 'w', newline='', encoding='utf-8') as f:\n"
        "    w = csv.DictWriter(f, fieldnames=['model','prompt_id','source_id','techniques','output'])\n"
        "    w.writeheader(); w.writerows(results)\n"
        "\n"
        "# TXT in the format manual_eval_metrics.py parses\n"
        "base = {r['prompt_id']: r for r in results if r['model']=='baseline'}\n"
        "ftr  = {r['prompt_id']: r for r in results if r['model']=='finetuned'}\n"
        "SEP = '='*80; DIV = '-'*80\n"
        "with open(TXT, 'w', encoding='utf-8') as f:\n"
        "    f.write('BASELINE vs FINE-TUNED COMPARISON\\n' + SEP + '\\n\\n')\n"
        "    for pid in [f'P{i}' for i in range(1, len(RECORDS)+1)]:\n"
        "        r = ftr[pid]\n"
        "        f.write(f'PROMPT {pid}: held-out {r[\"source_id\"]}\\n')\n"
        "        f.write(f'Techniques: {r[\"techniques\"]}\\n\\n')\n"
        "        f.write('BASELINE OUTPUT\\n' + DIV + '\\n' + base[pid]['output'] + '\\n\\n')\n"
        "        f.write('FINE-TUNED OUTPUT\\n' + DIV + '\\n' + ftr[pid]['output'] + '\\n\\n')\n"
        "        f.write(SEP + '\\n\\n')\n"
        "print('Wrote', CSV, 'and', TXT)"
    )

    evaluate = (
        "# Reference-free metrics (no LLM judge) on the generated comparison.\n"
        "import re, csv\n"
        "SECTIONS = ['[NATURAL LANGUAGE]','[MATHEMATICAL EXPRESSION]','[ATTACK GRAPH]']\n"
        "MITRE = re.compile(r'T\\d{4}(?:\\.\\d{3})?'); G = re.compile(r'G\\s*=\\s*\\(\\s*N')\n"
        "ARROW = re.compile(r'->'); STAGE = re.compile(r'^\\s*(?:Stage\\s*)?\\d+[.):\\s]', re.M)\n"
        "MD = re.compile(r'(\\*\\*|^#{1,3} )', re.M)\n"
        "rows = list(csv.DictReader(open(CSV, encoding='utf-8')))\n"
        "def metrics(t, tech):\n"
        "    found = [s for s in SECTIONS if s in t]\n"
        "    ids = set(MITRE.findall(tech)); out = set(MITRE.findall(t))\n"
        "    recall = round(len(ids & out)/len(ids), 3) if ids else 0.0\n"
        "    return dict(sections=len(found), in_order=int(found==SECTIONS),\n"
        "        mitre_recall=recall, g=int(bool(G.search(t))), arrows=len(ARROW.findall(t)),\n"
        "        stages=len(STAGE.findall(t)), markdown=len(MD.findall(t)), words=len(t.split()))\n"
        "agg = {}\n"
        "for r in rows:\n"
        "    m = metrics(r['output'], r['techniques']); agg.setdefault(r['model'], []).append(m)\n"
        "print(f\"{'metric':<14}{'baseline':>12}{'finetuned':>12}\")\n"
        "keys = ['sections','in_order','mitre_recall','g','arrows','stages','markdown','words']\n"
        "for k in keys:\n"
        "    b = agg.get('baseline', []); ft = agg.get('finetuned', [])\n"
        "    bm = round(sum(x[k] for x in b)/len(b), 3) if b else '-'\n"
        "    fm = round(sum(x[k] for x in ft)/len(ft), 3) if ft else '-'\n"
        "    print(f'{k:<14}{str(bm):>12}{str(fm):>12}')\n"
        "print('\\nFor the full report: python evaluation/manual_eval_metrics.py --txt prompt_gen_comparison.txt')"
    )

    confirm = (
        "import os\n"
        "for fn in ['prompt_gen_comparison.csv', 'prompt_gen_comparison.txt']:\n"
        "    p = os.path.join('/kaggle/working', fn)\n"
        "    print(('OK  ' if os.path.exists(p) else 'MISSING  ') + p,\n"
        "          (f'({os.path.getsize(p):,} bytes)' if os.path.exists(p) else ''))"
    )

    cells = [
        md_cell(md_intro, "md-intro"),
        code_cell(gpu, "gpu"),
        code_cell(install, "install"),
        ship_cell(files, "ship-code", "prompt_format.py + real held-out test_inputs.jsonl."),
        code_cell(discover, "discover-adapter"),
        code_cell(config, "config"),
        code_cell(generate, "generate"),
        code_cell(evaluate, "evaluate"),
        code_cell(confirm, "confirm"),
    ]
    write_notebook(HERE / "kaggle_prompt_gen.ipynb", cells, KAGGLE_META)


def build_model_comparison_notebook(colab: bool):
    """Same modules and run on both platforms; only setup and storage differ."""
    files = {
        "compare_models.py": read(EVAL / "compare_models.py"),
        "prompt_generator.py": read(HERE / "prompt_generator.py"),
        "prompt_format.py": read(FT / "prompt_format.py"),
        "data_split.py": read(FT / "data_split.py"),
        "judge_eval.py": read(EVAL / "judge_eval.py"),
        "manual_eval_metrics.py": read(EVAL / "manual_eval_metrics.py"),
        "attack_paths.json": read(EVAL / "inputs" / "attack_paths.json"),
    }

    if colab:
        steps = (
            "1. Runtime > Change runtime type: **T4 GPU**.\n"
            "2. Secrets (key icon on the left): add `OPENROUTER_API_KEY` and allow notebook access. "
            "Without it the run stops; add `--no_judge` to the run cell for format metrics only.\n"
            "3. Have the adapter zip ready (`finetuned_adapters.zip` from the training notebook). "
            "The adapter cell asks for it.\n"
            "4. Allow Google Drive when asked. Results are saved there, so a rerun after a "
            "disconnect skips everything already done."
        )
        storage = (
            "from google.colab import drive\n"
            "drive.mount('/content/drive')\n"
            "OUT_DIR = '/content/drive/MyDrive/model_comparison'\n"
            "print('Results go to', OUT_DIR)"
        )
        discover = (
            "import os, zipfile\n"
            "REQUIRED = ['adapter_config.json', 'adapter_model.safetensors']\n"
            "def find_adapter_dir(base='/content'):\n"
            "    for root, dirs, fs in os.walk(base):\n"
            "        dirs[:] = [d for d in dirs if d != 'drive']\n"
            "        if all(r in fs for r in REQUIRED):\n"
            "            return root\n"
            "    return None\n"
            "ADAPTER_DIR = find_adapter_dir()\n"
            "if ADAPTER_DIR is None:\n"
            "    from google.colab import files\n"
            "    print('Upload the adapter zip (finetuned_adapters.zip).')\n"
            "    for name in files.upload():\n"
            "        if name.endswith('.zip'):\n"
            "            zipfile.ZipFile(name).extractall('/content/adapter')\n"
            "    ADAPTER_DIR = find_adapter_dir()\n"
            "print('Adapter dir:', ADAPTER_DIR)\n"
            "assert ADAPTER_DIR, 'No adapter_config.json + adapter_model.safetensors in the upload.'"
        )
        secret = (
            "try:\n"
            "    from google.colab import userdata\n"
            "    os.environ['OPENROUTER_API_KEY'] = userdata.get('OPENROUTER_API_KEY')\n"
            "    print('Judge key loaded.')\n"
            "except Exception as e:\n"
            "    print('No OPENROUTER_API_KEY secret, so the run will stop before loading a model:', e)"
        )
    else:
        steps = (
            "1. Settings: accelerator **GPU T4 x2**, internet **on**.\n"
            "2. Input: attach the **finetuned** adapter dataset.\n"
            "3. Add-ons > Secrets: add `OPENROUTER_API_KEY`. Without it the run stops; add "
            "`--no_judge` to the run cell for format metrics only.\n"
            "4. Rerunning after a disconnect skips everything already in `/kaggle/working/model_comparison`."
        )
        storage = "OUT_DIR = '/kaggle/working/model_comparison'"
        discover = (
            "import os\n"
            "REQUIRED = ['adapter_config.json', 'adapter_model.safetensors']\n"
            "def find_adapter_dir(base='/kaggle/input'):\n"
            "    for root, _dirs, fs in os.walk(base):\n"
            "        if all(r in fs for r in REQUIRED):\n"
            "            return root\n"
            "    return None\n"
            "ADAPTER_DIR = find_adapter_dir()\n"
            "print('Adapter dir:', ADAPTER_DIR)\n"
            "assert ADAPTER_DIR, 'Attach the finetuned adapter dataset under Input.'"
        )
        secret = (
            "try:\n"
            "    from kaggle_secrets import UserSecretsClient\n"
            "    os.environ['OPENROUTER_API_KEY'] = UserSecretsClient().get_secret('OPENROUTER_API_KEY')\n"
            "    print('Judge key loaded.')\n"
            "except Exception as e:\n"
            "    print('No OPENROUTER_API_KEY secret, so the run will stop before loading a model:', e)"
        )

    md_intro = (
        f"# Fine-tuned Mistral vs RedSage Qwen ({'Colab' if colab else 'Kaggle'})\n\n"
        "Runs both models on the same attack paths with the same prompt, then scores "
        "them with the format metrics and the gemini-2.5-flash-lite judge. "
        "Generated by `create_notebook.py` from `evaluation/compare_models.py`.\n\n"
        "Before *Run all*:\n"
        f"{steps}\n\n"
        "About 10 generations at 2 to 3 minutes each, plus about 30 GB of model downloads."
    )

    install = (
        '!pip install -q -U "transformers>=5,<6" "peft>=0.18,<0.19" '
        '"bitsandbytes>=0.47,<0.50" "accelerate>=1.1"\n'
        "print('Done.')"
    )

    run = (
        '!python compare_models.py --adapter_path "{ADAPTER_DIR}" '
        '--attack_paths attack_paths.json --out_dir "{OUT_DIR}"'
    )

    show = (
        "from IPython.display import Markdown, display\n"
        "display(Markdown(open(os.path.join(OUT_DIR, 'report.md'), encoding='utf-8').read()))"
    )

    cells = [
        md_cell(md_intro, "intro"),
        code_cell(install, "install"),
        ship_cell(files, "ship-modules"),
        code_cell(storage, "storage"),
        code_cell(discover, "discover-adapter"),
        code_cell(secret, "judge-key"),
        code_cell(run, "run"),
        code_cell(show, "report"),
    ]
    name = "colab_compare_models.ipynb" if colab else "kaggle_compare_models.ipynb"
    write_notebook(HERE / name, cells, COLAB_META if colab else KAGGLE_META)


def main():
    build_training_notebook()
    build_inference_notebook()
    build_comparison_notebook()
    build_model_comparison_notebook(colab=False)
    build_model_comparison_notebook(colab=True)
    print("\nAll notebooks regenerated from the .py sources.")


if __name__ == "__main__":
    main()
