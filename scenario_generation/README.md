# Scenario Generation Module

End-to-end pipeline for generating tri-modal cyber attack scenarios from MITRE ATT&CK STIX data, fine-tuning a QLoRA adapter, and evaluating base vs fine-tuned quality.

## Current Status

Completed:
- STIX parsing pipeline is implemented (`dataset_pipeline/parse_stix.py`).
- Tri-modal dataset generation is implemented (`dataset_pipeline/generate_outputs.py`).
- Fine-tuning workflow is implemented for local and Colab (`fine_tuning/finetuning.py`, `fine_tuning/fine_tune.py`, `fine_tuning/colab_finetune_setup.ipynb`).
- Colab notebook now includes explicit upload + verification step so `training_data.jsonl` and `fine_tune.py` are available in `/content` before training.
- Evaluation scripts are in place (`evaluation/make_test_inputs.py`, `evaluation/evaluate.py`).

In progress / remaining:
- Run and record a full baseline-vs-fine-tuned evaluation run in `evaluation/evaluation_results.json`.
- Add a short experiment log (model, hyperparameters, dataset version, date, score deltas).
- Optional: improve attack-level balancing in parsing heuristics (currently skewed toward `medium`/`high`).

## Repository Layout

```
scenario_generation/
  dataset/
    raw/
    inputs/
    training_data.jsonl
  dataset_pipeline/
    parse_stix.py
    generate_outputs.py
    requirements.txt
  fine_tuning/
    finetuning.py
    fine_tune.py
    colab_finetune_setup.ipynb
    requirements_finetune.txt
  evaluation/
    make_test_inputs.py
    evaluate.py
```

## 1) Dataset Pipeline

Install pipeline dependencies:

```bash
pip install -r dataset_pipeline/requirements.txt
```

Download ATT&CK STIX bundle:

```bash
curl -L -o dataset/raw/enterprise-attack-18.1.json \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.1.json"
```

Parse STIX into structured inputs:

```bash
python dataset_pipeline/parse_stix.py \
  --stix dataset/raw/enterprise-attack-18.1.json \
  --out dataset/inputs/
```

Generate tri-modal training records (Gemini API):

```bash
export GEMINI_API_KEY=your_key_here
python dataset_pipeline/generate_outputs.py \
  --inputs dataset/inputs/training_inputs.jsonl \
  --out dataset/training_data.jsonl \
  --limit 80
```

## 2) Fine-Tuning (QLoRA)

Install fine-tuning dependencies:

```bash
pip install -r fine_tuning/requirements_finetune.txt
```

Run locally:

```bash
python fine_tuning/fine_tune.py \
  --data dataset/training_data.jsonl \
  --out fine_tuning/output/
```

Run in Colab:
- Open `fine_tuning/colab_finetune_setup.ipynb`.
- Run cells in order.
- Upload `training_data.jsonl` and `fine_tune.py` when prompted.
- Confirm files appear in `/content` before running training.

## 3) Evaluation

Create unseen test inputs:

```bash
python evaluation/make_test_inputs.py \
  --inputs dataset/inputs/training_inputs.jsonl \
  --out evaluation/test_inputs.jsonl \
  --train_count 80 \
  --sample_size 10
```

Evaluate base vs fine-tuned model:

```bash
export GEMINI_API_KEY=your_key_here
python evaluation/evaluate.py \
  --base_model mistralai/Mistral-7B-Instruct-v0.3 \
  --adapter_path fine_tuning/output \
  --test_inputs evaluation/test_inputs.jsonl \
  --out evaluation/evaluation_results.json
```

## Output Format

Each training example uses `instruction` + `input` + `output`.

Expected `output` sections:
- `[NATURAL LANGUAGE]`
- `[MATHEMATICAL EXPRESSION]`
- `[ATTACK GRAPH]`

## Known Notes

- Attack-level distribution is typically skewed to `medium`/`high` due to ATT&CK text style and current keyword heuristics.
- Colab runtime is ephemeral; download adapters after training or they are lost when the session ends.