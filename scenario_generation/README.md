# Scenario Generation Module

Fine-tuning pipeline for LLM-based cyber attack scenario generation.

## Setup
pip install -r dataset_pipeline/requirements.txt

## Pipeline
1. Download STIX data → dataset/raw/enterprise-attack-18.1.json
2. python dataset_pipeline/parse_stix.py --stix dataset/raw/enterprise-attack-18.1.json --out dataset/inputs/
3. export ANTHROPIC_API_KEY=...
   python dataset_pipeline/generate_outputs.py --inputs dataset/inputs/training_inputs.jsonl --out dataset/training_data.jsonl --limit 80
4. Fine-tuning: see fine_tuning/ (in progress)

## Output format
Each training example: instruction / input / output (tri-modal: NL + math + attack graph)