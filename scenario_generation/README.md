# Scenario Generation Module

Fine-tuning pipeline for LLM-based cyber attack scenario generation.

## Setup
pip install -r dataset_pipeline/requirements.txt

## Pipeline
1. Download STIX data → dataset/raw/enterprise-attack-18.1.json
Use command 
curl -L -o enterprise-attack-18.1.json \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.1.json"

2. python dataset_pipeline/parse_stix.py --stix dataset/raw/enterprise-attack-18.1.json --out dataset/inputs/
3. export ANTHROPIC_API_KEY=...
   python dataset_pipeline/generate_outputs.py --inputs dataset/inputs/training_inputs.jsonl --out dataset/training_data.jsonl --limit 80
4. Fine-tuning: see fine_tuning/ (in progress)

## Output format
Each training example: instruction / input / output (tri-modal: NL + math + attack graph)

points to note:
- after running the parse_stix.py, the output shows only medium and high level attack(106 and 103 respectively), and no low attack levels. 
- this is happenning cuz the heuristix only assigns low when it finds keywords like "script kiddie" or "novice". ATT&CK rarely uses those words
- should be find for now(1st iteration), the dataset will skew towards medium and high attacks - which is realistic considering enterprise cloud security scenarios