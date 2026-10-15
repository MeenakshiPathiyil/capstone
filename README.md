# Capstone: from cloud configuration to synthetic attack scenarios

Reads a CloudFormation template, finds the misconfigurations and the privilege
escalations in it, ranks the routes an attacker could take through it, and turns
each route into a tri-modal attack scenario (narrative, `G = (N, S, V, P, FS)`
expression, staged attack graph) with a fine-tuned Mistral-7B.

```
CloudFormation YAML ─▶ parser/ ─▶ data/normalized_resources.json
                                        │
                                        ▼
            engine/, security_state_graph/, attack_path/  (runner/graph_runner.py)
                                        │
                                        ▼
                              output/attack_paths.json
                                        │
                                        ▼
                  scenario_generation/  (fine-tuned Mistral-7B, evaluation)
```

| Stage | Code | What it does |
|---|---|---|
| 0. Parse | `parser/` | Normalizes a template, merging nested stacks, into resource records |
| 1. Infrastructure model | `models/`, `engine/connection_builder.py`, `main.py` | Resources and the connections between them |
| 2. Findings | `engine/`, `processing/`, `data/security_rules.yaml` | Misconfiguration rules plus IAM privilege escalation |
| 3. Graphs and paths | `security_state_graph/`, `attack_path/`, `runner/graph_runner.py` | Joins findings to the graph, builds the attack graph, ranks and exports paths |
| 4. Scenarios | `scenario_generation/` | Dataset, QLoRA fine-tuning, generation, evaluation, model comparison |

## Running it

Stages 0 to 3 need Python 3.9+ and PyYAML:

```bash
pip3 install -r requirements.txt
python3 -m parser.infra_parser     # sample_yamls/cloudformation5.yml -> data/normalized_resources.json
python3 -m runner.graph_runner     # findings, graphs and ranked paths -> output/
```

```
Done. 15 resources, 16 edges, 21 security findings, 22 attack paths.
```

Stage 4 needs a GPU (Colab or Kaggle) or an Apple Silicon Mac; see
[`scenario_generation/README.md`](scenario_generation/README.md).

## Tests

```bash
python3 -m pytest -q
```

Runs both halves (`tests/` and `scenario_generation/tests/`) with nothing but
PyYAML and pytest installed. Each half also runs on its own from its folder.

`output/` is generated and not tracked. Every file in it has a golden copy under
`tests/`, so a change in the pipeline's output shows up as a failing test, not
a dirty tree.

## Where the stages meet

- `data/normalized_resources.json` must equal the parser's output for the sample
  template (`tests/test_parser.py`).
- `scenario_generation/evaluation/inputs/attack_paths.json` is the copy of the
  export that scenario generation and its notebooks read. It must equal
  `tests/golden_attack_paths.json` (`tests/test_exporter.py`). When the export
  changes, copy the new golden file over it.
- The export's seven keys are the contract with the prompt
  (`scenario_generation/prompt_generator.py`, `ATTACK_PATH_KEYS`).

## The fine-tuned adapter

The LoRA adapter weights are shared outside git. Put `adapter_model.safetensors`
in `scenario_generation/fine_tuning/output/`, next to its committed config.

It was trained by the original Colab notebook, and everything here matches that
run: the prompt (`scenario_generation/fine_tuning/prompt_format.py`) and the 17
records it never saw (`scenario_generation/fine_tuning/data_split.py`). See
[`scenario_generation/fine_tuning/CHANGES.md`](scenario_generation/fine_tuning/CHANGES.md).

## More documentation

| Document | |
|---|---|
| [`docs/graph-pipeline.md`](docs/graph-pipeline.md) | Stages 1 to 3: sources, outputs, design decisions, what is not claimed |
| [`DEVELOPERS.md`](DEVELOPERS.md) | How the graph pipeline works, stage by stage |
| [`CODE_WALKTHROUGH.md`](CODE_WALKTHROUGH.md) | File-by-file walkthrough of the graph pipeline |
| [`CONTEXT.md`](CONTEXT.md) | Domain vocabulary |
| [`docs/adr/`](docs/adr/) | Architecture decisions |
| [`rulesets/`](rulesets/) | The canonical AWS Config ruleset, the Rhino extraction and the state vocabulary |
| [`scenario_generation/README.md`](scenario_generation/README.md) | Stage 4 |
