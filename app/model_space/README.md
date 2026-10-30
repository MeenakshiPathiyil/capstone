---
title: Capstone Scenario Model
colorFrom: gray
colorTo: red
sdk: gradio
sdk_version: 6.30.0
python_version: "3.12"
app_file: app.py
pinned: false
startup_duration_timeout: 1h
short_description: Private tri-modal attack scenario generator
---

# Capstone scenario model

Private Gradio Space that serves the fine-tuned Mistral-7B-Instruct-v0.3 LoRA
adapter for the capstone app. It loads the evaluated recipe (4-bit NF4, double
quantisation, adapter unmerged) at pinned revisions and exposes two API
endpoints:

- `/generate (prompt, max_new_tokens)`: one generation, returned with token
  counts, finish reason and the provenance it actually ran with.
- `/metadata ()`: provenance, limits and library versions, without a GPU.

The response contract is `scenario_contract.py`, copied in from
`app/api/scenario_contract.py` by `app/scripts/deploy_model_space.py`. Do not
edit the copy here; redeploy instead.

## Settings that this file does not control

- **Hardware.** ZeroGPU is selected in the Space settings (Settings ->
  Hardware), not by this README. Without it there is no GPU.
- **Visibility.** The deploy script creates the Space as private and refuses to
  upload to a public one.
- **Secret `HF_TOKEN`.** Add it yourself in Settings -> Variables and secrets.
  It is needed only to read the private adapter repo, so a fine-grained token
  with read access to that one repo is enough. The base model,
  `mistralai/Mistral-7B-Instruct-v0.3`, is not gated: there is no licence to
  accept and it downloads without a token.
- **Variables** `BASE_REVISION`, `ADAPTER_REPO`, `ADAPTER_REVISION`,
  `LOADING_RECIPE` are set by the deploy script. Optional `GPU_BASE_SECONDS`
  and `GPU_SECONDS_PER_TOKEN` tune the ZeroGPU duration request once a real
  generation has been timed.
