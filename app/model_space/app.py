"""Private ZeroGPU Space serving the fine-tuned scenario model.

Two API endpoints, called by the capstone backend with gradio_client:

    /generate (prompt: str, max_new_tokens: int) -> scenario_contract.build_response
    /metadata () -> provenance, limits and library versions, no GPU

Configuration comes from Space variables, set by app/scripts/deploy_model_space.py:
BASE_REVISION and ADAPTER_REVISION (full commit SHAs), ADAPTER_REPO and
LOADING_RECIPE. The HF_TOKEN secret, needed only to read the private adapter
(the base model is not gated), is added by the owner in the Space settings. Optional
GPU_BASE_SECONDS and GPU_SECONDS_PER_TOKEN tune the ZeroGPU duration request.

The model loads once at import, on "cuda" under ZeroGPU's emulation, as the
ZeroGPU docs require; only _generate_on_gpu holds a real GPU. Requests are
validated and tokenised before it, so a bad request costs no GPU quota.
"""

# spaces must be imported before torch or anything that initialises CUDA.
import spaces  # noqa: I001

import math
import os

import gradio as gr

import model_runtime
import scenario_contract as contract


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Space variable {name} is not set; run app/scripts/deploy_model_space.py")
    return value


LOADED = model_runtime.load(
    model_revision=_required_env("BASE_REVISION"),
    adapter_repo=_required_env("ADAPTER_REPO"),
    adapter_revision=_required_env("ADAPTER_REVISION"),
    loading_recipe=_required_env("LOADING_RECIPE"),
)

# Placeholders until a real generation has been timed on this hardware: the
# duration request must cover the slowest expected run or ZeroGPU aborts it,
# and a longer request lowers queue priority.
GPU_BASE_SECONDS = float(os.environ.get("GPU_BASE_SECONDS", "20"))
GPU_SECONDS_PER_TOKEN = float(os.environ.get("GPU_SECONDS_PER_TOKEN", "0.1"))


def _gpu_duration(prompt_ids, max_new_tokens):
    return math.ceil(GPU_BASE_SECONDS + GPU_SECONDS_PER_TOKEN * max_new_tokens)


@spaces.GPU(duration=_gpu_duration)
def _generate_on_gpu(prompt_ids, max_new_tokens):
    return model_runtime.generate(LOADED, prompt_ids, max_new_tokens)


def generate(prompt, max_new_tokens):
    """Generate one scenario for a finished prompt (scenario_contract.build_prompt)."""
    try:
        prompt_ids = model_runtime.encode_prompt(LOADED, prompt, max_new_tokens)
    except contract.ScenarioContractError as exc:
        raise gr.Error(str(exc), print_exception=False) from None
    return _generate_on_gpu(prompt_ids, max_new_tokens)


def metadata():
    """What this Space loaded and its limits."""
    return model_runtime.metadata(LOADED)


with gr.Blocks(title="Scenario model") as demo:
    gr.Markdown(
        "Private model endpoint for the capstone app. Prompts are built by the app "
        "with `scenario_contract.build_prompt`.")
    prompt_box = gr.Textbox(label="Prompt", lines=12)
    cap_box = gr.Number(
        label="max_new_tokens",
        value=contract.MAX_NEW_TOKENS,
        precision=0,
        minimum=1,
        maximum=contract.MAX_NEW_TOKENS,
    )
    generate_button = gr.Button("Generate", variant="primary")
    result_box = gr.JSON(label="Result")
    metadata_button = gr.Button("Metadata")
    metadata_box = gr.JSON(label="Metadata")

    generate_button.click(generate, inputs=[prompt_box, cap_box], outputs=result_box, api_name="generate")
    metadata_button.click(metadata, inputs=None, outputs=metadata_box, api_name="metadata")

demo.queue(max_size=20)


if __name__ == "__main__":
    demo.launch()
