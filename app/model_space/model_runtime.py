"""Load the evaluated adapter recipe and generate one scenario.

Shared by the Space (app.py) and the Kaggle pre-generation notebook, so both
load and sample exactly the same way. It follows
scenario_generation/fine_tuning/run_inference.py load_models and generate_one:
base model in 4-bit NF4 with double quantisation, compute dtype bf16 when the
GPU supports it and fp16 otherwise, the LoRA adapter attached unmerged, pad
falling back to EOS, the prompt tokenised without special tokens (it carries
its own <s>) and only the new tokens decoded.

Unlike run_inference.py every download is pinned: the base model and its
tokenizer to model_revision, the adapter to adapter_revision. Tokens come from
the environment (HF_TOKEN) or an explicit token argument, never from here.

scenario_contract.py sits next to this file wherever it runs: the deploy script
and export_records.py copy it in.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

import scenario_contract as contract


@dataclass
class LoadedModel:
    model: Any
    tokenizer: Any
    model_revision: str
    adapter_repo: str
    adapter_revision: str
    loading_recipe: str
    compute_dtype: str
    context_tokens: int
    runtime: dict[str, Any] = field(default_factory=dict)

    def provenance(self, max_new_tokens: int) -> dict[str, Any]:
        return contract.make_provenance(
            model_revision=self.model_revision,
            adapter_repo=self.adapter_repo,
            adapter_revision=self.adapter_revision,
            loading_recipe=self.loading_recipe,
            max_new_tokens=max_new_tokens,
        )


def _versions() -> dict[str, str]:
    import importlib.metadata as metadata

    versions = {}
    for package in ("torch", "transformers", "peft", "bitsandbytes", "accelerate", "tokenizers"):
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = "not installed"
    return versions


def load(
    *,
    model_revision: str,
    adapter_repo: str,
    adapter_revision: str,
    loading_recipe: str,
    token: str | None = None,
) -> LoadedModel:
    """Load base model, tokenizer and adapter at the given pinned revisions."""
    # Validates the SHAs, the repo id and the recipe before any download.
    contract.make_provenance(
        model_revision=model_revision,
        adapter_repo=adapter_repo,
        adapter_revision=adapter_revision,
        loading_recipe=loading_recipe,
    )
    if loading_recipe != contract.NF4_UNMERGED:
        raise contract.ScenarioContractError(f"this runtime implements only {contract.NF4_UNMERGED}")

    bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    compute_dtype = torch.bfloat16 if bf16 else torch.float16
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=compute_dtype,
    )

    base = AutoModelForCausalLM.from_pretrained(
        contract.BASE_MODEL_ID,
        revision=model_revision,
        quantization_config=bnb_config,
        device_map="auto",
        token=token,
    )
    context_tokens = int(base.config.max_position_embeddings)
    tokenizer = AutoTokenizer.from_pretrained(contract.BASE_MODEL_ID, revision=model_revision, token=token)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = PeftModel.from_pretrained(base, adapter_repo, revision=adapter_revision, token=token)
    model.config.use_cache = True
    model.eval()

    return LoadedModel(
        model=model,
        tokenizer=tokenizer,
        model_revision=model_revision,
        adapter_repo=adapter_repo,
        adapter_revision=adapter_revision,
        loading_recipe=loading_recipe,
        compute_dtype="bfloat16" if bf16 else "float16",
        context_tokens=context_tokens,
        runtime=_versions(),
    )


def encode_prompt(loaded: LoadedModel, prompt: Any, max_new_tokens: Any) -> list[int]:
    """Validated prompt token ids, or ScenarioContractError. Runs on the CPU."""
    max_new_tokens = contract.check_max_new_tokens(max_new_tokens)
    prompt = contract.check_prompt(prompt)
    bos = loaded.tokenizer.bos_token
    if not bos or not prompt.startswith(bos):
        raise contract.ScenarioContractError(
            f"prompt must start with the tokenizer's BOS token {bos!r}; "
            "build it with scenario_contract.build_prompt")
    ids = list(loaded.tokenizer(prompt, add_special_tokens=False)["input_ids"])
    if len(ids) + max_new_tokens > loaded.context_tokens:
        raise contract.ScenarioContractError(
            f"prompt is {len(ids)} tokens; with max_new_tokens {max_new_tokens} it exceeds "
            f"the model context of {loaded.context_tokens}")
    return ids


def generate(loaded: LoadedModel, prompt_ids: list[int], max_new_tokens: int) -> dict[str, Any]:
    """Generate once and return the contract response (scenario_contract.build_response)."""
    provenance = loaded.provenance(max_new_tokens)
    tokenizer = loaded.tokenizer
    kwargs = contract.generate_kwargs(
        provenance["generation_config"], tokenizer.eos_token_id, tokenizer.pad_token_id)

    input_ids = torch.tensor([prompt_ids], device=loaded.model.device)
    attention_mask = torch.ones_like(input_ids)
    started = time.monotonic()
    with torch.no_grad():
        output = loaded.model.generate(input_ids=input_ids, attention_mask=attention_mask, **kwargs)
    seconds = time.monotonic() - started

    new_ids = output[0][len(prompt_ids):].tolist()
    text = tokenizer.decode(new_ids, skip_special_tokens=True).strip()
    hit_eos = bool(new_ids) and new_ids[-1] == tokenizer.eos_token_id
    return contract.build_response(
        text=text,
        new_tokens=len(new_ids),
        hit_eos=hit_eos,
        seconds=seconds,
        provenance=provenance,
        extra={
            "prompt_tokens": len(prompt_ids),
            "runtime": {**loaded.runtime, "compute_dtype": loaded.compute_dtype},
        },
    )


def metadata(loaded: LoadedModel) -> dict[str, Any]:
    """Provenance and limits, without touching the GPU."""
    return {
        **loaded.provenance(contract.MAX_NEW_TOKENS),
        "prompt_versions": dict(contract.PROMPT_VERSIONS),
        "max_new_tokens_limit": contract.MAX_NEW_TOKENS,
        "max_prompt_chars": contract.MAX_PROMPT_CHARS,
        "context_tokens": loaded.context_tokens,
        "runtime": {**loaded.runtime, "compute_dtype": loaded.compute_dtype},
    }
