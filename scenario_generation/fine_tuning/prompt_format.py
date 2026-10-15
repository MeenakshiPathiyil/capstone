"""
prompt_format.py
----------------
THE single source of truth for the prompt that wraps each training record and
each inference request. Training (finetuning.py) and every inference path
(run_inference.py, evaluation/evaluate.py, the generated notebooks) all import
``build_chat`` from here, so the train-time and infer-time prompts can never
drift apart. Prompt drift was the original root cause of the off-format model
output, so this module is deliberately small and shared.

What the prompt looks like for Mistral-7B-Instruct-v0.3
------------------------------------------------------
Mistral's chat template has no separate ``system`` role that survives a single
user turn, so we fold the full ``instruction`` (the tri-modal formatting rules)
into the user turn together with the record's ``input``::

    <s>[INST] {instruction}\\n\\n{input}[/INST]                 # inference prompt
    <s>[INST] {instruction}\\n\\n{input}[/INST] {output}</s>    # full training text

The inference prompt is, by construction, a strict prefix of the training text,
which is exactly what the model needs to continue the completion at inference.
"""

from __future__ import annotations

from typing import Optional


# Mistral-7B-Instruct-v0.3 special tokens. Used only by the no-dependency manual
# fallback below; when a real tokenizer is supplied we read these from it.
DEFAULT_BOS = "<s>"
DEFAULT_EOS = "</s>"

# The marker that separates the prompt from the completion. Loss is computed only
# on the tokens that follow this marker (see finetuning.py completion-only setup).
RESPONSE_MARKER = "[/INST]"


def build_messages(record: dict, for_training: bool) -> list[dict]:
    """
    Build the chat ``messages`` list for one record.

    The full ``instruction`` field (all the [NATURAL LANGUAGE] / [MATHEMATICAL
    EXPRESSION] / [ATTACK GRAPH] rules) is folded into the user turn — never the
    short one-liner that older code used.
    """
    instruction = (record.get("instruction") or "").rstrip()
    input_text = record.get("input") or ""
    user_content = f"{instruction}\n\n{input_text}"

    messages = [{"role": "user", "content": user_content}]
    if for_training:
        output = (record.get("output") or "").strip()
        messages.append({"role": "assistant", "content": output})
    return messages


def _manual_chat(record: dict, for_training: bool,
                 bos: str = DEFAULT_BOS, eos: str = DEFAULT_EOS) -> str:
    """
    Dependency-free fallback that reproduces Mistral's chat template byte-for-byte.

    Mirrors output/chat_template.jinja:
      user turn      -> "[INST] " + content + "[/INST]"   (bos prepended once)
      assistant turn -> " " + content.strip() + eos
    Used when no tokenizer is available (e.g. ``--check_data`` on a machine with
    no transformers installed). The infer string stays a prefix of the train
    string here too.
    """
    instruction = (record.get("instruction") or "").rstrip()
    input_text = record.get("input") or ""
    prompt = f"{bos}[INST] {instruction}\n\n{input_text}[/INST]"
    if not for_training:
        return prompt
    output = (record.get("output") or "").strip()
    return f"{prompt} {output}{eos}"


def build_chat(record: dict, tokenizer: Optional[object], for_training: bool) -> str:
    """
    Return the canonical prompt string for ``record``.

    Parameters
    ----------
    record       : dict with at least ``instruction`` and ``input`` (and
                   ``output`` when ``for_training`` is True).
    tokenizer    : a HF tokenizer (uses ``apply_chat_template``) or ``None``
                   (falls back to the manual template above).
    for_training : True  -> include the assistant turn + EOS (full training text)
                   False -> stop after ``[/INST]`` (the generation prompt)

    Guarantee: ``build_chat(rec, tok, False)`` is always a strict prefix of
    ``build_chat(rec, tok, True)`` for the same record/tokenizer.
    """
    if tokenizer is not None and hasattr(tokenizer, "apply_chat_template"):
        try:
            return tokenizer.apply_chat_template(
                build_messages(record, for_training),
                tokenize=False,
                add_generation_prompt=not for_training,
            )
        except Exception:
            # Some odd template/version combo — fall back to the manual template,
            # using the tokenizer's real special tokens so it stays consistent.
            bos = getattr(tokenizer, "bos_token", None) or DEFAULT_BOS
            eos = getattr(tokenizer, "eos_token", None) or DEFAULT_EOS
            return _manual_chat(record, for_training, bos, eos)
    return _manual_chat(record, for_training)


def assert_parity(records: list[dict], tokenizer: Optional[object] = None) -> None:
    """
    Assert that the inference prompt is a strict prefix of the full training text
    for every record. This is the train/inference-parity guard (fix A acceptance).
    Raises AssertionError on the first violation.
    """
    for i, rec in enumerate(records):
        infer = build_chat(rec, tokenizer, for_training=False)
        train = build_chat(rec, tokenizer, for_training=True)
        assert train.startswith(infer), (
            f"Parity violated for record {i} "
            f"(source_id={rec.get('_meta', {}).get('source_id')}): "
            "inference prompt is not a prefix of the training text."
        )
        assert len(train) > len(infer), (
            f"Record {i} produced an empty completion span."
        )


def response_template_ids(tokenizer, sample_text: str, marker: str = RESPONSE_MARKER) -> list[int]:
    """
    Compute the token ids of ``marker`` (``[/INST]``) **in context**.

    The same string can tokenize differently standalone vs. mid-sequence, which
    is the classic footgun that makes DataCollatorForCompletionOnlyLM silently
    mask the entire example. We therefore diff the tokenization of the text up to
    *and including* the marker against the text up to *just before* it, and use
    the trailing ids — the ids the marker actually contributes in this context.

    Requires a real tokenizer; only called on the training/smoke path.
    """
    cut = sample_text.index(marker)
    end = cut + len(marker)
    before_ids = tokenizer(sample_text[:cut], add_special_tokens=False)["input_ids"]
    upto_ids = tokenizer(sample_text[:end], add_special_tokens=False)["input_ids"]

    # The marker's in-context ids are whatever was appended after `before_ids`.
    # Guard against rare boundary re-tokenization of the last shared token.
    k = 0
    while k < len(before_ids) and k < len(upto_ids) and before_ids[k] == upto_ids[k]:
        k += 1
    ids = upto_ids[k:]
    if not ids:
        # Fallback: standalone encoding (better than an empty template).
        ids = tokenizer(marker, add_special_tokens=False)["input_ids"]
    return ids
