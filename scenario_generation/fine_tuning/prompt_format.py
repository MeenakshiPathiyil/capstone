"""The prompt around every training example and every inference request.

The shipped adapter (fine_tuning/output) was trained by the original Colab
notebook on exactly this text, with TRL adding the <s> and appending the </s>:

    <s>[INST] {instruction}\\n\\n{input} [/INST]\\n{output}</s>

Note the space before [/INST] and the newline after it. Mistral's own chat
template has neither, so the tokenizer's apply_chat_template must not be used
for this model: its prompt is input the adapter never saw.

Training and every inference path build their text here, so the two cannot
drift. The prompt carries its own <s>, so tokenize it with
add_special_tokens=False.
"""

from __future__ import annotations


BOS = "<s>"
EOS = "</s>"


def user_message(record: dict) -> str:
    """The request itself, for a record with instruction and input. Another model
    gets this as its user turn, in its own chat template."""
    return f"{record['instruction']}\n\n{record['input']}"


def build_prompt(record: dict) -> str:
    """Everything before the model's answer."""
    return f"{BOS}[INST] {user_message(record)} [/INST]\n"


def build_completion(record: dict) -> str:
    """The answer the model is trained to produce after build_prompt(record)."""
    return f"{record['output']}{EOS}"
