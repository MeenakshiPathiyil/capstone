"""Tests for fine_tuning/prompt_format.py, the format the adapter was trained on."""

import prompt_format


def test_training_text_is_what_the_adapter_was_trained_on(sample_record):
    """The original Colab notebook built f"[INST] {instruction}\\n\\n{input} [/INST]\\n{output}"
    and TRL added <s> and </s>. Spelled out here rather than imported, so a tidy-up
    of the builder towards Mistral's chat template fails this test."""
    r = sample_record
    trained = f"<s>[INST] {r['instruction']}\n\n{r['input']} [/INST]\n{r['output']}</s>"

    assert prompt_format.build_prompt(r) + prompt_format.build_completion(r) == trained


def test_the_prompt_stops_where_the_answer_starts(sample_record):
    prompt = prompt_format.build_prompt(sample_record)

    assert prompt.startswith(prompt_format.BOS + "[INST] ")
    assert prompt.endswith(" [/INST]\n")
    assert sample_record["output"] not in prompt


def test_the_user_message_is_what_sits_between_the_inst_tags(sample_record):
    prompt = prompt_format.build_prompt(sample_record)

    assert prompt == f"<s>[INST] {prompt_format.user_message(sample_record)} [/INST]\n"
    assert prompt_format.user_message(sample_record) == (
        sample_record["instruction"] + "\n\n" + sample_record["input"])
