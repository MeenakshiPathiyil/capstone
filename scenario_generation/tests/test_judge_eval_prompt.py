"""test_judge_eval_prompt.py"""

import ast

import judge_eval
import prompt_format

from .conftest import EVALUATION_DIR


# ── Byte-for-byte parity with the canonical builder ───────────────────────────

def test_prompt_is_byte_identical_to_build_chat_without_tokenizer(sample_record):
    expected = prompt_format.build_chat(sample_record, None, for_training=False)
    assert judge_eval.build_eval_prompt(sample_record, None) == expected


def test_prompt_is_byte_identical_to_build_chat_with_tokenizer(sample_record, fake_tokenizer):
    expected = prompt_format.build_chat(sample_record, fake_tokenizer, for_training=False)
    assert judge_eval.build_eval_prompt(sample_record, fake_tokenizer) == expected


# ── The specific drift this file was written to catch ──────────────────────────

def test_prompt_has_no_space_before_the_response_marker(sample_record, fake_tokenizer):
    for tokenizer in (None, fake_tokenizer):
        prompt = judge_eval.build_eval_prompt(sample_record, tokenizer)
        assert prompt.endswith(prompt_format.RESPONSE_MARKER)
        assert not prompt.endswith(" " + prompt_format.RESPONSE_MARKER)


def test_judge_eval_defines_no_local_prompt_builder():
    """Guard against the local format_prompt() coming back on a future merge."""
    assert not hasattr(judge_eval, "format_prompt")
    assert judge_eval.build_eval_prompt.__module__ == "judge_eval"


# ── Train / inference parity of the judged prompt ──────────────────────────────

def test_judged_prompt_is_a_prefix_of_the_training_text(sample_record, fake_tokenizer):
    """The generation prompt must be a strict prefix of the full training text —"""
    for tokenizer in (None, fake_tokenizer):
        prompt = judge_eval.build_eval_prompt(sample_record, tokenizer)
        training_text = prompt_format.build_chat(sample_record, tokenizer, for_training=True)
        assert training_text.startswith(prompt)
        assert len(training_text) > len(prompt)


def test_tokenizer_call_does_not_add_a_second_bos(sample_record):
    """The other half of prompt fidelity: build_chat already emits ``<s>``, so both"""
    assert judge_eval.build_eval_prompt(sample_record, None).startswith(
        prompt_format.DEFAULT_BOS)

    for name in ("judge_eval.py", "evaluate.py"):
        tree = ast.parse((EVALUATION_DIR / name).read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "tokenizer"]
        assert calls, f"{name}: no tokenizer(...) call found — did generate_text move?"
        for call in calls:
            flags = {kw.arg: kw.value for kw in call.keywords}
            assert "add_special_tokens" in flags, f"{name}:{call.lineno}"
            assert isinstance(flags["add_special_tokens"], ast.Constant)
            assert flags["add_special_tokens"].value is False, f"{name}:{call.lineno}"


def test_full_instruction_is_folded_into_the_prompt(sample_record):
    """The whole instruction (all the formatting rules), not a one-liner summary,"""
    prompt = judge_eval.build_eval_prompt(sample_record, None)
    assert sample_record["instruction"].rstrip() in prompt
    assert sample_record["input"] in prompt
    assert sample_record["output"] not in prompt   # never leak the reference
