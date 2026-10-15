"""The prompt judge_eval.py generates from is the trained one."""

import ast

import judge_eval
import prompt_format

from .conftest import EVALUATION_DIR


def test_the_judged_prompt_is_the_trained_prompt(sample_record):
    assert judge_eval.build_eval_prompt(sample_record) == prompt_format.build_prompt(sample_record)


def test_judge_eval_defines_no_local_prompt_builder():
    """Guard against the local format_prompt() coming back on a future merge."""
    assert not hasattr(judge_eval, "format_prompt")
    assert judge_eval.build_eval_prompt.__module__ == "judge_eval"


def test_tokenizer_calls_do_not_add_a_second_bos():
    """The prompt already starts with <s>, so every tokenizer(...) call in the
    evaluation scripts must pass add_special_tokens=False."""
    for name in ("judge_eval.py", "evaluate.py"):
        tree = ast.parse((EVALUATION_DIR / name).read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "tokenizer"]
        assert calls, f"{name}: no tokenizer(...) call found; did generate_text move?"
        for call in calls:
            flags = {kw.arg: kw.value for kw in call.keywords}
            assert "add_special_tokens" in flags, f"{name}:{call.lineno}"
            assert isinstance(flags["add_special_tokens"], ast.Constant)
            assert flags["add_special_tokens"].value is False, f"{name}:{call.lineno}"


def test_the_whole_instruction_and_input_reach_the_model(sample_record):
    prompt = judge_eval.build_eval_prompt(sample_record)

    assert sample_record["instruction"] in prompt
    assert sample_record["input"] in prompt
    assert sample_record["output"] not in prompt
