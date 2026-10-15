"""test_prompt_generator_prompt.py"""

import ast
import json

import pytest

import prompt_format
import prompt_generator

from .conftest import (
    ATTACK_PATHS_FIXTURE,
    EVALUATION_DIR,
    PROMPT_GENERATOR_MODULE,
    scanned_python_files,
)


@pytest.fixture
def prompt_entry():
    """The first entry of the structured prompt library."""
    return prompt_generator.STRUCTURED_PROMPTS[0]


def canonical(prompt_entry, attack_path, tokenizer):
    """The prompt build_chat produces for this (prompt, path) pair."""
    record = {
        "instruction": prompt_generator.SYSTEM_INSTRUCTION,
        "input": prompt_generator.build_input_block(prompt_entry, attack_path),
    }
    return prompt_format.build_chat(record, tokenizer, for_training=False)


# ── Byte-for-byte parity with the canonical builder ───────────────────────────

def test_prompt_is_byte_identical_to_build_chat_without_tokenizer(prompt_entry, attack_path):
    assert (prompt_generator.format_model_input(prompt_entry, attack_path, None)
            == canonical(prompt_entry, attack_path, None))


def test_prompt_is_byte_identical_to_build_chat_with_tokenizer(
        prompt_entry, attack_path, fake_tokenizer):
    assert (prompt_generator.format_model_input(prompt_entry, attack_path, fake_tokenizer)
            == canonical(prompt_entry, attack_path, fake_tokenizer))


# ── The specific drift this file was written to catch ──────────────────────────

def test_prompt_has_no_space_before_the_response_marker(
        prompt_entry, attack_path, fake_tokenizer):
    for tokenizer in (None, fake_tokenizer):
        prompt = prompt_generator.format_model_input(prompt_entry, attack_path, tokenizer)
        assert prompt.endswith(prompt_format.RESPONSE_MARKER)
        assert not prompt.endswith(" " + prompt_format.RESPONSE_MARKER)


def test_prompt_generator_defines_no_local_prompt_builder():
    """Guard against the local template coming back on a future merge."""
    assert not hasattr(prompt_generator, "format_prompt")
    assert "prompt_format.build_chat" in PROMPT_GENERATOR_MODULE.read_text(
        encoding="utf-8")


# ── Train / inference parity of the generated prompt ──────────────────────────

def test_generated_prompt_is_a_prefix_of_the_training_text(
        prompt_entry, attack_path, fake_tokenizer):
    """The generation prompt must be a strict prefix of the full training text —"""
    for tokenizer in (None, fake_tokenizer):
        record = {
            "instruction": prompt_generator.SYSTEM_INSTRUCTION,
            "input": prompt_generator.build_input_block(prompt_entry, attack_path),
            "output": "[NATURAL LANGUAGE]\nsomething",
        }
        prompt = prompt_generator.format_model_input(prompt_entry, attack_path, tokenizer)
        training_text = prompt_format.build_chat(record, tokenizer, for_training=True)

        assert training_text.startswith(prompt)
        assert len(training_text) > len(prompt)


def test_tokenizer_call_does_not_add_a_second_bos():
    """The other half of prompt fidelity: build_chat already emits ``<s>``, so this"""
    for path in (PROMPT_GENERATOR_MODULE, EVALUATION_DIR / "evaluate.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "tokenizer"]
        assert calls, f"{path.name}: no tokenizer(...) call found — did generate_text move?"
        for call in calls:
            flags = {kw.arg: kw.value for kw in call.keywords}
            assert "add_special_tokens" in flags, f"{path.name}:{call.lineno}"
            assert isinstance(flags["add_special_tokens"], ast.Constant)
            assert flags["add_special_tokens"].value is False, f"{path.name}:{call.lineno}"


def test_full_instruction_and_the_path_facts_are_in_the_prompt(prompt_entry, attack_path):
    """The whole instruction (all the formatting rules) plus the record's input —"""
    prompt = prompt_generator.format_model_input(prompt_entry, attack_path, None)

    assert prompt_generator.SYSTEM_INSTRUCTION.rstrip() in prompt

    for line in ("SOURCE:", "INDUSTRY:", "ATTACK LEVEL:", "TECHNIQUES:", "SURFACES:"):
        assert line in prompt

    assert attack_path["source_id"] in prompt
    assert attack_path["source_name"] in prompt
    assert attack_path["techniques"] in prompt
    assert attack_path["surfaces"] in prompt
    assert prompt_entry["focus"] in prompt


# ── The dummy path is gone ────────────────────────────────────────────────────

def _assigned_names(source):
    """Every module-level-or-nested name assigned in a snippet of Python."""
    tree = ast.parse(source)
    return {
        target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def test_the_dummy_attack_path_is_gone_from_the_imported_module():
    """Every run used to generate four scenarios about the same invented campaign,"""
    assert not hasattr(prompt_generator, "DUMMY_ATTACK_PATH")
    assert prompt_generator.ATTACK_PATH_KEYS

    source = PROMPT_GENERATOR_MODULE.read_text(encoding="utf-8")

    assert not [
        name for name in _assigned_names(source) if "DUMMY" in name.upper()
    ]


@pytest.mark.parametrize("path", scanned_python_files(), ids=lambda p: p.name)
def test_no_module_carries_a_hardcoded_attack_path(path):
    """THE SCOPE THIS TEST USED TO HAVE, WIDENED."""
    source = path.read_text(encoding="utf-8")

    assert not [
        name for name in _assigned_names(source) if "DUMMY" in name.upper()
    ], path.name

    assert "DUMMY-MVP-001" not in source, path.name
    assert "MVP Test Campaign" not in source, path.name


# ── The cross-repository key set ──────────────────────────────────────────────

def test_attack_path_keys_are_exactly_what_the_prompt_reads(attack_path):
    """ATTACK_PATH_KEYS is what the loader validates; the seven subscripts inside"""
    expected = {
        "source_id",
        "source_name",
        "industry",
        "attack_level",
        "techniques",
        "surfaces",
        "objective",
    }

    assert set(prompt_generator.ATTACK_PATH_KEYS) == expected
    assert set(attack_path.keys()) == expected


def test_build_input_block_reads_every_declared_key(prompt_entry, attack_path):
    """A key declared but never read would make ATTACK_PATH_KEYS a stale comment."""
    for key in prompt_generator.ATTACK_PATH_KEYS:
        broken = {k: v for k, v in attack_path.items() if k != key}
        with pytest.raises(KeyError):
            prompt_generator.build_input_block(prompt_entry, broken)


# ── Loading a real export ─────────────────────────────────────────────────────

def test_the_real_export_loads(attack_path_records):
    records = prompt_generator.load_attack_paths(ATTACK_PATHS_FIXTURE)

    assert records == attack_path_records
    assert len(records) >= 1

    for record in records:
        for key in prompt_generator.ATTACK_PATH_KEYS:
            assert isinstance(record[key], str), key


def test_one_prompt_per_exported_path(prompt_entry, attack_path_records):
    """The loop is over the real paths now, so N paths produce N distinct prompts —"""
    prompts = [
        prompt_generator.format_model_input(prompt_entry, record, None)
        for record in prompt_generator.load_attack_paths(ATTACK_PATHS_FIXTURE)
    ]

    assert len(prompts) == len(attack_path_records)
    assert len(set(prompts)) == len(prompts)

    for prompt, record in zip(prompts, attack_path_records):
        assert record["source_id"] in prompt


def test_every_prompt_in_the_cross_product_is_canonical(attack_path_records):
    """Every prompt the script can emit — each library prompt against each exported"""
    for record in attack_path_records:
        for entry in prompt_generator.STRUCTURED_PROMPTS:
            assert (prompt_generator.format_model_input(entry, record, None)
                    == canonical(entry, record, None))


def test_a_missing_file_is_a_clear_error(tmp_path):
    """The most likely failure in practice: the export has not been copied over"""
    missing = tmp_path / "attack_paths.json"

    with pytest.raises(FileNotFoundError) as excinfo:
        prompt_generator.load_attack_paths(missing)

    message = str(excinfo.value)
    assert str(missing) in message
    assert "runner.graph_runner" in message      # tells you how to produce it


def test_a_missing_key_is_reported_before_the_model_loads(tmp_path):
    """A drifted export must fail with the name of the missing key, not with a"""
    drifted = tmp_path / "attack_paths.json"
    record = {key: "x" for key in prompt_generator.ATTACK_PATH_KEYS}
    del record["techniques"]
    drifted.write_text(json.dumps([record]), encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        prompt_generator.load_attack_paths(drifted)

    assert "techniques" in str(excinfo.value)


def test_an_empty_or_wrongly_shaped_export_is_rejected(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError):
        prompt_generator.load_attack_paths(empty)

    not_a_list = tmp_path / "object.json"
    not_a_list.write_text('{"source_id": "AP-001"}', encoding="utf-8")

    with pytest.raises(ValueError):
        prompt_generator.load_attack_paths(not_a_list)

    not_objects = tmp_path / "strings.json"
    not_objects.write_text('["AP-001"]', encoding="utf-8")

    with pytest.raises(ValueError):
        prompt_generator.load_attack_paths(not_objects)
