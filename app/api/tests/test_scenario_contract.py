"""The shared scenario contract: prompt, cache identity, Space response, sections."""

import hashlib
import importlib.util
import json
import re
import subprocess
import sys

import pytest

from app.api import scenario_contract as contract
from app.api.config import REPO_ROOT
from app.api.schemas import Scenario


SCENARIO_DIR = REPO_ROOT / "scenario_generation"
SAVED_OUTPUT_FILES = {
    "generated_scenarios_output.txt": SCENARIO_DIR / "fine_tuning" / "output" / "generated_scenarios_output.txt",
    "generated_scenarios.txt": SCENARIO_DIR / "fine_tuning" / "output" / "generated_scenarios.txt",
}

# AP-001 of scenario_generation/evaluation/inputs/attack_paths.json, copied so a
# pipeline change to that fixture cannot move the pinned prompt digest.
RECORD = {
    "source_id": "AP-001",
    "source_name": "OpenSecurityGroup -> PublicEC2Instance -> OverPermissiveInstanceProfile -> OverPermissiveRole -> InsecureS3Bucket",
    "industry": "Information technology service activities (ISIC J62)",
    "attack_level": "CRITICAL",
    "techniques": "T1190 - Exploit Public-Facing Application, T1078.004 - Valid Accounts: Cloud Accounts, T1199 - Trusted Relationship, T1098.001 - Account Manipulation: Additional Cloud Credentials, T1098.003 - Account Manipulation: Additional Cloud Roles, T1548.005 - Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API, T1580 - Cloud Infrastructure Discovery, T1619 - Cloud Storage Object Discovery, T1021 - Remote Services, T1021.007 - Remote Services: Cloud Services, T1530 - Data from Cloud Storage, T1537 - Transfer Data to Cloud Account, T1486 - Data Encrypted for Impact, T1485 - Data Destruction, T1490 - Inhibit System Recovery",
    "surfaces": "Internet-facing services / user endpoints, Application runtime environment, OS / IAM permission model, File system / cloud storage / databases",
    "objective": "Ransomware or destruction"
}

# sha256 of build_prompt(RECORD). If this fails the prompt text changed: bump
# scenario_contract.PROMPT_VERSION, then update the digest.
PROMPT_DIGEST = "ec577751b34f8ef537808a86e8c97d15bae07009437886dbe3be2c6c4880ca48"
PROMPT_VERSION_FOR_DIGEST = "P1.v1"

# The same for the training format: sha256 of build_prompt(RECORD, "training").
TRAINING_PROMPT_DIGEST = "e51820d8f3aa0cb8ca1716161609b6331b2d80a3f58a67f7ebcf2d6e9ce34147"
TRAINING_VERSION_FOR_DIGEST = "training.v1"

# cache_key(PROMPT, provenance()) at KEY_VERSION 1. If this fails the key
# payload changed, and every cached scenario would silently miss.
GOLDEN_KEY = "bdfbe44d99b62fc365e3f9965d5ecca2f1600aaeac1dd6c5807770ff6a05fcd1"

PROMPT = "<s>prompt text"
BASE_SHA = "1" * 40
ADAPTER_SHA = "2" * 40


def provenance(**overrides):
    values = dict(
        model_revision=BASE_SHA,
        adapter_repo="owner/scenario-adapter",
        adapter_revision=ADAPTER_SHA
    )
    values.update(overrides)

    return contract.make_provenance(**values)


def response_for(text, new_tokens, hit_eos, prov=None, **overrides):
    prov = prov or provenance()
    response = contract.build_response(
        text=text, new_tokens=new_tokens, hit_eos=hit_eos, seconds=12.5, provenance=prov
    )
    response.update(overrides)

    return response


WELL_FORMED = (
    "[NATURAL LANGUAGE]\nThe attacker exploits the web app (T1190).\n\n"
    "[MATHEMATICAL EXPRESSION]\nG = (N, S, V, P, FS)\n\n"
    "[ATTACK GRAPH]\n1. Web App -> Role"
)


# -- Importability -------------------------------------------------------------

def test_contract_imports_without_heavy_or_repository_modules():
    code = (
        "import sys, app.api.scenario_contract; "
        "print(sorted({m.split('.')[0] for m in sys.modules} & "
        "{'torch', 'transformers', 'peft', 'gradio', 'pydantic', 'scenario_generation', 'yaml'}))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == "[]"


def test_contract_imports_alone_as_the_space_and_kaggle_copy_it(tmp_path):
    (tmp_path / "scenario_contract.py").write_bytes(
        (REPO_ROOT / "app" / "api" / "scenario_contract.py").read_bytes()
    )
    code = "import scenario_contract as c; print(c.PROMPT_VERSION, len(c.generation_settings()))"
    result = subprocess.run(
        [sys.executable, "-S", "-c", code], cwd=tmp_path, capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split()[0] == contract.PROMPT_VERSION


# -- Prompt --------------------------------------------------------------------

def test_prompt_is_the_existing_builder_output_and_pinned():
    from scenario_generation import prompt_generator

    prompt = contract.build_prompt(RECORD)

    assert prompt == prompt_generator.format_model_input(prompt_generator.STRUCTURED_PROMPTS[0], RECORD)
    assert contract.PROMPT_VERSION == PROMPT_VERSION_FOR_DIGEST
    assert hashlib.sha256(prompt.encode("utf-8")).hexdigest() == PROMPT_DIGEST


def test_default_format_is_structured_p1_with_the_original_version():
    assert contract.DEFAULT_PROMPT_FORMAT == "structured-p1"
    assert contract.PROMPT_VERSION == contract.PROMPT_VERSIONS["structured-p1"] == "P1.v1"
    assert contract.build_prompt(RECORD) == contract.build_prompt(RECORD, "structured-p1")


def test_training_prompt_is_pinned_and_has_no_objective_or_focus_block():
    prompt = contract.build_prompt(RECORD, "training")

    assert contract.PROMPT_VERSIONS["training"] == TRAINING_VERSION_FOR_DIGEST
    assert hashlib.sha256(prompt.encode("utf-8")).hexdigest() == TRAINING_PROMPT_DIGEST
    assert prompt.startswith("<s>[INST] ")
    assert prompt.endswith(" [/INST]\n")
    assert "OBJECTIVE:" not in prompt
    assert "PROMPT FOCUS" not in prompt


def test_training_input_is_the_first_five_lines_of_the_structured_input():
    from scenario_generation import prompt_generator

    block = prompt_generator.build_input_block(prompt_generator.STRUCTURED_PROMPTS[0], RECORD)

    assert block.startswith(contract.training_input(RECORD) + "\nOBJECTIVE: ")


_SOURCE_RE = re.compile(r"SOURCE: (.*) \(([^()]*)\)")


def _record_from_training_input(text):
    """A seven-key record whose five facts lines are exactly `text`."""
    lines = text.split("\n")
    assert [line.split(":", 1)[0] for line in lines] == [
        "SOURCE", "INDUSTRY", "ATTACK LEVEL", "TECHNIQUES", "SURFACES"]
    name, source_id = _SOURCE_RE.fullmatch(lines[0]).groups()

    return {
        "source_id": source_id,
        "source_name": name,
        "industry": lines[1].split(": ", 1)[1],
        "attack_level": lines[2].split(": ", 1)[1],
        "techniques": lines[3].split(": ", 1)[1],
        "surfaces": lines[4].split(": ", 1)[1],
        "objective": "unused by the training format",
    }


def test_training_format_matches_training_prompt_for_every_reference_record():
    from scenario_generation.fine_tuning import prompt_format

    checked = 0
    for path in (SCENARIO_DIR / "dataset" / "training_data.jsonl", SCENARIO_DIR / "evaluation" / "test_inputs.jsonl"):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                example = json.loads(line)
                record = _record_from_training_input(example["input"])

                assert contract.build_prompt(record, "training") == prompt_format.build_prompt(example)
                checked += 1

    assert checked == 81 + 17


def test_formats_have_distinct_versions_prompts_and_cache_keys():
    structured = contract.build_prompt(RECORD, "structured-p1")
    training = contract.build_prompt(RECORD, "training")
    prov = provenance()

    assert structured != training
    assert len(set(contract.PROMPT_VERSIONS.values())) == len(contract.PROMPT_VERSIONS)
    assert contract.cache_key(structured, prov, contract.prompt_version_for("structured-p1")) != \
        contract.cache_key(training, prov, contract.prompt_version_for("training"))
    # The version alone separates keys, even for an identical prompt.
    assert contract.cache_key(training, prov, "P1.v1") != contract.cache_key(training, prov, "training.v1")


def test_prompt_format_and_version_lookups_round_trip():
    for name, version in contract.PROMPT_VERSIONS.items():
        assert contract.prompt_version_for(name) == version
        assert contract.prompt_format_for_version(version) == name


@pytest.mark.parametrize("bad", ["structured", "", None, "P1.v1", 1])
def test_unknown_prompt_formats_are_rejected(bad):
    with pytest.raises(contract.ScenarioContractError):
        contract.build_prompt(RECORD, bad)
    with pytest.raises(contract.ScenarioContractError):
        contract.prompt_version_for(bad)


def test_unknown_prompt_version_is_rejected():
    with pytest.raises(contract.ScenarioContractError, match="unknown prompt_version"):
        contract.prompt_format_for_version("P1.v0")


@pytest.mark.parametrize("prompt_format", sorted(contract.PROMPT_VERSIONS))
def test_every_format_requires_exactly_seven_string_fields(prompt_format):
    record = dict(RECORD)
    record.pop("objective")

    with pytest.raises(contract.ScenarioContractError):
        contract.build_prompt(record, prompt_format)


@pytest.mark.parametrize("change", [
    lambda r: r.pop("objective"),
    lambda r: r.update(extra="x"),
    lambda r: r.update(industry=None)
])
def test_build_prompt_requires_exactly_seven_string_fields(change):
    record = dict(RECORD)
    change(record)

    with pytest.raises(contract.ScenarioContractError):
        contract.build_prompt(record)


@pytest.mark.parametrize("value", [0, 1201, -1, True, 1.0, "100", None])
def test_token_cap_must_be_an_integer_from_1_to_1200(value):
    with pytest.raises(contract.ScenarioContractError):
        contract.check_max_new_tokens(value)


def test_token_cap_bounds_are_accepted():
    assert contract.check_max_new_tokens(1) == 1
    assert contract.check_max_new_tokens(1200) == 1200


def test_generation_settings_match_prompt_generator():
    settings = contract.generation_settings()

    assert settings["max_new_tokens"] == 1200
    assert settings["do_sample"] is True
    assert (settings["temperature"], settings["top_p"], settings["repetition_penalty"]) == (0.7, 0.9, 1.05)
    kwargs = contract.generate_kwargs(settings, eos_token_id=2, pad_token_id=2)
    assert kwargs == {
        "max_new_tokens": 1200, "do_sample": True, "temperature": 0.7, "top_p": 0.9,
        "repetition_penalty": 1.05, "eos_token_id": 2, "pad_token_id": 2, "use_cache": True
    }


# -- Cache identity ------------------------------------------------------------

def test_cache_key_is_stable():
    prov = provenance()
    reordered = dict(reversed(list(prov.items())))
    reordered["generation_config"] = dict(reversed(list(prov["generation_config"].items())))

    key = contract.cache_key(PROMPT, prov)

    assert re.fullmatch(r"[0-9a-f]{64}", key)
    assert key == contract.cache_key(PROMPT, reordered)
    assert key == GOLDEN_KEY


def _changed_config(key, value):
    prov = provenance()
    prov["generation_config"] = dict(prov["generation_config"], **{key: value})

    return prov


@pytest.mark.parametrize("prompt, prov, version", [
    (PROMPT + " ", provenance(), contract.PROMPT_VERSION),
    (PROMPT, provenance(), "P1.v2"),
    (PROMPT, dict(provenance(), model_id="mistralai/Other"), contract.PROMPT_VERSION),
    (PROMPT, provenance(model_revision="3" * 40), contract.PROMPT_VERSION),
    (PROMPT, provenance(adapter_repo="owner/other-adapter"), contract.PROMPT_VERSION),
    (PROMPT, provenance(adapter_revision="4" * 40), contract.PROMPT_VERSION),
    (PROMPT, dict(provenance(), loading_recipe="bf16-merged"), contract.PROMPT_VERSION),
    (PROMPT, provenance(max_new_tokens=1000), contract.PROMPT_VERSION),
    (PROMPT, _changed_config("do_sample", False), contract.PROMPT_VERSION),
    (PROMPT, _changed_config("temperature", 0.8), contract.PROMPT_VERSION),
    (PROMPT, _changed_config("top_p", 0.95), contract.PROMPT_VERSION),
    (PROMPT, _changed_config("repetition_penalty", 1.1), contract.PROMPT_VERSION),
    (PROMPT, _changed_config("pad_token_id", "tokenizer.pad_token_id"), contract.PROMPT_VERSION)
], ids=[
    "prompt", "prompt_version", "model_id", "model_revision", "adapter_repo", "adapter_revision",
    "loading_recipe", "max_new_tokens", "do_sample", "temperature", "top_p", "repetition_penalty",
    "pad_behaviour"
])
def test_cache_key_changes_with_each_provenance_input(prompt, prov, version):
    assert contract.cache_key(prompt, prov, version) != contract.cache_key(PROMPT, provenance())


@pytest.mark.parametrize("overrides", [
    {"model_revision": "main"},
    {"model_revision": "1" * 39},
    {"adapter_revision": "v1.0"},
    {"adapter_repo": "no-owner"},
    {"loading_recipe": "bf16-merged"}
])
def test_provenance_requires_pinned_shas_and_known_recipe(overrides):
    with pytest.raises(contract.ScenarioContractError):
        provenance(**overrides)


# -- Space response ------------------------------------------------------------

def test_valid_response_passes_with_extra_fields():
    response = response_for(WELL_FORMED, 300, True, runtime={"torch": "2.10.0"})

    assert contract.validate_result(response, provenance()) is response
    assert response["finish_reason"] == "eos"


@pytest.mark.parametrize("field, value", [
    ("model_id", "mistralai/Mistral-7B-Instruct-v0.2"),
    ("model_revision", "9" * 40),
    ("adapter_repo", "owner/other-adapter"),
    ("adapter_revision", "8" * 40),
    ("loading_recipe", "bf16-merged"),
    ("generation_config", dict(contract.generation_settings(), temperature=0.8))
])
def test_provenance_mismatch_is_rejected_not_relabelled(field, value):
    response = response_for(WELL_FORMED, 300, True, **{field: value})

    with pytest.raises(contract.ScenarioContractError, match="provenance mismatch"):
        contract.validate_result(response, provenance())


def test_response_for_a_different_token_cap_is_rejected():
    response = response_for(WELL_FORMED, 300, True, prov=provenance(max_new_tokens=600))

    with pytest.raises(contract.ScenarioContractError):
        contract.validate_result(response, provenance())


@pytest.mark.parametrize("overrides", [
    {"new_tokens": 1201},
    {"new_tokens": -1},
    {"new_tokens": True},
    {"hit_eos": 1},
    {"finish_reason": "stop"},
    {"finish_reason": "length"},
    {"seconds": float("nan")},
    {"text": None}
])
def test_malformed_or_inconsistent_response_is_rejected(overrides):
    response = response_for(WELL_FORMED, 300, True)
    response.update(overrides)

    with pytest.raises(contract.ScenarioContractError):
        contract.validate_result(response, provenance())


def test_response_missing_a_field_is_rejected():
    response = response_for(WELL_FORMED, 300, True)
    del response["adapter_revision"]

    with pytest.raises(contract.ScenarioContractError, match="missing adapter_revision"):
        contract.validate_result(response, provenance())


# -- Truncation honesty --------------------------------------------------------

def _payload(text, new_tokens, hit_eos, max_new_tokens=1200):
    prov = provenance(max_new_tokens=max_new_tokens)
    entry = contract.make_cache_entry(
        prompt=PROMPT, provenance=prov, response=response_for(text, new_tokens, hit_eos, prov=prov),
        source="live", generated_at="2026-10-24T10:00:00+00:00"
    )

    return contract.scenario_payload(entry)


def test_missing_headers_after_eos_are_not_truncation():
    payload = _payload("[NATURAL LANGUAGE]\nOnly a narrative.", 400, True)

    assert payload["sections"]["missing"] == ["mathematical", "attack_graph"]
    assert payload["reached_token_cap"] is False
    assert payload["finish_reason"] == "eos"


def test_missing_headers_without_eos_below_the_cap_are_not_truncation():
    payload = _payload("[NATURAL LANGUAGE]\nStopped early", 900, False)

    assert payload["sections"]["missing"] == ["mathematical", "attack_graph"]
    assert payload["reached_token_cap"] is False
    assert payload["finish_reason"] == "other"


def test_reaching_the_cap_without_eos_is_truncation():
    payload = _payload("[NATURAL LANGUAGE]\nCut off mid", 1200, False)

    assert payload["reached_token_cap"] is True
    assert payload["finish_reason"] == "length"


def test_eos_on_the_last_allowed_token_is_not_truncation():
    payload = _payload(WELL_FORMED, 64, True, max_new_tokens=64)

    assert payload["reached_token_cap"] is False
    assert payload["sections"]["missing"] == []


def test_scenario_payload_matches_the_api_schema():
    payload = _payload(WELL_FORMED, 300, True)

    scenario = Scenario.model_validate(payload)

    assert scenario.source == "live"
    assert scenario.sections.attack_graph == "1. Web App -> Role"
    assert scenario.prompt_version == contract.PROMPT_VERSION


# -- Cache entries -------------------------------------------------------------

def _entry():
    return contract.make_cache_entry(
        prompt=PROMPT, provenance=provenance(), response=response_for(WELL_FORMED, 300, True),
        source="pregenerated"
    )


def test_cache_entry_round_trips_through_json():
    entry = json.loads(json.dumps(_entry()))

    assert contract.validate_cache_entry(entry) == entry
    assert entry["cache_key"] == contract.cache_key(PROMPT, provenance())


@pytest.mark.parametrize("tamper", [
    lambda e: e.update(cache_key="0" * 64),
    lambda e: e["request"].update(prompt=PROMPT + "x"),
    lambda e: e["request"].update(adapter_revision="5" * 40),
    lambda e: e["response"].update(adapter_revision="5" * 40),
    lambda e: e.update(source="cached"),
    lambda e: e.update(generated_at="yesterday"),
    lambda e: e.update(schema_version=2)
])
def test_tampered_cache_entry_is_rejected(tamper):
    entry = _entry()
    tamper(entry)

    with pytest.raises(contract.ScenarioContractError):
        contract.validate_cache_entry(entry)


# -- Section parsing -----------------------------------------------------------

def test_well_formed_sections():
    sections = contract.parse_sections(WELL_FORMED)

    assert sections == {
        "natural_language": "The attacker exploits the web app (T1190).",
        "mathematical": "G = (N, S, V, P, FS)",
        "attack_graph": "1. Web App -> Role",
        "preamble": None,
        "missing": []
    }


def test_missing_middle_section_does_not_swallow_the_next_one():
    sections = contract.parse_sections("[NATURAL LANGUAGE]\nStory\n[ATTACK GRAPH]\n1. A -> B")

    assert sections["natural_language"] == "Story"
    assert sections["attack_graph"] == "1. A -> B"
    assert sections["missing"] == ["mathematical"]


def test_preamble_is_kept_apart_and_never_relabelled():
    with_header = contract.parse_sections("Sure, here it is.\n[NATURAL LANGUAGE]\nStory")
    without_headers = contract.parse_sections("Just prose, no headers.")

    assert with_header["preamble"] == "Sure, here it is."
    assert with_header["natural_language"] == "Story"
    assert without_headers["preamble"] == "Just prose, no headers."
    assert without_headers["natural_language"] is None
    assert without_headers["missing"] == ["natural_language", "mathematical", "attack_graph"]


def test_present_but_empty_section_is_not_missing():
    sections = contract.parse_sections("[NATURAL LANGUAGE]\nStory\n[MATHEMATICAL EXPRESSION]\n[ATTACK GRAPH]")

    assert sections["mathematical"] == ""
    assert sections["attack_graph"] == ""
    assert sections["missing"] == []


def _evaluator():
    path = SCENARIO_DIR / "evaluation" / "manual_eval_metrics.py"
    spec = importlib.util.spec_from_file_location("manual_eval_metrics_for_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def test_headers_are_the_evaluators():
    assert [header for _, header in contract.SECTION_HEADERS] == _evaluator().SECTIONS_ORDERED


def _reference_outputs():
    outputs = []
    for path in (SCENARIO_DIR / "dataset" / "training_data.jsonl", SCENARIO_DIR / "evaluation" / "test_inputs.jsonl"):
        with path.open(encoding="utf-8") as handle:
            outputs.extend(json.loads(line)["output"] for line in handle if line.strip())

    return outputs


def test_sections_equal_the_evaluator_regexes_on_every_reference_output():
    evaluator = _evaluator()
    outputs = _reference_outputs()
    regexes = {
        "natural_language": evaluator.NL_TEXT_RE,
        "mathematical": evaluator.MATH_TEXT_RE,
        "attack_graph": evaluator.GRAPH_TEXT_RE
    }

    assert len(outputs) == 81 + 17
    for text in outputs:
        sections = contract.parse_sections(text)
        assert sections["missing"] == []
        for field, regex in regexes.items():
            assert sections[field] == regex.search(text).group(1).strip()


# -- The saved real outputs ----------------------------------------------------

def _saved_outputs(path):
    """The OUTPUT text of every SAMPLE block in a saved generation file."""
    text = path.read_text(encoding="utf-8")
    blocks = re.split(r"\n={40,}\n", text)

    return [block.split("\nOUTPUT:\n", 1)[1] for block in blocks if re.match(r"SAMPLE \d+\n", block)]


@pytest.fixture(scope="module")
def saved():
    return {name: _saved_outputs(path) for name, path in SAVED_OUTPUT_FILES.items()}


def test_saved_files_hold_twenty_outputs(saved):
    assert {name: len(outputs) for name, outputs in saved.items()} == {
        "generated_scenarios_output.txt": 10,
        "generated_scenarios.txt": 10
    }


def test_exactly_the_ten_echoed_template_outputs_have_an_attack_graph(saved):
    with_graph = {
        name: [i + 1 for i, text in enumerate(outputs) if contract.parse_sections(text)["attack_graph"] is not None]
        for name, outputs in saved.items()
    }
    header_counts = {
        name: path.read_text(encoding="utf-8").count("[ATTACK GRAPH]")
        for name, path in SAVED_OUTPUT_FILES.items()
    }

    assert with_graph == {"generated_scenarios_output.txt": list(range(1, 11)), "generated_scenarios.txt": []}
    assert header_counts == {"generated_scenarios_output.txt": 10, "generated_scenarios.txt": 0}


def test_echoed_template_outputs_parse_as_the_template(saved):
    # These came from the old notebook, which echoed its prompt template into
    # the saved text (fine_tuning/CHANGES.md, fix I). Every header therefore
    # first appears in the echoed template, and first occurrence wins, as in
    # the evaluator; the real model text after the second header stays only
    # in the raw text. The Space decodes only new tokens, so this cannot recur.
    for text in saved["generated_scenarios_output.txt"]:
        sections = contract.parse_sections(text)
        assert sections["missing"] == []
        assert sections["preamble"].startswith("You are a cybersecurity expert.")
        assert sections["natural_language"].startswith("Write a detailed 3")
        assert sections["mathematical"] == "Represent the scenario as:\nG = (N, S, V, P, FS)"
        assert sections["attack_graph"].startswith("Stage 1:")
        assert sections["attack_graph"].endswith("Now generate for the following input:")
        assert text.count("[NATURAL LANGUAGE]") == 2


def test_header_free_outputs_are_all_preamble(saved):
    for text in saved["generated_scenarios.txt"]:
        sections = contract.parse_sections(text)
        assert sections["missing"] == ["natural_language", "mathematical", "attack_graph"]
        assert sections["preamble"] == text.strip()
        assert sections["natural_language"] is None
