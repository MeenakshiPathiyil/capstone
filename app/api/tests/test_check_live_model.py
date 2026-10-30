"""app.scripts.check_live_model over a mocked gradio Client. No network, no token."""

import json
from types import SimpleNamespace

import pytest

from app.api import scenario_cache as cache
from app.api import scenario_contract as contract
from app.api.config import REPO_ROOT
from app.scripts import _common, check_live_model as check


TOKEN = "hf_never_print_this_token_value"
SPACE_ID = "owner/scenario-space"
ADAPTER_REPO = "owner/scenario-adapter"
ADAPTER_SHA = "2" * 40
BASE_SHA = "1" * 40

GOOD = (
    "[NATURAL LANGUAGE]\nStory (T1190).\n[MATHEMATICAL EXPRESSION]\nG = (N, S, V, P, FS)\n"
    "[ATTACK GRAPH]\n1. A -> B"
)
PREAMBLE_AND_GAPS = "Sure, here is the scenario.\n[NATURAL LANGUAGE]\nOnly a story."


class FakeJob:
    def __init__(self, value):
        self.value = value

    def result(self, timeout=None):
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class FakeClient:
    """Answers /metadata and /generate; records every prompt it is asked for."""

    def __init__(self, provenance, text=GOOD, metadata_overrides=None, fail_on=None, tamper=None):
        self.provenance = provenance
        self.text = text
        self.metadata = {
            **provenance, "prompt_versions": contract.PROMPT_VERSIONS, "context_tokens": 32768,
            **(metadata_overrides or {}),
        }
        self.fail_on = fail_on
        self.tamper = tamper or {}
        self.prompts = []
        self.closed = False

    def predict(self, api_name=None):
        assert api_name == "/metadata"
        return self.metadata

    def submit(self, prompt, max_new_tokens, api_name=None):
        assert api_name == "/generate"
        self.prompts.append(prompt)
        if self.fail_on == len(self.prompts):
            return FakeJob(RuntimeError(f"ZeroGPU quota exceeded for token {TOKEN}"))
        response = contract.build_response(
            text=self.text, new_tokens=300, hit_eos=True, seconds=12.34, provenance=self.provenance,
            extra={"prompt_tokens": 700 + len(self.prompts)})
        response.update(self.tamper)
        return FakeJob(response)

    def close(self):
        self.closed = True


def provenance():
    return contract.make_provenance(
        model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA)


def args(tmp_path, *extra):
    return [
        "--space-id", SPACE_ID, "--adapter-repo", ADAPTER_REPO, "--adapter-revision", ADAPTER_SHA,
        "--base-revision", BASE_SHA, "--yes",
        "--output", str(tmp_path / "out.json"), "--cache-dir", str(tmp_path / "cache"), *extra,
    ]


def run(tmp_path, client, *extra):
    return check.main(args(tmp_path, *extra), client_factory=lambda space_id, token: client, token=TOKEN)


def test_default_base_revision_is_the_verified_main():
    assert check.DEFAULT_BASE_REVISION == "c170c708c41dac9275d15a8fff4eca08d52bab71"
    assert contract.is_commit_sha(check.DEFAULT_BASE_REVISION)
    assert check.DEFAULT_PATHS == ("AP-001", "AP-019")


def test_cases_are_each_path_in_both_formats_then_the_control():
    cases = check.build_cases(["AP-001", "AP-019"])

    assert [(case["path"], case["format"]) for case in cases] == [
        ("AP-001", "structured-p1"), ("AP-001", "training"),
        ("AP-019", "structured-p1"), ("AP-019", "training"),
        ("C0027", check.CONTROL_FORMAT),
    ]
    for case in cases[:4]:
        assert case["prompt"] == contract.build_prompt(case["record"], case["format"])
        assert case["prompt_version"] == contract.prompt_version_for(case["format"])


def test_the_control_is_the_held_out_record_exactly_as_training_builds_it():
    from scenario_generation.fine_tuning import prompt_format

    with (REPO_ROOT / "scenario_generation" / "evaluation" / "test_inputs.jsonl").open(encoding="utf-8") as handle:
        record = next(json.loads(line) for line in handle if '"C0027"' in line)

    prompt = check.build_cases(["AP-001"])[-1]["prompt"]

    assert prompt == prompt_format.build_prompt(record)
    assert prompt.startswith("<s>[INST] ") and "SOURCE: C0027 (C0027)" in prompt


def test_unknown_sample_path_is_an_error():
    with pytest.raises(_common.ScriptError, match="AP-999"):
        check.build_cases(["AP-999"])


def test_a_full_run_prints_the_table_writes_json_and_never_shows_the_token(tmp_path, capsys):
    client = FakeClient(provenance())

    assert run(tmp_path, client) == 0

    out = capsys.readouterr().out
    assert len(client.prompts) == 5
    assert client.closed
    assert "5 generations" in out and "ZeroGPU quota" in out
    for heading in ("format", "path", "prompt tok", "new tok", "finish", "seconds", "missing", "preamble"):
        assert heading in out
    assert "structured-p1" in out and "training (control)" in out
    assert "12.3" in out and "eos" in out
    assert "[NATURAL LANGUAGE] Story (T1190)." in out
    assert TOKEN not in out

    written = (tmp_path / "out.json").read_text()
    document = json.loads(written)
    assert TOKEN not in written
    assert document["provenance"] == provenance()
    assert [(item["format"], item["path"]) for item in document["results"]][-1] == ("training (control)", "C0027")
    assert all(item["valid"] and item["response"]["text"] == GOOD for item in document["results"])


def test_missing_sections_and_preamble_are_reported(tmp_path, capsys):
    assert run(tmp_path, FakeClient(provenance(), text=PREAMBLE_AND_GAPS), "--paths", "AP-001") == 0

    row = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("structured-p1"))

    assert "MATH,GRAPH" in row
    assert row.rstrip().endswith("yes")


def test_snippets_are_cut_to_about_300_characters():
    result = {"valid": True, "response": {"text": "word " * 400}}

    text = check.snippet(result)

    assert len(text) == check.SNIPPET_CHARS + 3 and text.endswith("...")


def test_a_space_with_other_revisions_is_refused_before_any_generation(tmp_path):
    client = FakeClient(provenance(), metadata_overrides={"adapter_revision": "9" * 40})

    with pytest.raises(_common.ScriptError, match="adapter_revision"):
        run(tmp_path, client)

    assert client.prompts == []
    assert not (tmp_path / "out.json").exists()


def test_a_failing_call_stops_the_run_redacts_the_token_and_keeps_results(tmp_path, capsys):
    client = FakeClient(provenance(), fail_on=2)

    assert run(tmp_path, client) == 1

    out = capsys.readouterr().out
    assert len(client.prompts) == 2
    assert "Stopping" in out
    assert TOKEN not in out and "***" in out
    written = (tmp_path / "out.json").read_text()
    assert TOKEN not in written
    results = json.loads(written)["results"]
    assert [item["valid"] for item in results] == [True, False]
    assert results[1]["error"].startswith("call failed")


def test_a_response_from_other_provenance_is_rejected_and_flagged(tmp_path, capsys):
    client = FakeClient(provenance(), tamper={"adapter_revision": "8" * 40})

    assert run(tmp_path, client, "--paths", "AP-001") == 1

    out = capsys.readouterr().out
    assert "provenance mismatch" in out
    assert "invalid" in out


def test_import_stores_valid_path_results_as_live_and_skips_the_control(tmp_path, capsys):
    cache_dir = tmp_path / "cache"

    assert run(tmp_path, FakeClient(provenance()), "--import") == 0

    stored = sorted(cache.scenarios_dir(cache_dir).glob("*.json"))
    assert len(stored) == 4  # 2 paths x 2 formats; the control is not imported
    versions = set()
    for path in stored:
        entry = cache.read_entry(cache_dir, path.stem)
        assert entry["source"] == "live"
        versions.add(entry["request"]["prompt_version"])
        assert entry["request"]["prompt"] != ""
    assert versions == {"P1.v1", "training.v1"}
    assert "created 4" in capsys.readouterr().out

    # An entry is found by the key the app would compute for the same path and format.
    record = check.load_sample_records(["AP-001"])["AP-001"]
    for prompt_format in contract.PROMPT_VERSIONS:
        prompt = contract.build_prompt(record, prompt_format)
        key = contract.cache_key(prompt, provenance(), contract.prompt_version_for(prompt_format))
        assert cache.read_entry(cache_dir, key) is not None

    # A second run never replaces what is stored: the first accepted result for a key wins.
    assert run(tmp_path, FakeClient(provenance()), "--import") == 0
    assert "kept_existing 4" in capsys.readouterr().out


def test_without_the_import_flag_the_cache_is_untouched(tmp_path):
    assert run(tmp_path, FakeClient(provenance())) == 0

    assert not cache.scenarios_dir(tmp_path / "cache").exists()


def test_invalid_results_are_never_imported(tmp_path):
    run(tmp_path, FakeClient(provenance(), tamper={"model_revision": "7" * 40}), "--import")

    assert not cache.scenarios_dir(tmp_path / "cache").exists()


def test_the_token_is_required_and_comes_from_the_environment_or_login(tmp_path, monkeypatch):
    monkeypatch.setattr(check, "hf_token", lambda: None)

    with pytest.raises(_common.ScriptError, match="HF_TOKEN"):
        check.main(args(tmp_path), client_factory=lambda *a: None)


def test_describe_removes_tokens_even_when_unknown():
    error = RuntimeError("bad token hf_abcdefghijklmnop1234 given")

    assert "hf_abcdefghijklmnop1234" not in check.describe(error, None)
    assert TOKEN not in check.describe(RuntimeError(TOKEN), TOKEN)
