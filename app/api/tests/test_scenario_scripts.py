"""Scenario deployment and cache scripts, with Hugging Face mocked out.

Nothing here contacts the network: HfApi is a Mock, and the tests that need
huggingface_hub's own classes are skipped where it is not installed.
"""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from app.api import scenario_cache as cache
from app.api import scenario_contract as contract
from app.api.config import REPO_ROOT
from app.scripts import _common, deploy_model_space, export_records, import_scenarios, upload_adapter


BASE_SHA = "1" * 40
ADAPTER_SHA = "2" * 40
ADAPTER_REPO = "owner/scenario-adapter"
SPACE_ID = "owner/scenario-space"


@pytest.mark.parametrize("script", [
    "upload_adapter", "deploy_model_space", "export_records", "import_scenarios", "check_live_model"])
def test_help_runs(script):
    result = subprocess.run(
        [sys.executable, "-m", f"app.scripts.{script}", "--help"],
        cwd=REPO_ROOT, capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("usage: python -m app.scripts.")


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if a script asks for an HfApi."""

    def refuse():
        raise AssertionError("contacted Hugging Face")

    monkeypatch.setattr(upload_adapter, "hf_api", refuse)
    monkeypatch.setattr(deploy_model_space, "hf_api", refuse)


# -- upload_adapter ------------------------------------------------------------

@pytest.fixture
def adapter_dir(tmp_path):
    folder = tmp_path / "output"
    (folder / "checkpoint-10").mkdir(parents=True)
    (folder / "checkpoint-10" / "optimizer.pt").write_bytes(b"x")
    (folder / "adapter_config.json").write_text(json.dumps({
        "base_model_name_or_path": contract.BASE_MODEL_ID, "peft_type": "LORA", "r": 16,
        "lora_alpha": 32, "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"]
    }))
    for name in ("adapter_model.safetensors", "README.md", "tokenizer_config.json",
                 "chat_template.jinja", "generated_scenarios.txt", "training_args.bin"):
        (folder / name).write_bytes(b"data")

    return folder


def test_upload_allowlist(adapter_dir):
    names = [path.name for path in upload_adapter.collect_files(adapter_dir)]

    assert names == ["adapter_config.json", "adapter_model.safetensors", "README.md", "tokenizer_config.json"]


def test_upload_requires_weights(adapter_dir):
    (adapter_dir / "adapter_model.safetensors").unlink()

    with pytest.raises(_common.ScriptError, match="adapter_model.safetensors"):
        upload_adapter.collect_files(adapter_dir)


def test_upload_rejects_an_adapter_for_another_base(adapter_dir):
    (adapter_dir / "adapter_config.json").write_text(json.dumps(
        {"base_model_name_or_path": "meta-llama/Llama-3-8B", "peft_type": "LORA"}))

    with pytest.raises(_common.ScriptError, match="base model"):
        upload_adapter.check_adapter_config(adapter_dir)


def test_upload_dry_run_contacts_nothing(adapter_dir, no_network, capsys):
    assert upload_adapter.main(["--repo-id", ADAPTER_REPO, "--adapter-dir", str(adapter_dir), "--dry-run"]) == 0
    assert "chat_template" not in capsys.readouterr().out


def test_upload_commits_only_the_allowlist_to_a_private_repo(adapter_dir):
    pytest.importorskip("huggingface_hub")
    api = mock.Mock()
    api.model_info.return_value = SimpleNamespace(private=True)
    api.create_commit.return_value = SimpleNamespace(oid=ADAPTER_SHA)
    files = upload_adapter.collect_files(adapter_dir)

    sha = upload_adapter.upload(api, ADAPTER_REPO, files)

    assert sha == ADAPTER_SHA
    api.create_repo.assert_called_once_with(ADAPTER_REPO, repo_type="model", private=True, exist_ok=True)
    operations = api.create_commit.call_args.kwargs["operations"]
    assert [op.path_in_repo for op in operations] == [path.name for path in files]


def test_upload_refuses_a_public_repo(adapter_dir):
    pytest.importorskip("huggingface_hub")
    api = mock.Mock()
    api.model_info.return_value = SimpleNamespace(private=False)

    with pytest.raises(_common.ScriptError, match="public"):
        upload_adapter.upload(api, ADAPTER_REPO, upload_adapter.collect_files(adapter_dir))
    api.create_commit.assert_not_called()


# -- deploy_model_space --------------------------------------------------------

DEPLOY_ARGS = [
    "--space-id", SPACE_ID, "--adapter-repo", ADAPTER_REPO,
    "--base-revision", BASE_SHA, "--adapter-revision", ADAPTER_SHA
]


def test_deploy_dry_run_contacts_nothing(no_network, capsys):
    assert deploy_model_space.main(DEPLOY_ARGS + ["--dry-run"]) == 0

    out = capsys.readouterr().out
    assert "scenario_contract.py" in out
    assert f"variable ADAPTER_REVISION={ADAPTER_SHA}" in out


@pytest.mark.parametrize("args", [
    ["--base-revision", "main"],
    ["--adapter-revision", ADAPTER_SHA[:12]],
    ["--adapter-repo", "noowner"],
    ["--space-id", "noowner"]
])
def test_deploy_rejects_unpinned_or_malformed_input_before_contacting(args, no_network):
    with pytest.raises(_common.ScriptError):
        deploy_model_space.main(DEPLOY_ARGS + args)


def _space_api(space_private=True, adapter_private=True):
    api = mock.Mock()
    api.whoami.return_value = {"name": "owner"}

    def model_info(repo_id, revision):
        return SimpleNamespace(sha=revision, private=adapter_private if repo_id == ADAPTER_REPO else False)

    uploaded = {}

    def upload_folder(**kwargs):
        uploaded["files"] = sorted(path.name for path in Path(kwargs["folder_path"]).iterdir())
        uploaded["kwargs"] = kwargs

        return SimpleNamespace(oid="c" * 40)

    api.model_info.side_effect = model_info
    api.space_info.return_value = SimpleNamespace(private=space_private)
    api.upload_folder.side_effect = upload_folder
    api.get_space_runtime.return_value = SimpleNamespace(
        stage="BUILDING", hardware=None, requested_hardware="zero-a10g")

    return api, uploaded


def test_deploy_sets_variables_then_uploads_space_and_contract(monkeypatch, capsys):
    pytest.importorskip("huggingface_hub")
    api, uploaded = _space_api()
    monkeypatch.setattr(deploy_model_space, "hf_api", lambda: api)

    assert deploy_model_space.main(DEPLOY_ARGS) == 0

    api.create_repo.assert_called_once_with(
        SPACE_ID, repo_type="space", space_sdk="gradio", private=True, exist_ok=True)
    assert [c.args for c in api.add_space_variable.call_args_list] == [
        (SPACE_ID, "BASE_REVISION", BASE_SHA),
        (SPACE_ID, "ADAPTER_REPO", ADAPTER_REPO),
        (SPACE_ID, "ADAPTER_REVISION", ADAPTER_SHA),
        (SPACE_ID, "LOADING_RECIPE", contract.NF4_UNMERGED)
    ]
    calls = [c[0] for c in api.mock_calls]
    assert calls.index("add_space_variable") < calls.index("upload_folder")
    assert uploaded["files"] == ["README.md", "app.py", "model_runtime.py", "requirements.txt", "scenario_contract.py"]
    assert uploaded["kwargs"]["repo_type"] == "space"
    assert "secret" not in " ".join(calls)
    out = capsys.readouterr().out
    assert "HF_TOKEN secret" in out
    assert "stage=BUILDING" in out


def test_deploy_refuses_a_public_space(monkeypatch):
    pytest.importorskip("huggingface_hub")
    api, _ = _space_api(space_private=False)
    monkeypatch.setattr(deploy_model_space, "hf_api", lambda: api)

    with pytest.raises(_common.ScriptError, match="public"):
        deploy_model_space.main(DEPLOY_ARGS)
    api.add_space_variable.assert_not_called()
    api.upload_folder.assert_not_called()


def test_deploy_refuses_a_public_adapter(monkeypatch):
    pytest.importorskip("huggingface_hub")
    api, _ = _space_api(adapter_private=False)
    monkeypatch.setattr(deploy_model_space, "hf_api", lambda: api)

    with pytest.raises(_common.ScriptError, match="public"):
        deploy_model_space.main(DEPLOY_ARGS)
    api.create_repo.assert_not_called()


# -- export_records -> Kaggle line -> import_scenarios -------------------------

def _fake_kaggle_results(bundle, out_path, text="[NATURAL LANGUAGE]\nStory\n[ATTACK GRAPH]\n1. A -> B"):
    """What the notebook writes, with a made-up response in place of the model."""

    provenance = bundle["provenance"]
    with out_path.open("w", encoding="utf-8") as out:
        for item in bundle["items"]:
            response = contract.build_response(
                text=text, new_tokens=321, hit_eos=True, seconds=40.0, provenance=provenance)
            entry = contract.make_cache_entry(
                prompt=item["prompt"], provenance=provenance, response=response, source="pregenerated",
                prompt_version=bundle["prompt_version"])
            line = contract.make_result_line(
                analysis_id=bundle["analysis_id"], source_id=item["source_id"], record=item["record"], entry=entry)
            out.write(contract.canonical_json(line) + "\n")


PIN_ARGS = ["--base-revision", BASE_SHA, "--adapter-repo", ADAPTER_REPO, "--adapter-revision", ADAPTER_SHA]


@pytest.fixture(scope="module")
def exported(sample_analysis, module_cache, tmp_path_factory):
    out = tmp_path_factory.mktemp("bundle") / "bundle"
    assert export_records.main([
        "--analysis-id", sample_analysis["id"], "--out", str(out), "--cache-dir", str(module_cache)
    ] + PIN_ARGS) == 0

    return out, json.loads((out / "bundle.json").read_text())


def test_export_writes_selected_records_prompts_and_code(exported, sample_analysis):
    out, bundle = exported
    selected = {p["source_id"]: p["export"] for p in sample_analysis["paths"] if p["exported"]}

    assert [item["source_id"] for item in bundle["items"]] == list(selected)
    for item in bundle["items"]:
        assert item["record"] == selected[item["source_id"]]
        assert item["prompt"] == contract.build_prompt(item["record"])
        assert item["cache_key"] == contract.cache_key(item["prompt"], bundle["provenance"], "P1.v1")
    assert (bundle["prompt_format"], bundle["prompt_version"]) == ("structured-p1", "P1.v1")
    assert bundle["analysis_id"] == sample_analysis["id"]
    assert bundle["analysis"]["input_sha256"] == sample_analysis["input_sha256"]
    assert bundle["files"] == {
        name: _common.sha256_file(out / name)
        for name in ("model_runtime.py", "requirements.txt", "scenario_contract.py")
    }
    assert (out / "scenario_contract.py").read_bytes() == _common.CONTRACT_FILE.read_bytes()


def test_export_and_import_in_the_training_format(sample_analysis, module_cache, tmp_path):
    out = tmp_path / "training-bundle"
    assert export_records.main([
        "--analysis-id", sample_analysis["id"], "--out", str(out), "--cache-dir", str(module_cache),
        "--prompt-format", "training"
    ] + PIN_ARGS) == 0
    bundle = json.loads((out / "bundle.json").read_text())

    assert (bundle["prompt_format"], bundle["prompt_version"]) == ("training", "training.v1")
    for item in bundle["items"]:
        assert item["prompt"] == contract.build_prompt(item["record"], "training")
        assert item["cache_key"] == contract.cache_key(item["prompt"], bundle["provenance"], "training.v1")

    results = tmp_path / "training.jsonl"
    _fake_kaggle_results(bundle, results)
    other_cache = tmp_path / "cache"

    assert import_scenarios.import_file(results, other_cache) == {"created": len(bundle["items"])}
    stored = cache.read_entry(other_cache, bundle["items"][0]["cache_key"])
    assert stored["request"]["prompt_version"] == "training.v1"


def test_import_rejects_a_prompt_that_does_not_match_its_version(exported, module_cache, tmp_path):
    _, bundle = exported
    item = bundle["items"][0]
    provenance = bundle["provenance"]
    response = contract.build_response(
        text="[NATURAL LANGUAGE]\nStory", new_tokens=5, hit_eos=True, seconds=1.0, provenance=provenance)
    lines = []
    for version, prompt in (
        ("training.v1", item["prompt"]),  # structured prompt claiming the training version
        ("P1.v0", item["prompt"]),        # a version that does not exist
    ):
        entry = contract.make_cache_entry(
            prompt=prompt, provenance=provenance, response=response, source="pregenerated",
            prompt_version=version)
        lines.append(contract.canonical_json(contract.make_result_line(
            analysis_id=bundle["analysis_id"], source_id=item["source_id"], record=item["record"], entry=entry)))
    bad = tmp_path / "bad.jsonl"
    bad.write_text("\n".join(lines) + "\n")

    assert import_scenarios.import_file(bad, module_cache, dry_run=True) == {"rejected": 2}


def test_export_rejects_unselected_paths(sample_analysis, module_cache, tmp_path):
    with pytest.raises(_common.ScriptError, match="not selected"):
        export_records.main([
            "--analysis-id", sample_analysis["id"], "--out", str(tmp_path / "b"),
            "--cache-dir", str(module_cache), "--paths", "AP-999"
        ])


def test_import_merges_links_and_never_overwrites(exported, sample_analysis, module_cache, tmp_path):
    _, bundle = exported
    results = tmp_path / "scenarios.jsonl"
    _fake_kaggle_results(bundle, results)
    analysis_id = sample_analysis["id"]

    first = import_scenarios.import_file(results, module_cache)
    assert first == {"created": len(bundle["items"])}
    links = cache.read_links(module_cache, analysis_id)
    assert links == {item["source_id"]: item["cache_key"] for item in bundle["items"]}

    key = bundle["items"][0]["cache_key"]
    stored = cache.read_entry(module_cache, key)
    assert stored["source"] == "pregenerated"
    assert contract.scenario_payload(stored)["sections"]["missing"] == ["mathematical"]

    # The same file again changes nothing; a different sample for the same keys
    # is not allowed to replace what is stored.
    assert import_scenarios.import_file(results, module_cache) == {"unchanged": len(bundle["items"])}
    different = tmp_path / "different.jsonl"
    _fake_kaggle_results(bundle, different, text="[NATURAL LANGUAGE]\nAnother sample")
    assert import_scenarios.import_file(different, module_cache) == {"kept_existing": len(bundle["items"])}
    assert cache.read_entry(module_cache, key) == stored


def test_import_rejects_bad_lines(exported, module_cache, tmp_path, capsys):
    _, bundle = exported
    good = tmp_path / "good.jsonl"
    _fake_kaggle_results(bundle, good)
    line = json.loads(good.read_text().splitlines()[0])

    def variant(change):
        copy = json.loads(json.dumps(line))
        change(copy)

        return json.dumps(copy)

    bad_lines = [
        "not json",
        variant(lambda line: line["entry"]["response"].update(adapter_revision="9" * 40)),
        variant(lambda line: line["entry"].update(cache_key="0" * 64)),
        variant(lambda line: line["entry"].update(source="live")),
        variant(lambda line: line["record"].update(industry="Changed")),
        variant(lambda line: line.update(source_id="AP-999"))
    ]
    bad = tmp_path / "bad.jsonl"
    bad.write_text("\n".join(bad_lines) + "\n")

    assert import_scenarios.import_file(bad, module_cache, dry_run=True) == {"rejected": len(bad_lines)}
    assert import_scenarios.main([str(bad), "--cache-dir", str(module_cache)]) == 1
    assert "provenance mismatch" in capsys.readouterr().out


def test_import_without_the_saved_analysis_stores_but_does_not_link(exported, tmp_path):
    _, bundle = exported
    results = tmp_path / "scenarios.jsonl"
    _fake_kaggle_results(bundle, results)
    empty_cache = tmp_path / "other-cache"

    counts = import_scenarios.import_file(results, empty_cache)

    assert counts == {"created": len(bundle["items"])}
    assert cache.read_links(empty_cache, bundle["analysis_id"]) == {}


# -- scenario_cache ------------------------------------------------------------

def test_corrupt_entry_is_an_explicit_error_and_can_be_replaced(tmp_path):
    prov = contract.make_provenance(model_revision=BASE_SHA, adapter_repo=ADAPTER_REPO, adapter_revision=ADAPTER_SHA)
    response = contract.build_response(text="x", new_tokens=1, hit_eos=True, seconds=1.0, provenance=prov)
    entry = contract.make_cache_entry(prompt="<s>p", provenance=prov, response=response, source="live")
    path = cache.entry_path(tmp_path, entry["cache_key"])
    path.parent.mkdir(parents=True)
    path.write_text("{truncated")

    with pytest.raises(cache.CacheError):
        cache.read_entry(tmp_path, entry["cache_key"])
    assert cache.merge_entry(tmp_path, entry) == "replaced_invalid"
    assert cache.read_entry(tmp_path, entry["cache_key"]) == entry
    assert not [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]


def test_link_keeps_an_existing_link_unless_replaced(tmp_path):
    analysis_id = "0f8fad5b-d9cb-469f-a165-70867728950e"

    assert cache.link(tmp_path, analysis_id, "AP-001", "a" * 64) == "linked"
    assert cache.link(tmp_path, analysis_id, "AP-001", "b" * 64) == "kept_existing"
    assert cache.link(tmp_path, analysis_id, "AP-001", "b" * 64, replace=True) == "linked"
    assert cache.read_links(tmp_path, analysis_id) == {"AP-001": "b" * 64}
    with pytest.raises(ValueError):
        cache.links_path(tmp_path, "../escape")
