"""Saved analyses: durable, independent, re-run only when their schema is stale."""

import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api import analysis as analysis_module
from app.api.main import create_app
from app.api.tests.conftest import SAMPLE_PATH, make_settings, upload


def fresh_client(cache_dir):
    return TestClient(create_app(make_settings(cache_dir)))


def test_a_new_app_serves_a_saved_analysis_from_disk(tmp_path):

    cache = tmp_path / "cache"

    with fresh_client(cache) as first:
        saved = upload(first, "cloudformation5.yml", SAMPLE_PATH.read_bytes()).json()
        state = first.get("/api/analyses/%s/graph?view=state" % saved["id"]).json()

    app = create_app(make_settings(cache))

    with TestClient(app) as second:

        response = second.get("/api/analyses/%s" % saved["id"])

        assert response.status_code == 200
        assert response.json() == saved

        assert second.get(
            "/api/analyses/%s/graph?view=state" % saved["id"]
        ).json() == state

    # served without running the analyser again
    assert app.state.worker.last_pid is None


def test_same_bytes_with_other_options_do_not_overwrite(tmp_path):

    cache = tmp_path / "cache"
    data = SAMPLE_PATH.read_bytes()

    with fresh_client(cache) as client:
        first = upload(client, "a.yml", data).json()
        second = upload(client, "b.yml", data, industry="Education (ISIC P)").json()
        third = upload(client, "a.yml", data, min_level="CRITICAL").json()

    assert len({first["id"], second["id"], third["id"]}) == 3
    assert first["input_sha256"] == second["input_sha256"] == third["input_sha256"]

    with fresh_client(cache) as client:

        for saved in (first, second, third):
            assert client.get("/api/analyses/%s" % saved["id"]).json() == saved

    assert third["summary"]["paths_exported"] == 14


def test_the_store_layout(tmp_path):

    cache = tmp_path / "cache"

    with fresh_client(cache) as client:
        saved = upload(client, "cloudformation5.yml", SAMPLE_PATH.read_bytes()).json()

    directory = cache / "analyses" / saved["id"]

    assert sorted(path.name for path in directory.iterdir()) == [
        "analysis.json",
        "graph_attack.json",
        "graph_state.json",
        "input.yml",
        "manifest.json",
        "normalized_resources.json"
    ]

    assert (directory / "input.yml").read_bytes() == SAMPLE_PATH.read_bytes()

    manifest = json.loads((directory / "manifest.json").read_text())

    assert manifest["input_name"] == "cloudformation5.yml"
    assert manifest["source"] == {"kind": "upload"}
    assert "analyser_fingerprint" not in manifest

    # no staging directory is left behind
    assert [path.name for path in (cache / "analyses").iterdir()] == [saved["id"]]


@pytest.mark.parametrize("bad_id", [
    "not-a-uuid",
    "..",
    "%2e%2e%2fmanifest.json",
    str(uuid.uuid4()).upper(),
    str(uuid.uuid4())
])
def test_malformed_and_unknown_ids_are_404(client, bad_id):

    for suffix in ("", "/graph", "/fixes"):
        response = client.get("/api/analyses/%s%s" % (bad_id, suffix))
        assert response.status_code == 404, (bad_id, suffix)


def test_a_stale_schema_version_is_rerun_from_the_stored_input(tmp_path):

    cache = tmp_path / "cache"

    with fresh_client(cache) as client:
        saved = upload(client, "cloudformation5.yml", SAMPLE_PATH.read_bytes()).json()

    path = cache / "analyses" / saved["id"] / "analysis.json"

    stale = dict(saved, schema_version=0, summary={"old": True})
    path.write_text(json.dumps(stale))

    app = create_app(make_settings(cache))

    with TestClient(app) as client:
        reread = client.get("/api/analyses/%s" % saved["id"]).json()

    assert reread == saved
    assert app.state.worker.last_pid is not None
    assert json.loads(path.read_text())["schema_version"] == 1


def test_an_analysis_saved_before_contextual_risk_is_served_without_it(tmp_path):
    """Saved before paths had `risk`: same schema version, so served as saved,
    with risk null, and not re-run."""

    cache = tmp_path / "cache"

    with fresh_client(cache) as client:
        saved = upload(client, "cloudformation5.yml", SAMPLE_PATH.read_bytes()).json()

    path = cache / "analyses" / saved["id"] / "analysis.json"

    old = json.loads(path.read_text())

    for item in old["paths"]:
        del item["risk"]

    path.write_text(json.dumps(old))

    app = create_app(make_settings(cache))

    with TestClient(app) as client:
        response = client.get("/api/analyses/%s" % saved["id"])

    assert response.status_code == 200
    assert [item["risk"] for item in response.json()["paths"]] == [None] * 22
    assert response.json() == dict(
        saved, paths=[dict(item, risk=None) for item in saved["paths"]]
    )
    assert app.state.worker.last_pid is None


def test_a_corrupt_analysis_file_is_rerun(tmp_path):

    cache = tmp_path / "cache"

    with fresh_client(cache) as client:
        saved = upload(client, "cloudformation5.yml", SAMPLE_PATH.read_bytes()).json()

    (cache / "analyses" / saved["id"] / "analysis.json").write_text("{not json")
    (cache / "analyses" / saved["id"] / "graph_attack.json").write_text("[]")

    with fresh_client(cache) as client:
        assert client.get("/api/analyses/%s" % saved["id"]).json() == saved
        graph = client.get("/api/analyses/%s/graph?view=attack" % saved["id"]).json()

    assert len(graph["edges"]) == 19


def test_an_unreadable_manifest_is_409(tmp_path):

    cache = tmp_path / "cache"

    with fresh_client(cache) as client:
        saved = upload(client, "cloudformation5.yml", SAMPLE_PATH.read_bytes()).json()

    (cache / "analyses" / saved["id"] / "manifest.json").write_text("{")

    with fresh_client(cache) as client:
        response = client.get("/api/analyses/%s" % saved["id"])

    assert response.status_code == 409


def test_a_failed_publication_leaves_nothing_visible(client, settings, monkeypatch):

    def failing_rename(source, destination):
        raise OSError("disk full")

    monkeypatch.setattr(analysis_module.os, "rename", failing_rename)

    with pytest.raises(OSError):
        upload(client, "cloudformation5.yml", SAMPLE_PATH.read_bytes())

    monkeypatch.setattr(analysis_module.os, "rename", os.rename)

    assert list(settings.analyses_dir.iterdir()) == []
