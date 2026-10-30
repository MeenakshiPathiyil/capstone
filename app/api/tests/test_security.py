"""What a hostile web page or a hostile upload can and cannot do to the API.

Host and Origin checks, response headers, the worker's environment, and the
mode of the directories the app creates.
"""

import json
import os
import stat

import pytest
from fastapi.testclient import TestClient

from app.api import scenario_cache
from app.api.config import WEB_DIST_DIR, make_private_dir
from app.api.main import CONTENT_SECURITY_POLICY, create_app
from app.api.tests.conftest import INDUSTRY, SAMPLE_PATH, make_settings, upload
from app.api.worker import run_job, scrub_environment


# A POST the app answers without running an analysis: an unknown sample is 404
# once the request is past the Host and Origin checks, 403 or 400 before them.
PROBE = {"sample_id": "nope", "industry": INDUSTRY}


def post_probe(client, **headers):
    return client.post("/api/analyses/sample", json=PROBE, headers=headers)


# -- Host ------------------------------------------------------------------------

@pytest.mark.parametrize(
    "host", ["127.0.0.1", "127.0.0.1:8000", "localhost", "localhost:5173", "testserver"]
)
def test_the_local_host_names_are_served(client, host):

    assert client.get("/api/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example"])
def test_any_other_host_is_refused(client, host):
    """A DNS rebinding page reaches this server under its own name."""

    response = client.get("/api/health", headers={"Host": host})

    assert response.status_code == 400


def test_the_allowed_hosts_are_a_setting(tmp_path):

    settings = make_settings(tmp_path / "cache", allowed_hosts=["analyser.example"])

    with TestClient(create_app(settings), base_url="http://analyser.example") as client:

        assert client.get("/api/health").status_code == 200
        assert client.get("/api/health", headers={"Host": "localhost"}).status_code == 400


# -- Origin ----------------------------------------------------------------------

def test_a_post_from_another_origin_is_403_and_does_nothing(client, settings):

    response = upload(client, "a.yml", SAMPLE_PATH.read_bytes())

    assert response.status_code == 201

    saved = len(list(settings.analyses_dir.iterdir()))

    evil = client.post(
        "/api/analyses",
        files={"file": ("a.yml", SAMPLE_PATH.read_bytes(), "application/octet-stream")},
        data={"industry": INDUSTRY},
        headers={"Origin": "http://evil.example"}
    )

    assert evil.status_code == 403
    assert evil.headers["content-type"] == "application/json"
    assert "origin" in evil.json()["detail"]
    assert len(list(settings.analyses_dir.iterdir())) == saved

    # the fix-impact POST, and the scenario POST, are guarded the same way
    assert client.post(
        "/api/analyses/%s/fixes" % response.json()["id"],
        headers={"Origin": "http://evil.example"}
    ).status_code == 403


@pytest.mark.parametrize("origin", [
    "http://evil.example",
    "null",
    "https://localhost:5173",
    "http://localhost:5174",
    "http://testserver:9999",
    "http://127.0.0.1:5173.evil.example"
])
def test_a_post_from_an_origin_that_is_not_allowed_is_403(client, origin):

    assert post_probe(client, Origin=origin).status_code == 403


@pytest.mark.parametrize("origin", [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    # the app's own origin: the production build served by this app
    "http://testserver"
])
def test_a_post_from_an_allowed_origin_gets_through(client, origin):

    assert post_probe(client, Origin=origin).status_code == 404


def test_the_vite_proxy_forwards_the_browsers_host_and_origin(client):
    """vite.config.ts proxies /api with the string form, which leaves
    changeOrigin off: Host stays localhost:5173 (the browser's own) and Origin
    is the page's, so both pass."""

    assert post_probe(
        client, Host="localhost:5173", Origin="http://localhost:5173"
    ).status_code == 404

    assert post_probe(
        client, Host="127.0.0.1:5173", Origin="http://127.0.0.1:5173"
    ).status_code == 404

    # if it did rewrite Host to the API's address, the Origin is still allowed
    assert post_probe(
        client, Host="127.0.0.1:8000", Origin="http://localhost:5173"
    ).status_code == 404


def test_the_production_build_posts_to_its_own_origin(client):

    assert post_probe(
        client, Host="127.0.0.1:8000", Origin="http://127.0.0.1:8000"
    ).status_code == 404


def test_requests_without_an_origin_and_reads_from_anywhere_are_allowed(client):

    assert post_probe(client).status_code == 404
    assert client.get("/api/health", headers={"Origin": "http://evil.example"}).status_code == 200


def test_the_cors_origins_are_a_setting(tmp_path):

    settings = make_settings(tmp_path / "cache", cors_origins=["https://app.example"])

    with TestClient(create_app(settings)) as client:

        assert post_probe(client, Origin="https://app.example").status_code == 404
        assert post_probe(client, Origin="http://localhost:5173").status_code == 403


# -- Response headers ------------------------------------------------------------

def expect_headers(response, csp=True):

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"

    if csp:
        assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


@pytest.mark.parametrize("path", ["/api/health", "/api/meta", "/api/nothing"])
def test_every_response_carries_the_security_headers(client, path):

    expect_headers(client.get(path))


def test_refusals_carry_them_too(client):

    expect_headers(post_probe(client, Origin="http://evil.example"))
    expect_headers(client.get("/api/health", headers={"Host": "evil.example"}))
    expect_headers(client.get("/api/analyses/not-a-uuid"))


def test_the_policy_allows_what_the_built_app_needs_and_nothing_else():

    directives = dict(
        item.split(" ", 1) for item in CONTENT_SECURITY_POLICY.split("; ")
    )

    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self'"
    # React Flow positions nodes with style attributes
    assert "'unsafe-inline'" in directives["style-src"]
    assert "'unsafe-inline'" not in directives["script-src"]
    assert "'unsafe-eval'" not in CONTENT_SECURITY_POLICY
    assert directives["img-src"] == "'self' data: blob:"
    assert directives["font-src"] == "'self' data:"
    assert directives["connect-src"] == "'self'"
    assert directives["object-src"] == "'none'"
    assert directives["frame-ancestors"] == "'none'"


def test_the_api_docs_keep_working_without_the_policy(client):
    """Swagger UI loads its script from a CDN, which the policy would block."""

    docs = client.get("/docs")

    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers
    expect_headers(docs, csp=False)


@pytest.mark.skipif(not (WEB_DIST_DIR / "index.html").is_file(), reason="web app not built")
def test_the_web_app_is_served_with_the_policy(client):

    page = client.get("/")

    assert page.status_code == 200
    expect_headers(page)


# -- The worker's environment ----------------------------------------------------

def test_the_scrub_removes_hugging_face_settings_and_nothing_else(monkeypatch):

    secret = {
        "HF_TOKEN": "hf_secret",
        "HF_HOME": "/somewhere",
        "HF_ENDPOINT": "https://example.invalid",
        "HUGGING_FACE_HUB_TOKEN": "hf_other",
        "SPACE_ID": "owner/space",
        "BASE_REVISION": "a" * 40,
        "ADAPTER_REPO": "owner/adapter",
        "ADAPTER_REVISION": "b" * 40,
        "LOADING_RECIPE": "nf4",
        "BASE_MODEL_ID": "m"
    }

    kept = {"CAPSTONE_CACHE_DIR": "/cache", "SOMETHING_ELSE": "1", "SHF_X": "1"}

    for name, value in {**secret, **kept}.items():
        monkeypatch.setenv(name, value)

    scrub_environment()

    assert not set(secret) & set(os.environ)
    assert all(os.environ[name] == value for name, value in kept.items())
    assert "PATH" in os.environ


def test_a_job_scrubs_before_it_reads_the_upload(monkeypatch):

    monkeypatch.setenv("HF_TOKEN", "hf_secret")
    monkeypatch.setenv("SPACE_ID", "owner/space")

    sent = []

    class Connection:
        def send_bytes(self, data):
            sent.append(json.loads(data))

        def close(self):
            pass

    run_job(
        Connection(),
        "analysis",
        json.dumps({
            "source": {"kind": "sample", "sample_id": "nope"},
            "industry": INDUSTRY,
            "min_level": "HIGH",
            "max_resources": 500
        })
    )

    assert sent and sent[0]["status"] == 404
    assert "HF_TOKEN" not in os.environ and "SPACE_ID" not in os.environ


def test_the_scenario_settings_still_reach_the_api_process(monkeypatch, tmp_path):
    """Only the child is scrubbed: the parent's Settings read them as before."""

    monkeypatch.setenv("HF_TOKEN", "hf_secret")
    monkeypatch.setenv("SPACE_ID", "owner/space")

    from app.api.config import Settings

    settings = Settings(_env_file=None, cache_dir=tmp_path)

    assert settings.space_id == "owner/space"
    assert settings.hf_token.get_secret_value() == "hf_secret"


# -- Directory modes -------------------------------------------------------------

def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_the_directories_the_app_creates_are_private(tmp_path):

    previous = os.umask(0o022)

    try:
        settings = make_settings(tmp_path / "fresh" / "cache")

        with TestClient(create_app(settings)) as client:

            created = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

        scenario_cache.write_json_atomic(
            scenario_cache.links_path(settings.cache_dir, created["id"]), {"x": 1}
        )

    finally:
        os.umask(previous)

    assert mode(settings.cache_dir) == 0o700
    assert mode(settings.analyses_dir) == 0o700
    assert mode(settings.analyses_dir / created["id"]) == 0o700
    assert mode(settings.cache_dir / "scenarios") == 0o700
    assert mode(settings.cache_dir / "scenarios" / "links") == 0o700


def test_make_private_dir_leaves_an_existing_directory_alone(tmp_path):

    existing = tmp_path / "shared"
    existing.mkdir(mode=0o755)
    os.chmod(existing, 0o755)

    make_private_dir(existing / "inner" / "deeper")

    assert mode(existing) == 0o755
    assert mode(existing / "inner") == 0o700
    assert mode(existing / "inner" / "deeper") == 0o700
