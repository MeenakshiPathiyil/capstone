"""Shared fixtures: an app over a temporary cache, and saved sample analyses."""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.config import REPO_ROOT, Settings
from app.api.main import create_app


SAMPLE_PATH = REPO_ROOT / "sample_yamls" / "cloudformation5.yml"

INDUSTRY = "Information technology service activities (ISIC J62)"


# Settings read from the environment that would let a test reach Hugging Face.
LIVE_ENV = (
    "HF_TOKEN",
    "SPACE_ID",
    "BASE_MODEL_ID",
    "BASE_REVISION",
    "ADAPTER_REPO",
    "ADAPTER_REVISION",
    "LOADING_RECIPE"
)

# A developer's real model configuration never reaches a test, including the
# module-scoped apps built before any function-scoped fixture runs.
for name in LIVE_ENV:
    os.environ.pop(name, None)


def make_settings(cache_dir, **overrides):
    """Settings over `cache_dir`, never the real app/.cache or app/api/.env."""

    return Settings(_env_file=None, cache_dir=Path(cache_dir), **overrides)


def upload(client, name, data, industry=INDUSTRY, **fields):
    """POST one file to /api/analyses."""

    return client.post(
        "/api/analyses",
        files={"file": (name, data, "application/octet-stream")},
        data=dict({"industry": industry}, **fields)
    )


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path / "cache")


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def module_cache(tmp_path_factory):
    return tmp_path_factory.mktemp("cache")


@pytest.fixture(scope="module")
def shared_client(module_cache):
    """One app for the read-only tests of a module, so the sample runs once."""

    with TestClient(create_app(make_settings(module_cache))) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def sample_analysis(shared_client):
    """sample_yamls/cloudformation5.yml, uploaded with the default options."""

    response = upload(shared_client, SAMPLE_PATH.name, SAMPLE_PATH.read_bytes())

    assert response.status_code == 201, response.text

    return response.json()
