"""The committed OpenAPI snapshot is exactly what the app factory generates."""

import os
import subprocess
import sys

from app.api import schemas
from app.api.config import REPO_ROOT
from app.scripts.export_openapi import openapi_document


SNAPSHOT = REPO_ROOT / "app" / "api" / "tests" / "fixtures" / "openapi.json"

REGENERATE = (
    "python -m app.scripts.export_openapi --output app/api/tests/fixtures/openapi.json"
)


def test_the_snapshot_matches_the_app():

    assert SNAPSHOT.read_text(encoding="utf-8") == openapi_document(), (
        "The API contract changed. Regenerate the snapshot with: " + REGENERATE
    )


def test_the_export_command_runs_without_a_server_or_credentials(tmp_path):

    output = tmp_path / "openapi.json"

    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in ("HF_TOKEN", "SPACE_ID")
    }

    completed = subprocess.run(
        [sys.executable, "-m", "app.scripts.export_openapi", "--output", str(output)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60
    )

    assert completed.returncode == 0, completed.stderr
    assert output.read_text(encoding="utf-8") == SNAPSHOT.read_text(encoding="utf-8")


def test_every_model_is_in_the_contract():
    """Including the scenario models."""

    import json

    components = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["components"]["schemas"]

    for model in [
        schemas.Analysis, schemas.GraphView, schemas.FixImpactResult,
        schemas.FixImpact, schemas.Health, schemas.Meta, schemas.ScenarioState,
        schemas.Scenario, schemas.ScenarioSections, schemas.ErrorResponse
    ]:
        assert model.__name__ in components

    # FastAPI's list-of-errors shape is replaced by {"detail": str} everywhere
    assert "HTTPValidationError" not in components

    assert "analyser_fingerprint" not in json.dumps(components)
    assert "retry_allowed" not in json.dumps(components)
