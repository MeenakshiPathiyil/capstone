"""The bounded worker: a stalled child is really stopped, and the slot is freed."""

import os
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.api.tests import stalled_job
from app.api.tests.conftest import INDUSTRY, make_settings
from app.api.worker import run_job


SAMPLE = {"sample_id": "cloudformation5", "industry": INDUSTRY}


def is_running(pid):
    """True while a process with this pid exists (zombies included)."""

    try:
        os.kill(pid, 0)

    except ProcessLookupError:
        return False

    return True


def wait_until(condition, timeout=20.0):

    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)

    return False


@pytest.fixture
def stalling_app(tmp_path):
    return create_app(make_settings(tmp_path / "cache", analysis_timeout_s=1.0))


def test_a_stalled_child_is_stopped_and_the_next_request_succeeds(stalling_app):

    worker = stalling_app.state.worker

    with TestClient(stalling_app) as client:

        worker.target = stalled_job.stall

        started = time.monotonic()
        response = client.post("/api/analyses/sample", json=SAMPLE)
        elapsed = time.monotonic() - started

        assert response.status_code == 504
        assert "longer than 1 seconds" in response.json()["detail"]

        # stopped at the deadline, well inside the terminate grace period
        assert elapsed < 4.0

        # the child is gone, reaped rather than left a zombie, and the slot free
        assert not is_running(worker.last_pid)
        assert not worker.busy
        assert worker._active == set()

        # nothing was saved
        assert not stalling_app.state.settings.analyses_dir.exists() or not list(
            stalling_app.state.settings.analyses_dir.iterdir()
        )

        worker.target = run_job

        assert client.post("/api/analyses/sample", json=SAMPLE).status_code == 201


def test_a_busy_slot_is_503_and_reads_stay_responsive(tmp_path):

    app = create_app(make_settings(tmp_path / "cache", analysis_timeout_s=3.0))
    worker = app.state.worker

    with TestClient(app) as client:

        saved = client.post("/api/analyses/sample", json=SAMPLE).json()

        worker.target = stalled_job.stall

        outcome = {}

        def stalled_request():
            outcome["response"] = client.post("/api/analyses/sample", json=SAMPLE)

        thread = threading.Thread(target=stalled_request)
        thread.start()

        assert wait_until(lambda: worker.busy)

        busy = client.post("/api/analyses/sample", json=SAMPLE)

        assert busy.status_code == 503
        assert busy.headers["retry-after"] == "2"

        # health and saved reads do not wait for the slot
        started = time.monotonic()

        assert client.get("/api/health").json()["ok"] is True
        assert client.get("/api/analyses/%s" % saved["id"]).status_code == 200

        assert time.monotonic() - started < 1.0
        assert worker.busy

        thread.join(timeout=20)

        assert outcome["response"].status_code == 504
        assert not worker.busy

        worker.target = run_job

        assert client.post("/api/analyses/sample", json=SAMPLE).status_code == 201


def test_a_child_that_dies_without_a_reply_is_500(tmp_path):

    app = create_app(make_settings(tmp_path / "cache"))

    with TestClient(app) as client:

        app.state.worker.target = stalled_job.crash

        response = client.post("/api/analyses/sample", json=SAMPLE)

        assert response.status_code == 500
        assert "exited without a result" in response.json()["detail"]
        assert not app.state.worker.busy


def test_shutdown_stops_a_running_child(tmp_path):

    app = create_app(make_settings(tmp_path / "cache", analysis_timeout_s=30.0))
    worker = app.state.worker

    with TestClient(app) as client:

        worker.target = stalled_job.stall

        outcome = {}

        thread = threading.Thread(
            target=lambda: outcome.update(
                response=client.post("/api/analyses/sample", json=SAMPLE)
            )
        )
        thread.start()

        assert wait_until(lambda: worker.busy and worker.last_pid is not None)
        assert wait_until(lambda: is_running(worker.last_pid))

        pid = worker.last_pid

        started = time.monotonic()
        worker.shutdown()

        thread.join(timeout=20)

        assert time.monotonic() - started < 5.0
        assert not is_running(pid)
        assert outcome["response"].status_code == 500
