"""The scenario service and routes, over a fake model Space and a fake HfApi.

Nothing here touches the network: the real SpaceClient runs against FakeHfApi
(runtime stage, restart, quota) and FakeGradio (the /generate job).
"""

import json
import logging
import shutil
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.api import scenario_cache as cache
from app.api import scenario_contract as contract
from app.api.config import REPO_ROOT
from app.api.main import create_app
from app.api.report import pdf
from app.api.report.router import cached_scenarios, selected_records
from app.api.scenarios import quota_message
from app.api.space_client import Quota, SpaceClient, create_space_client
from app.api.tests.conftest import SAMPLE_PATH, make_settings, upload


TOKEN = "hf_test_secret_value_never_shown"
SPACE_ID = "owner/scenario-space"
ADAPTER_REPO = "owner/scenario-adapter"
BASE_SHA = "a" * 40
ADAPTER_SHA = "b" * 40

PROVENANCE = contract.make_provenance(
    model_revision=BASE_SHA,
    adapter_repo=ADAPTER_REPO,
    adapter_revision=ADAPTER_SHA
)

TEXT = (
    "[NATURAL LANGUAGE]\nThe attacker reaches the bucket.\n"
    "[MATHEMATICAL EXPRESSION]\nP = a * b\n"
    "[ATTACK GRAPH]\n1. Scan\n2. Exploit"
)


# ==============================================================================
# Fakes
# ==============================================================================

class HTTPError(Exception):
    """Shaped like huggingface_hub's HfHubHTTPError: carries a response."""

    def __init__(self, status, message="error"):
        super().__init__(message)
        self.response = SimpleNamespace(status_code=status)


class FakeHfApi:
    """get_space_runtime returns stages in order; the last one repeats."""

    def __init__(self, stages=("RUNNING",), quota=None):
        self.stages = list(stages)
        self.runtime_calls = 0
        self.restarts = 0
        self.runtime_error = None
        self.quota_value = quota
        self.quota_calls = 0

    def get_space_runtime(self, repo_id):
        assert repo_id == SPACE_ID
        self.runtime_calls += 1

        if self.runtime_error is not None:
            raise self.runtime_error

        stage = self.stages[0] if len(self.stages) == 1 else self.stages.pop(0)

        return SimpleNamespace(stage=stage)

    def restart_space(self, repo_id):
        assert repo_id == SPACE_ID
        self.restarts += 1

    def get_zero_gpu_quota(self):
        self.quota_calls += 1

        if isinstance(self.quota_value, Exception):
            raise self.quota_value

        if self.quota_value is None:
            raise HTTPError(403, "token lacks read-billing")

        return self.quota_value


class FakeJob:

    def __init__(self, gradio, prompt, max_new_tokens):
        self.gradio = gradio
        self.prompt = prompt
        self.max_new_tokens = max_new_tokens

    def done(self):
        return self.gradio.release.is_set()

    def result(self, timeout=None):
        return self.gradio.responder(self.prompt, self.max_new_tokens)

    def cancel(self):
        self.gradio.cancels += 1
        return True


class FakeClient:

    def __init__(self, gradio):
        self.gradio = gradio

    def submit(self, prompt, max_new_tokens, api_name=None):
        assert api_name == "/generate"
        self.gradio.submissions.append(prompt)
        return FakeJob(self.gradio, prompt, max_new_tokens)

    def close(self):
        self.gradio.closed += 1


def good_response(prompt, max_new_tokens):
    return contract.build_response(
        text=TEXT, new_tokens=321, hit_eos=True, seconds=4.2, provenance=PROVENANCE
    )


class FakeGradio:
    """The gradio Client factory. Jobs finish once `release` is set."""

    def __init__(self):
        self.release = threading.Event()
        self.release.set()
        self.responder = good_response
        self.submissions = []
        self.cancels = 0
        self.closed = 0

    def __call__(self):
        return FakeClient(self)


# ==============================================================================
# Fixtures and helpers
# ==============================================================================

@pytest.fixture(scope="module")
def saved(tmp_path_factory):
    """One saved sample analysis, copied into every test's cache."""

    root = tmp_path_factory.mktemp("scenario-analyses")

    with TestClient(create_app(make_settings(root))) as client:
        response = upload(client, SAMPLE_PATH.name, SAMPLE_PATH.read_bytes())

    assert response.status_code == 201, response.text

    return root, response.json()


@pytest.fixture
def cache_dir(saved, tmp_path):
    root, _ = saved
    destination = tmp_path / "cache"
    shutil.copytree(root / "analyses", destination / "analyses")
    return destination


@pytest.fixture
def analysis(saved):
    return saved[1]


def exported(analysis, count):
    """The first `count` exported path ids whose export records all differ."""

    chosen, records = [], []

    for path in analysis["paths"]:
        if path["exported"] and path["export"] not in records:
            chosen.append(path["source_id"])
            records.append(path["export"])

    assert len(chosen) >= count
    return chosen[:count]


def record_of(analysis, source_id):
    return next(p["export"] for p in analysis["paths"] if p["source_id"] == source_id)


def live_settings(cache_dir, **overrides):
    values = dict(
        HF_TOKEN=TOKEN,
        SPACE_ID=SPACE_ID,
        BASE_REVISION=BASE_SHA,
        ADAPTER_REPO=ADAPTER_REPO,
        ADAPTER_REVISION=ADAPTER_SHA,
        LOADING_RECIPE=contract.NF4_UNMERGED
    )
    values.update(overrides)
    return make_settings(cache_dir, **values)


@contextmanager
def running(cache_dir, api=None, gradio=None, live=True, **overrides):
    """A TestClient over a fresh app; live ones use the fakes."""

    if not live:
        settings = make_settings(cache_dir, **overrides)
        factory = None

    else:
        settings = live_settings(cache_dir, **overrides)
        api = api or FakeHfApi()
        gradio = gradio or FakeGradio()

        def factory(settings):
            return SpaceClient(
                settings.space_id,
                settings.hf_token.get_secret_value(),
                hf_api=api,
                gradio_client_factory=gradio,
                request_timeout_s=2,
                startup_timeout_s=settings.space_startup_timeout_s,
                generation_timeout_s=settings.generation_timeout_s,
                poll_interval_s=0.01
            )

    with TestClient(create_app(settings, space_factory=factory)) as client:
        yield client


def url(analysis_id, source_id):
    return "/api/analyses/%s/paths/%s/scenario" % (analysis_id, source_id)


def wait_for(client, analysis_id, source_id, statuses, timeout=10):
    """GET the scenario until its status is one of `statuses`."""

    deadline = time.monotonic() + timeout

    while True:
        response = client.get(url(analysis_id, source_id))
        assert response.status_code == 200, response.text
        state = response.json()

        if state["status"] in statuses:
            return state

        assert time.monotonic() < deadline, state
        time.sleep(0.01)


def wait_until(condition, timeout=10):
    deadline = time.monotonic() + timeout

    while not condition():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def store_entry(cache_dir, analysis, source_id, source="pregenerated", link=False,
                text=TEXT, analysis_id=None, prompt_format=contract.DEFAULT_PROMPT_FORMAT):
    """Put a valid entry for the path, made in `prompt_format`, under its key."""

    prompt = contract.build_prompt(record_of(analysis, source_id), prompt_format)
    response = contract.build_response(
        text=text, new_tokens=50, hit_eos=True, seconds=1.0, provenance=PROVENANCE
    )
    entry = contract.make_cache_entry(
        prompt=prompt, provenance=PROVENANCE, response=response, source=source,
        prompt_version=contract.prompt_version_for(prompt_format)
    )
    cache.merge_entry(cache_dir, entry)

    if link:
        cache.link(cache_dir, analysis_id or analysis["id"], source_id, entry["cache_key"])

    return entry


def cached_entries(cache_dir):
    directory = cache.scenarios_dir(cache_dir)
    return sorted(directory.glob("*.json")) if directory.exists() else []


# ==============================================================================
# Routes: lookup errors and idle
# ==============================================================================

def test_unrequested_paths_are_idle(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)

    for live in (True, False):
        with running(cache_dir, live=live) as client:
            state = client.get(url(analysis["id"], source_id)).json()

        assert state == {
            "status": "idle",
            "queue_position": None,
            "elapsed_s": None,
            "eta_s": None,
            "scenario": None,
            "error": None
        }


def test_unknown_analysis_or_path_is_404_and_a_non_exported_path_is_409(cache_dir, analysis):

    hidden = next(p["source_id"] for p in analysis["paths"] if not p["exported"])
    (source_id,) = exported(analysis, 1)

    with running(cache_dir) as client:
        for method in (client.get, client.post):
            assert method(url(str(uuid.uuid4()), source_id)).status_code == 404
            assert method(url("not-a-uuid", source_id)).status_code == 404
            assert method(url(analysis["id"], "AP-999")).status_code == 404

            response = method(url(analysis["id"], hidden))
            assert response.status_code == 409
            assert "minimum level" in response.json()["detail"]


# ==============================================================================
# Cache
# ==============================================================================

def test_a_cache_hit_is_served_without_generating(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    entry = store_entry(cache_dir, analysis, source_id)
    gradio = FakeGradio()

    with running(cache_dir, gradio=gradio) as client:
        before = client.get(url(analysis["id"], source_id)).json()
        response = client.post(url(analysis["id"], source_id))

    assert before["status"] == "cached"
    assert response.status_code == 200
    state = response.json()
    assert state["status"] == "cached"
    scenario = state["scenario"]
    assert scenario["cache_key"] == entry["cache_key"]
    # The cache hit is the retrieval status; the generation source is kept.
    assert scenario["source"] == "pregenerated"
    assert scenario["sections"]["attack_graph"] == "1. Scan\n2. Exploit"
    assert scenario["sections"]["missing"] == []
    assert scenario["reached_token_cap"] is False
    assert gradio.submissions == []
    # The POST linked the path to the entry.
    assert cache.read_links(cache_dir, analysis["id"]) == {source_id: entry["cache_key"]}


def test_a_get_cache_hit_links_the_path_so_the_report_includes_it(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    entry = store_entry(cache_dir, analysis, source_id)

    assert cache.read_links(cache_dir, analysis["id"]) == {}

    with running(cache_dir) as client:
        state = client.get(url(analysis["id"], source_id)).json()
        again = client.get(url(analysis["id"], source_id)).json()

    assert state["status"] == "cached"
    assert again == state
    assert cache.read_links(cache_dir, analysis["id"]) == {source_id: entry["cache_key"]}

    scenarios = cached_scenarios(cache_dir, analysis["id"], selected_records(analysis))

    assert list(scenarios) == [source_id]

    context = pdf.build_context(analysis, None, "all", scenarios)
    blocks = {block["source_id"]: block for block in context["paths"]}

    assert blocks[source_id]["scenario"] is not None
    assert [b["source_id"] for b in blocks.values() if b["scenario"]] == [source_id]


def test_a_link_to_a_scenario_made_for_another_path_is_ignored(cache_dir, analysis):

    first, second = exported(analysis, 2)

    entry = store_entry(cache_dir, analysis, first)

    # The second path is linked to the first path's scenario, as a stale link
    # would be after an analysis was rebuilt and its paths renumbered.
    cache.link(cache_dir, analysis["id"], second, entry["cache_key"])

    with running(cache_dir) as client:
        state = client.get(url(analysis["id"], second)).json()
        own = client.get(url(analysis["id"], first)).json()

    assert state["status"] == "idle"
    assert state["scenario"] is None
    assert state["error"] is None

    # the path the scenario was made for still shows it
    assert own["status"] == "cached"
    assert own["scenario"]["cache_key"] == entry["cache_key"]

    # and a request for the second path is not answered with the first's
    with running(cache_dir, live=False) as client:
        response = client.post(url(analysis["id"], second))

    assert response.status_code == 503


# ==============================================================================
# Prompt format
# ==============================================================================

def test_the_prompt_format_setting_defaults_to_structured_and_is_validated(cache_dir):
    assert make_settings(cache_dir).scenario_prompt_format == "structured-p1"
    assert make_settings(cache_dir, SCENARIO_PROMPT_FORMAT="training").prompt_version == "training.v1"

    with pytest.raises(ValueError, match="SCENARIO_PROMPT_FORMAT"):
        make_settings(cache_dir, SCENARIO_PROMPT_FORMAT="chatml")


def test_a_generation_uses_the_configured_format_and_records_its_version(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    record = record_of(analysis, source_id)
    seen = {}

    for prompt_format in contract.PROMPT_VERSIONS:
        gradio = FakeGradio()

        with running(cache_dir, gradio=gradio, SCENARIO_PROMPT_FORMAT=prompt_format) as client:
            assert client.post(url(analysis["id"], source_id)).status_code == 202
            state = wait_for(client, analysis["id"], source_id, ("done", "failed"))

        assert state["status"] == "done", state
        assert gradio.submissions == [contract.build_prompt(record, prompt_format)]
        assert state["scenario"]["prompt_version"] == contract.prompt_version_for(prompt_format)
        seen[prompt_format] = state["scenario"]["cache_key"]

        # forget the link so the next format has to look under its own key
        cache.links_path(cache_dir, analysis["id"]).unlink()

    # One entry per format: the versions keep the cache keys apart.
    assert len(set(seen.values())) == 2
    assert len(cached_entries(cache_dir)) == 2


def test_switching_the_format_keeps_linked_results_visible_and_labelled(cache_dir, analysis):

    source_id, other = exported(analysis, 2)
    old = store_entry(cache_dir, analysis, source_id, link=True, prompt_format="structured-p1")
    gradio = FakeGradio()

    with running(cache_dir, gradio=gradio, SCENARIO_PROMPT_FORMAT="training") as client:
        got = client.get(url(analysis["id"], source_id)).json()
        posted = client.post(url(analysis["id"], source_id))

    assert got["status"] == "cached"
    assert got["scenario"]["cache_key"] == old["cache_key"]
    assert got["scenario"]["prompt_version"] == "P1.v1"
    assert posted.status_code == 200
    assert posted.json()["scenario"]["prompt_version"] == "P1.v1"
    assert gradio.submissions == []

    # and the other way round, for a second path
    cache.link(cache_dir, analysis["id"], other, store_entry(
        cache_dir, analysis, other, prompt_format="training")["cache_key"])

    with running(cache_dir, SCENARIO_PROMPT_FORMAT="structured-p1") as client:
        state = client.get(url(analysis["id"], other)).json()

    assert state["status"] == "cached"
    assert state["scenario"]["prompt_version"] == "training.v1"


def test_an_unlinked_entry_is_found_only_under_the_configured_format(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    entry = store_entry(cache_dir, analysis, source_id, prompt_format="training")

    with running(cache_dir, SCENARIO_PROMPT_FORMAT="structured-p1") as client:
        assert client.get(url(analysis["id"], source_id)).json()["status"] == "idle"

    with running(cache_dir, SCENARIO_PROMPT_FORMAT="training") as client:
        state = client.get(url(analysis["id"], source_id)).json()

    assert state["status"] == "cached"
    assert state["scenario"]["cache_key"] == entry["cache_key"]
    assert cache.read_links(cache_dir, analysis["id"]) == {source_id: entry["cache_key"]}


def test_entry_matches_uses_the_entrys_own_format(analysis):

    (source_id,) = exported(analysis, 1)
    record = record_of(analysis, source_id)

    for prompt_format in contract.PROMPT_VERSIONS:
        entry = contract.make_cache_entry(
            prompt=contract.build_prompt(record, prompt_format),
            provenance=PROVENANCE,
            response=contract.build_response(
                text=TEXT, new_tokens=5, hit_eos=True, seconds=1.0, provenance=PROVENANCE),
            source="live",
            prompt_version=contract.prompt_version_for(prompt_format)
        )

        assert cache.entry_matches(entry, record)

        # a prompt of the other format under this entry's version is not a match
        other = next(name for name in contract.PROMPT_VERSIONS if name != prompt_format)
        entry["request"]["prompt"] = contract.build_prompt(record, other)
        assert not cache.entry_matches(entry, record)

        entry["request"]["prompt_version"] = "unknown.v9"
        assert not cache.entry_matches(entry, record)


def test_a_report_leaves_out_a_scenario_linked_to_the_wrong_path(cache_dir, analysis):

    first, second = exported(analysis, 2)

    entry = store_entry(cache_dir, analysis, first, link=True)
    cache.link(cache_dir, analysis["id"], second, entry["cache_key"])

    scenarios = cached_scenarios(cache_dir, analysis["id"], selected_records(analysis))

    assert list(scenarios) == [first]
    assert scenarios[first]["cache_key"] == entry["cache_key"]


# ==============================================================================
# Queue
# ==============================================================================

def test_jobs_queue_in_order_and_duplicates_join_the_active_job(cache_dir, analysis):

    first, second, third = exported(analysis, 3)

    # A second analysis with the same paths: identical prompts, identical keys.
    twin = str(uuid.uuid4())
    shutil.copytree(cache_dir / "analyses" / analysis["id"], cache_dir / "analyses" / twin)

    gradio = FakeGradio()
    gradio.release.clear()

    with running(cache_dir, gradio=gradio) as client:

        response = client.post(url(analysis["id"], first))
        assert response.status_code == 202
        wait_until(lambda: len(gradio.submissions) == 1)

        running_state = client.get(url(analysis["id"], first)).json()
        assert running_state["status"] == "running"
        assert running_state["queue_position"] is None
        assert running_state["elapsed_s"] >= 0

        # The same path again, and the twin analysis's path: the same job.
        assert client.post(url(analysis["id"], first)).status_code == 202
        joined = client.post(url(twin, first))
        assert joined.status_code == 202
        assert joined.json()["status"] == "running"

        queued = [client.post(url(analysis["id"], path)) for path in (second, third)]
        assert [r.status_code for r in queued] == [202, 202]
        assert [r.json()["status"] for r in queued] == ["queued", "queued"]
        # Jobs ahead, the running one included.
        assert [r.json()["queue_position"] for r in queued] == [1, 2]

        gradio.release.set()

        for analysis_id, path in ((analysis["id"], first), (twin, first),
                                  (analysis["id"], second), (analysis["id"], third)):
            state = wait_for(client, analysis_id, path, ("done", "failed"))
            assert state["status"] == "done", state
            assert state["scenario"]["source"] == "live"
            assert state["scenario"]["new_tokens"] == 321

    # One generation per distinct prompt, in FIFO order.
    assert gradio.submissions == [
        contract.build_prompt(record_of(analysis, path)) for path in (first, second, third)
    ]
    assert len(cached_entries(cache_dir)) == 3
    assert cache.read_links(cache_dir, twin).keys() == {first}


def test_queue_position_counts_the_jobs_ahead_from_the_moment_of_enqueue(cache_dir, analysis):

    first, second, third = exported(analysis, 3)
    gradio = FakeGradio()
    gradio.release.clear()

    with running(cache_dir, gradio=gradio) as client:

        # Nothing ahead: queued for an instant, with no one in front.
        enqueued = client.post(url(analysis["id"], first)).json()
        assert enqueued["status"] == "queued"
        assert enqueued["queue_position"] == 0

        wait_until(lambda: len(gradio.submissions) == 1)

        # The running job is ahead of the next, then both are.
        positions = []

        for path in (second, third):
            posted = client.post(url(analysis["id"], path)).json()
            assert posted["status"] == "queued"
            positions.append(posted["queue_position"])

        assert positions == [1, 2]

        # A GET reports the same numbers as the POST did.
        assert [client.get(url(analysis["id"], path)).json()["queue_position"]
                for path in (second, third)] == [1, 2]

        gradio.release.set()
        wait_for(client, analysis["id"], third, ("done",))


def test_a_full_queue_is_503_with_retry_after(cache_dir, analysis):

    first, second, third = exported(analysis, 3)
    gradio = FakeGradio()
    gradio.release.clear()

    with running(cache_dir, gradio=gradio, scenario_queue_max=1) as client:
        assert client.post(url(analysis["id"], first)).status_code == 202
        wait_until(lambda: len(gradio.submissions) == 1)
        assert client.post(url(analysis["id"], second)).status_code == 202

        full = client.post(url(analysis["id"], third))

        assert full.status_code == 503
        assert full.headers["Retry-After"] == "30"
        assert "queue is full" in full.json()["detail"]
        assert client.get(url(analysis["id"], third)).json()["status"] == "idle"

        gradio.release.set()
        wait_for(client, analysis["id"], second, ("done",))


def test_only_a_new_live_job_counts_toward_the_scenario_limit(cache_dir, analysis):

    cached, first, second = exported(analysis, 3)
    store_entry(cache_dir, analysis, cached)
    gradio = FakeGradio()
    gradio.release.clear()

    with running(cache_dir, gradio=gradio, rate_limits_enabled=True,
                 rate_limit_scenarios=(1, 3600)) as client:

        # a cache hit and a joined job cost nothing
        assert client.post(url(analysis["id"], cached)).status_code == 200
        assert client.post(url(analysis["id"], first)).status_code == 202
        assert client.post(url(analysis["id"], first)).status_code == 202
        assert client.post(url(analysis["id"], cached)).status_code == 200

        over = client.post(url(analysis["id"], second))

        assert over.status_code == 429
        assert 3590 <= int(over.headers["Retry-After"]) <= 3600
        assert over.json()["detail"] == (
            "Too many scenario generations from this address: the limit is 1 per hour."
        )
        assert client.get(url(analysis["id"], second)).json()["status"] == "idle"

        gradio.release.set()
        wait_for(client, analysis["id"], first, ("done",))

    assert len(gradio.submissions) == 1


# ==============================================================================
# Space runtime
# ==============================================================================

def test_a_sleeping_space_is_restarted_once_and_shows_warming_up(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(stages=["SLEEPING"])

    with running(cache_dir, api=api) as client:
        client.post(url(analysis["id"], source_id))

        state = wait_for(client, analysis["id"], source_id, ("warming_up",))
        assert state["elapsed_s"] is not None

        # Still asleep for a while after the restart: polled, not restarted again.
        wait_until(lambda: api.runtime_calls >= 5)
        api.stages[:] = ["STARTING", "RUNNING"]

        assert wait_for(client, analysis["id"], source_id, ("done", "failed"))["status"] == "done"

    assert api.restarts == 1


def test_a_building_space_is_polled_without_a_restart(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(stages=["BUILDING", "BUILDING", "APP_STARTING", "RUNNING"])
    gradio = FakeGradio()

    with running(cache_dir, api=api, gradio=gradio) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("done", "failed"))

    assert state["status"] == "done"
    assert api.restarts == 0
    assert api.runtime_calls == 4
    assert len(gradio.submissions) == 1


def test_a_space_that_never_starts_fails_at_the_startup_cap(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(stages=["BUILDING"])
    gradio = FakeGradio()

    with running(cache_dir, api=api, gradio=gradio, space_startup_timeout_s=0.2) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("failed",))

    assert "did not start within 0.2 s" in state["error"]
    assert "BUILDING" in state["error"]
    assert gradio.submissions == []


@pytest.mark.parametrize("stage, words", [
    ("PAUSED", "paused"),
    ("RUNTIME_ERROR", "RUNTIME_ERROR"),
    ("BUILD_ERROR", "deploy_model_space.py")
])
def test_a_paused_or_broken_space_fails_with_a_setup_message(cache_dir, analysis, stage, words):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(stages=[stage])
    gradio = FakeGradio()

    with running(cache_dir, api=api, gradio=gradio) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("failed",))

        client.get("/api/health")
        wait_until(lambda: client.get("/api/health").json()["space_stage"] == stage)
        health = client.get("/api/health").json()

    assert words in state["error"]
    assert api.restarts == 0
    assert gradio.submissions == []
    assert words in health["model_unavailable_reason"]


@pytest.mark.parametrize("stage", ["PAUSED", "RUNTIME_ERROR", "BUILD_ERROR"])
def test_a_known_paused_or_broken_space_refuses_up_front(cache_dir, analysis, stage):

    cached_path, other = exported(analysis, 2)
    store_entry(cache_dir, analysis, cached_path, link=True)
    api = FakeHfApi(stages=[stage])
    gradio = FakeGradio()

    with running(cache_dir, api=api, gradio=gradio) as client:
        health = health_after_refresh(client, api)
        calls = api.runtime_calls

        refused = client.post(url(analysis["id"], other))
        served = client.post(url(analysis["id"], cached_path))
        idle = client.get(url(analysis["id"], other)).json()

    assert health["space_stage"] == stage
    assert refused.status_code == 503
    # The same message health shows, and nothing to retry: only the owner can fix it.
    assert refused.json()["detail"] == health["model_unavailable_reason"]
    assert "Retry-After" not in refused.headers
    assert idle["status"] == "idle"
    assert served.status_code == 200
    assert served.json()["status"] == "cached"

    # POST used the snapshot: no extra call to Hugging Face, no job, no restart.
    assert api.runtime_calls == calls
    assert api.restarts == 0
    assert gradio.submissions == []


def test_a_stale_or_unknown_space_snapshot_does_not_block_a_post(cache_dir, analysis):

    stale_path, unknown_path = exported(analysis, 2)
    api = FakeHfApi(stages=["PAUSED"])
    gradio = FakeGradio()

    with running(cache_dir, api=api, gradio=gradio) as client:
        health_after_refresh(client, api)
        service = client.app.state.scenarios
        assert service.status.stage == "PAUSED"

        # Older than the TTL: the worker's own stage handling decides.
        service.status.stage_at = time.monotonic() - 10 * service.settings.space_status_ttl_s
        stale = client.post(url(analysis["id"], stale_path))
        assert stale.status_code == 202
        failed = wait_for(client, analysis["id"], stale_path, ("failed",))
        assert "paused" in failed["error"]

        # Unknown: the stage could not be read.
        service.status.stage = None
        service.status.stage_at = None
        unknown = client.post(url(analysis["id"], unknown_path))
        assert unknown.status_code == 202
        wait_for(client, analysis["id"], unknown_path, ("failed",))

    assert api.restarts == 0


def test_a_running_snapshot_does_not_block_a_post(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(stages=["RUNNING"])

    with running(cache_dir, api=api) as client:
        health_after_refresh(client, api)
        assert client.post(url(analysis["id"], source_id)).status_code == 202
        assert wait_for(client, analysis["id"], source_id, ("done",))


def test_an_unreadable_space_is_a_setup_error(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi()
    api.runtime_error = HTTPError(404)

    with running(cache_dir, api=api) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("failed",))

    assert "HTTP 404" in state["error"]
    assert "SPACE_ID" in state["error"]


# ==============================================================================
# Generation failures
# ==============================================================================

def test_a_provider_error_fails_the_job_and_caches_nothing(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    gradio = FakeGradio()

    def fail(prompt, max_new_tokens):
        raise RuntimeError("CUDA out of memory")

    gradio.responder = fail

    with running(cache_dir, gradio=gradio) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("failed",))

    assert state["error"] == "The model Space reported an error: CUDA out of memory"
    assert state["scenario"] is None
    assert cached_entries(cache_dir) == []
    assert gradio.closed == 1


def test_a_provenance_mismatch_is_rejected_not_relabelled(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    gradio = FakeGradio()

    def other_adapter(prompt, max_new_tokens):
        return contract.build_response(
            text=TEXT, new_tokens=10, hit_eos=True, seconds=1.0,
            provenance=dict(PROVENANCE, adapter_revision="c" * 40)
        )

    gradio.responder = other_adapter

    with running(cache_dir, gradio=gradio) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("failed",))

    assert "rejected and not saved" in state["error"]
    assert "provenance mismatch" in state["error"]
    assert "adapter_revision" in state["error"]
    assert cached_entries(cache_dir) == []
    assert cache.read_links(cache_dir, analysis["id"]) == {}


def test_a_timeout_cancels_the_job_and_is_not_retried(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    gradio = FakeGradio()
    gradio.release.clear()

    with running(cache_dir, gradio=gradio, generation_timeout_s=0.2) as client:
        client.post(url(analysis["id"], source_id))
        state = wait_for(client, analysis["id"], source_id, ("failed",))

        time.sleep(0.3)
        later = client.get(url(analysis["id"], source_id)).json()

    assert "did not finish within 0.2 s" in state["error"]
    assert "Remote GPU work may still be running" in state["error"]
    assert gradio.cancels == 1
    # No automatic replay.
    assert later["status"] == "failed"
    assert len(gradio.submissions) == 1


def test_an_explicit_post_after_a_failure_starts_a_new_job(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    gradio = FakeGradio()
    attempts = []

    def fail_once(prompt, max_new_tokens):
        attempts.append(prompt)

        if len(attempts) == 1:
            raise RuntimeError("Space crashed")

        return good_response(prompt, max_new_tokens)

    gradio.responder = fail_once

    with running(cache_dir, gradio=gradio) as client:
        client.post(url(analysis["id"], source_id))
        assert wait_for(client, analysis["id"], source_id, ("failed",))["error"]

        retry = client.post(url(analysis["id"], source_id))
        assert retry.status_code == 202
        assert retry.json()["error"] is None

        state = wait_for(client, analysis["id"], source_id, ("done", "failed"))

    assert state["status"] == "done"
    assert len(gradio.submissions) == 2


# ==============================================================================
# Quota and health
# ==============================================================================

def health_after_refresh(client, api):
    """Health once the background refresh its first call starts has finished."""

    service = client.app.state.scenarios
    calls = api.quota_calls
    client.get("/api/health")
    wait_until(lambda: api.quota_calls > calls and service._refresh.done())
    return client.get("/api/health").json()


def test_unknown_quota_is_null_and_does_not_block(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(quota=None)

    with running(cache_dir, api=api) as client:
        health = health_after_refresh(client, api)
        response = client.post(url(analysis["id"], source_id))

        assert wait_for(client, analysis["id"], source_id, ("done",))

    assert health["ok"] is True
    assert health["space_configured"] is True
    assert health["space_stage"] == "RUNNING"
    assert health["gpu_quota_remaining_s"] is None
    assert health["gpu_quota_resets_at"] is None
    assert health["est_generations_left"] is None
    assert health["model_unavailable_reason"] is None
    assert response.status_code == 202


def test_known_exhausted_quota_is_503_but_cached_scenarios_stay(cache_dir, analysis):

    cached_path, other = exported(analysis, 2)
    store_entry(cache_dir, analysis, cached_path, link=True)

    resets_at = datetime.now(timezone.utc) + timedelta(hours=1)
    api = FakeHfApi(quota=SimpleNamespace(remaining=0, resets_at=resets_at, base=300))
    gradio = FakeGradio()

    with running(cache_dir, api=api, gradio=gradio) as client:
        health = health_after_refresh(client, api)
        refused = client.post(url(analysis["id"], other))
        served = client.post(url(analysis["id"], cached_path))

    assert health["gpu_quota_remaining_s"] == 0
    assert datetime.fromisoformat(health["gpu_quota_resets_at"]) == resets_at
    assert "quota" in health["model_unavailable_reason"]
    assert health["est_generations_left"] is None

    assert refused.status_code == 503
    assert "quota" in refused.json()["detail"]
    assert 3500 <= int(refused.headers["Retry-After"]) <= 3600
    # A person-readable time, not a raw ISO timestamp.
    assert resets_at.isoformat() not in refused.json()["detail"]
    assert "+00:00" not in refused.json()["detail"]
    assert resets_at.strftime("%H:%M UTC") in refused.json()["detail"]

    assert served.status_code == 200
    assert served.json()["status"] == "cached"
    assert gradio.submissions == []


def test_exhausted_quota_with_an_unknown_reset_still_says_to_retry_shortly(cache_dir, analysis):

    (source_id,) = exported(analysis, 1)
    api = FakeHfApi(quota=SimpleNamespace(remaining=0, resets_at=None, base=300))

    with running(cache_dir, api=api) as client:
        health_after_refresh(client, api)
        refused = client.post(url(analysis["id"], source_id))

    assert refused.status_code == 503
    assert "quota" in refused.json()["detail"]
    assert refused.headers["Retry-After"] == "30"


def test_the_quota_message_formats_the_reset_time_in_utc():

    reset = datetime(2026, 10, 25, 11, 0, tzinfo=timezone.utc)

    assert quota_message(Quota(remaining_s=0, resets_at=reset)) == (
        "The ZeroGPU quota for this Hugging Face account is used up until "
        "25 Oct 2026, 11:00 UTC."
    )

    # Another offset is converted; a naive time is taken as UTC; days are not padded.
    plus_two = datetime(2026, 1, 5, 1, 30, tzinfo=timezone(timedelta(hours=2)))
    assert "4 Jan 2026, 23:30 UTC" in quota_message(Quota(remaining_s=0, resets_at=plus_two))
    assert "5 Jan 2026, 09:05 UTC" in quota_message(
        Quota(remaining_s=0, resets_at=datetime(2026, 1, 5, 9, 5))
    )

    assert quota_message(Quota(remaining_s=0)).endswith("is used up.")


def test_remaining_quota_is_reported_and_an_elapsed_reset_is_not_exhaustion(cache_dir):

    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    api = FakeHfApi(quota=SimpleNamespace(remaining=0, resets_at=past))

    with running(cache_dir, api=api) as client:
        health = health_after_refresh(client, api)

        api.quota_value = SimpleNamespace(remaining=181.7, resets_at=None)
        client.app.state.scenarios.status.checked = None
        later = health_after_refresh(client, api)

    assert health["gpu_quota_remaining_s"] == 0
    assert health["model_unavailable_reason"] is None
    assert later["gpu_quota_remaining_s"] == 181


def test_health_reads_hugging_face_at_most_once_per_ttl(cache_dir):

    api = FakeHfApi(quota=SimpleNamespace(remaining=60, resets_at=None))

    with running(cache_dir, api=api) as client:
        for _ in range(10):
            assert client.get("/api/health").status_code == 200

        wait_until(lambda: api.quota_calls == 1)

        for _ in range(10):
            client.get("/api/health")

    assert api.runtime_calls == 1
    assert api.quota_calls == 1


def test_a_failing_space_never_fails_core_health(cache_dir):

    api = FakeHfApi()
    api.runtime_error = ConnectionError("no route to host")
    api.quota_value = ConnectionError("no route to host")

    with running(cache_dir, api=api) as client:
        health = health_after_refresh(client, api)

    assert health["ok"] is True
    assert health["space_stage"] is None
    assert health["gpu_quota_remaining_s"] is None


# ==============================================================================
# Configuration and restart
# ==============================================================================

def test_a_restart_forgets_jobs_but_keeps_finished_scenarios(cache_dir, analysis):

    finished, unfinished = exported(analysis, 2)
    gradio = FakeGradio()

    with running(cache_dir, gradio=gradio) as client:
        client.post(url(analysis["id"], finished))
        wait_for(client, analysis["id"], finished, ("done",))

        gradio.release.clear()
        client.post(url(analysis["id"], unfinished))
        wait_until(lambda: len(gradio.submissions) == 2)

    # Shutting down cancelled the remote request of the running job.
    assert gradio.cancels == 1

    with running(cache_dir, gradio=FakeGradio()) as client:
        assert client.get(url(analysis["id"], unfinished)).json()["status"] == "idle"
        assert client.get(url(analysis["id"], finished)).json()["status"] == "cached"


def test_without_live_config_cached_scenarios_stay_readable(cache_dir, analysis):

    linked, imported, nothing = exported(analysis, 3)

    with running(cache_dir) as client:
        client.post(url(analysis["id"], linked))
        wait_for(client, analysis["id"], linked, ("done",))

    # A pregenerated import, linked the way import_scenarios.py links it.
    store_entry(cache_dir, analysis, imported, link=True)

    with running(cache_dir, live=False) as client:
        health = client.get("/api/health").json()
        got = client.get(url(analysis["id"], linked)).json()
        posted = client.post(url(analysis["id"], imported))
        idle = client.get(url(analysis["id"], nothing)).json()
        refused = client.post(url(analysis["id"], nothing))

    assert health["ok"] is True
    assert health["space_configured"] is False
    assert health["space_stage"] is None
    assert "not configured" in health["model_unavailable_reason"]

    assert got["status"] == "cached"
    assert got["scenario"]["source"] == "live"
    assert posted.status_code == 200
    assert posted.json()["scenario"]["source"] == "pregenerated"
    assert idle["status"] == "idle"

    # Not configured will not fix itself: nothing to retry.
    assert refused.status_code == 503
    assert "Retry-After" not in refused.headers
    assert "BASE_REVISION" in refused.json()["detail"]


def test_partial_or_invalid_config_disables_live_generation(cache_dir):

    cases = [
        (dict(HF_TOKEN=TOKEN, SPACE_ID=SPACE_ID), "set BASE_REVISION, ADAPTER_REPO"),
        (dict(BASE_REVISION="main"), "full 40-character commit SHA"),
        (dict(LOADING_RECIPE="bf16-merged"), "loading_recipe"),
        (dict(BASE_MODEL_ID="mistralai/Mistral-7B-v0.1"), "BASE_MODEL_ID must be")
    ]

    for overrides, words in cases:

        if "BASE_REVISION" in overrides or "LOADING_RECIPE" in overrides \
                or "BASE_MODEL_ID" in overrides:
            settings = live_settings(cache_dir, **overrides)
        else:
            settings = make_settings(cache_dir, **overrides)

        assert words in settings.live_config_problem(), overrides

        with TestClient(create_app(settings)) as client:
            health = client.get("/api/health").json()

        assert words in health["model_unavailable_reason"]
        assert client.app.state.scenarios.space is None


def test_production_apps_use_the_real_client_and_import_nothing_eagerly(cache_dir):

    settings = live_settings(cache_dir)

    app = create_app(settings)
    assert app.state.scenarios._space_factory is create_space_client

    # Built from settings alone: no network until a job or a health refresh.
    space = create_space_client(settings)
    assert type(space._hf_api).__name__ == "HfApi"
    assert space.generation_timeout_s == 600
    assert space.startup_timeout_s == 300

    code = (
        "import sys, app.api.main\n"
        "print(sorted(m for m in ('gradio_client', 'huggingface_hub') if m in sys.modules))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
        timeout=60
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "[]"


# ==============================================================================
# The token
# ==============================================================================

def test_the_token_never_reaches_a_response_or_a_log_line(cache_dir, analysis, caplog):

    caplog.set_level(logging.DEBUG)

    first, second = exported(analysis, 2)
    api = FakeHfApi(quota=HTTPError(401, "bad token %s" % TOKEN))
    gradio = FakeGradio()

    def leak(prompt, max_new_tokens):
        raise RuntimeError("authorization: Bearer %s rejected" % TOKEN)

    gradio.responder = leak
    bodies = []

    with running(cache_dir, api=api, gradio=gradio) as client:
        bodies.append(client.post(url(analysis["id"], first)).text)
        failed = wait_for(client, analysis["id"], first, ("failed",))
        bodies.append(json.dumps(failed))

        api.runtime_error = RuntimeError("runtime said %s" % TOKEN)
        bodies.append(client.post(url(analysis["id"], second)).text)
        bodies.append(json.dumps(wait_for(client, analysis["id"], second, ("failed",))))

        client.app.state.scenarios.status.checked = None
        health = health_after_refresh(client, api)
        bodies.append(json.dumps(health))
        bodies.append(client.get("/openapi.json").text)

    assert "***" in failed["error"]

    for body in bodies:
        assert TOKEN not in body

    assert TOKEN not in caplog.text
    assert all(TOKEN not in str(record.args) for record in caplog.records)

    for path in cache_dir.rglob("*"):
        if path.is_file():
            assert TOKEN not in path.read_text(encoding="utf-8", errors="ignore")
