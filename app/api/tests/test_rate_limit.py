"""Per-client rate limits, the client address behind a proxy, and ANALYSER_COMMIT.

The report and scenario buckets are tested next to their routes, in
test_report.py and test_scenarios.py.
"""

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.api import rate_limit
from app.api.analysis import AnalysisService, analyser_commit
from app.api.config import Settings
from app.api.main import create_app
from app.api.rate_limit import RateLimiter, client_address, client_key
from app.api.tests.conftest import INDUSTRY, SAMPLE_PATH, make_settings, upload
from app.api.worker import JobError, Worker


SAMPLE = {"sample_id": "cloudformation5", "industry": INDUSTRY}


class StubWorker:
    """Counts the jobs it is given and fails each one, so no child is spawned."""

    def __init__(self):
        self.busy = False
        self.calls = 0

    async def run(self, kind, payload, timeout):

        if self.busy:
            raise Worker().busy_error()

        self.calls += 1

        raise JobError(504, "stub")

    def shutdown(self):
        pass


def stubbed(tmp_path, **overrides):
    """A TestClient over an app whose analyses never run, and its StubWorker."""

    worker = StubWorker()
    app = create_app(make_settings(tmp_path / "cache", **overrides), worker=worker)

    return TestClient(app), worker


class Clock:

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def request_from(host="10.0.0.1", forwarded=()):
    """A bare request from `host`, with one X-Forwarded-For header per entry."""

    return Request({
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"x-forwarded-for", value.encode()) for value in forwarded],
        "client": (host, 50000) if host else None
    })


def limiter(tmp_path, clock=None, **overrides):
    settings = make_settings(tmp_path / "cache", rate_limits_enabled=True, **overrides)
    return RateLimiter(settings, clock or Clock())


def refused(function):
    with pytest.raises(JobError) as caught:
        function()

    assert caught.value.status == 429

    return caught.value


# -- Limits ----------------------------------------------------------------------

def test_limits_are_off_by_default(tmp_path):

    assert Settings(_env_file=None).rate_limits_enabled is False

    client, worker = stubbed(tmp_path)

    with client:
        statuses = {client.post("/api/analyses/sample", json=SAMPLE).status_code
                    for _ in range(25)}

    assert statuses == {504}
    assert worker.calls == 25


def test_past_the_limit_is_429_with_retry_after_and_the_usual_error_shape(tmp_path):

    client, worker = stubbed(tmp_path, rate_limits_enabled=True, rate_limit_analyses=(2, 600))

    with client:
        # an upload and a sample share the analyses bucket
        assert upload(client, "a.yml", SAMPLE_PATH.read_bytes()).status_code == 504
        assert client.post("/api/analyses/sample", json=SAMPLE).status_code == 504

        over = client.post("/api/analyses/sample", json=SAMPLE)

    assert over.status_code == 429
    assert 590 <= int(over.headers["Retry-After"]) <= 600
    assert over.json() == {
        "detail": "Too many analyses from this address: the limit is 2 per 10 minutes."
    }
    # refused before any work started
    assert worker.calls == 2


def test_a_refused_or_invalid_request_costs_nothing(tmp_path):

    client, worker = stubbed(tmp_path, rate_limits_enabled=True, rate_limit_analyses=(1, 600))

    with client:
        worker.busy = True

        for _ in range(3):
            assert client.post("/api/analyses/sample", json=SAMPLE).status_code == 503

        worker.busy = False

        unknown = {"sample_id": "nope", "industry": INDUSTRY}

        assert client.post("/api/analyses/sample", json=unknown).status_code == 404
        assert upload(client, "a.txt", b"x").status_code == 415

        # the one allowed request is still there, and then it is used up
        assert client.post("/api/analyses/sample", json=SAMPLE).status_code == 504
        assert client.post("/api/analyses/sample", json=SAMPLE).status_code == 429


def test_a_saved_fix_impact_is_served_without_counting(tmp_path):

    settings = make_settings(
        tmp_path / "cache", rate_limits_enabled=True, rate_limit_analyses=(2, 600)
    )

    with TestClient(create_app(settings)) as client:
        analysis = client.post("/api/analyses/sample", json=SAMPLE).json()
        fixes = "/api/analyses/%s/fixes" % analysis["id"]

        assert client.post(fixes, params={"top": "5"}).status_code == 200
        assert client.post(fixes, params={"top": "5"}).status_code == 200

        # another scope is new work, and the bucket is empty
        assert client.post(fixes, params={"top": "3"}).status_code == 429

        # reading saved state is never limited
        assert client.get("/api/analyses/%s" % analysis["id"]).status_code == 200
        assert client.get(fixes, params={"top": "5"}).status_code == 200


def test_the_window_slides(tmp_path):

    clock = Clock()
    limits = limiter(tmp_path, clock, rate_limit_scenarios=(2, 3600))
    request = request_from()

    limits.charge("scenarios", request)
    clock.now += 1000
    limits.charge("scenarios", request)

    assert refused(lambda: limits.charge("scenarios", request)).headers == {
        "Retry-After": "2600"
    }

    # the first request leaves the window, the second is still in it
    clock.now += 2600
    limits.charge("scenarios", request)

    assert refused(lambda: limits.charge("scenarios", request)).headers == {
        "Retry-After": "1000"
    }


def test_buckets_and_clients_are_counted_apart(tmp_path):

    limits = limiter(
        tmp_path,
        rate_limit_analyses=(1, 600),
        rate_limit_reports=(1, 600),
        rate_limit_scenarios=(1, 3600)
    )
    first, second = request_from("10.0.0.1"), request_from("10.0.0.2")

    limits.charge("analyses", first)
    refused(lambda: limits.charge("analyses", first))

    # the same client's other buckets, and another client's analyses, are untouched
    limits.charge("reports", first)
    limits.charge("scenarios", first)
    limits.charge("analyses", second)

    detail = refused(lambda: limits.charge("reports", first)).detail
    assert detail == "Too many PDF reports from this address: the limit is 1 per 10 minutes."

    detail = refused(lambda: limits.charge("scenarios", first)).detail
    assert detail == "Too many scenario generations from this address: the limit is 1 per hour."


def test_idle_clients_are_forgotten_and_the_number_tracked_is_capped(tmp_path, monkeypatch):

    clock = Clock()
    limits = limiter(tmp_path, clock, rate_limit_analyses=(1, 600))

    for host in ("10.0.0.1", "10.0.0.2"):
        limits.charge("analyses", request_from(host))

    assert len(limits._hits) == 2

    # once their requests have left the window, the next sweep drops them
    clock.now += 601
    limits.charge("analyses", request_from("10.0.0.3"))

    assert list(limits._hits) == [("analyses", "10.0.0.3")]

    # past the cap, the least recently seen client is forgotten
    monkeypatch.setattr(rate_limit, "MAX_CLIENTS", 2)

    limits.charge("analyses", request_from("10.0.0.4"))
    limits.charge("analyses", request_from("10.0.0.5"))

    assert list(limits._hits) == [("analyses", "10.0.0.4"), ("analyses", "10.0.0.5")]


def test_an_ipv6_client_is_counted_by_its_slash_64(tmp_path):

    assert client_key("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"
    assert client_key("203.0.113.7") == "203.0.113.7"
    assert client_key("testclient") == "testclient"

    limits = limiter(tmp_path, rate_limit_analyses=(1, 600))

    limits.charge("analyses", request_from("2001:db8:1:2:aaaa::1"))
    refused(lambda: limits.charge("analyses", request_from("2001:db8:1:2:bbbb::9")))


# -- Client address --------------------------------------------------------------

@pytest.mark.parametrize("hops, host, forwarded, address", [
    # without trusted proxies the header is ignored
    (0, "10.0.0.1", ["203.0.113.7"], "10.0.0.1"),
    # one proxy: the rightmost entry, never a spoofed one left of it
    (1, "10.0.0.1", ["203.0.113.7"], "203.0.113.7"),
    (1, "10.0.0.1", ["6.6.6.6, 203.0.113.7"], "203.0.113.7"),
    (1, "10.0.0.1", ["6.6.6.6", "203.0.113.7"], "203.0.113.7"),
    (1, "10.0.0.1", [" 6.6.6.6 ,203.0.113.7 , "], "203.0.113.7"),
    # two proxies: the address the outer one saw
    (2, "10.0.0.1", ["6.6.6.6, 203.0.113.7, 10.1.1.1"], "203.0.113.7"),
    # a missing or short header falls back to the connection
    (1, "10.0.0.1", [], "10.0.0.1"),
    (1, "10.0.0.1", [" , "], "10.0.0.1"),
    (2, "10.0.0.1", ["203.0.113.7"], "10.0.0.1"),
    (1, None, [], "unknown")
])
def test_the_client_address_reads_only_trusted_proxy_entries(hops, host, forwarded, address):

    assert client_address(request_from(host, forwarded), hops) == address


@pytest.mark.parametrize("hops", [0, 1])
def test_a_spoofed_forwarded_entry_does_not_escape_the_limit(tmp_path, hops):

    client, _ = stubbed(
        tmp_path,
        rate_limits_enabled=True,
        rate_limit_analyses=(1, 600),
        trusted_proxy_hops=hops
    )

    def post(forwarded):
        return client.post(
            "/api/analyses/sample", json=SAMPLE, headers={"X-Forwarded-For": forwarded}
        )

    with client:
        assert post("1.1.1.1, 203.0.113.7").status_code == 504
        assert post("2.2.2.2, 203.0.113.7").status_code == 429

        # behind one proxy another caller is another client; without one the
        # header means nothing and every request is the same connection's
        assert post("203.0.113.8").status_code == (504 if hops == 1 else 429)


def test_the_proxy_hops_cannot_be_negative():

    with pytest.raises(ValueError):
        Settings(_env_file=None, trusted_proxy_hops=-1)


def test_the_limits_are_read_from_the_environment(monkeypatch):

    monkeypatch.setenv("CAPSTONE_RATE_LIMITS_ENABLED", "true")
    monkeypatch.setenv("CAPSTONE_RATE_LIMIT_SCENARIOS", "[2, 1800]")
    monkeypatch.setenv("CAPSTONE_TRUSTED_PROXY_HOPS", "1")

    settings = Settings(_env_file=None)

    assert settings.rate_limits_enabled is True
    assert settings.rate_limit_scenarios == (2, 1800)
    assert settings.rate_limit_analyses == (20, 600)
    assert settings.trusted_proxy_hops == 1

    monkeypatch.setenv("CAPSTONE_RATE_LIMIT_SCENARIOS", "[0, 1800]")

    with pytest.raises(ValueError):
        Settings(_env_file=None)


# -- ANALYSER_COMMIT -------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("feedc0ffee12", "feedc0ffee12"),
    (" feedc0ffee12\n", "feedc0ffee12"),
    ("", None),
    ("  ", None)
])
def test_analyser_commit_is_read_from_the_environment(monkeypatch, value, expected):

    monkeypatch.setenv("ANALYSER_COMMIT", value)

    assert Settings(_env_file=None).analyser_commit == expected


def test_the_analyser_commit_falls_back_to_git_when_unset(tmp_path, monkeypatch):

    monkeypatch.delenv("ANALYSER_COMMIT", raising=False)

    service = AnalysisService(make_settings(tmp_path / "cache"), StubWorker())

    assert service._commit() == analyser_commit()


def test_a_set_analyser_commit_is_what_an_analysis_records(tmp_path, monkeypatch):

    monkeypatch.setenv("ANALYSER_COMMIT", "feedc0ffee12")

    with TestClient(create_app(make_settings(tmp_path / "cache"))) as client:
        created = client.post("/api/analyses/sample", json=SAMPLE)

    assert created.status_code == 201, created.text
    assert created.json()["analyser_commit"] == "feedc0ffee12"
