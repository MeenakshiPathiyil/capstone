"""GET and POST /api/analyses/{id}/fixes: suppression impact, cached per scope."""

import copy
import json

import pytest

from app.api import analysis as analysis_module
from app.api.tests.conftest import INDUSTRY, SAMPLE_PATH, upload


@pytest.fixture(scope="module")
def top5(shared_client, sample_analysis):
    """Fix impact for the default scope, computed once for the module."""

    response = shared_client.post("/api/analyses/%s/fixes?top=5" % sample_analysis["id"])

    assert response.status_code == 200, response.text

    return response.json()


def test_not_computed_is_404_then_computed_is_served(client):

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    url = "/api/analyses/%s/fixes" % analysis["id"]

    assert client.get(url).status_code == 404

    computed = client.post(url)

    assert computed.status_code == 200
    assert client.get(url).json() == computed.json()

    # a second POST serves the saved result rather than recomputing
    assert client.post(url).json()["computed_at"] == computed.json()["computed_at"]


def test_the_default_scope_draws_candidates_from_the_top_five(top5, sample_analysis):

    assert top5["analysis_id"] == sample_analysis["id"]
    assert top5["scope_top"] == 5

    paths = {path["source_id"]: path for path in sample_analysis["paths"]}

    in_scope = {
        finding_id
        for path in sample_analysis["paths"][:5]
        for finding_id in path["finding_ids"]
    }

    assert {result["finding_id"] for result in top5["results"]} == in_scope
    assert top5["candidate_count"] == len(in_scope)

    findings = {finding["id"]: finding for finding in sample_analysis["findings"]}

    for result in top5["results"]:

        assert result["scope_top"] == 5
        assert result["baseline_selected_paths"] == 19
        assert result["selected_paths_removed"] == len(result["removed_ids"])
        assert (
            result["selected_paths_remaining"] + result["selected_paths_removed"] == 19
        )
        assert result["selected_paths_added"] == len(result["added_paths"])

        # suppressing a finding can only remove a path that walks its resource
        resource = findings[result["finding_id"]]["resource"]

        for source_id in result["removed_ids"]:
            assert paths[source_id]["exported"]
            assert resource in paths[source_id]["hops"]


def test_results_are_ranked_by_paths_removed(top5):

    removed = [result["selected_paths_removed"] for result in top5["results"]]

    assert removed == sorted(removed, reverse=True)
    assert removed[0] > 0


# -- How a suppression is judged -----------------------------------------------------
#
# fixes_job re-searches once per candidate finding. These tests script that
# re-search (one scripted outcome per suppressed finding, over the sample's real
# ranked paths) so each way a selected set can change is exercised exactly.

SAMPLE_TEXT = SAMPLE_PATH.read_text(encoding="utf-8")


def drop_below_threshold(paths, index):
    """The same paths, one of them now scored MEDIUM (below the HIGH selection)."""

    paths[index]["attack_level"] = "MEDIUM"

    return paths


def disappear(paths, index):
    """The same paths without one: the search no longer finds it."""

    del paths[index]

    return paths


def add_new_path(paths):
    """The same paths plus one with a hop chain the baseline never had."""

    new = copy.deepcopy(paths[0])
    new["hops"] = ["OpenSecurityGroup", "SomewhereNew"]
    new["attack_level"] = "CRITICAL"

    return paths + [new]


@pytest.fixture
def scripted(monkeypatch):
    """(real, run): the real analysis, and run(outcomes) -> fixes_job's results.

    outcomes maps a candidate's index (in fixes_job's own candidate order) to
    a function that turns the baseline's ranked paths into what the search
    finds with that finding suppressed.
    """

    import attack_path.path_finder as path_finder
    import security_state_graph.state_graph as state_graph

    records, _ = analysis_module.records_from_text(SAMPLE_TEXT, 500)
    real = analysis_module.run_pipeline_on(records, INDUSTRY, "HIGH")
    ids = analysis_module.assign_finding_ids(real.state_graph)

    everything = {(f["resource"], f["rule_id"]) for f in real.findings}

    real_graph = state_graph.SecurityStateGraph
    real_search = path_finder.find_attack_paths

    class Reduced:
        def __init__(self, infra, findings):
            (self.suppressed,) = everything - {
                (f["resource"], f["rule_id"]) for f in findings
            }

    def graph(infra, findings):
        if len(findings) < len(real.findings):
            return Reduced(infra, findings)

        return real_graph(infra, findings)

    def run(outcomes, scope_top=5):

        candidates = []

        for path in real.selected[:scope_top]:
            for finding in path["states"]:
                key = (finding["resource"], finding["rule_id"])
                if key not in candidates:
                    candidates.append(key)

        by_key = {candidates[index]: outcome for index, outcome in outcomes.items()}

        def search(graph_):

            if not isinstance(graph_, Reduced):
                return real_search(graph_)

            outcome = by_key.get(graph_.suppressed)

            return outcome(copy.deepcopy(real.paths)) if outcome else copy.deepcopy(real.paths)

        monkeypatch.setattr(state_graph, "SecurityStateGraph", graph)
        monkeypatch.setattr(path_finder, "find_attack_paths", search)

        body = analysis_module.fixes_job({
            "source": {"kind": "upload", "text": SAMPLE_TEXT},
            "industry": INDUSTRY,
            "min_level": "HIGH",
            "max_resources": 500,
            "scope_top": scope_top,
            "saved_paths": [[p["hops"], p["objective"]] for p in real.paths]
        })

        return {
            result["finding_id"]: result for result in body["results"]
        }, [ids[key] for key in candidates]

    return real, run


def test_a_path_that_drops_below_the_threshold_and_one_that_disappears_both_count(scripted):

    real, run = scripted

    results, candidates = run({
        0: lambda paths: drop_below_threshold(paths, 5),
        1: lambda paths: disappear(paths, 7)
    })

    dropped, gone = results[candidates[0]], results[candidates[1]]

    # AP-006 is still found but no longer selected; AP-008 is not found at all.
    assert dropped["removed_ids"] == ["AP-006"]
    assert gone["removed_ids"] == ["AP-008"]

    for result in (dropped, gone):
        assert result["selected_paths_removed"] == 1
        assert result["selected_paths_remaining"] == 18
        assert result["selected_paths_added"] == 0
        assert result["baseline_selected_paths"] == 19


def test_a_rank_shift_is_not_mistaken_for_changed_paths(scripted):
    """Removing the top path moves every other path up one rank. Compared by
    rank, 18 paths would look changed; by hops and objective, exactly one is."""

    real, run = scripted

    results, candidates = run({0: lambda paths: disappear(paths, 0)})

    shifted = results[candidates[0]]

    assert shifted["removed_ids"] == ["AP-001"]
    assert shifted["selected_paths_removed"] == 1
    assert shifted["selected_paths_remaining"] == 18
    assert shifted["selected_paths_added"] == 0
    assert shifted["added_paths"] == []


def test_a_newly_selected_path_is_reported_as_added(scripted):

    real, run = scripted

    results, candidates = run({0: add_new_path})

    added = results[candidates[0]]

    assert added["selected_paths_added"] == 1
    assert added["added_paths"] == [{
        "hops": ["OpenSecurityGroup", "SomewhereNew"],
        "objective": real.paths[0]["objective"]
    }]
    assert added["selected_paths_removed"] == 0
    assert added["removed_ids"] == []
    assert added["selected_paths_remaining"] == 19


def test_paths_with_identical_hops_but_different_objectives_are_different_paths(scripted):

    real, run = scripted

    selected = [(tuple(p["hops"]), p["objective"]) for p in real.selected]

    # The first selected path that shares its hop chain with an earlier one
    # under another objective.
    later = next(
        index for index, (hops, objective) in enumerate(selected)
        if any(
            hops == earlier_hops and objective != earlier_objective
            for earlier_hops, earlier_objective in selected[:index]
        )
    )

    earlier = selected.index(next(
        identity for identity in selected[:later] if identity[0] == selected[later][0]
    ))

    results, candidates = run({0: lambda paths: disappear(paths, later)})

    result = results[candidates[0]]

    # Only the later objective's path is gone; the one on the same hops stays.
    assert result["removed_ids"] == ["AP-%03d" % (later + 1)]
    assert "AP-%03d" % (earlier + 1) not in result["removed_ids"]
    assert result["selected_paths_removed"] == 1
    assert result["selected_paths_remaining"] == 18
    assert result["selected_paths_added"] == 0


def test_a_suppression_that_changes_nothing_reports_nothing(scripted):

    _, run = scripted

    results, candidates = run({})

    for finding_id in candidates:
        assert results[finding_id]["selected_paths_removed"] == 0
        assert results[finding_id]["selected_paths_added"] == 0
        assert results[finding_id]["removed_ids"] == []


def fixes_files(module_cache, analysis_id):
    return sorted(
        path.name
        for path in (module_cache / "analyses" / analysis_id).glob("fixes-top-*.json")
    )


def test_a_count_that_reaches_the_selected_count_is_the_all_scope(
    shared_client, sample_analysis, top5, module_cache
):

    url = "/api/analyses/%s/fixes" % sample_analysis["id"]

    everything = shared_client.post(url + "?top=all").json()

    # "all" means every selected path: null, whatever the count is
    assert everything["scope_top"] is None
    assert everything["candidate_count"] >= top5["candidate_count"]

    # 19 is the selected count, 50 is above it: both are the same scope, so the
    # saved "all" result is returned rather than another computed
    for spelling in ("19", "20", "50", "999999"):
        assert shared_client.get(url + "?top=" + spelling).json() == everything
        assert shared_client.post(url + "?top=" + spelling).json() == everything

    # a count below the selected count is its own scope
    assert shared_client.get(url + "?top=5").json() == top5
    assert shared_client.get(url + "?top=3").status_code == 404
    assert shared_client.get(url + "?top=18").status_code == 404

    # one file per scope; none named for the clamped count
    assert fixes_files(module_cache, sample_analysis["id"]) == [
        "fixes-top-5.json", "fixes-top-all.json"
    ]


def test_posting_a_count_above_the_selected_count_computes_the_all_scope_once(client):

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    url = "/api/analyses/%s/fixes" % analysis["id"]

    first = client.post(url + "?top=50").json()

    assert first["scope_top"] is None
    assert client.get(url + "?top=all").json() == first
    assert client.post(url + "?top=19").json()["computed_at"] == first["computed_at"]


@pytest.mark.parametrize("top", ["0", "-1", "five", "1.5"])
def test_a_bad_scope_is_422(shared_client, sample_analysis, top):

    response = shared_client.get(
        "/api/analyses/%s/fixes?top=%s" % (sample_analysis["id"], top)
    )

    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)


def test_zero_selected_paths_give_an_empty_result(client):

    analysis = upload(client, "empty.yaml", b"Resources: {}\n").json()

    response = client.post("/api/analyses/%s/fixes?top=all" % analysis["id"])

    assert response.status_code == 200
    assert response.json()["results"] == []
    assert response.json()["candidate_count"] == 0


def test_fixes_follow_the_analysis_options(client):

    response = client.post(
        "/api/analyses/sample",
        json={"sample_id": "cloudformation5", "industry": INDUSTRY,
              "min_level": "CRITICAL"}
    )

    analysis = response.json()

    result = client.post("/api/analyses/%s/fixes?top=all" % analysis["id"]).json()

    assert {item["baseline_selected_paths"] for item in result["results"]} == {14}


# -- Scope on an analysis with nothing selected -------------------------------------

def test_with_nothing_selected_every_scope_is_the_one_all_scope(client, settings):

    analysis = upload(client, "empty.yaml", b"Resources: {}\n").json()

    url = "/api/analyses/%s/fixes" % analysis["id"]

    for top in ("1", "42", "999999", "all"):
        response = client.post(url + "?top=" + top)

        assert response.status_code == 200
        assert response.json()["scope_top"] is None

    files = sorted(
        path.name
        for path in (settings.analyses_dir / analysis["id"]).glob("fixes-top-*.json")
    )

    assert files == ["fixes-top-all.json"]


@pytest.mark.parametrize("top", ["9" * 7, "9" * 300, "9" * 5000])
def test_a_top_with_too_many_digits_is_422_not_a_file_name_error(client, top):

    analysis = upload(client, "empty.yaml", b"Resources: {}\n").json()

    for method in (client.get, client.post):

        response = method("/api/analyses/%s/fixes?top=%s" % (analysis["id"], top))

        assert response.status_code == 422
        assert isinstance(response.json()["detail"], str)


# -- Fix impact re-runs from the stored input, never from the repo -------------------

def in_process(service):
    """Run the service's worker jobs in this process, where a monkeypatch of the
    repo's sample paths is visible, instead of in a spawned child."""

    async def run(kind, payload, timeout):

        job = {
            "analysis": analysis_module.analysis_job,
            "fixes": analysis_module.fixes_job
        }[kind]

        return json.loads(json.dumps(job(json.loads(json.dumps(payload)))))

    service.worker.run = run


@pytest.mark.parametrize("sample_id", ["cloudformation5", "nested"])
def test_a_sample_is_re_run_from_its_stored_input(client, tmp_path, monkeypatch, sample_id):

    created = client.post(
        "/api/analyses/sample", json={"sample_id": sample_id, "industry": INDUSTRY}
    )

    assert created.status_code == 201, created.text

    saved = created.json()
    fixes_url = "/api/analyses/%s/fixes?top=all" % saved["id"]

    before = client.post(fixes_url).json()

    service = client.app.state.analyses

    # From now on the repo has no such sample: any read of it would fail.
    missing = tmp_path / "gone" / "parent.yaml"

    monkeypatch.setitem(analysis_module.SAMPLES[sample_id], "path", missing)

    source = service._stored_source(saved["id"], service._manifest(saved["id"]))

    assert source["kind"] in ("upload", "records")

    in_process(service)

    # fix impact, recomputed
    (service.store.directory(saved["id"]) / "fixes-top-all.json").unlink()

    after = client.post(fixes_url)

    assert after.status_code == 200, after.text
    assert after.json()["results"] == before["results"]

    # rebuild: an unsupported schema version makes GET re-run the analysis
    stored = service.store.read_json(saved["id"], "analysis.json")
    stored["schema_version"] = 0
    service.store.replace_json(saved["id"], "analysis.json", stored)

    rebuilt = client.get("/api/analyses/%s" % saved["id"])

    assert rebuilt.status_code == 200, rebuilt.text
    assert rebuilt.json() == saved


def test_a_nested_sample_keeps_its_provenance_hashes(client):

    saved = client.post(
        "/api/analyses/sample", json={"sample_id": "nested", "industry": INDUSTRY}
    ).json()

    manifest = client.app.state.analyses._manifest(saved["id"])

    assert manifest["nested_inputs"]
    assert all(len(item["sha256"]) == 64 for item in manifest["nested_inputs"])
    assert manifest["nested_report"] == saved["nested_report"]
    assert manifest["input_sha256"]


def test_a_nested_analysis_without_its_stored_merge_is_409(client):

    saved = client.post(
        "/api/analyses/sample", json={"sample_id": "nested", "industry": INDUSTRY}
    ).json()

    service = client.app.state.analyses

    manifest = service._manifest(saved["id"])
    del manifest["nested_report"]
    service.store.replace_json(saved["id"], "manifest.json", manifest)

    response = client.post("/api/analyses/%s/fixes?top=all" % saved["id"])

    assert response.status_code == 409
    assert "no readable input" in response.json()["detail"]


# -- The saved analysis and the re-run must agree ------------------------------------

def test_fixes_are_refused_when_the_analyser_now_ranks_the_paths_differently(client):

    saved = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    service = client.app.state.analyses

    # What an older analyser would have saved: the first two paths the other way round.
    stored = service.store.read_json(saved["id"], "analysis.json")
    stored["paths"][0], stored["paths"][1] = stored["paths"][1], stored["paths"][0]
    service.store.replace_json(saved["id"], "analysis.json", stored)

    response = client.post("/api/analyses/%s/fixes?top=all" % saved["id"])

    assert response.status_code == 409
    assert response.json() == {"detail": analysis_module.OLDER_ANALYSER_MESSAGE}
    assert "upload the template again" in response.json()["detail"]

    # nothing was saved for it
    assert not list(service.store.directory(saved["id"]).glob("fixes-top-*.json"))


def test_fixes_job_checks_hops_and_objective_in_order(monkeypatch):

    records, _ = analysis_module.records_from_text(SAMPLE_TEXT, 500)
    real = analysis_module.run_pipeline_on(records, INDUSTRY, "HIGH")

    saved = [[p["hops"], p["objective"]] for p in real.paths]

    def payload(paths):
        return {
            "source": {"kind": "upload", "text": SAMPLE_TEXT},
            "industry": INDUSTRY,
            "min_level": "HIGH",
            "max_resources": 500,
            "scope_top": 1,
            "saved_paths": paths
        }

    assert analysis_module.fixes_job(payload(saved))["results"]

    changed_objective = copy.deepcopy(saved)
    changed_objective[3][1] = "another_objective"

    reordered = copy.deepcopy(saved)
    reordered.reverse()

    shorter = saved[:-1]

    for paths in (changed_objective, reordered, shorter):
        with pytest.raises(analysis_module.InputError) as caught:
            analysis_module.fixes_job(payload(paths))

        assert caught.value.status == 409
