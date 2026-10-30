"""GET /api/analyses/{id}/report.pdf and the report builder behind it.

Text assertions run on what pypdf extracts from the rendered PDF, so they check
the document a reader gets, not the HTML. Layout quality (clipping, overflow,
chain breaks, fonts) is not something text can prove; it is reviewed by
rendering every page to PNG (see the report module's review notes).
"""

import copy
import io
import json
import re
import threading
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api import scenario_cache, scenario_contract as contract
from app.api.main import create_app
from app.api.report import pdf, router as report_router
from app.api.tests.conftest import SAMPLE_PATH, make_settings, upload


AVAILABLE, UNAVAILABLE_REASON = pdf.probe()

needs_weasyprint = pytest.mark.skipif(
    not AVAILABLE, reason="WeasyPrint cannot render here: %s" % UNAVAILABLE_REASON
)

pypdf = pytest.importorskip("pypdf")

GENERATED_AT = "2026-10-24T11:20:00Z"

SUPPRESSION_LABEL = (
    "Paths no longer at or above the selected risk level after suppressing this finding."
)


# ==============================================================================
# Helpers
# ==============================================================================

def read_pdf(data):
    return pypdf.PdfReader(io.BytesIO(data))


def page_texts(reader):
    return [page.extract_text() or "" for page in reader.pages]


def flat(text):
    """Extracted text with zero-width break hints removed and spaces collapsed."""

    return re.sub(r"\s+", " ", text.replace("​", "")).strip()


def squeezed(text):
    """Extracted text with every kind of whitespace removed, for long ids."""

    return re.sub(r"\s+", "", text.replace("​", ""))


def outline_titles(reader):
    titles = []

    def walk(items):
        for item in items:
            if isinstance(item, list):
                walk(item)
            else:
                titles.append(flat(item.title))

    walk(reader.outline)

    return titles


def path_headings(titles):
    """AP ids that have their own heading (bookmark) in the report."""

    return [
        match.group(1)
        for match in (re.match(r"^(AP-\d{3}) ", title) for title in titles)
        if match
    ]


def render(analysis, fix_impact=None, top=5, scenarios=None):
    context = pdf.build_context(
        analysis, fix_impact, top, scenarios or {}, generated_at=GENERATED_AT
    )

    return read_pdf(pdf.render_pdf(context))


def get_report(client, analysis_id, top=None):
    url = "/api/analyses/%s/report.pdf" % analysis_id

    return client.get(url, params={"top": top} if top is not None else None)


def scenario(text, new_tokens=900, hit_eos=True, prompt=None):
    """A Scenario payload as the API returns it, from fixed text. `prompt` is
    the prompt it was made from; a report only shows a scenario made from the
    path's own prompt."""

    provenance = contract.make_provenance(
        model_revision="a" * 40,
        adapter_repo="example/attack-scenarios",
        adapter_revision="b" * 40
    )

    response = contract.build_response(
        text=text, new_tokens=new_tokens, hit_eos=hit_eos, seconds=12.5,
        provenance=provenance
    )

    entry = contract.make_cache_entry(
        prompt=prompt or "prompt for %s" % text[:20],
        provenance=provenance,
        response=response,
        source="pregenerated",
        generated_at="2026-10-23T09:00:00+00:00"
    )

    return entry, contract.scenario_payload(entry)


def prompt_of(analysis, source_id):
    """The prompt for one path's export record."""

    return contract.build_prompt(
        next(p["export"] for p in analysis["paths"] if p["source_id"] == source_id)
    )


FULL_SCENARIO = (
    "[NATURAL LANGUAGE]\nThe attacker reaches the instance over SSH.\n"
    "[MATHEMATICAL EXPRESSION]\nreach(internet, PublicEC2Instance) => shell\n"
    "[ATTACK GRAPH]\nInternet -> OpenSecurityGroup -> PublicEC2Instance\n"
)

NO_GRAPH_SCENARIO = (
    "[NATURAL LANGUAGE]\nThe attacker reaches the instance over SSH.\n"
    "[MATHEMATICAL EXPRESSION]\nreach(internet, PublicEC2Instance) => shell\n"
)


# ==============================================================================
# Fixtures: the sample, rendered once per scope
# ==============================================================================

@pytest.fixture(scope="module")
def fixes5(shared_client, sample_analysis):
    response = shared_client.post("/api/analyses/%s/fixes?top=5" % sample_analysis["id"])

    assert response.status_code == 200, response.text

    return response.json()


@pytest.fixture(scope="module")
def report5(shared_client, sample_analysis, fixes5):
    """top=5, with the top=5 fix impact already computed."""

    if not AVAILABLE:
        pytest.skip(UNAVAILABLE_REASON)

    response = get_report(shared_client, sample_analysis["id"], "5")

    assert response.status_code == 200, response.text

    return response


@pytest.fixture(scope="module")
def reader5(report5):
    return read_pdf(report5.content)


@pytest.fixture(scope="module")
def text5(reader5):
    return flat(" ".join(page_texts(reader5)))


@pytest.fixture(scope="module")
def reader_all(shared_client, sample_analysis):
    """top=all, for which no fix impact has been computed."""

    if not AVAILABLE:
        pytest.skip(UNAVAILABLE_REASON)

    response = get_report(shared_client, sample_analysis["id"], "all")

    assert response.status_code == 200, response.text

    return read_pdf(response.content)


# ==============================================================================
# The HTTP contract
# ==============================================================================

@needs_weasyprint
def test_report_is_a_pdf_attachment_with_a_clean_filename(report5, sample_analysis):

    assert report5.headers["content-type"] == "application/pdf"
    assert report5.content.startswith(b"%PDF-")

    date = sample_analysis["created_at"][:10]

    assert report5.headers["content-disposition"] == (
        'attachment; filename="attack-path-assessment-cloudformation5-%s.pdf"' % date
    )


def test_filename_is_sanitized():

    analysis = {"input_name": '../..\\Évil "name"; rm -rf.yml', "created_at": "2026-10-24T10:00:00Z"}

    assert pdf.report_filename(analysis) == (
        "attack-path-assessment-evil-name-rm-rf-2026-10-24.pdf"
    )

    assert pdf.report_filename({"input_name": "", "created_at": "2026-01-02T00:00:00Z"}) == (
        "attack-path-assessment-template-2026-01-02.pdf"
    )


def test_unknown_analysis_is_404(client):

    response = get_report(client, "00000000-0000-4000-8000-000000000000")

    assert response.status_code == 404
    assert response.json() == {"detail": "Analysis not found."}


@pytest.mark.parametrize("top", ["0", "-1", "five", "1.5"])
def test_invalid_top_is_422(shared_client, sample_analysis, top):

    response = get_report(shared_client, sample_analysis["id"], top)

    assert response.status_code == 422
    assert "detail" in response.json()


def test_unavailable_renderer_is_503(client):

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    client.app.state.weasyprint = (False, "WeasyPrint is not installed.")

    response = get_report(client, analysis["id"])

    assert response.status_code == 503
    assert response.json() == {
        "detail": "PDF reports are unavailable: WeasyPrint is not installed."
    }

    health = client.get("/api/health").json()

    assert health["weasyprint"] is False
    assert health["pdf_unavailable_reason"] == "WeasyPrint is not installed."
    assert health["ok"] is True


@needs_weasyprint
def test_downloading_never_computes_fix_impact(client):

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    response = get_report(client, analysis["id"])

    assert response.status_code == 200

    assert "Impact estimates not included" in flat(
        " ".join(page_texts(read_pdf(response.content)))
    )

    # still not computed: the download did not start the computation
    assert client.get("/api/analyses/%s/fixes?top=5" % analysis["id"]).status_code == 404


# ==============================================================================
# Content: the sample at top=5, with impact
# ==============================================================================

@needs_weasyprint
def test_cover_carries_title_counts_and_provenance(reader5, sample_analysis):

    cover = flat(reader5.pages[0].extract_text())

    assert cover.startswith("SECURITY ASSESSMENT")
    assert "Attack Path Assessment" in cover
    assert "cloudformation5.yml" in cover
    assert sample_analysis["input_sha256"] in squeezed(cover)
    assert sample_analysis["industry"] in cover
    assert sample_analysis["analyser_commit"] in cover
    assert "22 findings" in cover
    assert "22 attack paths (19 at HIGH or above)" in cover
    assert "Top 5 of 19 selected paths" in cover


@needs_weasyprint
def test_summary_numbers_equal_the_saved_analysis(text5, sample_analysis):

    summary = sample_analysis["summary"]

    severities = ", ".join(
        "%d %s" % (count, severity)
        for severity, count in summary["findings_by_severity"].items()
        if count
    )

    assert (
        "The template defines %d resources connected by %d dependency edges."
        % (summary["resources"], summary["edges"])
    ) in text5

    assert (
        "The analyser raised %d findings (%s) and found %d attack paths "
        "(%d at HIGH or above) starting from %d entry points."
        % (
            summary["findings"], severities, summary["paths"],
            summary["paths_exported"], summary["entry_points"]
        )
    ) in text5

    assert "The highest path score is %s." % summary["top_score"] in text5

    # the level strip on the cover
    for level, count in summary["paths_by_level"].items():
        assert "%d %s" % (count, level) in text5

    # the plan's fixed sample numbers, so a drift in the analysis shows here too
    assert "22 findings" in text5
    assert "22 attack paths (19 at HIGH or above)" in text5


@needs_weasyprint
def test_sections_and_top_five_paths(reader5):

    titles = outline_titles(reader5)

    for heading in [
        "1 Executive summary",
        "2 Scope, method and assumptions",
        "3 Resource inventory",
        "4 Prioritised remediation",
        "5 Attack paths",
        "6 All findings"
    ]:
        assert heading in titles

    assert path_headings(titles) == ["AP-001", "AP-002", "AP-003", "AP-004", "AP-005"]


@needs_weasyprint
def test_paths_show_chain_breakdown_and_steps(text5, sample_analysis):

    first = sample_analysis["paths"][0]

    assert "AP-001 CRITICAL Ransomware or destruction" in text5
    assert "Score 56.04 = (findings 68 + objective 5) × length 0.614" in text5

    for step in first["steps"]:
        assert step["action"] in text5
        assert step["technique"] in text5

    for hop in first["hops"]:
        assert hop in squeezed(text5)

    assert "Same route as AP-002, other objective" in text5


@needs_weasyprint
def test_paths_show_their_contextual_risk_and_the_method_explains_it(text5):

    assert (
        "Contextual risk 55.5 (rank 3 of 11) from impact 50, exposure 90 (direct), "
        "path ease 30.12 · target not tagged"
    ) in text5

    assert text5.count("Contextual risk ") == 5

    assert "Contextual risk, a second opinion" in text5
    assert (
        "contextual risk = 100 × (impact/100)0.45 × (exposure/100)0.35 × (path ease/100)0.2"
    ) in text5
    assert "Its weights are provisional and not calibrated" in text5


def test_the_contextual_risk_line_names_only_the_tags_it_knows(sample_analysis):

    risk = dict(sample_analysis["paths"][0]["risk"])

    assert pdf.risk_tags(risk) == "target not tagged"

    risk.update(environment="prod", asset_criticality="high", sensitive_data=False)

    assert pdf.risk_tags(risk) == (
        "target tagged environment prod, high criticality, no sensitive data"
    )

    assert pdf.risk_block(risk, 11)["reachability"] == "direct"
    assert pdf.risk_block(None, 11) is None


@needs_weasyprint
def test_an_analysis_saved_before_contextual_risk_renders_without_it(sample_analysis):

    analysis = copy.deepcopy(sample_analysis)

    for path in analysis["paths"]:
        path["risk"] = None

    text = flat(" ".join(page_texts(render(analysis, top=2))))

    assert "AP-002" in text
    assert "ontextual" not in text


@needs_weasyprint
def test_cached_impact_is_used_with_the_precise_label(text5, fixes5, sample_analysis):

    assert SUPPRESSION_LABEL in text5
    assert "Impact estimates not included" not in text5
    assert "Suppression is not repair" in text5

    findings = {finding["id"]: finding for finding in sample_analysis["findings"]}

    top = fixes5["results"][0]

    assert "%s on %s: %d of %d selected paths no longer at or above HIGH" % (
        findings[top["finding_id"]]["rule"]["display_name"],
        findings[top["finding_id"]]["resource"],
        top["selected_paths_removed"],
        top["baseline_selected_paths"]
    ) in text5

    assert "Candidates: the %d findings on the top 5 selected paths." % (
        fixes5["candidate_count"]
    ) in text5


@needs_weasyprint
def test_every_page_has_content_and_the_running_footer(reader5, sample_analysis):

    texts = page_texts(reader5)
    total = len(texts)

    for number, text in enumerate(texts[1:], start=2):

        footer = "page %d of %d" % (number, total)

        assert footer in flat(text), number
        assert "analyser %s" % sample_analysis["analyser_commit"] in flat(text)
        assert "Template cloudformation5.yml" in flat(text)

        body = flat(text).replace(footer, "")

        assert len(body) > 200, "page %d is nearly empty" % number


@needs_weasyprint
def test_honest_wording(text5):

    assert "\u2014" not in text5  # no em dash anywhere
    assert "not calibrated" in text5
    assert "No AWS account was accessed" in text5
    assert "generated by a fine-tuned language model" in text5


# ==============================================================================
# Scopes
# ==============================================================================

@needs_weasyprint
def test_top_three(shared_client, sample_analysis):

    response = get_report(shared_client, sample_analysis["id"], "3")

    assert response.status_code == 200

    reader = read_pdf(response.content)

    assert path_headings(outline_titles(reader)) == ["AP-001", "AP-002", "AP-003"]
    assert "Top 3 of 19 selected paths" in flat(reader.pages[0].extract_text())


@needs_weasyprint
def test_all_selected_paths_without_impact(reader_all):

    titles = outline_titles(reader_all)
    text = flat(" ".join(page_texts(reader_all)))

    assert path_headings(titles) == ["AP-%03d" % rank for rank in range(1, 20)]
    assert "All 19 selected paths" in text

    # no result was computed for the "all" scope, so none is shown
    assert "Impact estimates not included" in text
    assert SUPPRESSION_LABEL not in text


@needs_weasyprint
def test_a_count_above_the_selected_paths_clamps(shared_client, sample_analysis):

    response = get_report(shared_client, sample_analysis["id"], "500")

    assert response.status_code == 200

    reader = read_pdf(response.content)

    assert len(path_headings(outline_titles(reader))) == 19
    assert "All 19 selected paths" in flat(reader.pages[0].extract_text())


def with_many_paths(analysis, count):
    """A copy of the analysis with `count` selected paths, ranked AP-001 up."""

    analysis = copy.deepcopy(analysis)

    template = [path for path in analysis["paths"] if path["exported"]]

    paths = []

    for index in range(count):
        path = copy.deepcopy(template[index % len(template)])
        path["source_id"] = "AP-%03d" % (index + 1)
        path["rank"] = index + 1
        paths.append(path)

    analysis["paths"] = paths
    analysis["summary"]["paths"] = analysis["summary"]["paths_exported"] = count

    return analysis


@pytest.mark.parametrize("top", ["all", 80, 51])
def test_paths_are_capped_and_the_report_says_so(sample_analysis, top):

    analysis = with_many_paths(sample_analysis, 120)

    context = pdf.build_context(analysis, None, top, {})

    assert len(context["paths"]) == pdf.MAX_REPORT_PATHS == 50
    assert context["paths"][-1]["source_id"] == "AP-050"
    assert context["scope"]["included"] == 50
    assert context["scope"]["label"] == "Top 50 of 120 selected paths"
    assert context["scope"]["cap_note"] == (
        "Showing the top 50 of 120 selected paths; see the app for the rest."
    )

    # Findings are not cut.
    assert sum(len(group["rows"]) for group in context["findings"]) == len(analysis["findings"])


def test_no_cap_note_when_every_path_in_scope_fits(sample_analysis):

    analysis = with_many_paths(sample_analysis, 120)

    for top in (50, 5):
        context = pdf.build_context(analysis, None, top, {})

        assert context["scope"]["cap_note"] is None

    assert pdf.build_context(sample_analysis, None, "all", {})["scope"]["cap_note"] is None


@needs_weasyprint
def test_a_report_of_more_paths_than_the_cap_renders_the_note_and_at_most_the_cap(sample_analysis):

    reader = render(with_many_paths(sample_analysis, 60), top="all")

    text = flat(" ".join(page_texts(reader)))

    assert text.count("Showing the top 50 of 60 selected paths; see the app for the rest.") == 2
    assert path_headings(outline_titles(reader)) == ["AP-%03d" % rank for rank in range(1, 51)]


@needs_weasyprint
def test_impact_for_another_scope_is_not_mixed_in(sample_analysis, fixes5):

    reader = render(sample_analysis, fixes5, top=3)

    text = flat(" ".join(page_texts(reader)))

    assert "Impact estimates not included" in text
    assert SUPPRESSION_LABEL not in text


# ==============================================================================
# Edge cases
# ==============================================================================

@needs_weasyprint
@pytest.mark.parametrize("top", [None, "all"])
def test_zero_paths_gives_a_findings_only_report(client, top):

    template = b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"

    analysis = upload(client, "lonely.yaml", template).json()

    assert analysis["summary"]["paths"] == 0

    response = get_report(client, analysis["id"], top)

    assert response.status_code == 200

    reader = read_pdf(response.content)
    titles = outline_titles(reader)
    text = flat(" ".join(page_texts(reader)))

    assert "Attack paths" not in " ".join(titles)
    assert path_headings(titles) == []
    assert "5 All findings" in titles
    assert "No attack path was found" in text
    assert "covers findings only" in text
    assert "%d findings" % analysis["summary"]["findings"] in text or (
        "1 finding" in text and analysis["summary"]["findings"] == 1
    )
    assert "No selected paths" in text


@needs_weasyprint
def test_empty_template_still_renders(client):

    analysis = upload(client, "empty.yaml", b"Resources: {}\n").json()

    response = get_report(client, analysis["id"])

    assert response.status_code == 200

    text = flat(" ".join(page_texts(read_pdf(response.content))))

    assert "0 findings" in text
    assert "No findings. Every rule passed" in text


@needs_weasyprint
def test_long_ids_and_evidence_render_in_full(sample_analysis):

    long_id = "Very" + "LongResourceIdentifier" * 6

    analysis = json.loads(
        json.dumps(sample_analysis).replace("OverPermissiveRole", long_id)
    )

    step = analysis["paths"][0]["steps"][0]

    step["evidence"].append({
        "key": "exposed_cidr_list",
        "value": ["10.%d.0.0/16" % index for index in range(40)]
    })

    step["evidence"].append({"key": "note", "value": "x" * 300})

    reader = render(analysis, top=1)

    text = squeezed(" ".join(page_texts(reader)))

    assert long_id in text
    assert "10.39.0.0/16" in text
    assert "x" * 300 in text


@needs_weasyprint
def test_missing_scenario_sections_are_labelled_honestly(sample_analysis):

    _, capped = scenario(NO_GRAPH_SCENARIO, new_tokens=1200, hit_eos=False)
    _, finished = scenario(NO_GRAPH_SCENARIO, new_tokens=640, hit_eos=True)
    _, full = scenario(FULL_SCENARIO)

    reader = render(
        sample_analysis, top=3,
        scenarios={"AP-001": capped, "AP-002": finished, "AP-003": full}
    )

    pages = [flat(text) for text in page_texts(reader)]
    text = " ".join(pages)

    assert text.count("AI-GENERATED Scenario narrative") == 3
    assert text.count("Attack graph section not generated.") == 2

    # the token-limit reason only where the cap was actually reached
    assert text.count("Generation stopped at the 1200-token limit") == 1

    assert "Internet -> OpenSecurityGroup -> PublicEC2Instance" in text
    assert "3 paths in this report have one." in text


@needs_weasyprint
def test_no_scenario_blocks_without_cached_scenarios(text5):

    assert "AI-GENERATED Scenario narrative" not in text5
    assert "None of the paths in this report has one." in text5


@needs_weasyprint
def test_linked_cached_scenarios_are_included(client, settings):

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    entry, _ = scenario(FULL_SCENARIO, prompt=prompt_of(analysis, "AP-002"))

    scenario_cache.merge_entry(settings.cache_dir, entry)
    scenario_cache.link(settings.cache_dir, analysis["id"], "AP-002", entry["cache_key"])

    response = get_report(client, analysis["id"], "3")

    assert response.status_code == 200

    text = flat(" ".join(page_texts(read_pdf(response.content))))

    assert text.count("AI-GENERATED Scenario narrative") == 1
    assert "The attacker reaches the instance over SSH." in text
    assert "pre-generated" in text


@needs_weasyprint
def test_untrusted_text_is_escaped_not_interpreted(client):

    industry = '<b>Bold</b> & "quoted" <img src="file:///etc/passwd">'

    analysis = upload(
        client, "<i>odd</i>.yaml", SAMPLE_PATH.read_bytes(), industry=industry
    ).json()

    response = get_report(client, analysis["id"], "1")

    assert response.status_code == 200

    text = flat(" ".join(page_texts(read_pdf(response.content))))

    assert industry in text


def test_the_url_fetcher_serves_only_packaged_assets():

    if not AVAILABLE:
        pytest.skip(UNAVAILABLE_REASON)

    module = pdf.weasyprint()

    fetcher = pdf.static_fetcher_class(module)(allowed_protocols=["file"])

    font = (pdf.STATIC_DIR / "fonts" / "Inter-Regular.woff2").resolve()

    assert fetcher.fetch(font.as_uri()).read()[:4] == b"wOF2"

    for url in [
        "file:///etc/passwd",
        (pdf.STATIC_DIR / ".." / "pdf.py").resolve().as_uri(),
        "https://example.com/font.woff2",
        "data:text/plain,hello"
    ]:
        with pytest.raises(ValueError):
            fetcher.fetch(url)


def test_build_context_is_pure_and_scoped(sample_analysis, fixes5):

    before = copy.deepcopy(sample_analysis)

    context = pdf.build_context(
        sample_analysis, fixes5, "all", {}, generated_at=datetime(2026, 10, 24, tzinfo=timezone.utc)
    )

    assert sample_analysis == before

    # fixes5 is for top=5, so it is not used for the "all" scope
    assert context["impact"] is None
    assert context["scope"] == {
        "requested": "all", "top": None, "selected": 19, "included": 19,
        "label": "All 19 selected paths", "cap_note": None
    }

    context = pdf.build_context(sample_analysis, fixes5, 5, {})

    assert context["impact"]["candidate_count"] == fixes5["candidate_count"]
    assert [path["source_id"] for path in context["paths"]] == [
        "AP-001", "AP-002", "AP-003", "AP-004", "AP-005"
    ]


# ==============================================================================
# One render at a time, on its own thread
# ==============================================================================

class FakeRender:
    """Stands in for build_report: records each call and holds it until released."""

    def __init__(self, hold=True):
        self.release = threading.Event()
        self.started = threading.Event()
        self.calls = []
        self.threads = []

        if not hold:
            self.release.set()

    def __call__(self, analysis, fix_impact, top, scenarios):
        self.calls.append(top)
        self.threads.append(threading.current_thread().name)
        self.started.set()
        self.release.wait(10)

        return b"%PDF-fake " + str(top).encode()


def wait_until(condition, timeout=10.0):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)

    return False


def in_thread(function, *args):
    outcome = {}

    thread = threading.Thread(target=lambda: outcome.update(response=function(*args)))
    thread.start()

    return thread, outcome


@pytest.fixture
def renderable(client, monkeypatch):
    """A client whose renders are FakeRender's, and one saved analysis."""

    fake = FakeRender()

    monkeypatch.setattr(report_router, "build_report", fake)

    client.app.state.weasyprint = (True, None)

    analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

    return client, analysis, fake


def test_a_second_render_while_one_runs_is_503_with_retry_after(renderable):

    client, analysis, fake = renderable

    first, outcome = in_thread(get_report, client, analysis["id"], "3")

    assert fake.started.wait(10)

    # another report, and even the same one, is turned away at once
    for top in ("2", "3"):
        busy = get_report(client, analysis["id"], top)

        assert busy.status_code == 503
        assert busy.headers["retry-after"] == "5"
        assert "being rendered" in busy.json()["detail"]

    fake.release.set()
    first.join(10)

    assert outcome["response"].status_code == 200
    assert outcome["response"].content == b"%PDF-fake 3"

    # the slot is free again
    assert get_report(client, analysis["id"], "2").status_code == 200


def test_a_render_runs_on_its_own_thread_and_never_blocks_the_analysis_worker(renderable):

    client, analysis, fake = renderable

    first, outcome = in_thread(get_report, client, analysis["id"], "3")

    assert fake.started.wait(10)

    # the analysis worker's wait, and every other route, still run at full speed
    started = time.monotonic()

    created = client.post(
        "/api/analyses/sample",
        json={"sample_id": "cloudformation5", "industry": "x"}
    )

    assert created.status_code == 201
    assert client.get("/api/health").json()["ok"] is True
    assert time.monotonic() - started < 15

    fake.release.set()
    first.join(10)

    assert fake.threads and all(name.startswith("pdf-render") for name in fake.threads)


def test_a_render_past_its_timeout_is_504_and_holds_the_slot_until_it_ends(
    tmp_path, monkeypatch
):

    fake = FakeRender()

    monkeypatch.setattr(report_router, "build_report", fake)

    app = create_app(make_settings(tmp_path / "cache", pdf_timeout_s=0.3))

    with TestClient(app) as client:

        app.state.weasyprint = (True, None)

        analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

        slow = get_report(client, analysis["id"], "3")

        assert slow.status_code == 504
        assert "longer than 0.3 seconds" in slow.json()["detail"]

        # the thread cannot be stopped, so the slot stays taken
        assert get_report(client, analysis["id"], "2").status_code == 503

        fake.release.set()

        assert wait_until(
            lambda: get_report(client, analysis["id"], "2").status_code == 200
        )


def test_a_repeat_download_is_served_without_rendering_again(renderable):

    client, analysis, fake = renderable

    fake.release.set()

    first = get_report(client, analysis["id"], "3")
    again = get_report(client, analysis["id"], "3")

    assert first.status_code == again.status_code == 200
    assert again.content == first.content
    assert fake.calls == ["3"]

    # a different scope is a different report
    assert get_report(client, analysis["id"], "4").status_code == 200
    assert fake.calls == ["3", "4"]

    # "all" and a count that reaches the selected count are one report
    get_report(client, analysis["id"], "all")
    get_report(client, analysis["id"], "19")
    get_report(client, analysis["id"], "500")

    assert fake.calls == ["3", "4", "all"]


def test_a_kept_report_is_not_reused_when_what_it_shows_changes(renderable, settings):

    client, analysis, fake = renderable

    fake.release.set()

    get_report(client, analysis["id"], "3")

    # a linked scenario for a shown path changes the report
    entry, _ = scenario(FULL_SCENARIO, prompt=prompt_of(analysis, "AP-002"))

    scenario_cache.merge_entry(settings.cache_dir, entry)
    scenario_cache.link(settings.cache_dir, analysis["id"], "AP-002", entry["cache_key"])

    get_report(client, analysis["id"], "3")

    # and so does a fix-impact result for the scope
    client.post("/api/analyses/%s/fixes?top=3" % analysis["id"])

    get_report(client, analysis["id"], "3")
    get_report(client, analysis["id"], "3")

    assert fake.calls == ["3", "3", "3"]


def test_the_pdf_finds_fix_impact_computed_under_either_spelling(shared_client, sample_analysis):
    """Impact computed for top=all is found by a report asked for top=50, and the
    other way round: one scope, one result."""

    for computed, requested in (("all", "50"), ("50", "all")):

        analysis = upload(shared_client, "b.yml", SAMPLE_PATH.read_bytes()).json()

        url = "/api/analyses/%s" % analysis["id"]

        assert shared_client.post(url + "/fixes?top=" + computed).status_code == 200

        fix_impact = shared_client.get(url + "/fixes?top=" + requested).json()

        context = pdf.build_context(analysis, fix_impact, requested, {})

        assert context["impact"] is not None
        assert context["scope"]["top"] is None
        assert context["impact"]["scope"] == "every selected path"


def test_only_a_render_counts_toward_the_report_limit(tmp_path, monkeypatch):

    fake = FakeRender(hold=False)

    monkeypatch.setattr(report_router, "build_report", fake)

    settings = make_settings(
        tmp_path / "cache", rate_limits_enabled=True, rate_limit_reports=(2, 600)
    )
    app = create_app(settings)

    with TestClient(app) as client:

        app.state.weasyprint = (True, None)

        analysis = upload(client, "a.yml", SAMPLE_PATH.read_bytes()).json()

        # a repeat is served from what was kept, and costs nothing
        for top in ("3", "3", "4", "4"):
            assert get_report(client, analysis["id"], top).status_code == 200

        over = get_report(client, analysis["id"], "2")

        assert over.status_code == 429
        assert int(over.headers["Retry-After"]) > 0
        assert "PDF reports" in over.json()["detail"]
        assert get_report(client, analysis["id"], "3").status_code == 200

    assert fake.calls == ["3", "4"]
