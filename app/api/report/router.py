"""GET /api/analyses/{id}/report.pdf: the saved analysis as a PDF assessment.

Reads only what is already saved: the analysis, a fix-impact result for the
same scope if one was computed, and scenarios already linked to the analysis's
paths in the local cache. Downloading a report never computes fix impact and
never asks the model for anything.
"""

import asyncio
import logging
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from app.api import scenario_cache, scenario_contract, schemas
from app.api.rate_limit import admission
from app.api.report import pdf
from app.api.worker import JobError


log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyses", tags=["report"])

ReportTop = Annotated[
    str,
    Query(
        pattern=r"^([1-9][0-9]{0,5}|all)$",
        description="How many of the top selected paths to detail, or \"all\". "
                    "A value that reaches the selected count means all of them; "
                    "at most 50 paths are detailed, and the report says when "
                    "it shows fewer than were asked for. With no selected "
                    "paths the report covers findings only.",
    )
]

# Rendered reports kept for repeat downloads of the same report.
RENDERED_KEPT = 4


class Renderer:
    """One PDF render at a time, off the event loop's default thread pool.

    A render is CPU and memory heavy (a 50-path report takes about 7 s; the
    report detail is capped at 50 paths because the cost grows faster than
    the path count), so a second request while one runs gets 503 at once. The render has
    its own single thread, so it cannot take a thread the analysis worker's
    wait needs. A thread cannot be stopped: after a timeout the request ends
    with 504 but the slot stays taken until the thread really finishes.

    Finished reports are kept by everything they were built from, so a repeat
    download costs nothing and never waits for the slot.
    """

    def __init__(self, retry_after_s, timeout_s):
        self.retry_after_s = retry_after_s
        self.timeout_s = timeout_s

        self._slot = asyncio.Semaphore(1)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pdf-render")
        self._kept = OrderedDict()

    def shutdown(self):
        self._executor.shutdown(wait=False, cancel_futures=True)

    async def render(self, key, function, *args, admit=None):
        """The PDF bytes for `key`: kept, or built by function(*args) in the slot.

        admit (a rate limit) is called only when a render is about to start.
        """

        if key in self._kept:
            self._kept.move_to_end(key)
            return self._kept[key]

        # No await between the check and the acquire, so this cannot race.
        if self._slot.locked():
            raise JobError(
                503,
                "Another report is being rendered. Try again shortly.",
                {"Retry-After": str(self.retry_after_s)}
            )

        if admit is not None:
            admit()

        await self._slot.acquire()

        work = asyncio.get_running_loop().run_in_executor(self._executor, function, *args)

        def finished(done):
            self._slot.release()

            if not done.cancelled():
                done.exception()

        work.add_done_callback(finished)

        try:
            data = await asyncio.wait_for(asyncio.shield(work), self.timeout_s)

        except TimeoutError:
            raise JobError(
                504, "The report took longer than %g seconds and was stopped."
                % self.timeout_s
            ) from None

        self._kept[key] = data

        while len(self._kept) > RENDERED_KEPT:
            self._kept.popitem(last=False)

        return data


def cached_scenarios(cache_root, analysis_id, records):
    """{AP id: Scenario} for the paths that already have a linked scenario.

    records is {AP id: export record} for the paths to look up. A link whose
    entry was made from a different prompt than the path's record now is
    ignored, as is an unreadable or invalid cache entry (logged); neither fails
    the download.
    """

    try:
        links = scenario_cache.read_links(cache_root, analysis_id)

    except (scenario_cache.CacheError, ValueError) as error:
        log.warning("Scenario links for %s unreadable: %s", analysis_id, error)
        return {}

    scenarios = {}

    for source_id, record in records.items():

        key = links.get(source_id)

        if key is None:
            continue

        try:
            entry = scenario_cache.read_entry(cache_root, key)

            if entry is None or not scenario_cache.entry_matches(entry, record):
                continue

            scenarios[source_id] = schemas.Scenario.model_validate(
                scenario_contract.scenario_payload(entry)
            ).model_dump(mode="json")

        except (scenario_cache.CacheError, ValueError) as error:
            log.warning("Scenario %s for %s left out: %s", key[:12], source_id, error)

    return scenarios


def selected_records(analysis):
    """{AP id: export record} of the selected paths."""

    return {
        path["source_id"]: path["export"]
        for path in analysis["paths"]
        if path["exported"] and path["export"]
    }


def build_report(analysis, fix_impact, top, scenarios):
    """PDF bytes. Blocking: layout and rendering, run in the render thread."""

    context = pdf.build_context(analysis, fix_impact, top, scenarios)

    return pdf.render_pdf(context)


@router.get(
    "/{analysis_id}/report.pdf",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}},
            "description": "The assessment as a PDF attachment, named "
                           "attack-path-assessment-<template>-<analysis date>.pdf."
        },
        **{
            code: {"model": schemas.ErrorResponse, "description": "Error"}
            for code in (404, 409, 422, 429, 503, 504)
        }
    }
)
async def get_report(request: Request, analysis_id: str, top: ReportTop = "5"):
    """The saved analysis as a PDF security assessment.

    Includes fix impact only when a result for the same scope was already
    computed (POST /fixes); otherwise the report says "Impact estimates not
    included". Scenarios appear only for paths that already have one cached.
    One report renders at a time; another request meanwhile is 503 with
    Retry-After. A repeat of a finished report is served without rendering
    and does not count toward the per-client report limit (429).
    """

    state = request.app.state
    service = state.analyses

    # An unknown analysis is 404 whether or not this machine can render.
    analysis = await service.get(analysis_id)

    if getattr(state, "weasyprint", None) is None:
        state.weasyprint = await asyncio.to_thread(pdf.probe)

    available, reason = state.weasyprint

    if not available:
        raise JobError(503, "PDF reports are unavailable: %s" % reason)

    # Same scope normalization as the fixes endpoint, so top=50 finds the
    # result saved for the clamped scope. Never computes anything.
    fix_impact = await service.cached_fixes(analysis_id, top)

    scenarios = await asyncio.to_thread(
        cached_scenarios,
        state.settings.cache_dir,
        analysis_id,
        selected_records(analysis)
    )

    # Everything the report is built from, so a changed input is a new report.
    key = (
        analysis_id,
        analysis["created_at"],
        analysis["analyser_commit"],
        pdf.normalize_top(top, analysis["summary"]["paths_exported"])[0],
        fix_impact["computed_at"] if fix_impact else None,
        tuple(sorted((source_id, item["cache_key"]) for source_id, item in scenarios.items()))
    )

    data = await state.renderer.render(
        key, build_report, analysis, fix_impact, top, scenarios,
        admit=admission(request, "reports")
    )

    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="%s"' % pdf.report_filename(analysis),
            "Cache-Control": "no-store"
        }
    )
