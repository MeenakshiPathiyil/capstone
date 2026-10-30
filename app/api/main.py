"""The FastAPI app. `create_app()` builds one; `app` is the default for uvicorn.

Routes are grouped into one APIRouter per area (meta, analyses) and included in
create_app. A new area adds its own router module and one include_router line.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse
from pydantic.json_schema import models_json_schema
from starlette.datastructures import Headers, MutableHeaders

from app.api import scenarios, schemas
from app.api.rate_limit import RateLimiter, admission
from app.api.analysis import (
    ACCEPTED_EXTENSIONS,
    INDUSTRIES,
    SAMPLES,
    UNEXPECTED_MESSAGE,
    AnalysisService
)
from app.api.config import WEB_DIST_DIR, Settings
from app.api.report import pdf as report_pdf
from app.api.report.router import Renderer, router as report_router
from app.api.worker import JobError, Worker


log = logging.getLogger(__name__)

TITLE = "Capstone attack path analyser"
VERSION = "0.1.0"

# Multipart framing and the form fields around the file. The file itself is
# checked against max_upload_bytes exactly once it is read.
MULTIPART_OVERHEAD_BYTES = 64 * 1024

TOO_LARGE = "The file is larger than the %d byte limit."

TopQuery = Annotated[
    str,
    Query(
        pattern=r"^([1-9][0-9]{0,5}|all)$",
        description="How many of the top selected paths to draw candidates from, "
                    "or \"all\". A value that reaches the selected count is the "
                    "same scope as \"all\".",
    )
]


def errors(*codes):
    """OpenAPI entries for the error statuses a route can return."""

    return {
        code: {"model": schemas.ErrorResponse, "description": "Error"}
        for code in codes
    }


def service(request: Request) -> AnalysisService:
    return request.app.state.analyses


# ==============================================================================
# Meta and health
# ==============================================================================

meta_router = APIRouter(prefix="/api", tags=["meta"])


@meta_router.get("/meta", response_model=schemas.Meta)
def get_meta(request: Request):
    """Styles, enums, samples and limits the web app needs before anything else."""

    from attack_path.exporter import DEFAULT_INDUSTRY
    from attack_path.path_finder import load_objectives
    from attack_path.renderer import SEVERITY_STYLES
    from attack_path.scoring import ATTACK_LEVELS

    settings = request.app.state.settings

    return {
        "severity_styles": SEVERITY_STYLES,
        "attack_levels": ATTACK_LEVELS,
        "objectives": [
            {
                "id": objective["id"],
                "name": objective["name"],
                "base_weight": float(objective.get("base_weight") or 0.0)
            }
            for objective in load_objectives()
        ],
        "industries": [DEFAULT_INDUSTRY] + [
            industry for industry in INDUSTRIES if industry != DEFAULT_INDUSTRY
        ],
        "default_industry": DEFAULT_INDUSTRY,
        "samples": [
            {
                "id": sample_id,
                "name": sample["name"],
                "description": sample["description"],
                "kind": sample["kind"]
            }
            for sample_id, sample in SAMPLES.items()
        ],
        "limits": {
            "max_upload_bytes": settings.max_upload_bytes,
            "max_resources": settings.max_resources,
            "accepted_extensions": ACCEPTED_EXTENSIONS
        }
    }


def probe_weasyprint():
    """(available, reason): renders one tiny page, cached per process."""

    return report_pdf.probe()


@meta_router.get("/health", response_model=schemas.Health)
async def get_health(request: Request):
    """Core readiness, plus the optional PDF and model capabilities.

    The PDF probe runs once per app and is cached. Neither optional capability
    can make `ok` false.
    """

    state = request.app.state

    if state.weasyprint is None:
        state.weasyprint = await asyncio.to_thread(probe_weasyprint)

    available, reason = state.weasyprint

    return {
        "ok": True,
        "weasyprint": available,
        "pdf_unavailable_reason": reason,
        # Cached Space stage and quota; never waits on Hugging Face.
        **state.scenarios.health()
    }


# ==============================================================================
# Analyses
# ==============================================================================

analyses_router = APIRouter(prefix="/api/analyses", tags=["analyses"])


def created(response, analysis):
    response.headers["Location"] = "/api/analyses/%s" % analysis["id"]
    return analysis


@analyses_router.post(
    "",
    status_code=201,
    response_model=schemas.Analysis,
    responses=errors(413, 415, 422, 429, 503, 504)
)
async def create_analysis(
    request: Request,
    response: Response,
    file: Annotated[UploadFile, File(description="A CloudFormation template.")],
    industry: Annotated[str, Form(max_length=200)],
    min_level: Annotated[schemas.AttackLevel, Form()] = "HIGH"
):
    """Analyse one uploaded template and save the result."""

    limit = request.app.state.settings.max_upload_bytes

    # One byte past the limit is enough to know it is too large.
    data = await file.read(limit + 1)

    return created(
        response,
        await service(request).create_from_upload(
            file.filename, data, industry, min_level, admission(request, "analyses")
        )
    )


@analyses_router.post(
    "/sample",
    status_code=201,
    response_model=schemas.Analysis,
    responses=errors(404, 413, 422, 429, 503, 504)
)
async def create_sample_analysis(
    request: Request,
    response: Response,
    body: schemas.SampleRequest
):
    """Analyse one of the bundled samples (see GET /api/meta) and save the result."""

    return created(
        response,
        await service(request).create_from_sample(
            body.sample_id, body.industry, body.min_level, admission(request, "analyses")
        )
    )


@analyses_router.get(
    "/{analysis_id}",
    response_model=schemas.Analysis,
    responses=errors(404, 409, 422, 503, 504)
)
async def get_analysis(request: Request, analysis_id: str):
    """A saved analysis, as it was saved."""

    return await service(request).get(analysis_id)


@analyses_router.get(
    "/{analysis_id}/graph",
    response_model=schemas.GraphView,
    responses=errors(404, 409, 422, 503, 504)
)
async def get_graph(
    request: Request,
    analysis_id: str,
    view: Literal["state", "attack"] = "state"
):
    """The resource graph (`state`) or the attacker-state graph (`attack`)."""

    return await service(request).graph(analysis_id, view)


@analyses_router.get(
    "/{analysis_id}/fixes",
    response_model=schemas.FixImpactResult,
    responses=errors(404, 409, 422, 503, 504)
)
async def get_fixes(request: Request, analysis_id: str, top: TopQuery = "5"):
    """Fix impact for this scope if it has been computed; 404 if not."""

    cached = await service(request).cached_fixes(analysis_id, top)

    if cached is None:
        raise JobError(404, "Fix impact for top=%s has not been computed." % top)

    return cached


@analyses_router.post(
    "/{analysis_id}/fixes",
    response_model=schemas.FixImpactResult,
    responses=errors(404, 409, 422, 429, 503, 504)
)
async def compute_fixes(request: Request, analysis_id: str, top: TopQuery = "5"):
    """Compute fix impact for this scope, or return the saved result.

    Each candidate finding is suppressed in turn and the selected paths are
    found again. That models removing the evidence, not a verified repair.
    """

    return await service(request).compute_fixes(
        analysis_id, top, admission(request, "analyses")
    )


# ==============================================================================
# The app
# ==============================================================================

class UploadLimit:
    """Refuse a request body past the limit while it streams in.

    Content-Length alone is not trusted: the body is counted as it arrives and
    the request fails with 413 as soon as the count passes the limit.
    """

    def __init__(self, app, max_upload_bytes):
        self.app = app
        self.limit = max_upload_bytes + MULTIPART_OVERHEAD_BYTES
        self.message = TOO_LARGE % max_upload_bytes

    async def __call__(self, scope, receive, send):

        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        message = self.message

        length = dict(scope.get("headers") or []).get(b"content-length", b"")

        if length.isdigit() and int(length) > self.limit:
            return await JSONResponse({"detail": message}, 413)(scope, receive, send)

        received = 0

        async def counted():

            nonlocal received

            event = await receive()

            if event["type"] == "http.request":

                received = received + len(event.get("body", b""))

                if received > self.limit:
                    raise HTTPException(413, message)

            return event

        return await self.app(scope, counted, send)


class OriginGuard:
    """Refuse a state-changing request that a page on another origin sent.

    A browser attaches Origin to a cross-origin POST, and a form post needs no
    CORS preflight, so CORS alone does not stop one. The request is allowed
    when it has no Origin (curl, tests, same-origin GETs), when the Origin is
    one of the configured origins, or when it is the app's own origin. Host is
    already checked by TrustedHostMiddleware, so the app's own origin can be
    read from it.
    """

    SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

    def __init__(self, app, allowed_origins):
        self.app = app
        self.allowed = set(allowed_origins)

    async def __call__(self, scope, receive, send):

        if scope["type"] == "http" and scope["method"] not in self.SAFE_METHODS:

            headers = Headers(scope=scope)
            origin = headers.get("origin")

            if (
                origin is not None
                and origin not in self.allowed
                and urlsplit(origin).netloc.lower() != headers.get("host", "").lower()
            ):
                return await JSONResponse(
                    {"detail": "This request came from an origin that is not allowed."},
                    403
                )(scope, receive, send)

        return await self.app(scope, receive, send)


# What the built web app (app/web/dist) needs and nothing more: its own
# scripts, stylesheets and fonts, inline styles (React Flow positions nodes
# with style attributes), data and blob images, and the API on the same origin.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
])

# Swagger UI and ReDoc load their scripts from a CDN and run inline code, so
# the policy would only break them.
NO_CSP_PATHS = ("/docs", "/redoc")


class SecurityHeaders:
    """Add the headers that keep a browser from guessing, framing or leaking."""

    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer"
    }

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):

        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def with_headers(message):

            if message["type"] == "http.response.start":

                headers = MutableHeaders(scope=message)

                for name, value in self.HEADERS.items():
                    headers[name] = value

                if scope["path"] not in NO_CSP_PATHS:
                    headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY

            await send(message)

        return await self.app(scope, receive, with_headers)


def validation_message(error: RequestValidationError):
    """FastAPI's validation errors as one readable line."""

    parts = []

    for item in error.errors():

        location = ".".join(
            str(part) for part in item.get("loc", ()) if part not in ("body", "query")
        )

        parts.append("%s: %s" % (location, item.get("msg")) if location else item.get("msg"))

    return "; ".join(parts) or "Invalid request."


def add_web_app(app):
    """Serve the production build of app/web at /, with client-side routes."""

    root = WEB_DIST_DIR.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def web(path: str):

        if path == "api" or path.startswith("api/"):
            raise HTTPException(404, "Not Found")

        candidate = (root / path).resolve()

        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)

        return FileResponse(root / "index.html")


def openapi_with_unrouted_models(app):
    """app.openapi, with the models no route returns yet added to components."""

    def openapi():

        if app.openapi_schema:
            return app.openapi_schema

        document = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes
        )

        _, definitions = models_json_schema(
            [(model, "serialization") for model in schemas.UNROUTED_MODELS],
            ref_template="#/components/schemas/{model}"
        )

        components = document.setdefault("components", {}).setdefault("schemas", {})

        for name, definition in definitions.get("$defs", {}).items():
            components.setdefault(name, definition)

        document["components"]["schemas"] = dict(sorted(components.items()))

        app.openapi_schema = document

        return document

    return openapi


def create_app(
    settings: Settings | None = None,
    worker: Worker | None = None,
    space_factory=None
):
    """A new app. Nothing is computed or read from the cache until a request.

    space_factory replaces the real model Space client; tests only.
    """

    settings = settings or Settings()

    worker = worker or Worker(retry_after_s=settings.busy_retry_after_s)

    @asynccontextmanager
    async def lifespan(app):
        await app.state.scenarios.start()
        try:
            yield
        finally:
            await app.state.scenarios.stop()
            worker.shutdown()
            app.state.renderer.shutdown()

    app = FastAPI(
        title=TITLE,
        version=VERSION,
        description="Upload a CloudFormation template; get its findings, ranked "
                    "attack paths, graphs and fix impact.",
        lifespan=lifespan
    )

    app.state.settings = settings
    app.state.worker = worker
    app.state.limiter = RateLimiter(settings)
    app.state.analyses = AnalysisService(settings, worker)
    app.state.scenarios = scenarios.ScenarioService(
        settings, app.state.analyses, space_factory
    )
    app.state.weasyprint = None
    app.state.renderer = Renderer(settings.pdf_retry_after_s, settings.pdf_timeout_s)

    @app.exception_handler(JobError)
    async def job_error(request, error: JobError):
        return JSONResponse(
            {"detail": error.detail}, error.status, headers=error.headers
        )

    @app.exception_handler(Exception)
    async def unexpected(request, error: Exception):
        # The traceback is logged by the server; the client gets a fixed message.
        log.error("Unhandled error on %s %s", request.method, request.url.path,
                  exc_info=error)
        return JSONResponse({"detail": UNEXPECTED_MESSAGE}, 500)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error: RequestValidationError):
        return JSONResponse({"detail": validation_message(error)}, 422)

    app.include_router(meta_router)
    app.include_router(analyses_router)
    app.include_router(scenarios.router)
    app.include_router(report_router)

    if (WEB_DIST_DIR / "index.html").is_file():
        add_web_app(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        expose_headers=["Location", "Retry-After"]
    )

    app.add_middleware(UploadLimit, max_upload_bytes=settings.max_upload_bytes)

    # Last added is outermost: headers on every response, the Host check
    # before anything reads the request, the Origin check before any route.
    app.add_middleware(OriginGuard, allowed_origins=settings.cors_origins)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(SecurityHeaders)

    app.openapi = openapi_with_unrouted_models(app)

    return app


app = create_app()
