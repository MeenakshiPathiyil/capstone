"""The private model Space, seen from the API: runtime stage, quota, generation.

A thin layer over huggingface_hub.HfApi (runtime, restart, ZeroGPU quota) and
gradio_client.Client (the /generate endpoint). Both are blocking libraries, so
every call runs in a thread and is bounded by hf_request_timeout_s; generation
is bounded separately by a monotonic deadline.

Runtime stages (plan section 7.2):
    RUNNING                               go
    BUILDING, STARTING, APP_STARTING      poll, never restart
    SLEEPING                              one restart_space, then poll
    PAUSED, *_ERROR, anything else        fail with a setup message
Waiting for RUNNING is capped at space_startup_timeout_s.

The token is passed to the two libraries and nowhere else. Every message this
module produces has it removed, in case a library echoes it back.

Nothing is imported from huggingface_hub or gradio_client until a real client
is built by create_space_client(); tests pass fakes for both instead.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


log = logging.getLogger(__name__)

GENERATE_API = "/generate"

RUNNING_STAGES = frozenset({"RUNNING", "RUNNING_BUILDING", "RUNNING_APP_STARTING"})
STARTING_STAGES = frozenset({"BUILDING", "STARTING", "APP_STARTING"})
SLEEPING = "SLEEPING"
ERROR_STAGES = frozenset({"BUILD_ERROR", "RUNTIME_ERROR", "CONFIG_ERROR", "NO_APP_FILE"})

# Error text from a provider is cut to this length before it reaches a user.
MAX_MESSAGE_CHARS = 500


class SpaceError(Exception):
    """A failure whose message is safe to show the user as is."""


class SpaceSetupError(SpaceError):
    """The Space cannot serve until its owner changes something."""


class GenerationTimeout(SpaceError):
    """The generation deadline passed; remote GPU work may still be running."""


@dataclass(frozen=True)
class Quota:
    """The caller's ZeroGPU quota, as far as Hugging Face tells us."""

    remaining_s: int | None = None
    resets_at: datetime | None = None

    @property
    def known(self) -> bool:
        return self.remaining_s is not None

    def exhausted(self, now: datetime | None = None) -> bool:
        """True only for a known, current exhaustion. Unknown is never exhausted."""

        if self.remaining_s is None or self.remaining_s > 0:
            return False

        now = now or datetime.now(timezone.utc)

        return self.resets_at is None or self.resets_at > now


def stage_name(stage: Any) -> str:
    """SpaceStage members and plain strings alike, as the stage string."""

    return str(getattr(stage, "value", stage))


def stage_problem(stage: str) -> str | None:
    """The setup message for a stage the Space cannot serve from, else None."""

    if stage in RUNNING_STAGES or stage in STARTING_STAGES or stage == SLEEPING:
        return None

    if stage == "PAUSED":
        return (
            "The model Space is paused. Its owner must restart it in the Space "
            "settings on Hugging Face."
        )

    if stage in ERROR_STAGES:
        return (
            "The model Space is in %s. Check its logs on Hugging Face and redeploy "
            "it with app/scripts/deploy_model_space.py." % stage
        )

    return (
        "The model Space is %s and cannot serve requests. Its owner must restart "
        "it in the Space settings on Hugging Face." % stage
    )


class SpaceClient:
    """One configured model Space. Async methods; blocking work runs in threads."""

    def __init__(
        self,
        space_id: str,
        token: str,
        *,
        hf_api: Any,
        gradio_client_factory: Callable[[], Any],
        request_timeout_s: float = 20.0,
        startup_timeout_s: float = 300.0,
        generation_timeout_s: float = 600.0,
        poll_interval_s: float = 2.0
    ):
        self.space_id = space_id
        self._token = token
        self._hf_api = hf_api
        self._gradio_client_factory = gradio_client_factory
        self.request_timeout_s = request_timeout_s
        self.startup_timeout_s = startup_timeout_s
        self.generation_timeout_s = generation_timeout_s
        self.poll_interval_s = poll_interval_s

    # -- Messages ----------------------------------------------------------------

    def redact(self, text: str) -> str:
        """text without the token, cut to MAX_MESSAGE_CHARS."""

        text = str(text)

        if self._token:
            text = text.replace(self._token, "***")

        if len(text) > MAX_MESSAGE_CHARS:
            text = text[:MAX_MESSAGE_CHARS - 3] + "..."

        return text

    def _describe(self, error: BaseException) -> str:
        """An exception as one line, with its HTTP status when it has one."""

        status = getattr(getattr(error, "response", None), "status_code", None)
        detail = str(error).strip().splitlines()[0] if str(error).strip() else ""
        name = type(error).__name__

        if status is not None:
            return self.redact("HTTP %s from Hugging Face (%s)" % (status, name))

        return self.redact("%s: %s" % (name, detail) if detail else name)

    # -- Bounded calls -----------------------------------------------------------

    async def _call(self, what: str, function: Callable, *args, **kwargs):
        """function(*args) in a thread, bounded by request_timeout_s."""

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(function, *args, **kwargs),
                self.request_timeout_s
            )

        except TimeoutError:
            raise SpaceError(
                "Hugging Face did not answer %s within %g s." % (what, self.request_timeout_s)
            ) from None

    def _http_status(self, error: BaseException) -> int | None:
        return getattr(getattr(error, "response", None), "status_code", None)

    # -- Runtime -----------------------------------------------------------------

    async def runtime_stage(self) -> str:
        """The Space's current stage. Reads only; never wakes or restarts it."""

        try:
            runtime = await self._call(
                "the runtime request", self._hf_api.get_space_runtime, self.space_id
            )

        except SpaceError:
            raise

        except Exception as error:

            if self._http_status(error) in (401, 403, 404):
                raise SpaceSetupError(
                    "Cannot read the model Space %s (%s). Check SPACE_ID and that "
                    "HF_TOKEN can read it." % (self.space_id, self._describe(error))
                ) from None

            raise SpaceError(
                "Cannot read the model Space's state: %s." % self._describe(error)
            ) from None

        return stage_name(runtime.stage)

    async def _restart(self) -> None:

        try:
            await self._call("the restart request", self._hf_api.restart_space, self.space_id)

        except SpaceError:
            raise

        except Exception as error:
            raise SpaceSetupError(
                "The model Space is asleep and could not be woken (%s). HF_TOKEN needs "
                "write access to the Space to restart it." % self._describe(error)
            ) from None

    async def ensure_running(self, on_stage: Callable[[str], None] | None = None) -> str:
        """Wait until the Space is RUNNING, waking it once if it sleeps.

        on_stage is called with every stage read. Raises SpaceSetupError for a
        stage only its owner can fix, SpaceError when it does not start in time.
        """

        deadline = time.monotonic() + self.startup_timeout_s
        restarted = False

        while True:

            stage = await self.runtime_stage()

            if on_stage is not None:
                on_stage(stage)

            if stage in RUNNING_STAGES:
                return stage

            problem = stage_problem(stage)

            if problem:
                raise SpaceSetupError(problem)

            if stage == SLEEPING and not restarted:
                log.info("Model Space %s is sleeping; restarting it once.", self.space_id)
                await self._restart()
                restarted = True

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise SpaceError(
                    "The model Space did not start within %g s (last stage %s). "
                    "Try again in a few minutes." % (self.startup_timeout_s, stage)
                )

            await asyncio.sleep(min(self.poll_interval_s, remaining))

    # -- Quota -------------------------------------------------------------------

    async def quota(self) -> Quota:
        """The caller's ZeroGPU quota, or an unknown Quota. Never raises.

        Advisory only: the provider enforces its own limit at generation time.
        The token needs the billing-read permission for this to be known.
        """

        probe = getattr(self._hf_api, "get_zero_gpu_quota", None)

        if probe is None:
            return Quota()

        try:
            reported = await self._call("the quota request", probe)

        except Exception as error:
            log.info("ZeroGPU quota unknown: %s", self._describe(error))
            return Quota()

        remaining = getattr(reported, "remaining", None)
        resets_at = getattr(reported, "resets_at", None)

        if isinstance(remaining, bool) or not isinstance(remaining, (int, float)) \
                or not math.isfinite(remaining):
            return Quota()

        if not isinstance(resets_at, datetime) or resets_at.tzinfo is None:
            resets_at = None

        return Quota(remaining_s=max(int(math.floor(remaining)), 0), resets_at=resets_at)

    # -- Generation --------------------------------------------------------------

    async def _cancel(self, job: Any) -> None:
        """Ask the SDK to cancel a submitted job; best effort, bounded."""

        try:
            await self._call("the cancel request", job.cancel)

        except Exception as error:
            log.warning("Cancelling the scenario job failed: %s", self._describe(error))

    async def generate(
        self,
        prompt: str,
        max_new_tokens: int,
        on_submitted: Callable[[], None] | None = None
    ) -> Any:
        """The Space's raw /generate result for one prompt.

        Raises GenerationTimeout after generation_timeout_s (the job is
        cancelled first; the Space may still finish the GPU work) and
        SpaceError for every other failure.
        """

        try:
            client = await self._call("the connection", self._gradio_client_factory)

        except SpaceError:
            raise

        except Exception as error:
            raise SpaceError(
                "Cannot connect to the model Space: %s." % self._describe(error)
            ) from None

        try:
            try:
                job = await self._call(
                    "the submission",
                    client.submit,
                    prompt,
                    max_new_tokens,
                    api_name=GENERATE_API
                )

            except SpaceError:
                raise

            except Exception as error:
                raise SpaceError(
                    "The model Space refused the request: %s." % self._describe(error)
                ) from None

            if on_submitted is not None:
                on_submitted()

            deadline = time.monotonic() + self.generation_timeout_s

            try:
                while not job.done():

                    remaining = deadline - time.monotonic()

                    if remaining <= 0:
                        await self._cancel(job)
                        raise GenerationTimeout(
                            "The model did not finish within %g s, so the request was "
                            "cancelled. Remote GPU work may still be running and use "
                            "quota; wait a few minutes before trying again."
                            % self.generation_timeout_s
                        )

                    await asyncio.sleep(min(self.poll_interval_s, remaining))

            except asyncio.CancelledError:
                await self._cancel(job)
                raise

            try:
                return job.result(timeout=0)

            except Exception as error:
                raise SpaceError(
                    "The model Space reported an error: %s" % self._provider_message(error)
                ) from None

        finally:
            close = getattr(client, "close", None)

            if close is not None:
                try:
                    await self._call("the disconnect", close)

                except Exception:
                    pass

    def _provider_message(self, error: BaseException) -> str:
        """A provider error's own message (a gr.Error text, a quota notice)."""

        text = str(error).strip()

        return self.redact(text) if text else type(error).__name__


# -- The real client ----------------------------------------------------------------

def create_space_client(settings) -> SpaceClient:
    """A SpaceClient over the real huggingface_hub and gradio_client.

    Called once, at service start, and only with a complete live configuration.
    """

    import httpx
    import httpx2
    from gradio_client import Client
    from huggingface_hub import HfApi, get_session

    token = settings.hf_token.get_secret_value()
    timeout = settings.hf_request_timeout_s

    # huggingface_hub's shared session has no timeout of its own. Every call is
    # already bounded by SpaceClient._call; this also ends the worker thread.
    get_session().timeout = httpx2.Timeout(timeout)

    def gradio_client():
        # The SSE streams carry heartbeats well within the read timeout.
        return Client(
            settings.space_id,
            token=token,
            verbose=False,
            analytics_enabled=False,
            download_files=False,
            httpx_kwargs={"timeout": httpx.Timeout(timeout, read=max(timeout, 90.0))}
        )

    return SpaceClient(
        settings.space_id,
        token,
        hf_api=HfApi(token=token),
        gradio_client_factory=gradio_client,
        request_timeout_s=timeout,
        startup_timeout_s=settings.space_startup_timeout_s,
        generation_timeout_s=settings.generation_timeout_s
    )
