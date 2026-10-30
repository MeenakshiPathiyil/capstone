"""Bounded analysis work: one spawned child process per job, with a real deadline.

The parent holds a single slot. A job spawns a fresh Python process, sends it a
JSON request and reads one JSON reply over a pipe. If the reply has not arrived
by the deadline the child is terminated, given two seconds, then killed, and
always joined, so a stalled analysis cannot outlive its request or hold the slot.
A thread waiting on a stalled computation could not be stopped at all, which is
why the work runs in a process.

Only JSON crosses the pipe in either direction, so nothing the child read from
an upload is ever unpickled by the API.

A spawned child re-imports the parent's __main__ module, as multiprocessing
always does. uvicorn, pytest and `python -m` entrypoints are safe; a script that
builds the app must keep its work under `if __name__ == "__main__":`.
"""

import asyncio
import contextlib
import io
import json
import logging
import multiprocessing
import os


# How long a terminated child gets to exit before it is killed.
TERMINATE_GRACE_S = 2.0

# The largest reply the parent will read. A sample analysis is about 1 MiB and
# the largest allowed template well under 30 MiB; past this the reply is refused
# before it is read into memory.
MAX_REPLY_BYTES = 64 * 1024 * 1024

# Settings of the live scenario generator that the analysis never reads.
# Prefixes are matched too (HF_*, HUGGING_FACE_*).
SECRET_ENVIRONMENT = (
    "HF_", "HUGGING_FACE_", "SPACE_ID", "BASE_MODEL_ID", "BASE_REVISION",
    "ADAPTER_REPO", "ADAPTER_REVISION", "LOADING_RECIPE"
)

log = logging.getLogger(__name__)


def too_large_message(paths=None):
    """The 413 text for an analysis whose result cannot be returned."""

    produced = (
        "The analysis produced more data than the app can handle (%s paths)." % format(paths, ",")
        if paths else "The analysis produced more data than the app can handle."
    )

    return produced + " Try a smaller template or a higher minimum level."


class JobError(Exception):
    """A request that ends in an HTTP error, with its status and message."""

    def __init__(self, status, detail, headers=None):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.headers = headers or {}


# ------------------------------------------------------------------------------
# Child side
# ------------------------------------------------------------------------------

def scrub_environment():
    """Drop the Hugging Face credentials and settings from this process.

    A child inherits the API's environment, and it parses untrusted uploads.
    It never talks to Hugging Face, so nothing there is its to hold.
    """

    for name in list(os.environ):
        if name.startswith(SECRET_ENVIRONMENT):
            del os.environ[name]


def run_job(connection, kind, request):
    """Child entrypoint: run one job and send its JSON reply.

    The reply is {"ok": true, "result": ...} or {"ok": false, "status", "detail"}.
    The pipeline prints its warnings; they are captured here because the same
    warnings reach the caller as data in the result.
    """

    from app.api import analysis

    scrub_environment()

    jobs = {
        "analysis": analysis.analysis_job,
        "fixes": analysis.fixes_job
    }

    try:
        with contextlib.redirect_stdout(io.StringIO()):
            reply = {"ok": True, "result": jobs[kind](json.loads(request))}

        data = json.dumps(reply, allow_nan=False)

        # Said here, where the path count is known, rather than by the parent
        # refusing to read the reply.
        if len(data) > MAX_REPLY_BYTES:
            paths = reply["result"].get("analysis", {}).get("summary", {}).get("paths")
            data = json.dumps({
                "ok": False, "status": 413, "detail": too_large_message(paths)
            })

    except analysis.InputError as error:
        data = json.dumps({"ok": False, "status": error.status, "detail": error.detail})

    except RecursionError:
        data = json.dumps({
            "ok": False, "status": 422, "detail": analysis.RECURSION_MESSAGE
        })

    except Exception:
        # The traceback stays in the server log; the client gets a fixed message.
        log.exception("Analysis job %s failed.", kind)
        data = json.dumps({
            "ok": False, "status": 500, "detail": analysis.UNEXPECTED_MESSAGE
        })

    connection.send_bytes(data.encode("utf-8"))
    connection.close()


# ------------------------------------------------------------------------------
# Parent side
# ------------------------------------------------------------------------------

class ReplyTooLarge(Exception):
    """The child's reply is longer than the parent will read."""


def receive(connection, timeout, max_bytes=MAX_REPLY_BYTES):
    """The child's reply, None if it exited without one.

    Raises TimeoutError, or ReplyTooLarge before reading a reply past max_bytes.
    """

    if not connection.poll(timeout):
        raise TimeoutError()

    try:
        return connection.recv_bytes(max_bytes)

    except EOFError:
        return None

    except OSError:

        # A length past the maximum closes the read-only end and raises
        # "bad message length". Any other OSError is a real fault.
        if connection.closed:
            raise ReplyTooLarge() from None

        raise


def stop(process):
    """Terminate, wait, kill, and always reap. Safe on an exited process."""

    if process.is_alive():
        process.terminate()
        process.join(TERMINATE_GRACE_S)

    if process.is_alive():
        process.kill()

    process.join()


class Worker:
    """One analysis slot. Busy callers get 503 with Retry-After at once."""

    def __init__(self, retry_after_s=2, target=run_job, max_reply_bytes=MAX_REPLY_BYTES):
        self.retry_after_s = retry_after_s
        self.max_reply_bytes = max_reply_bytes

        # The child entrypoint. A module-level function, because a spawned
        # process imports it by name; tests swap in a stalled one.
        self.target = target

        self._slot = asyncio.Semaphore(1)
        self._active = set()
        self._context = multiprocessing.get_context("spawn")

        # The pid of the most recent child, for tests that check it is gone.
        self.last_pid = None

    @property
    def busy(self):
        return self._slot.locked()

    def busy_error(self):
        return JobError(
            503,
            "The analyser is busy with another request. Try again shortly.",
            {"Retry-After": str(self.retry_after_s)}
        )

    async def run(self, kind, payload, timeout):
        """Run one job in a fresh child and return its result."""

        # No await between the check and the acquire, so on one event loop this
        # cannot race.
        if self._slot.locked():
            raise self.busy_error()

        async with self._slot:
            reply = await self._spawn(kind, json.dumps(payload), timeout)

        if reply is None:
            raise JobError(500, "The analysis worker exited without a result.")

        body = json.loads(reply)

        if not body["ok"]:
            raise JobError(body["status"], body["detail"])

        return body["result"]

    async def _spawn(self, kind, request, timeout):

        receiver, sender = self._context.Pipe(duplex=False)

        process = self._context.Process(
            target=self.target,
            args=(sender, kind, request),
            daemon=True
        )

        process.start()

        # The child holds the only write end now, so its exit reads as EOF.
        sender.close()

        self._active.add(process)
        self.last_pid = process.pid

        try:
            return await asyncio.to_thread(
                receive, receiver, timeout, self.max_reply_bytes
            )

        except ReplyTooLarge:
            raise JobError(413, too_large_message()) from None

        except TimeoutError:
            raise JobError(
                504, "The analysis took longer than %g seconds and was stopped." % timeout
            ) from None

        except BaseException:
            # Cancelled (shutdown or a dropped request): signal now, reap below.
            process.terminate()
            raise

        finally:
            await asyncio.shield(asyncio.to_thread(stop, process))
            receiver.close()
            self._active.discard(process)

    def shutdown(self):
        """Stop every running child. Called once from the app's lifespan."""

        for process in list(self._active):
            stop(process)

        self._active.clear()
