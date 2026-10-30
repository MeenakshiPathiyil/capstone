"""Dev-only launcher: the real API over a fake model Space, for UI work and e2e.

Runs app.api.main.create_app with the real ScenarioService and SpaceClient, and
swaps only the two Hugging Face libraries for in-process fakes, the same seam
app/api/tests/test_scenarios.py uses (create_app(space_factory=...)). Every
response goes through the real provenance helpers in app/api/scenario_contract.py,
so it is validated and cached exactly like a live one.

Nothing here is imported by the app, and the settings are placeholders: the
token is the literal string "fake-token-for-local-ui", never a real credential.
Any HF_TOKEN or Space setting in the calling shell is overwritten, and
app/api/.env is not read.

Usage, from the repository root:

    FAKE_SCENARIO_MODE=ok app/.venv/bin/python app/web/e2e/fake_model_server.py

Environment:

    FAKE_SCENARIO_MODE       what the fake Space does (default ok)
        ok          RUNNING; each generation takes FAKE_SCENARIO_DELAY_S and
                    returns a complete three-section scenario
        preamble    as ok, with a line of text before the first section
        truncated   the output stops at the 1200-token cap inside the
                    mathematical expression; the attack graph is missing
        error       the Space reports a provider error for every generation
        slow        the Space starts asleep and takes FAKE_SCENARIO_STARTUP_S
                    to wake (warming_up), then each generation takes
                    FAKE_SCENARIO_DELAY_S (default 20 s here); use it for the
                    queued, warming_up and running states
        quota       the ZeroGPU quota is known to be used up; health reports
                    why and POST answers 503 with Retry-After
        paused      the Space is paused; health reports why
        off         no live configuration at all, as before the model is
                    deployed; health reports why and POST answers 503
    FAKE_SCENARIO_HOST       default 127.0.0.1
    FAKE_SCENARIO_PORT       default 8000
    FAKE_SCENARIO_DELAY_S    seconds per generation (default 3; slow: 20)
    FAKE_SCENARIO_STARTUP_S  seconds the slow Space takes to wake (default 10)
    FAKE_SCENARIO_CACHE_DIR  analyses and scenarios; default a fresh temporary
                             directory that is removed on exit, so every run
                             starts from the same empty state
    FAKE_WEB_DIST_DIR        a production build of app/web to serve at /
                             instead of app/web/dist; the Playwright suite
                             builds its own copy, so a concurrent
                             `npm run build` cannot pull files from under it

Generated text is a pure function of the prompt and the mode, and the reported
token counts and seconds are constants, so runs are repeatable.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

import uvicorn  # noqa: E402

from app.api import main as api_main  # noqa: E402
from app.api import scenario_contract as contract  # noqa: E402
from app.api.config import Settings  # noqa: E402
from app.api.main import create_app  # noqa: E402
from app.api.space_client import SpaceClient  # noqa: E402


MODES = ("ok", "preamble", "truncated", "error", "slow", "quota", "paused", "off")

LIVE_ENV = (
    "HF_TOKEN",
    "SPACE_ID",
    "BASE_MODEL_ID",
    "BASE_REVISION",
    "ADAPTER_REPO",
    "ADAPTER_REVISION",
    "LOADING_RECIPE",
)

FAKE_TOKEN = "fake-token-for-local-ui"
FAKE_SPACE_ID = "local/fake-scenario-space"
FAKE_ADAPTER_REPO = "local/capstone-scenario-adapter"
# Stable, obviously fake 40-character "commits".
FAKE_BASE_REVISION = hashlib.sha1(b"fake base model revision").hexdigest()
FAKE_ADAPTER_REVISION = hashlib.sha1(b"fake adapter revision").hexdigest()

PROVIDER_ERROR = (
    "GPU task aborted: the ZeroGPU worker was reclaimed before the generation "
    "finished (CUDA error: an illegal memory access was encountered)."
)


def env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return float(value) if value else default


# ==============================================================================
# Scenario text
# ==============================================================================

def prompt_fields(prompt: str) -> dict:
    """The record fields build_prompt() wrote into the prompt."""

    def line(label: str) -> str:
        match = re.search(r"^%s: (.*)$" % label, prompt, re.MULTILINE)
        return match.group(1).strip() if match else ""

    source = line("SOURCE")
    source_match = re.match(r"^(.*) \(([^()]*)\)$", source)
    chain, source_id = source_match.groups() if source_match else (source, "")
    techniques = [
        item.split(" - ", 1)[0].strip()
        for item in line("TECHNIQUES").split(", ")
        if re.match(r"^T\d{4}", item.strip())
    ]

    return {
        "source_id": source_id,
        "hops": [hop.strip() for hop in chain.split("->") if hop.strip()],
        "techniques": techniques,
        "objective": line("OBJECTIVE") or "Data exposure",
        "industry": line("INDUSTRY"),
    }


AP001_HOPS = [
    "OpenSecurityGroup",
    "PublicEC2Instance",
    "OverPermissiveInstanceProfile",
    "OverPermissiveRole",
    "InsecureS3Bucket",
]

AP001_NATURAL_LANGUAGE = """\
The attack begins from the internet. The attacker sweeps the organisation's public address range and finds PublicEC2Instance answering on SSH (port 22) and RDP (port 3389), both opened to 0.0.0.0/0 by OpenSecurityGroup. A password spray against the exposed administrative service succeeds against a reused local account, and the attacker lands an interactive shell on the instance (T1190).

From that foothold the attacker queries the instance metadata service at 169.254.169.254 and reads the temporary credentials issued to OverPermissiveInstanceProfile (T1552.005). The credentials belong to OverPermissiveRole, and the attacker replays them from their own tooling as a valid cloud identity (T1078.004). A quick enumeration of IAM, EC2 and S3 shows that the role carries a wildcard policy (T1580).

The attacker then makes the access durable. They create a second access key for a dormant IAM user (T1098.001) and attach an administrator policy to the role (T1098.003), so rotating the instance credentials no longer locks them out. Elevated work is done through short-lived sts:AssumeRole sessions, which keeps it out of long-term key monitoring (T1548.005).

With administrative reach the attacker lists every bucket in the account (T1619) and settles on InsecureS3Bucket, which holds customer exports and application backups and has neither versioning nor object lock. Working through the AWS APIs with the forged session (T1021.007), they copy the bucket's contents (T1530) and replicate them to an account they control (T1537).

The impact follows. The attacker re-encrypts every object in place with a KMS key only they hold (T1486), deletes the originals and the backup prefixes (T1485), and removes the bucket's lifecycle and replication rules so the data cannot be restored (T1490). A ransom note left at the bucket root asks for payment in exchange for the key."""

AP001_MATHEMATICAL = """\
N = {n1: Internet, n2: OpenSecurityGroup, n3: PublicEC2Instance, n4: OverPermissiveInstanceProfile, n5: OverPermissiveRole, n6: InsecureS3Bucket, n7: Attacker AWS Account}
S = {s1: SSH and RDP open to 0.0.0.0/0, s2: Instance metadata reachable without hop limit, s3: Wildcard IAM policy on the role, s4: Bucket without versioning or object lock}
V = {v1: T1190, v2: T1552.005, v3: T1078.004, v4: T1580, v5: T1098.001, v6: T1098.003, v7: T1548.005, v8: T1619, v9: T1021.007, v10: T1530, v11: T1537, v12: T1486, v13: T1485, v14: T1490}
P = {p1: n1 -> n2 -> n3, p2: n3 -> n4, p3: n4 -> n5, p4: n5 -> n6, p5: n6 -> n7}
FS = {Customer data encrypted for ransom and copied out, backups destroyed}
G = (N, S, V, P, FS)"""

AP001_ATTACK_GRAPH = """\
Stage 1 (Initial Access): Internet [T1190] -> PublicEC2Instance through OpenSecurityGroup
Stage 2 (Credential Access): PublicEC2Instance [T1552.005] -> OverPermissiveInstanceProfile
Stage 3 (Privilege Escalation): OverPermissiveInstanceProfile [T1078.004] -> OverPermissiveRole
Stage 4 (Persistence): OverPermissiveRole [T1098.001, T1098.003] -> Administrator access
Stage 5 (Discovery): OverPermissiveRole [T1580, T1619] -> InsecureS3Bucket
Stage 6 (Exfiltration): InsecureS3Bucket [T1530, T1537] -> Attacker AWS Account
Stage 7 (Impact): InsecureS3Bucket [T1486, T1485, T1490] -> Encrypted and unrecoverable data
Final Impact: Customer data is encrypted for ransom, a copy is held by the attacker and the backups are gone."""


def generic_sections(fields: dict) -> tuple[str, str, str]:
    """A plausible scenario for any path, built from its own hops and techniques."""

    hops = fields["hops"] or ["EntryPoint", "Target"]
    techniques = fields["techniques"] or ["T1078"]
    first, last = hops[0], hops[-1]
    middle = hops[1:-1]
    objective = fields["objective"]

    def tech(index: int) -> str:
        return techniques[min(index, len(techniques) - 1)]

    narrative = [
        "The attack begins at %s, the entry point of this path. The attacker finds it "
        "reachable from outside the account and uses it to gain an initial foothold (%s)."
        % (first, tech(0))
    ]

    if middle:
        narrative.append(
            "From there the attacker moves through %s, using the permissions each resource "
            "grants to reach the next one (%s, %s). Every hop reuses credentials or trust "
            "that the template already configures, so no exploit beyond the first is needed."
            % (", ".join(middle), tech(1), tech(2))
        )

    narrative.append(
        "The path ends at %s, where the attacker achieves the objective: %s (%s)."
        % (last, objective.lower(), tech(len(techniques) - 1))
    )

    nodes = ", ".join("n%d: %s" % (index + 1, hop) for index, hop in enumerate(hops))
    used = ", ".join("v%d: %s" % (index + 1, t) for index, t in enumerate(techniques[:8]))
    edges = ", ".join(
        "p%d: n%d -> n%d" % (index + 1, index + 1, index + 2) for index in range(len(hops) - 1)
    )
    mathematical = "\n".join([
        "N = {%s}" % nodes,
        "S = {s1: Entry reachable from the internet, s2: Over-broad trust between resources}",
        "V = {%s}" % used,
        "P = {%s}" % (edges or "p1: n1"),
        "FS = {%s}" % objective,
        "G = (N, S, V, P, FS)",
    ])

    stages = [
        "Stage %d: %s [%s] -> %s" % (index + 1, hops[index], tech(index), hops[index + 1])
        for index in range(len(hops) - 1)
    ] or ["Stage 1: %s [%s] -> %s" % (first, tech(0), objective)]
    stages.append("Final Impact: %s at %s." % (objective, last))

    return "\n\n".join(narrative), mathematical, "\n".join(stages)


def scenario_text(prompt: str, mode: str) -> tuple[str, int, bool, float]:
    """(text, new_tokens, hit_eos, seconds) for one prompt in one mode."""

    fields = prompt_fields(prompt)

    if fields["hops"] == AP001_HOPS:
        sections = (AP001_NATURAL_LANGUAGE, AP001_MATHEMATICAL, AP001_ATTACK_GRAPH)
    else:
        sections = generic_sections(fields)

    natural_language, mathematical, attack_graph = sections

    if mode == "truncated":
        # The cap lands part-way through the V set: no attack graph at all.
        lines = mathematical.splitlines()
        cut = lines[2][: max(len(lines[2]) // 2, 1)]
        text = "[NATURAL LANGUAGE]\n%s\n\n[MATHEMATICAL EXPRESSION]\n%s\n%s" % (
            natural_language, "\n".join(lines[:2]), cut
        )
        return text, contract.MAX_NEW_TOKENS, False, 63.8

    text = "[NATURAL LANGUAGE]\n%s\n\n[MATHEMATICAL EXPRESSION]\n%s\n\n[ATTACK GRAPH]\n%s" % (
        natural_language, mathematical, attack_graph
    )

    if mode == "preamble":
        text = "Here is the tri-modal scenario for %s.\n\n%s" % (
            fields["source_id"] or "this path", text
        )

    return text, 912, True, 41.3


# ==============================================================================
# Fakes for huggingface_hub.HfApi and gradio_client.Client
# ==============================================================================

class FakeHttpError(Exception):
    """Shaped like huggingface_hub's HfHubHTTPError: it carries a response."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.response = SimpleNamespace(status_code=status)


class FakeHfApi:
    """Runtime stage, restart and ZeroGPU quota, as the mode prescribes."""

    def __init__(self, mode: str, startup_s: float):
        self.mode = mode
        self.startup_s = startup_s
        self.awake_at: float | None = None
        self.lock = threading.Lock()
        # The quota resets on the next full hour, at least an hour from now.
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        self.resets_at = now + timedelta(hours=2)

    def get_space_runtime(self, repo_id):
        with self.lock:
            if self.mode == "paused":
                stage = "PAUSED"
            elif self.mode != "slow":
                stage = "RUNNING"
            elif self.awake_at is None:
                stage = "SLEEPING"
            elif time.monotonic() < self.awake_at:
                stage = "STARTING"
            else:
                stage = "RUNNING"

        return SimpleNamespace(stage=stage)

    def restart_space(self, repo_id):
        with self.lock:
            if self.awake_at is None:
                self.awake_at = time.monotonic() + self.startup_s

    def get_zero_gpu_quota(self):
        if self.mode == "quota":
            return SimpleNamespace(remaining=0, resets_at=self.resets_at)

        # Most tokens cannot read billing; the quota is then unknown.
        raise FakeHttpError(403, "token lacks the read-billing permission")


class FakeJob:

    def __init__(self, gradio: "FakeGradio", prompt: str, max_new_tokens: int):
        self.gradio = gradio
        self.prompt = prompt
        self.max_new_tokens = max_new_tokens
        self.finishes_at = time.monotonic() + gradio.delay_s

    def done(self):
        return time.monotonic() >= self.finishes_at

    def result(self, timeout=None):
        if self.gradio.mode == "error":
            raise RuntimeError(PROVIDER_ERROR)

        text, new_tokens, hit_eos, seconds = scenario_text(self.prompt, self.gradio.mode)

        return contract.build_response(
            text=text,
            new_tokens=min(new_tokens, self.max_new_tokens),
            hit_eos=hit_eos,
            seconds=seconds,
            provenance=self.gradio.provenance,
        )

    def cancel(self):
        self.finishes_at = time.monotonic()
        return True


class FakeClient:

    def __init__(self, gradio: "FakeGradio"):
        self.gradio = gradio

    def submit(self, prompt, max_new_tokens, api_name=None):
        assert api_name == "/generate", api_name
        return FakeJob(self.gradio, prompt, max_new_tokens)

    def close(self):
        pass


class FakeGradio:
    """The gradio Client factory: SpaceClient calls it once per generation."""

    def __init__(self, mode: str, delay_s: float, provenance: dict):
        self.mode = mode
        self.delay_s = delay_s
        self.provenance = provenance

    def __call__(self):
        return FakeClient(self)


# ==============================================================================
# Launcher
# ==============================================================================

def configure_environment(mode: str) -> None:
    """Placeholder live settings, or none at all for mode off."""

    for name in LIVE_ENV:
        os.environ.pop(name, None)

    if mode == "off":
        return

    os.environ.update({
        "HF_TOKEN": FAKE_TOKEN,
        "SPACE_ID": FAKE_SPACE_ID,
        "BASE_REVISION": FAKE_BASE_REVISION,
        "ADAPTER_REPO": FAKE_ADAPTER_REPO,
        "ADAPTER_REVISION": FAKE_ADAPTER_REVISION,
        "LOADING_RECIPE": contract.NF4_UNMERGED,
    })


def warm_health(base_url: str, server: uvicorn.Server) -> None:
    """Read /api/health twice once the server is up.

    The first read starts the service's background stage and quota refresh;
    after the second, every later read (the UI's first included) already sees
    this mode's stage and quota.
    """

    deadline = time.monotonic() + 30

    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)

    for _ in range(2):
        try:
            urllib.request.urlopen(base_url + "/api/health", timeout=5).read()
        except OSError as error:
            print("fake_model_server: health warm-up failed: %s" % error, file=sys.stderr)
            return
        time.sleep(0.3)


def main() -> None:
    mode = os.environ.get("FAKE_SCENARIO_MODE", "ok").strip().lower()

    if mode not in MODES:
        sys.exit("FAKE_SCENARIO_MODE must be one of %s, not %r." % (", ".join(MODES), mode))

    host = os.environ.get("FAKE_SCENARIO_HOST", "127.0.0.1")
    port = int(os.environ.get("FAKE_SCENARIO_PORT", "8000"))
    delay_s = env_float("FAKE_SCENARIO_DELAY_S", 20.0 if mode == "slow" else 3.0)
    startup_s = env_float("FAKE_SCENARIO_STARTUP_S", 10.0)

    configured_cache = os.environ.get("FAKE_SCENARIO_CACHE_DIR")
    cache_dir = Path(configured_cache or tempfile.mkdtemp(prefix="capstone-fake-model-"))

    configure_environment(mode)

    # _env_file=None: never read app/api/.env, which may hold real settings.
    settings = Settings(_env_file=None, cache_dir=cache_dir)

    api = FakeHfApi(mode, startup_s)

    def space_factory(settings: Settings) -> SpaceClient:
        gradio = FakeGradio(mode, delay_s, settings.scenario_provenance())
        return SpaceClient(
            settings.space_id,
            settings.hf_token.get_secret_value(),
            hf_api=api,
            gradio_client_factory=gradio,
            request_timeout_s=5,
            startup_timeout_s=settings.space_startup_timeout_s,
            generation_timeout_s=settings.generation_timeout_s,
            poll_interval_s=0.25,
        )

    web_dist = os.environ.get("FAKE_WEB_DIST_DIR")

    if web_dist:
        # create_app serves whatever build this module-level path names.
        api_main.WEB_DIST_DIR = Path(web_dist).resolve()

    app = create_app(settings, space_factory=space_factory)
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info"))

    threading.Thread(
        target=warm_health, args=("http://%s:%d" % (host, port), server), daemon=True
    ).start()

    print(
        "fake_model_server: mode=%s delay=%gs cache=%s web=%s on http://%s:%d"
        % (mode, delay_s, cache_dir, api_main.WEB_DIST_DIR, host, port),
        flush=True,
    )

    try:
        server.run()
    finally:
        if not configured_cache:
            shutil.rmtree(cache_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
