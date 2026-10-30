"""Settings, read from the environment (or app/api/.env) once per app."""

from pathlib import Path

from pydantic import Field, NonNegativeInt, PositiveInt, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.api import scenario_contract as contract


API_DIR = Path(__file__).resolve().parent
APP_DIR = API_DIR.parent
REPO_ROOT = APP_DIR.parent

# The production build of app/web, served at / when it exists.
WEB_DIST_DIR = APP_DIR / "web" / "dist"

MIB = 1024 * 1024


def make_private_dir(path):
    """Create `path` and any missing parents readable by this user only (0o700)."""

    path = Path(path)

    for directory in reversed([path, *path.parents]):
        if not directory.exists():
            directory.mkdir(mode=0o700, exist_ok=True)


class Settings(BaseSettings):
    """Every tunable of the API. App settings use the CAPSTONE_ prefix.

    The live scenario settings (HF_TOKEN, SPACE_ID, BASE_MODEL_ID,
    BASE_REVISION, ADAPTER_REPO, ADAPTER_REVISION, LOADING_RECIPE) keep their
    unprefixed names, shared with the Space and the deploy scripts. The token is
    held as a SecretStr; only space_client.py reads its value, to authenticate
    to Hugging Face, and it never reaches a response, a manifest or a log.
    ANALYSER_COMMIT, which a build without .git sets, is unprefixed too.
    """

    model_config = SettingsConfigDict(
        env_prefix="CAPSTONE_",
        env_file=API_DIR / ".env",
        extra="ignore"
    )

    # Saved analyses live under <cache_dir>/analyses/<uuid>/.
    cache_dir: Path = APP_DIR / ".cache"

    max_upload_bytes: int = 2 * MIB
    max_resources: int = 500

    # Wall-clock deadlines for the child process, from spawn.
    analysis_timeout_s: float = 30.0
    impact_timeout_s: float = 60.0

    # Seconds a client is told to wait when the single analysis slot is taken.
    busy_retry_after_s: int = 2

    # How long one PDF render may run, and how long a client is told to wait
    # when another render holds the single render slot.
    pdf_timeout_s: float = 120.0
    pdf_retry_after_s: int = 5

    # The Vite dev server. Production serves the web build from this app, so it
    # needs no CORS at all. A POST whose Origin is neither one of these nor the
    # app's own is refused.
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ]

    # Host names (no port) the app answers to; any other Host header is 400,
    # which is what stops a DNS rebinding page from reading a local server.
    # Add the public name when this is deployed.
    allowed_hosts: list[str] = ["127.0.0.1", "localhost", "testserver"]

    # Per-client limits on the work a request can start, each as (requests,
    # window in seconds), a JSON list in the environment: "[20, 600]". Off by
    # default; a public deployment turns them on. Analyses count every spawned
    # analysis or fix-impact job, reports every PDF render, scenarios every
    # live generation queued. A cached result or a refused request costs nothing.
    rate_limits_enabled: bool = False
    rate_limit_analyses: tuple[PositiveInt, PositiveInt] = (20, 600)
    rate_limit_reports: tuple[PositiveInt, PositiveInt] = (10, 600)
    rate_limit_scenarios: tuple[PositiveInt, PositiveInt] = (4, 3600)

    # How many proxies in front of the app append to X-Forwarded-For. 0 keys a
    # client by the connection's address; N by the Nth address from the right
    # of the header (Cloud Run's front end appends the caller's, so 1 there).
    # Addresses further left are whatever the client sent and never trusted.
    trusted_proxy_hops: NonNegativeInt = 0

    # The commit shown as the analyser version. Unset, it is read from git; a
    # build without .git sets it.
    analyser_commit: str | None = Field(default=None, validation_alias="ANALYSER_COMMIT")

    # Live scenario generation (plan section 7.2). All six must be set and
    # valid, or live generation is off; cached scenarios stay readable.
    hf_token: SecretStr | None = Field(default=None, validation_alias="HF_TOKEN")
    space_id: str | None = Field(default=None, validation_alias="SPACE_ID")
    base_model_id: str = Field(
        default=contract.BASE_MODEL_ID, validation_alias="BASE_MODEL_ID"
    )
    # Full 40-character commit SHAs, the same ones the Space was deployed with.
    base_revision: str | None = Field(default=None, validation_alias="BASE_REVISION")
    adapter_repo: str | None = Field(default=None, validation_alias="ADAPTER_REPO")
    adapter_revision: str | None = Field(
        default=None, validation_alias="ADAPTER_REVISION"
    )
    loading_recipe: str | None = Field(default=None, validation_alias="LOADING_RECIPE")

    # The prompt format new generations use: "structured-p1" (the default) or
    # "training" (see scenario_contract.PROMPT_VERSIONS). Cached and linked
    # scenarios keep the format they were made with.
    scenario_prompt_format: str = Field(
        default=contract.DEFAULT_PROMPT_FORMAT, validation_alias="SCENARIO_PROMPT_FORMAT"
    )

    # Jobs waiting behind the one the scenario worker is running.
    scenario_queue_max: int = 20
    # Seconds a client is told to wait when no scenario job can be accepted.
    scenario_retry_after_s: int = 30
    # How long a sleeping or starting Space may take to reach RUNNING.
    space_startup_timeout_s: float = 300.0
    # From submission to result, on a monotonic clock.
    generation_timeout_s: float = 600.0
    # Bound on every single call to Hugging Face (runtime, restart, quota,
    # connecting to the Space).
    hf_request_timeout_s: float = 20.0
    # How long /api/health reuses the last runtime stage and quota it read.
    space_status_ttl_s: float = 30.0

    @field_validator("scenario_prompt_format")
    @classmethod
    def _known_prompt_format(cls, value: str) -> str:
        try:
            return contract.check_prompt_format(value.strip())

        except contract.ScenarioContractError as error:
            raise ValueError("SCENARIO_PROMPT_FORMAT: %s" % error) from None

    @field_validator("analyser_commit")
    @classmethod
    def _commit_or_none(cls, value: str | None) -> str | None:
        return (value or "").strip() or None

    @property
    def prompt_version(self) -> str:
        """The prompt_version new generations are made and cached with."""

        return contract.prompt_version_for(self.scenario_prompt_format)

    @property
    def analyses_dir(self) -> Path:
        return self.cache_dir / "analyses"

    @property
    def space_configured(self) -> bool:
        """SPACE_ID and HF_TOKEN are set. Live generation needs more; see below."""

        return bool(self.space_id and self.hf_token)

    def live_config_problem(self) -> str | None:
        """Why live generation is off, or None when it is fully configured.

        Names the settings only, never their values' secrets.
        """

        missing = [
            name for name, value in (
                ("SPACE_ID", self.space_id),
                ("HF_TOKEN", self.hf_token and self.hf_token.get_secret_value()),
                ("BASE_REVISION", self.base_revision),
                ("ADAPTER_REPO", self.adapter_repo),
                ("ADAPTER_REVISION", self.adapter_revision),
                ("LOADING_RECIPE", self.loading_recipe)
            )
            if not value
        ]

        if missing:
            return "Live scenario generation is not configured: set %s." % ", ".join(missing)

        if not contract.is_repo_id(self.space_id):
            return "SPACE_ID must look like owner/name."

        if self.base_model_id != contract.BASE_MODEL_ID:
            return "BASE_MODEL_ID must be %s, the model the adapter was trained on." % (
                contract.BASE_MODEL_ID
            )

        try:
            self.scenario_provenance()

        except contract.ScenarioContractError as error:
            return "Live scenario configuration is invalid: %s." % error

        return None

    def scenario_provenance(self) -> dict:
        """The pinned model provenance every live request is made and cached with."""

        return contract.make_provenance(
            model_revision=self.base_revision,
            adapter_repo=self.adapter_repo,
            adapter_revision=self.adapter_revision,
            loading_recipe=self.loading_recipe
        )
