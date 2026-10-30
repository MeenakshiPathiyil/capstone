"""The API contract. Every response body is one of these models.

The OpenAPI document generated from them (app/scripts/export_openapi.py) is what
the web app's TypeScript types are generated from, so a field changes here first.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["critical", "high", "medium", "low", "unknown"]
AttackLevel = Literal["CRITICAL", "HIGH", "MEDIUM"]
SampleKind = Literal["single", "nested"]
WarningKind = Literal[
    "orphan_finding",
    "rule_error",
    "nested_skipped",
    "transform_unexpanded",
    "graph_truncated",
    "graph_mapping",
    "depth_limit"
]
ScenarioStatus = Literal[
    "idle", "cached", "queued", "warming_up", "running", "done", "failed"
]


class Strict(BaseModel):
    """Unknown fields are an error in both directions."""

    # Response fields with a default are still always present, so the schema
    # says so and the generated TypeScript does not mark them optional.
    model_config = ConfigDict(
        extra="forbid",
        json_schema_serialization_defaults_required=True
    )


class ErrorResponse(Strict):
    """Every error body: one human-readable message."""

    detail: str


# -- Meta and health ------------------------------------------------------------

class Style(Strict):
    fill: str
    stroke: str


class ObjectiveMeta(Strict):
    id: str
    name: str
    base_weight: float


class Sample(Strict):
    id: str
    name: str
    description: str
    kind: SampleKind


class Limits(Strict):
    max_upload_bytes: int
    max_resources: int
    accepted_extensions: list[str]


class Meta(Strict):
    # Keyed by severity plus the two pseudo keys "clean" and "unknown".
    severity_styles: dict[str, Style]
    attack_levels: list[AttackLevel]
    objectives: list[ObjectiveMeta]
    # DEFAULT_INDUSTRY first. Free text is allowed; these are suggestions.
    industries: list[str]
    default_industry: str
    samples: list[Sample]
    limits: Limits


class Health(Strict):
    # The API can accept and serve analyses. Independent of the two below.
    ok: bool
    weasyprint: bool
    pdf_unavailable_reason: str | None = None
    # SPACE_ID and HF_TOKEN are set. Live generation needs the pinned revisions
    # too; model_unavailable_reason is null exactly when POST can start it.
    space_configured: bool
    # Last stage read from Hugging Face (RUNNING, SLEEPING, ...), null if unknown.
    space_stage: str | None = None
    model_unavailable_reason: str | None = None
    # Null when the token cannot read the quota; the provider still enforces it.
    gpu_quota_remaining_s: int | None = None
    gpu_quota_resets_at: datetime | None = None
    # Stays null until throughput and quota have been measured.
    est_generations_left: int | None = None


# -- Analysis ---------------------------------------------------------------------

class SampleRequest(Strict):
    sample_id: str
    industry: str = Field(min_length=1, max_length=200)
    min_level: AttackLevel = "HIGH"


class Reference(Strict):
    source: str
    id: str
    url: str


class Technique(Strict):
    id: str
    name: str


class Remediation(Strict):
    fix: str
    snippet: str | None = None
    url: str


class RuleInfo(Strict):
    rule_id: str
    source_id: str
    display_name: str
    summary: str
    attack_techniques: list[Technique]
    references: list[Reference]
    # Null when data/remediations.yaml has no entry for this check.
    remediation: Remediation | None = None


class Finding(Strict):
    # f"{resource}::{rule_id}"
    id: str
    resource: str
    resource_type: str
    rule_id: str
    source_id: str
    state: str
    semantic: str | None
    severity: Severity
    rule: RuleInfo
    # AP ids of the ranked paths whose findings include this one.
    on_paths: list[str]


class Connection(Strict):
    target: str
    type: str
    relation: str | None = None


class Resource(Strict):
    id: str
    type: str
    max_severity: Severity | None
    is_entry: bool
    entry_reason: str
    # Finding ids.
    findings: list[str]
    # The abstract attributes the rules read (processing/attributes.py).
    attributes: dict[str, Any]
    raw_properties: dict[str, Any]
    connections: list[Connection]


class Evidence(Strict):
    key: str
    value: Any


class RequiredCapability(Strict):
    # Which end of the step the finding has to be on: "source" or "target".
    end: str | None = None
    source_id: list[str] | None = None
    source_id_prefix: list[str] | None = None
    state: list[str] | None = None
    semantic: list[str] | None = None


class Step(Strict):
    source: str
    target: str
    category: str | None
    relation: str | None
    action_id: str | None
    action: str
    tactic: str | None
    technique: str | None
    # The ATT&CK matrix's name for the technique id, null when it is not in it.
    technique_name: str | None
    # The facts that held, out of the alternatives in precondition_options.
    precondition: list[str]
    precondition_options: list[str]
    postcondition: list[str]
    required_permissions: list[str]
    required_capabilities: list[RequiredCapability]
    # The step's input bindings, minus `target` and `source`. Lists stay lists.
    evidence: list[Evidence]
    output: dict[str, Any]
    fallback: bool


class ScoreBreakdown(Strict):
    severity_total: float
    objective_weight: float
    hops: int
    length_factor: float
    public_entry: bool
    boost: float
    score: float
    threshold_high: float
    threshold_critical: float


class PathRisk(Strict):
    """The contextual risk model's second opinion on a path (risk_scoring/).

    It does not change the path's score, level, rank or export. Its weights are
    provisional and uncalibrated.
    """

    # Every score is 0 to 100, rounded to two places.
    score: float
    impact: float
    exposure: float
    path_ease: float
    # Dense rank by score among this analysis's paths, 1 = highest. Equal
    # scores share a rank.
    rank: int
    reachability: Literal["direct", "via_path", "post_compromise"]
    # Resources reachable from the target, and the median over every resource.
    downstream_count: int
    graph_median: float
    # Read from the target's tags; null when no tag says.
    asset_criticality: Literal["high", "medium", "low"] | None
    sensitive_data: bool | None
    environment: Literal["prod", "dev", "test"] | None


class ExportRecord(Strict):
    """The seven-key record the scenario generator reads, unchanged."""

    source_id: str
    source_name: str
    industry: str
    attack_level: str
    techniques: str
    surfaces: str
    objective: str


class Path(Strict):
    # "AP-001", by overall rank. Matches attack_path_steps.json.
    source_id: str
    rank: int
    # True when the path is at or above the analysis's min_level.
    exported: bool
    entry_id: str
    target_id: str
    hops: list[str]
    length: int
    public_entry: bool
    objective: str
    objective_name: str
    objective_techniques: list[str]
    score: float
    attack_level: AttackLevel
    breakdown: ScoreBreakdown
    # Equal for paths with identical hops (one route, several objectives).
    chain_group: int
    steps: list[Step]
    finding_ids: list[str]
    export: ExportRecord | None = None
    # Null in analyses saved before the model was added.
    risk: PathRisk | None = None


class PathIdentity(Strict):
    hops: list[str]
    objective: str


class FixImpact(Strict):
    """What suppressing one finding does to the selected path set.

    Suppression models evidence removal, not a verified repair.
    """

    finding_id: str
    # Paths no longer at or above the selected risk level.
    selected_paths_removed: int
    selected_paths_remaining: int
    selected_paths_added: int
    baseline_selected_paths: int
    removed_ids: list[str]
    added_paths: list[PathIdentity]
    scope_top: int | None


class FixImpactResult(Strict):
    analysis_id: str
    # Null when the scope is every selected path, which includes a requested
    # count that reaches the selected count.
    scope_top: int | None
    candidate_count: int
    computed_at: datetime
    results: list[FixImpact]


class Warning(Strict):  # noqa: A001 - the contract's name for it
    kind: WarningKind
    message: str


class Summary(Strict):
    resources: int
    edges: int
    findings: int
    findings_by_severity: dict[Severity, int]
    paths: int
    paths_exported: int
    paths_by_level: dict[AttackLevel, int]
    entry_points: int
    top_score: float | None


class NestedMerged(Strict):
    stack: str
    # Relative to the repository root.
    template: str
    resources: int


class NestedSkipped(Strict):
    stack: str
    reason: str
    url: str | None = None


class NestedReport(Strict):
    merged: list[NestedMerged]
    skipped: list[NestedSkipped]


class Analysis(Strict):
    id: str
    created_at: datetime
    input_name: str
    input_sha256: str
    industry: str
    min_level: AttackLevel
    analyser_commit: str
    schema_version: int
    summary: Summary
    resources: list[Resource]
    findings: list[Finding]
    paths: list[Path]
    # An optional initial snapshot; the fixes endpoint is authoritative.
    top_fixes: list[FixImpact] = []
    warnings: list[Warning]
    nested_report: NestedReport | None = None


# -- Graph --------------------------------------------------------------------------

class GraphNode(Strict):
    # Opaque display key, stable within one saved analysis.
    key: str
    label_lines: list[str]
    # A key of Meta.severity_styles.
    style: str
    is_entry: bool
    # Null only for the attacker root of the attack view.
    resource: str | None
    # Attack view only: the facts the attacker holds in this state.
    facts: list[str] | None = None


class GraphEdge(Strict):
    key: str
    source: str
    target: str
    label: str
    categories: list[str]
    reversed: bool
    # AP ids of the ranked paths that use this edge.
    path_ids: list[str]
    action_id: str | None = None
    tactic: str | None = None
    technique: str | None = None


class GraphView(Strict):
    view: Literal["state", "attack"]
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    dropped_edges: int
    truncated: bool
    warnings: list[Warning]


# -- Scenario (app/api/scenarios.py) ------------------------------------------------------

class ScenarioSections(Strict):
    natural_language: str | None = None
    mathematical: str | None = None
    attack_graph: str | None = None
    # Text before the first header, kept apart rather than relabelled.
    preamble: str | None = None
    missing: list[str]


class Scenario(Strict):
    cache_key: str
    # How it was generated. A cache hit changes ScenarioState.status, not this.
    source: Literal["pregenerated", "live"]
    text: str
    sections: ScenarioSections
    reached_token_cap: bool
    hit_eos: bool
    new_tokens: int
    max_new_tokens: int
    finish_reason: Literal["eos", "length", "other"]
    seconds: float
    model_id: str
    model_revision: str
    adapter_repo: str
    adapter_revision: str
    loading_recipe: str
    prompt_version: str
    generation_config: dict[str, Any]
    generated_at: datetime


class ScenarioState(Strict):
    # idle: never requested; queued/warming_up/running: a job is active (poll);
    # done: generated by this server for this path; cached: served from the
    # local cache; failed: the last job failed (see error), POST to start anew.
    status: ScenarioStatus
    # Jobs ahead of this one, the running one included. Only while queued.
    queue_position: int | None = None
    elapsed_s: float | None = None
    eta_s: float | None = None
    scenario: Scenario | None = None
    error: str | None = None


# Models no route returns yet, added to the OpenAPI components so the web app's
# generated types are complete before those routes exist.
UNROUTED_MODELS = []
