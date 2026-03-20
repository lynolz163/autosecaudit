"""Pydantic API schemas for the web console."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


RoleName = Literal["admin", "operator", "viewer"]
SafetyGradeName = Literal["conservative", "balanced", "aggressive"]
AutonomyModeName = Literal["constrained", "adaptive", "supervised"]
MissionChatActionName = Literal["ask", "confirm", "executed", "preview"]
MissionWorkflowStateName = Literal["needs_input", "launch_preview", "launch_confirm", "launch_executed"]


class StrictModel(BaseModel):
    """Base model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid")


class FlexibleModel(BaseModel):
    """Base model that allows extra keys for evolving payloads."""

    model_config = ConfigDict(extra="allow")


class PasswordPolicyResponse(StrictModel):
    min_length: int
    require_mixed_case: bool
    require_digit: bool
    require_special: bool


class AuthStatusResponse(StrictModel):
    has_users: bool
    bootstrap_enabled: bool
    default_admin_env_configured: bool
    roles: list[RoleName]
    token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    password_policy: PasswordPolicyResponse


class UserView(StrictModel):
    user_id: int | None = None
    username: str
    role: RoleName
    display_name: str | None = None
    enabled: bool
    created_at: str | None = None
    updated_at: str | None = None
    last_login_at: str | None = None
    auth_type: str | None = None


class PermissionSummaryResponse(StrictModel):
    role: RoleName
    can_view: bool
    can_operate: bool
    can_admin: bool


class AuthMeResponse(StrictModel):
    user: UserView
    permissions: PermissionSummaryResponse


class TokenBundleResponse(StrictModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    refresh_expires_in: int
    user: UserView


class LoginRequest(StrictModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=1)


class BootstrapRequest(StrictModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    display_name: str | None = None


class UserListResponse(StrictModel):
    items: list[UserView]
    actor: str


class UserItemResponse(StrictModel):
    item: UserView


class UserDeleteResponse(StrictModel):
    ok: bool
    user_id: int


class UserCreateRequest(StrictModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    role: RoleName = "viewer"
    display_name: str | None = None
    enabled: bool = True


class UserUpdateRequest(StrictModel):
    username: str | None = None
    password: str | None = None
    role: RoleName | None = None
    display_name: str | None = None
    enabled: bool | None = None


class AssetView(StrictModel):
    asset_id: int
    name: str
    target: str
    scope: str | None = None
    default_mode: Literal["agent", "plan", "plugins"]
    tags: list[str] = Field(default_factory=list)
    default_payload: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    created_at: str | None = None
    updated_at: str | None = None
    notes: str | None = None


class AssetCreateRequest(StrictModel):
    name: str = Field(min_length=1)
    target: str = Field(min_length=1)
    scope: str | None = None
    default_mode: Literal["agent", "plan", "plugins"] = "agent"
    tags: list[str] = Field(default_factory=list)
    default_payload: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    notes: str | None = None


class AssetUpdateRequest(StrictModel):
    name: str | None = None
    target: str | None = None
    scope: str | None = None
    default_mode: Literal["agent", "plan", "plugins"] | None = None
    tags: list[str] | None = None
    default_payload: dict[str, Any] | None = None
    enabled: bool | None = None
    notes: str | None = None


class AssetListResponse(StrictModel):
    items: list[AssetView]


class AssetItemResponse(StrictModel):
    item: AssetView


class AssetDeleteResponse(StrictModel):
    ok: bool


class JsonObjectRequest(RootModel[dict[str, Any]]):
    pass


class ScheduleView(StrictModel):
    schedule_id: int
    asset_id: int | None = None
    name: str
    cron_expr: str
    payload: dict[str, Any] = Field(default_factory=dict)
    notify_on: list[str] = Field(default_factory=list)
    enabled: bool
    created_at: str | None = None
    updated_at: str | None = None
    last_run_at: str | None = None
    last_job_id: str | None = None
    last_error: str | None = None
    next_run_at: str | None = None


class ScheduleCreateRequest(StrictModel):
    asset_id: int | None = None
    name: str = Field(min_length=1)
    cron_expr: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    notify_on: list[str] = Field(default_factory=list)
    enabled: bool = True


class ScheduleUpdateRequest(StrictModel):
    asset_id: int | None = None
    name: str | None = None
    cron_expr: str | None = None
    payload: dict[str, Any] | None = None
    notify_on: list[str] | None = None
    enabled: bool | None = None
    last_run_at: str | None = None
    last_job_id: str | None = None
    last_error: str | None = None


class ScheduleListResponse(StrictModel):
    items: list[ScheduleView]


class ScheduleItemResponse(StrictModel):
    item: ScheduleView


class ScheduleDeleteResponse(StrictModel):
    ok: bool


class NotificationSettingsResponse(StrictModel):
    item: dict[str, Any]


# ---------------------------------------------------------------------------
# LLM settings
# ---------------------------------------------------------------------------


class LlmPresetView(StrictModel):
    """One preset provider template shown in the UI."""

    id: str
    label: str
    provider_type: str = "openai_compatible"
    base_url: str
    default_model: str
    note: str | None = None


class LlmSettingsResponse(StrictModel):
    """Current persisted LLM configuration."""

    configured: bool = False
    preset_id: str | None = None
    provider_type: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key_configured: bool = False
    temperature: float = 0.0
    max_output_tokens: int = 1200
    timeout_seconds: float = 300.0
    source: str = "none"
    presets: list[LlmPresetView] = Field(default_factory=list)


class LlmSettingsSaveRequest(StrictModel):
    """Payload to save LLM configuration via web UI."""

    preset_id: str | None = None
    provider_type: str = "openai_compatible"
    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)
    api_key: str | None = None
    temperature: float = 0.0
    max_output_tokens: int = 1200
    timeout_seconds: float = 300.0


class LlmTestRequest(StrictModel):
    """Payload to test LLM connectivity."""

    provider_type: str = "openai_compatible"
    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)
    api_key: str | None = None
    timeout_seconds: float = 300.0


class LlmTestResponse(StrictModel):
    ok: bool
    model: str
    latency_ms: int | None = None
    reply_preview: str | None = None
    error: str | None = None


class AuditEventView(StrictModel):
    event_id: int
    created_at: str | None = None
    actor: str
    event_type: str
    resource_type: str
    resource_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class AuditEventListResponse(StrictModel):
    items: list[AuditEventView]


class PluginResolvedDirView(StrictModel):
    configured_path: str
    resolved_path: str
    exists: bool
    is_dir: bool


class PluginRuntimeErrorView(StrictModel):
    path: str
    error: str


class PluginRuntimeView(StrictModel):
    last_loaded_at: str | None = None
    resolved_dirs: list[str] = Field(default_factory=list)
    loaded_plugin_ids: list[str] = Field(default_factory=list)
    errors: list[PluginRuntimeErrorView] = Field(default_factory=list)


class PluginSettingsView(StrictModel):
    plugin_dirs: list[str] = Field(default_factory=list)
    updated_at: str | None = None
    resolved_dirs: list[PluginResolvedDirView] = Field(default_factory=list)
    runtime: PluginRuntimeView


class PluginCatalogItemView(StrictModel):
    plugin_id: str
    name: str
    category: str
    read_only: bool
    version: str
    risk_level: str
    description: str | None = None
    module_name: str
    module_path: str | None = None
    builtin: bool
    source_type: str
    reloadable: bool


class PluginMetricsView(StrictModel):
    total_plugins: int
    builtin_plugins: int
    external_plugins: int


class PluginCatalogResponse(StrictModel):
    items: list[PluginCatalogItemView]
    settings: PluginSettingsView
    metrics: PluginMetricsView
    actor: str | None = None


class PluginSettingsRequest(StrictModel):
    plugin_dirs: list[str] = Field(default_factory=list)


class PluginSettingsResponse(StrictModel):
    item: PluginSettingsView


class CodexConfigResponse(StrictModel):
    configured: bool
    provider_alias: str
    provider_type: str
    base_url: str
    profile_id: str
    profiles_file: str
    authorize_url: str
    token_url: str
    client_id_configured: bool
    scopes: list[str] = Field(default_factory=list)
    builtin_preset_enabled: bool
    preset_source: str
    login_backend: str
    agent_provider_alias: str
    agent_provider_type: str
    agent_base_url: str
    agent_api_key_env: str
    actor: str | None = None


class CodexLoginStartResponse(StrictModel):
    session_id: str
    authorize_url: str
    redirect_uri: str
    provider_alias: str
    profile_id: str
    base_url: str


class CodexLoginStatusResponse(StrictModel):
    session_id: str
    status: str
    created_at: str
    updated_at: str
    error: str | None = None
    provider_alias: str | None = None
    profile_id: str | None = None
    model_count: int | None = None
    login_backend: str
    actor: str | None = None


class CodexModelItem(StrictModel):
    id: str
    label: str
    owned_by: str | None = None
    created: int | None = None


class CodexModelsResponse(StrictModel):
    provider_alias: str
    provider_type: str
    base_url: str
    profile_id: str
    models: list[CodexModelItem] = Field(default_factory=list)
    login_backend: str
    agent_provider_alias: str
    agent_provider_type: str
    agent_base_url: str
    agent_api_key_env: str
    actor: str | None = None


class JobView(FlexibleModel):
    job_id: str
    status: str
    session_status: str | None = None
    created_at: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    last_updated_at: str | None = None
    target: str | None = None
    mode: str | None = None
    safety_grade: SafetyGradeName = "balanced"
    report_lang: str = "zh-CN"
    pid: int | None = None
    return_code: int | None = None
    output_dir: str | None = None
    resume: bool | None = None
    llm_config: str | None = None
    surface_file: str | None = None
    error: str | None = None
    cancel_requested: bool = False
    log_line_count: int = 0
    artifact_count: int = 0
    command_preview: list[str] = Field(default_factory=list)
    pending_approval: dict[str, Any] = Field(default_factory=dict)
    loop_guard: dict[str, Any] = Field(default_factory=dict)


class JobCreateRequest(FlexibleModel):
    target: str = Field(min_length=1)
    mode: Literal["agent", "plan", "plugins"] = "agent"
    safety_grade: SafetyGradeName = "balanced"
    autonomy_mode: AutonomyModeName = "adaptive"
    report_lang: str = "zh-CN"
    scope: str | None = None
    plugins: str | None = None
    timeout: float | None = Field(default=None, ge=1.0, le=3600.0)
    budget: int | None = Field(default=None, ge=1, le=100000)
    max_iterations: int = Field(default=5, ge=1, le=100)
    global_timeout: float = Field(default=600.0, ge=10.0, le=86400.0)
    llm_config: str | None = None
    llm_source: Literal["system", "custom"] = "system"
    no_llm_hints: bool = False
    resume: str | None = None
    plan_filename: str | None = None
    tools: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    multi_agent: bool = False
    multi_agent_rounds: int = Field(default=1, ge=1, le=8)
    approval_granted: bool | None = None
    knowledge_summary: str | None = None
    knowledge_tags: list[str] = Field(default_factory=list)
    knowledge_refs: list[str] = Field(default_factory=list)
    surface: dict[str, Any] | None = None
    surface_file: str | None = None


class MissionRequest(StrictModel):
    message: str = Field(min_length=1)
    session_id: str | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class MissionTurnView(StrictModel):
    role: Literal["user", "system"]
    message: str
    summary: list[str] = Field(default_factory=list)


class MissionDraftView(StrictModel):
    raw_message: str
    target: str | None = None
    scope: str | None = None
    intent: str
    depth: str
    mode: str
    report_lang: str = "zh-CN"
    safety_grade: SafetyGradeName = "balanced"
    autonomy_mode: AutonomyModeName = "adaptive"
    multi_agent: bool = False
    multi_agent_rounds: int = 1
    authorization_confirmed: bool = False
    approval_granted: bool | None = None
    selected_tools: list[str] = Field(default_factory=list)
    selected_skills: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    summary: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)


class MissionDraftResponse(StrictModel):
    session_id: str
    messages: list[MissionTurnView] = Field(default_factory=list)
    draft: MissionDraftView


class MissionExecutionResponse(StrictModel):
    session_id: str
    messages: list[MissionTurnView] = Field(default_factory=list)
    draft: MissionDraftView
    job: JobView


class MissionChatResponse(StrictModel):
    session_id: str
    action: MissionChatActionName
    workflow_state: MissionWorkflowStateName
    assistant_message: str
    messages: list[MissionTurnView] = Field(default_factory=list)
    draft: MissionDraftView
    job: JobView | None = None


class JobListResponse(StrictModel):
    items: list[JobView]


class JobItemResponse(StrictModel):
    job: JobView


class JobLogLine(StrictModel):
    ts: str
    line: str


class JobLogsResponse(StrictModel):
    job_id: str
    offset: int
    next_offset: int
    total: int
    items: list[JobLogLine]


class ArtifactView(StrictModel):
    path: str
    size: int
    mtime: int


class JobArtifactsResponse(StrictModel):
    job_id: str
    items: list[ArtifactView]


class DoctorCheckView(StrictModel):
    check_id: str
    status: Literal["pass", "warn", "fail"]
    message: str
    detail: str | None = None


class DoctorReportResponse(FlexibleModel):
    summary: dict[str, int] = Field(default_factory=dict)
    checks: list[DoctorCheckView] = Field(default_factory=list)


class DashboardSummaryResponse(FlexibleModel):
    generated_at: str
    metrics: dict[str, int | float]
    severity_counts: dict[str, int]
    recent_jobs: list[dict[str, str | None]]


class GlobalSearchItem(FlexibleModel):
    kind: str
    route: Literal["jobs", "reports", "assets", "schedules"]
    title: str
    subtitle: str | None = None
    summary: str | None = None
    score: float = 0.0
    target: str | None = None
    job_id: str | None = None
    asset_id: int | None = None
    schedule_id: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GlobalSearchResponse(StrictModel):
    query: str
    total: int = 0
    groups: dict[str, int] = Field(default_factory=dict)
    items: list[GlobalSearchItem] = Field(default_factory=list)


class ReportItem(FlexibleModel):
    job_id: str
    target: str | None = None
    target_key: str | None = None
    mode: str | None = None
    status: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    updated_at: str | None = None
    report_paths: dict[str, str | None] = Field(default_factory=dict)
    available_formats: list[str] = Field(default_factory=list)
    preview_path: str | None = None
    finding_total: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    decision_summary: str | None = None


class ReportListResponse(StrictModel):
    items: list[ReportItem]


class ReportItemResponse(StrictModel):
    item: ReportItem


class ReportFinding(FlexibleModel):
    fingerprint: str
    plugin_id: str
    plugin_name: str
    category: str | None = None
    finding_id: str | None = None
    title: str
    description: str | None = None
    severity: str
    recommendation: str | None = None
    evidence: dict[str, object] = Field(default_factory=dict)
    evidence_text: str
    cve_id: str | None = None
    cvss_score: float | None = None
    cve_verified: bool = False
    related_asset_ids: list[str] = Field(default_factory=list)


class ReportDiff(FlexibleModel):
    baseline_job_id: str | None = None
    baseline_updated_at: str | None = None
    new_count: int = 0
    resolved_count: int = 0
    persistent_count: int = 0
    new_findings: list[ReportFinding] = Field(default_factory=list)
    resolved_findings: list[ReportFinding] = Field(default_factory=list)
    persistent_findings: list[ReportFinding] = Field(default_factory=list)
    new_assets_count: int = 0
    resolved_assets_count: int = 0
    persistent_assets_count: int = 0
    new_assets: list[dict[str, Any]] = Field(default_factory=list)
    resolved_assets: list[dict[str, Any]] = Field(default_factory=list)
    new_services_count: int = 0
    resolved_services_count: int = 0
    persistent_services_count: int = 0
    new_services: list[dict[str, Any]] = Field(default_factory=list)
    resolved_services: list[dict[str, Any]] = Field(default_factory=list)
    new_asset_severity_counts: dict[str, int] = Field(default_factory=dict)
    resolved_asset_severity_counts: dict[str, int] = Field(default_factory=dict)
    persistent_asset_severity_counts: dict[str, int] = Field(default_factory=dict)
    new_service_protocol_counts: list[dict[str, Any]] = Field(default_factory=list)
    resolved_service_protocol_counts: list[dict[str, Any]] = Field(default_factory=list)
    persistent_service_protocol_counts: list[dict[str, Any]] = Field(default_factory=list)


class ReportHistoryItem(FlexibleModel):
    job_id: str
    target: str | None = None
    status: str | None = None
    mode: str | None = None
    updated_at: str | None = None
    ended_at: str | None = None
    finding_total: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    is_current: bool = False


class ReportExecutionHistoryItem(FlexibleModel):
    index: int | None = None
    tool: str | None = None
    target: str | None = None
    phase: str | None = None
    status: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    action_cost: int | None = None
    budget_before: int | None = None
    budget_after: int | None = None
    error: str | None = None
    metadata_summary: dict[str, Any] = Field(default_factory=dict)
    ranking_explanation: dict[str, Any] = Field(default_factory=dict)


class ReportAsset(FlexibleModel):
    id: str
    kind: str
    parent_id: str | None = None
    source_tool: str | None = None
    display_name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    finding_count: int = 0
    related_findings: list[dict[str, Any]] = Field(default_factory=list)


class ReportAnalysis(FlexibleModel):
    job_id: str
    target: str | None = None
    baseline_job_id: str | None = None
    session_status: str | None = None
    pending_approval: dict[str, Any] = Field(default_factory=dict)
    loop_guard: dict[str, Any] = Field(default_factory=dict)
    thought_stream: list[dict[str, Any]] = Field(default_factory=list)
    evidence_graph: dict[str, Any] = Field(default_factory=dict)
    cve_validation: dict[str, Any] = Field(default_factory=dict)
    remediation_priority: list[dict[str, Any]] = Field(default_factory=list)
    path_graph: dict[str, Any] = Field(default_factory=dict)
    knowledge_context: dict[str, Any] = Field(default_factory=dict)
    history: list[ReportHistoryItem] = Field(default_factory=list)
    history_count: int = 0
    execution_history: list[ReportExecutionHistoryItem] = Field(default_factory=list)
    execution_history_count: int = 0
    findings: list[ReportFinding] = Field(default_factory=list)
    finding_count: int = 0
    assets: list[ReportAsset] = Field(default_factory=list)
    asset_summary: dict[str, Any] = Field(default_factory=dict)
    verification_ranking: list[dict[str, Any]] = Field(default_factory=list)
    asset_phase_trends: list[dict[str, Any]] = Field(default_factory=list)
    asset_batch_trends: list[dict[str, Any]] = Field(default_factory=list)
    diff: ReportDiff
    available_exports: list[str] = Field(default_factory=list)


class ReportAnalysisResponse(StrictModel):
    item: ReportItem
    analysis: ReportAnalysis


class CveSearchRequest(StrictModel):
    keyword: str | None = None
    cpe_name: str | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None
    max_results: int = Field(default=20, ge=1, le=200)
    components: list[str] = Field(default_factory=list)


class CveSearchItem(StrictModel):
    cve_id: str
    severity: str
    description: str
    affected_versions: list[str] = Field(default_factory=list)
    has_nuclei_template: bool = False
    cvss_score: float | None = None
    component: str | None = None
    version: str | None = None
    source: str = "nvd"


class CveSearchResponse(StrictModel):
    items: list[CveSearchItem] = Field(default_factory=list)


class CveVerifyCandidate(StrictModel):
    cve_id: str
    target: str
    component: str | None = None
    version: str | None = None
    safe_only: bool = True
    allow_high_risk: bool = False
    authorization_confirmed: bool = False


class CveVerifyRequest(StrictModel):
    target: str = Field(min_length=1)
    safety_grade: SafetyGradeName = "balanced"
    authorization_confirmed: bool = False
    safe_only: bool = True
    allow_high_risk: bool = False
    cve_ids: list[str] = Field(default_factory=list)
    cve_candidates: list[CveVerifyCandidate] = Field(default_factory=list)


class CveVerifyResponse(StrictModel):
    job: JobView


class CveJobResultResponse(StrictModel):
    job_id: str
    findings: list[ReportFinding] = Field(default_factory=list)
    candidates: list[CveSearchItem] = Field(default_factory=list)
    verification: list[dict[str, Any]] = Field(default_factory=list)


class RagDocumentView(StrictModel):
    id: str
    title: str
    summary: str = ""
    content: str = ""
    tags: list[str] = Field(default_factory=list)
    recommended_tools: list[str] = Field(default_factory=list)
    severity_hint: str = "info"
    references: list[str] = Field(default_factory=list)
    source: str = "file"


class RagCorpusResponse(StrictModel):
    corpus_path: str
    exists: bool
    writable: bool
    external_document_count: int = 0
    effective_document_count: int = 0
    documents: list[RagDocumentView] = Field(default_factory=list)


class RagCorpusSaveRequest(StrictModel):
    documents: list[RagDocumentView] = Field(default_factory=list)


class RagSearchRequest(StrictModel):
    query: str | None = None
    component: str | None = None
    version: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    max_results: int = Field(default=8, ge=1, le=20)
    min_score: float = Field(default=1.0, ge=0.0, le=100.0)


class RagSearchItem(FlexibleModel):
    doc_id: str
    title: str
    summary: str | None = None
    snippet: str | None = None
    source: str | None = None
    tags: list[str] = Field(default_factory=list)
    recommended_tools: list[str] = Field(default_factory=list)
    severity_hint: str | None = None
    references: list[str] = Field(default_factory=list)
    score: float | None = None


class RagSearchResponse(StrictModel):
    corpus_path: str
    items: list[RagSearchItem] = Field(default_factory=list)
