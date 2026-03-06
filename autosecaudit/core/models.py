"""Shared data models used by AutoSecAudit."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
import logging

if TYPE_CHECKING:
    from .command import SafeCommandRunner
    from .logging_utils import OperationRecorder


Severity = Literal["info", "low", "medium", "high", "critical"]
PluginStatus = Literal["passed", "failed", "error", "skipped"]
PluginCategory = Literal["discovery", "validation"]
OperationStatus = Literal["start", "success", "warning", "error", "timeout", "info"]
AssetKind = Literal["domain", "ip", "host", "origin", "url", "service", "cve", "component", "credential_form", "api"]


def utc_now_iso() -> str:
    """Return a UTC timestamp in ISO8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RuntimeConfig:
    """Runtime settings for a full audit execution."""

    target: str
    output_dir: Path
    log_dir: Path
    enabled_plugins: list[str] | None = None
    plugin_timeout_seconds: float = 15.0
    strict_safe_mode: bool = True
    command_allowlist: tuple[str, ...] = ("python", "nslookup", "dig", "ping", "tracert", "host")


@dataclass
class Asset:
    """Normalized asset node for graph-style audit state."""

    kind: AssetKind | str
    id: str
    parent_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    source_tool: str = ""


@dataclass
class ServiceAsset(Asset):
    """Service-oriented asset helper."""

    host: str = ""
    port: int = 0
    proto: str = "tcp"
    service: str = ""
    banner: str = ""
    tls: bool = False
    auth_required: bool | None = None


@dataclass
class WebAsset(Asset):
    """Web-oriented asset helper."""

    origin: str = ""
    paths: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    forms: list[dict[str, Any]] = field(default_factory=list)
    js: list[str] = field(default_factory=list)
    api_schemas: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Finding:
    """A single audit finding produced by a plugin."""

    finding_id: str
    title: str
    description: str
    severity: Severity
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None
    reproduction_steps: list[str] = field(default_factory=list)
    related_asset_ids: list[str] = field(default_factory=list)
    cve_id: str | None = None
    cvss_score: float | None = None
    cve_verified: bool = False


@dataclass
class PluginResult:
    """Standardized output contract for plugin execution."""

    plugin_id: str
    plugin_name: str
    category: PluginCategory
    status: PluginStatus
    started_at: str
    ended_at: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OperationEvent:
    """Structured operation-level log entry."""

    timestamp: str
    plugin_id: str
    action: str
    status: OperationStatus
    detail: str


@dataclass
class AuditSessionResult:
    """Final result object for a full AutoSecAudit run."""

    target: str
    started_at: str
    ended_at: str
    plugin_results: list[PluginResult]
    summary: dict[str, Any]


@dataclass
class AuditContext:
    """Mutable execution context shared across plugins."""

    config: RuntimeConfig
    logger: logging.Logger
    recorder: OperationRecorder
    command_runner: SafeCommandRunner

    def log_operation(
        self,
        plugin_id: str,
        action: str,
        status: OperationStatus,
        detail: str,
    ) -> None:
        """Write a structured operation event to logger and JSONL event stream."""
        self.recorder.record(
            OperationEvent(
                timestamp=utc_now_iso(),
                plugin_id=plugin_id,
                action=action,
                status=status,
                detail=detail,
            )
        )
