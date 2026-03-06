"""Standardized agent tool output helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from autosecaudit.core.models import Asset


@dataclass(frozen=True)
class StandardFinding:
    """Normalized finding emitted by agent tools."""

    id: str
    tool: str
    severity: str
    category: str
    title: str
    description: str
    evidence: dict[str, Any]
    remediation: str
    reproduction_steps: list[str] = field(default_factory=list)
    related_asset_ids: list[str] = field(default_factory=list)
    cwe_id: str | None = None
    cvss_score: float | None = None
    cve_id: str | None = None
    cve_verified: bool = False


@dataclass(frozen=True)
class DiscoveredAsset:
    """Normalized asset/breadcrumb discovered by a tool."""

    type: str
    data: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StandardToolOutput:
    """Unified agent tool output."""

    status: str
    findings: list[StandardFinding] = field(default_factory=list)
    discovered_assets: list[DiscoveredAsset] = field(default_factory=list)
    graph_assets: list[Asset | dict[str, Any]] = field(default_factory=list)
    surface_updates: dict[str, Any] = field(default_factory=dict)
    follow_up_hints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_data(self) -> dict[str, Any]:
        """Convert standardized output into legacy-compatible tool result data."""
        return {
            "status": self.status,
            "payload": dict(self.metadata),
            "findings": [asdict(item) for item in self.findings],
            "breadcrumbs_delta": [asdict(item) for item in self.discovered_assets],
            "assets_delta": [self._asset_to_dict(item) for item in self.graph_assets],
            "surface_delta": dict(self.surface_updates),
            "follow_up_hints": list(self.follow_up_hints),
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def _asset_to_dict(item: Asset | dict[str, Any]) -> dict[str, Any]:
        if is_dataclass(item):
            return asdict(item)
        if isinstance(item, dict):
            return dict(item)
        return {}


def normalize_findings(findings: list[Any]) -> list[dict[str, Any]]:
    """Convert dataclass or dict findings into dictionaries."""
    normalized: list[dict[str, Any]] = []
    for item in findings:
        if is_dataclass(item):
            payload = asdict(item)
        elif isinstance(item, dict):
            payload = dict(item)
        else:
            continue
        normalized.append(payload)
    return normalized
