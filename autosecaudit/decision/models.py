"""Decision-layer data models."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class DecisionRecommendation:
    """Tool recommendation parsed from classic LLM response format."""

    target: str
    prompt: str
    raw_response: str
    suggested_tools: list[str]
    rejected_tools: list[str] = field(default_factory=list)
    reason: str | None = None
    parse_error: str | None = None


@dataclass(frozen=True)
class PlannedAction:
    """One executable audit action with deterministic metadata."""

    action_id: str
    tool_name: str
    target: str
    options: dict[str, Any]
    priority: int
    cost: int
    capabilities: list[str]
    idempotency_key: str
    reason: str
    preconditions: list[str]
    stop_conditions: list[str]


@dataclass(frozen=True)
class ActionPlan:
    """Top-level planner output."""

    decision_summary: str
    actions: list[PlannedAction]


@dataclass(frozen=True)
class ScopeModel:
    """Parsed scope information."""

    domains: set[str]
    ips: set[IPAddress]
    networks: list[IPNetwork]


@dataclass(frozen=True)
class CandidateAction:
    """Internal candidate action before final budget filtering."""

    tool_name: str
    target: str
    options: dict[str, Any]
    priority: int
    cost: int
    reason: str
    preconditions: list[str]
    stop_conditions: list[str]
    capabilities: list[str] = field(default_factory=lambda: ["network_read"])


@dataclass(frozen=True)
class ResolvedTarget:
    """Resolved target candidate before action construction."""

    target: str
    target_type: str
    context: dict[str, Any] = field(default_factory=dict)

