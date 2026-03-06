"""Autonomy profiles shared by mission intake, policy, and execution."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from autosecaudit.agent_safety import normalize_safety_grade


DEFAULT_AUTONOMY_MODE = "adaptive"
AUTONOMY_MODES = frozenset({"constrained", "adaptive", "supervised"})
PLAYWRIGHT_TOOL_NAMES = frozenset({"dynamic_crawl", "active_web_crawler", "page_vision_analyzer"})

AUTONOMY_ALLOWED_RISK_LEVELS: dict[str, frozenset[str]] = {
    "constrained": frozenset({"safe", "low"}),
    "adaptive": frozenset({"safe", "low", "medium"}),
    "supervised": frozenset({"safe", "low", "medium", "high"}),
}

AUTONOMY_DENIED_TOOLS: dict[str, frozenset[str]] = {
    "constrained": frozenset({"cve_verify", "poc_sandbox_exec"}),
    "adaptive": frozenset({"poc_sandbox_exec"}),
    "supervised": frozenset(),
}

_AUTONOMY_OPTION_LIMITS: dict[str, dict[str, dict[str, Any]]] = {
    "constrained": {
        "nmap_scan": {"ports": "top-100", "version_detection": False, "timeout_seconds": 60},
        "dynamic_crawl": {"max_depth": 1},
        "active_web_crawler": {"max_depth": 1, "limit": 20},
        "page_vision_analyzer": {"timeout_seconds": 12, "full_page": False},
        "dirsearch_scan": {"threads": 2, "timeout_seconds": 45, "max_results": 100},
        "param_fuzzer": {"mode": "lightweight", "max_probes": 3},
        "nuclei_exploit_check": {"severity": ["info", "low", "medium"], "timeout_seconds": 120},
        "cve_verify": {"safe_only": True, "allow_high_risk": False, "timeout_seconds": 120},
        "poc_sandbox_exec": {"safe_mode": True, "timeout_seconds": 15},
    },
    "adaptive": {
        "nmap_scan": {"ports": "top-1000", "version_detection": False, "timeout_seconds": 90},
        "dynamic_crawl": {"max_depth": 2},
        "active_web_crawler": {"max_depth": 2, "limit": 50},
        "page_vision_analyzer": {"timeout_seconds": 20},
        "dirsearch_scan": {"threads": 4, "timeout_seconds": 90, "max_results": 300},
        "param_fuzzer": {"mode": "lightweight", "max_probes": 6},
        "nuclei_exploit_check": {"severity": ["info", "low", "medium"], "timeout_seconds": 180},
        "cve_verify": {"safe_only": True, "allow_high_risk": False, "timeout_seconds": 180},
        "poc_sandbox_exec": {"safe_mode": True, "timeout_seconds": 20},
    },
    "supervised": {},
}


def default_autonomy_mode(*, safety_grade: str | None = None) -> str:
    """Derive a sane autonomy default from the current safety grade."""
    return "supervised" if normalize_safety_grade(safety_grade or "balanced") == "aggressive" else DEFAULT_AUTONOMY_MODE


def normalize_autonomy_mode(value: Any, *, safety_grade: str | None = None) -> str:
    """Normalize autonomy mode with a safety-grade aware fallback."""
    text = str(value or "").strip().lower()
    if text in AUTONOMY_MODES:
        return text
    return default_autonomy_mode(safety_grade=safety_grade)


def autonomy_allowed_risk_levels(mode: str) -> frozenset[str]:
    """Return the risk levels allowed by one autonomy profile."""
    normalized = normalize_autonomy_mode(mode)
    return AUTONOMY_ALLOWED_RISK_LEVELS.get(normalized, AUTONOMY_ALLOWED_RISK_LEVELS[DEFAULT_AUTONOMY_MODE])


def autonomy_denied_tools(mode: str) -> frozenset[str]:
    """Return tool names denied by one autonomy profile."""
    normalized = normalize_autonomy_mode(mode)
    return AUTONOMY_DENIED_TOOLS.get(normalized, AUTONOMY_DENIED_TOOLS[DEFAULT_AUTONOMY_MODE])


def apply_autonomy_option_caps(
    *,
    tool_name: str,
    options: dict[str, Any] | None,
    autonomy_mode: str,
) -> tuple[dict[str, Any], list[str]]:
    """Return capped options and a human-readable list of applied caps."""
    normalized_mode = normalize_autonomy_mode(autonomy_mode)
    limits = _AUTONOMY_OPTION_LIMITS.get(normalized_mode, {}).get(str(tool_name).strip(), {})
    output = dict(options or {})
    adjustments: list[str] = []

    for key, limit in limits.items():
        current = output.get(key)
        next_value = _apply_one_cap(current=current, limit=limit)
        if current != next_value:
            output[key] = next_value
            adjustments.append(f"{key} -> {next_value!r}")

    return output, adjustments


def _apply_one_cap(*, current: Any, limit: Any) -> Any:
    if isinstance(limit, bool):
        return limit
    if isinstance(limit, (int, float)) and not isinstance(limit, bool):
        try:
            parsed = float(current)
        except (TypeError, ValueError):
            return limit
        bounded = min(parsed, float(limit))
        if isinstance(limit, int) and not isinstance(limit, bool):
            return int(bounded)
        return bounded
    if isinstance(limit, list):
        allowed = {str(item).strip().lower() for item in limit if str(item).strip()}
        if isinstance(current, list):
            filtered = [item for item in current if str(item).strip().lower() in allowed]
            if filtered:
                return filtered
        return deepcopy(limit)
    return deepcopy(limit)
