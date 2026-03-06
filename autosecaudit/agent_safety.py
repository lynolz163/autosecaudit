"""Shared safety-grade definitions for agent planning and policy."""

from __future__ import annotations

from typing import Final


AGENT_SAFETY_GRADES: Final[tuple[str, ...]] = (
    "conservative",
    "balanced",
    "aggressive",
)
DEFAULT_AGENT_SAFETY_GRADE: Final[str] = "balanced"

SAFETY_GRADE_DENIED_TOOLS: Final[dict[str, frozenset[str]]] = {
    "conservative": frozenset(
        {
            "dynamic_crawl",
            "active_web_crawler",
            "page_vision_analyzer",
            "dirsearch_scan",
            "nuclei_exploit_check",
            "param_fuzzer",
            "cve_verify",
            "poc_sandbox_exec",
        }
    ),
    "balanced": frozenset({"poc_sandbox_exec"}),
    "aggressive": frozenset(),
}

SAFETY_GRADE_ACTION_LIMITS: Final[dict[str, int]] = {
    "conservative": 5,
    "balanced": 8,
    "aggressive": 15,
}

# Recommended defaults when the Web UI submits with its own defaults.
# Keys: max_iterations, global_timeout_seconds
SAFETY_GRADE_DEFAULTS: Final[dict[str, dict[str, int | float]]] = {
    "conservative": {"max_iterations": 3, "global_timeout_seconds": 300.0},
    "balanced": {"max_iterations": 5, "global_timeout_seconds": 600.0},
    "aggressive": {"max_iterations": 10, "global_timeout_seconds": 1800.0},
}


def normalize_safety_grade(value: object) -> str:
    """Return one supported safety grade with a stable default."""
    candidate = str(value or "").strip().lower()
    if candidate in AGENT_SAFETY_GRADES:
        return candidate
    return DEFAULT_AGENT_SAFETY_GRADE
