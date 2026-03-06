"""Agent tool abstraction for registry-based orchestration."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from autosecaudit.tools.base_tool import ToolExecutionResult


class BaseAgentTool(ABC):
    """
    Abstract agent tool contract.

    Every tool must expose static metadata for planner/scheduler alignment and
    implement a safe execution entrypoint that returns ToolExecutionResult.
    """

    name: str = ""
    description: str = ""
    cost: int = 0
    priority: int = 50
    category: str = "generic"
    input_schema: dict[str, Any] = {}
    output_schema: dict[str, Any] = {}
    target_types: list[str] = ["url"]
    capabilities: list[str] = ["network_read"]
    phase_affinity: list[str] = ["any"]
    depends_on: list[str] = []
    risk_level: str = "safe"
    retry_policy: dict[str, Any] = {"max_retries": 0, "backoff": "none"}
    default_options: dict[str, Any] = {}

    def check_availability(self) -> tuple[bool, str | None]:
        """
        Return whether the tool is currently runnable in this environment.

        Default implementation assumes the tool is available. Tools with
        external runtime dependencies (e.g., binaries, browser engines) should
        override this to provide a deterministic preflight check.
        """
        return True, None

    def get_default_options(self) -> dict[str, Any]:
        """Return a copy of planner default options for this tool."""
        return dict(self.default_options)

    @abstractmethod
    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        """Execute tool logic and return structured output."""
        raise NotImplementedError
