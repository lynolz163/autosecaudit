"""Base abstractions for read-only security tooling."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolExecutionResult:
    """Standard execution result for tools."""

    ok: bool
    tool_name: str
    target: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    raw_output: str | None = None
    duration_ms: int = 0


class BaseTool(ABC):
    """Abstract base class for pluggable tools."""

    name: str = "base_tool"
    read_only: bool = True

    @abstractmethod
    def run(self, target: str, options: str | dict[str, Any]) -> ToolExecutionResult:
        """Execute tool logic against a target and return structured result."""
        raise NotImplementedError
