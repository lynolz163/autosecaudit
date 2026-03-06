"""Registry for agent tools."""

from __future__ import annotations

from typing import TypeVar

from .tools import BaseAgentTool


class ToolRegistryError(RuntimeError):
    """Raised when registry operations fail."""


_ToolType = TypeVar("_ToolType", bound=BaseAgentTool)
_TOOL_CLASSES: dict[str, type[BaseAgentTool]] = {}
_TOOL_INSTANCES: dict[str, BaseAgentTool] = {}


def register_tool(tool_cls: type[_ToolType]) -> type[_ToolType]:
    """
    Register one tool class into global registry.

    Raises:
        ToolRegistryError: when class is invalid or tool name is duplicated.
    """
    if not issubclass(tool_cls, BaseAgentTool):
        raise ToolRegistryError(f"{tool_cls!r} must inherit BaseAgentTool")

    tool_name = str(getattr(tool_cls, "name", "")).strip()
    if not tool_name:
        raise ToolRegistryError(f"{tool_cls.__name__} has empty tool name")
    if tool_name in _TOOL_CLASSES:
        raise ToolRegistryError(f"duplicate tool registration: {tool_name}")

    _TOOL_CLASSES[tool_name] = tool_cls
    return tool_cls


def get_tool(name: str) -> BaseAgentTool:
    """
    Get a tool instance by name (singleton cache).

    Raises:
        KeyError: when tool is not registered.
    """
    tool_name = str(name).strip()
    if tool_name not in _TOOL_CLASSES:
        raise KeyError(f"tool not registered: {tool_name}")
    if tool_name not in _TOOL_INSTANCES:
        _TOOL_INSTANCES[tool_name] = _TOOL_CLASSES[tool_name]()
    return _TOOL_INSTANCES[tool_name]


def list_tools() -> list[str]:
    """Return sorted registered tool names."""
    return sorted(_TOOL_CLASSES.keys())
