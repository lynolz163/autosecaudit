"""Agent-mode orchestration core components."""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "Action",
    "ActionScheduler",
    "AuditPipeline",
    "AgentOrchestrator",
    "AgentRunResult",
    "BaseAgentTool",
    "FeedbackEngine",
    "PolicyBlock",
    "PolicyEngine",
    "SkillDrivenPlanner",
    "SkillLoader",
    "SkillRegistry",
    "MultiAgentMessageRouter",
    "SessionTreeLogger",
    "SandboxRunner",
    "ToolCircuitBreaker",
    "get_tool",
    "list_tools",
    "register_tool",
]


def __getattr__(name: str) -> Any:
    if name in {"AgentOrchestrator", "AgentRunResult"}:
        module = import_module("autosecaudit.agent_core.orchestrator")
        return getattr(module, name)
    if name in {"PolicyBlock", "PolicyEngine"}:
        module = import_module("autosecaudit.agent_core.policy")
        return getattr(module, name)
    if name in {"Action", "ActionScheduler"}:
        module = import_module("autosecaudit.agent_core.scheduler")
        return getattr(module, name)
    if name == "AuditPipeline":
        module = import_module("autosecaudit.agent_core.audit_pipeline")
        return getattr(module, name)
    if name == "FeedbackEngine":
        module = import_module("autosecaudit.agent_core.feedback_engine")
        return getattr(module, name)
    if name == "SkillDrivenPlanner":
        module = import_module("autosecaudit.agent_core.skill_planner")
        return getattr(module, name)
    if name in {"SkillLoader", "SkillRegistry"}:
        module = import_module("autosecaudit.agent_core.skill_loader")
        return getattr(module, name)
    if name == "MultiAgentMessageRouter":
        module = import_module("autosecaudit.agent_core.message_router")
        return getattr(module, name)
    if name == "SessionTreeLogger":
        module = import_module("autosecaudit.agent_core.session_tree")
        return getattr(module, name)
    if name == "SandboxRunner":
        module = import_module("autosecaudit.agent_core.sandbox_runner")
        return getattr(module, name)
    if name == "ToolCircuitBreaker":
        module = import_module("autosecaudit.agent_core.circuit_breaker")
        return getattr(module, name)
    if name in {"get_tool", "list_tools", "register_tool"}:
        module = import_module("autosecaudit.agent_core.tool_registry")
        return getattr(module, name)
    if name == "BaseAgentTool":
        module = import_module("autosecaudit.agent_core.tools")
        return getattr(module, name)
    raise AttributeError(name)
