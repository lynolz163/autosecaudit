"""Core building blocks for AutoSecAudit."""

from .command import CommandExecution, SafeCommandRunner
from .models import (
    AuditContext,
    AuditSessionResult,
    Finding,
    OperationEvent,
    PluginResult,
    RuntimeConfig,
)
from .plugin import AuditPlugin
from .plugin_loader import PluginHotLoader
from .registry import PluginRegistry, registry
from .report import (
    ReportArtifacts,
    ReportWriter,
    generate_agent_json_report,
    generate_agent_visual_html_report,
    generate_markdown_report,
)
from .runner import AuditRunner
from .safety import SafetyPolicy, SafetyPolicyError

__all__ = [
    "AuditContext",
    "AuditPlugin",
    "AuditRunner",
    "AuditSessionResult",
    "CommandExecution",
    "Finding",
    "OperationEvent",
    "PluginHotLoader",
    "PluginRegistry",
    "PluginResult",
    "ReportArtifacts",
    "ReportWriter",
    "generate_agent_json_report",
    "generate_agent_visual_html_report",
    "generate_markdown_report",
    "RuntimeConfig",
    "SafeCommandRunner",
    "SafetyPolicy",
    "SafetyPolicyError",
    "registry",
]
