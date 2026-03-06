"""Safety policy checks for plugins and execution mode."""

from __future__ import annotations

from dataclasses import dataclass

from .models import PluginCategory
from .plugin import AuditPlugin


class SafetyPolicyError(RuntimeError):
    """Raised when a plugin violates configured safety constraints."""


@dataclass(frozen=True)
class SafetyPolicy:
    """Enforces default-safe constraints for audit execution."""

    strict_read_only: bool = True
    allowed_categories: tuple[PluginCategory, ...] = ("discovery", "validation")

    def validate_plugin(self, plugin: AuditPlugin) -> None:
        """Validate whether a plugin is allowed to execute under current policy."""
        if plugin.category not in self.allowed_categories:
            raise SafetyPolicyError(
                f"Plugin {plugin.plugin_id} has unsupported category {plugin.category!r}"
            )
        if self.strict_read_only and not plugin.read_only:
            raise SafetyPolicyError(f"Plugin {plugin.plugin_id} is not marked as read_only")
