"""Plugin base interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from .models import AuditContext, PluginCategory, PluginResult


class AuditPlugin(ABC):
    """Base class for all audit plugins."""

    plugin_id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    category: ClassVar[PluginCategory] = "validation"
    read_only: ClassVar[bool] = True
    version: ClassVar[str] = "1.0.0"
    risk_level: ClassVar[str] = "safe"
    description: ClassVar[str] = ""

    @abstractmethod
    def run(self, context: AuditContext) -> PluginResult:
        """Execute plugin logic and return a normalized result."""
        raise NotImplementedError
