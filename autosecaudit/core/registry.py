"""Plugin registry and factory utilities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Sequence

from .plugin import AuditPlugin


@dataclass(frozen=True)
class RegisteredPlugin:
    """Metadata tracked for one registered plugin type."""

    plugin_id: str
    plugin_cls: type[AuditPlugin]
    module_name: str
    module_path: str | None
    builtin: bool

    @property
    def manifest(self) -> dict[str, object]:
        """Return a JSON-safe manifest summary."""
        description = str(getattr(self.plugin_cls, "description", "") or "").strip()
        if not description:
            description = str((self.plugin_cls.__doc__ or "")).strip()
        return {
            "plugin_id": self.plugin_id,
            "name": str(self.plugin_cls.name),
            "category": str(self.plugin_cls.category),
            "read_only": bool(self.plugin_cls.read_only),
            "version": str(getattr(self.plugin_cls, "version", "1.0.0") or "1.0.0"),
            "risk_level": str(getattr(self.plugin_cls, "risk_level", "safe") or "safe"),
            "description": description or None,
            "module_name": self.module_name,
            "module_path": self.module_path,
            "builtin": self.builtin,
            "source_type": "builtin" if self.builtin else "external",
            "reloadable": bool(self.module_path),
        }


class PluginRegistry:
    """Holds plugin classes and instantiates them on demand."""

    def __init__(self) -> None:
        self._plugin_types: dict[str, type[AuditPlugin]] = {}
        self._plugin_records: dict[str, RegisteredPlugin] = {}

    def register(self, plugin_cls: type[AuditPlugin]) -> type[AuditPlugin]:
        """Register a plugin class and return it for decorator-style usage."""
        if not issubclass(plugin_cls, AuditPlugin):
            raise TypeError(f"{plugin_cls!r} must inherit from AuditPlugin")

        plugin_id = (plugin_cls.plugin_id or "").strip()
        if not plugin_id:
            raise ValueError(f"Plugin {plugin_cls.__name__} must define a non-empty plugin_id")
        if plugin_id in self._plugin_types:
            raise ValueError(f"Duplicate plugin_id detected: {plugin_id}")
        if not (plugin_cls.name or "").strip():
            raise ValueError(f"Plugin {plugin_id} must define a non-empty name")

        module_name = str(plugin_cls.__module__ or "").strip() or "__main__"
        module = sys.modules.get(module_name)
        module_path: str | None = None
        if module is not None:
            raw_path = getattr(module, "__file__", None)
            if raw_path:
                try:
                    module_path = str(Path(raw_path).resolve())
                except OSError:
                    module_path = str(raw_path)
        builtin = module_name == "autosecaudit.plugins" or module_name.startswith("autosecaudit.plugins.")

        self._plugin_types[plugin_id] = plugin_cls
        self._plugin_records[plugin_id] = RegisteredPlugin(
            plugin_id=plugin_id,
            plugin_cls=plugin_cls,
            module_name=module_name,
            module_path=module_path,
            builtin=builtin,
        )
        return plugin_cls

    def available_ids(self) -> list[str]:
        """Return all registered plugin IDs sorted alphabetically."""
        return sorted(self._plugin_types.keys())

    def get_plugin_record(self, plugin_id: str) -> RegisteredPlugin:
        """Return registry metadata for one plugin."""
        try:
            return self._plugin_records[str(plugin_id)]
        except KeyError as exc:
            raise KeyError(plugin_id) from exc

    def list_plugin_manifests(self) -> list[dict[str, object]]:
        """Return manifest summaries for all registered plugins."""
        items = [record.manifest for record in self._plugin_records.values()]
        items.sort(key=lambda item: (0 if item["builtin"] else 1, str(item["plugin_id"])))
        return items

    def plugin_ids_for_module(self, module_name: str) -> list[str]:
        """Return plugin IDs registered from one module."""
        target = str(module_name).strip()
        return sorted(
            plugin_id
            for plugin_id, record in self._plugin_records.items()
            if record.module_name == target
        )

    def unregister_plugin(self, plugin_id: str) -> None:
        """Remove one registered plugin by ID."""
        key = str(plugin_id).strip()
        self._plugin_types.pop(key, None)
        self._plugin_records.pop(key, None)

    def unregister_module(self, module_name: str) -> list[str]:
        """Remove all plugins originating from one module."""
        removed = self.plugin_ids_for_module(module_name)
        for plugin_id in removed:
            self.unregister_plugin(plugin_id)
        return removed

    def unregister_external(self) -> list[str]:
        """Remove all non-built-in plugins."""
        removed = [
            plugin_id
            for plugin_id, record in self._plugin_records.items()
            if not record.builtin
        ]
        for plugin_id in removed:
            self.unregister_plugin(plugin_id)
        return sorted(removed)

    def create_plugins(self, enabled_plugins: Sequence[str] | None = None) -> list[AuditPlugin]:
        """
        Create plugin instances.

        If `enabled_plugins` is None, all registered plugins are instantiated.
        """
        if enabled_plugins is None:
            selected_ids = self.available_ids()
        else:
            selected_ids = []
            seen: set[str] = set()
            unknown: list[str] = []
            for plugin_id in enabled_plugins:
                if plugin_id in seen:
                    continue
                seen.add(plugin_id)
                if plugin_id not in self._plugin_types:
                    unknown.append(plugin_id)
                    continue
                selected_ids.append(plugin_id)
            if unknown:
                raise KeyError(f"Unknown plugin IDs: {', '.join(unknown)}")

        return [self._plugin_types[plugin_id]() for plugin_id in selected_ids]


registry = PluginRegistry()
