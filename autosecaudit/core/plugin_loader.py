"""Dynamic plugin loading helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Iterable

from .plugin import AuditPlugin
from .registry import PluginRegistry


@dataclass(frozen=True)
class PluginLoadIssue:
    """One plugin loading problem."""

    path: str
    error: str


class PluginHotLoader:
    """Load and reload plugin modules from filesystem paths."""

    def __init__(self, registry: PluginRegistry, *, builtin_package: str = "autosecaudit.plugins") -> None:
        self._registry = registry
        self._builtin_package = builtin_package

    def ensure_builtins_loaded(self) -> None:
        """Import built-in plugin package exactly once."""
        importlib.import_module(self._builtin_package)

    def list_plugins(self) -> list[dict[str, object]]:
        """Return the current registry manifest list."""
        self.ensure_builtins_loaded()
        return self._registry.list_plugin_manifests()

    def load_from_directories(self, directories: Iterable[Path | str]) -> dict[str, object]:
        """Reload all external plugins from the provided directories."""
        self.ensure_builtins_loaded()
        normalized_dirs = self._normalize_directories(directories)
        self._registry.unregister_external()
        loaded_ids: list[str] = []
        issues: list[PluginLoadIssue] = []
        for directory in normalized_dirs:
            try:
                plugin_files = self._iter_plugin_files(directory)
            except Exception as exc:  # noqa: BLE001
                issues.append(PluginLoadIssue(path=str(directory), error=str(exc)))
                continue
            for path in plugin_files:
                try:
                    loaded_ids.extend(self.load_plugin(path))
                except Exception as exc:  # noqa: BLE001
                    issues.append(PluginLoadIssue(path=str(path), error=str(exc)))
        return {
            "plugin_dirs": [str(path) for path in normalized_dirs],
            "loaded_plugin_ids": sorted(set(loaded_ids)),
            "errors": [{"path": issue.path, "error": issue.error} for issue in issues],
        }

    def load_plugin(self, path: Path | str) -> list[str]:
        """Load or reload one plugin module from a file path."""
        self.ensure_builtins_loaded()
        plugin_path = Path(path).resolve()
        if not plugin_path.exists() or not plugin_path.is_file():
            raise FileNotFoundError(f"plugin_file_not_found: {plugin_path}")
        if plugin_path.suffix.lower() != ".py":
            raise ValueError(f"unsupported_plugin_type: {plugin_path.suffix}")

        module_name = self._module_name_for_path(plugin_path)
        self._registry.unregister_module(module_name)
        self._remove_module(module_name)

        try:
            module = self._import_module_from_path(module_name, plugin_path)
        except Exception:
            self._registry.unregister_module(module_name)
            self._remove_module(module_name)
            raise

        self._auto_register_module_plugins(module)
        plugin_ids = self._registry.plugin_ids_for_module(module_name)
        if not plugin_ids:
            self._remove_module(module_name)
            raise ValueError(f"no_plugins_registered: {plugin_path}")
        return plugin_ids

    def reload_plugin(self, plugin_id: str) -> list[str]:
        """Reload a registered plugin using its original module path."""
        self.ensure_builtins_loaded()
        record = self._registry.get_plugin_record(plugin_id)
        if not record.module_path:
            raise ValueError(f"plugin_not_reloadable: {plugin_id}")
        module_path = Path(record.module_path)
        if not module_path.exists():
            raise FileNotFoundError(f"plugin_file_not_found: {module_path}")
        self._registry.unregister_module(record.module_name)
        self._remove_module(record.module_name)
        try:
            module = self._import_module_from_path(record.module_name, module_path)
        except Exception:
            self._registry.unregister_module(record.module_name)
            self._remove_module(record.module_name)
            raise
        self._auto_register_module_plugins(module)
        plugin_ids = self._registry.plugin_ids_for_module(record.module_name)
        if not plugin_ids:
            raise ValueError(f"no_plugins_registered: {module_path}")
        return plugin_ids

    def _normalize_directories(self, directories: Iterable[Path | str]) -> list[Path]:
        output: list[Path] = []
        seen: set[str] = set()
        for item in directories:
            raw = str(item).strip()
            if not raw:
                continue
            resolved = Path(raw).resolve()
            marker = str(resolved).lower()
            if marker in seen:
                continue
            seen.add(marker)
            output.append(resolved)
        output.sort(key=lambda item: str(item).lower())
        return output

    def _iter_plugin_files(self, directory: Path) -> list[Path]:
        if not directory.exists() or not directory.is_dir():
            raise FileNotFoundError(f"plugin_directory_not_found: {directory}")
        output: list[Path] = []
        for path in directory.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if path.name.startswith("__"):
                continue
            output.append(path.resolve())
        output.sort(key=lambda item: str(item).lower())
        return output

    def _module_name_for_path(self, path: Path) -> str:
        digest = hashlib.sha1(str(path).lower().encode("utf-8")).hexdigest()[:12]
        stem = "".join(ch if ch.isalnum() else "_" for ch in path.stem).strip("_") or "plugin"
        return f"autosecaudit.dynamic_plugins.{stem}_{digest}"

    def _import_module_from_path(self, module_name: str, path: Path) -> ModuleType:
        package_name = "autosecaudit.dynamic_plugins"
        if package_name not in sys.modules:
            package = ModuleType(package_name)
            package.__path__ = []  # type: ignore[attr-defined]
            sys.modules[package_name] = package

        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"unable_to_build_module_spec: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    def _remove_module(self, module_name: str) -> None:
        sys.modules.pop(module_name, None)

    def _auto_register_module_plugins(self, module: ModuleType) -> None:
        for value in vars(module).values():
            if not isinstance(value, type):
                continue
            if value is AuditPlugin or not issubclass(value, AuditPlugin):
                continue
            if str(getattr(value, "__module__", "")) != str(getattr(module, "__name__", "")):
                continue
            plugin_id = str(getattr(value, "plugin_id", "") or "").strip()
            if not plugin_id:
                continue
            try:
                self._registry.get_plugin_record(plugin_id)
            except KeyError:
                self._registry.register(value)
