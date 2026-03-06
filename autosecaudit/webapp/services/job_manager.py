"""Background job service for the AutoSecAudit web UI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Any

from autosecaudit.agent_core.builtin_tools import load_builtin_agent_tools
from autosecaudit.agent_core.skill_loader import load_builtin_skill_registry
from autosecaudit.agent_core.tool_registry import get_tool, list_tools
from autosecaudit.agent_safety import DEFAULT_AGENT_SAFETY_GRADE, SAFETY_GRADE_DEFAULTS, normalize_safety_grade
from autosecaudit.core.plugin_loader import PluginHotLoader
from autosecaudit.core.registry import registry
from autosecaudit.integrations import (
    BaseNotifier,
    LLMRouter,
    LLMRouterError,
    NoopNotifier,
    NotificationEvent,
    build_notifier_from_config,
)
from autosecaudit.webapp.job_index import JobIndexStore


VALID_MODES = {"plugins", "plan", "agent"}
DEFAULT_LLM_TIMEOUT_SECONDS = 300.0
LEGACY_LLM_TIMEOUT_SECONDS = 20.0
WEB_RUNTIME_LLM_API_KEY_ENV = "AUTOSECAUDIT_WEB_RUNTIME_LLM_API_KEY"


def _utc_now() -> str:
    """Return UTC timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sanitize_slug(value: str) -> str:
    """Convert arbitrary text to safe path segment."""
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    cleaned = cleaned.strip("-._")
    return cleaned[:80] or "job"


def _to_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    """Parse bounded integer."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _to_float(
    value: Any,
    default: float,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Parse bounded float."""
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _normalize_llm_timeout(value: Any) -> float:
    """Normalize LLM timeout and transparently upgrade the legacy 20s default."""
    if value in (None, ""):
        return DEFAULT_LLM_TIMEOUT_SECONDS
    parsed = _to_float(value, DEFAULT_LLM_TIMEOUT_SECONDS, minimum=3.0, maximum=600.0)
    if abs(parsed - LEGACY_LLM_TIMEOUT_SECONDS) < 1e-9:
        return DEFAULT_LLM_TIMEOUT_SECONDS
    return parsed


def _is_terminal_job_status(status: str) -> bool:
    """Return whether one web job status is terminal."""
    return str(status) in {"completed", "failed", "error", "canceled"}


def _normalize_agent_safety_grade(value: Any) -> str:
    """Normalize incoming web payload safety grade."""
    return normalize_safety_grade(value or DEFAULT_AGENT_SAFETY_GRADE)

class JobManager:
    """Manage background CLI jobs for web UI."""

    def __init__(
        self,
        *,
        workspace_dir: Path,
        output_root: Path,
        python_executable: str,
        max_jobs: int = 200,
        max_running_jobs: int = 4,
        job_store_path: Path | None = None,
    ) -> None:
        self._workspace_dir = workspace_dir.resolve()
        self._output_root = output_root.resolve()
        self._python_executable = python_executable
        self._max_jobs = max(1, int(max_jobs))
        self._max_running_jobs = max(1, int(max_running_jobs))
        self._jobs: dict[str, dict[str, Any]] = {}
        self._counter = 0
        self._lock = threading.RLock()
        self._updates = threading.Condition(self._lock)
        self._closed = False
        self._output_root.mkdir(parents=True, exist_ok=True)
        store_path = job_store_path or (self._output_root / ".autosecaudit-web.sqlite3")
        self._store = JobIndexStore(store_path)
        self._notifier_config = self._store.get_setting("notification_config", default={}).get("value") or {}
        self._notifier: BaseNotifier = self._build_notifier(self._notifier_config)
        plugin_setting = self._store.get_setting("plugin_runtime_config", default={"plugin_dirs": []})
        self._plugin_settings_updated_at = plugin_setting.get("updated_at")
        self._plugin_settings = self._normalize_plugin_settings(plugin_setting.get("value"))
        self._plugin_loader = PluginHotLoader(registry)
        self._plugin_runtime: dict[str, Any] = {
            "last_loaded_at": None,
            "resolved_dirs": [],
            "loaded_plugin_ids": [],
            "errors": [],
        }
        self._reload_plugin_runtime()
        self._restore_persisted_jobs()

    @property
    def store(self) -> JobIndexStore:
        """Expose the backing store to higher-level services."""
        return self._store

    def close(self) -> None:
        """Close persistence resources."""
        if self._closed:
            return
        self._closed = True
        try:
            self._notifier.flush(timeout_seconds=1.5)
        except Exception:  # noqa: BLE001
            pass
        try:
            self._notifier.close()
        except Exception:  # noqa: BLE001
            pass
        self._store.close()

    def get_notification_settings(self) -> dict[str, Any]:
        """Return current notification settings."""
        return dict(self._notifier_config) if isinstance(self._notifier_config, dict) else {}

    def update_notification_settings(self, config: dict[str, Any]) -> dict[str, Any]:
        """Persist and reload notification settings."""
        normalized = config if isinstance(config, dict) else {}
        self._notifier_config = normalized
        self._store.set_setting("notification_config", normalized, updated_at=_utc_now())
        try:
            self._notifier.close()
        except Exception:  # noqa: BLE001
            pass
        self._notifier = self._build_notifier(normalized)
        return self.get_notification_settings()

    def get_plugin_settings(self) -> dict[str, Any]:
        """Return persisted hot-load plugin settings and runtime summary."""
        configured_dirs = list(self._plugin_settings.get("plugin_dirs", []))
        resolved_dirs = self._resolve_plugin_dirs(configured_dirs)
        return {
            "plugin_dirs": configured_dirs,
            "updated_at": self._plugin_settings_updated_at,
            "resolved_dirs": [
                {
                    "configured_path": raw,
                    "resolved_path": str(resolved),
                    "exists": resolved.exists(),
                    "is_dir": resolved.is_dir(),
                }
                for raw, resolved in zip(configured_dirs, resolved_dirs, strict=False)
            ],
            "runtime": {
                "last_loaded_at": self._plugin_runtime.get("last_loaded_at"),
                "resolved_dirs": list(self._plugin_runtime.get("resolved_dirs", [])),
                "loaded_plugin_ids": list(self._plugin_runtime.get("loaded_plugin_ids", [])),
                "errors": list(self._plugin_runtime.get("errors", [])),
            },
        }

    def update_plugin_settings(self, config: dict[str, Any]) -> dict[str, Any]:
        """Persist and reload plugin runtime settings."""
        normalized = self._normalize_plugin_settings(config)
        updated_at = _utc_now()
        self._store.set_setting("plugin_runtime_config", normalized, updated_at=updated_at)
        self._plugin_settings = normalized
        self._plugin_settings_updated_at = updated_at
        self._reload_plugin_runtime()
        return self.get_plugin_settings()

    def list_plugins(self) -> dict[str, Any]:
        """Return plugin registry inventory plus runtime metadata."""
        items = self._plugin_loader.list_plugins()
        return {
            "items": items,
            "settings": self.get_plugin_settings(),
            "metrics": {
                "total_plugins": len(items),
                "builtin_plugins": sum(1 for item in items if bool(item.get("builtin"))),
                "external_plugins": sum(1 for item in items if not bool(item.get("builtin"))),
            },
        }

    def reload_plugins(self, plugin_id: str | None = None) -> dict[str, Any]:
        """Reload all configured plugins or one specific module."""
        if plugin_id:
            loaded_ids = self._plugin_loader.reload_plugin(plugin_id)
            self._plugin_runtime["last_loaded_at"] = _utc_now()
            self._plugin_runtime["loaded_plugin_ids"] = sorted(
                set(list(self._plugin_runtime.get("loaded_plugin_ids", [])) + list(loaded_ids))
            )
            self._plugin_runtime["errors"] = [
                item
                for item in self._plugin_runtime.get("errors", [])
                if str(item.get("path", "")).lower() != str(plugin_id).lower()
            ]
        else:
            self._reload_plugin_runtime()
        return self.list_plugins()

    def submit(self, payload: dict[str, Any], *, actor: str = "web") -> dict[str, Any]:
        """Create and start one job from JSON payload."""
        target = str(payload.get("target", "")).strip()
        if not target:
            raise ValueError("target is required")

        mode = str(payload.get("mode", "agent")).strip().lower()
        if mode not in VALID_MODES:
            raise ValueError(f"invalid mode: {mode}")

        with self._lock:
            if len(self._jobs) >= self._max_jobs:
                raise ValueError(
                    f"job_limit_reached: max_jobs={self._max_jobs}. "
                    "Remove old jobs or increase --max-jobs."
                )
            active_count = sum(
                1 for item in self._jobs.values() if str(item.get("status", "")) in {"queued", "running"}
            )
            if active_count >= self._max_running_jobs:
                raise ValueError(
                    f"running_job_limit_reached: max_running_jobs={self._max_running_jobs}. "
                    "Wait for current jobs to finish or increase --max-running-jobs."
                )
            job_id = self._next_job_id_locked()

        output_dir = self._output_root / f"{job_id}-{_sanitize_slug(target.replace('://', '_'))}"
        output_dir.mkdir(parents=True, exist_ok=True)
        selected_tools = self._coerce_text_list(payload.get("tools"))
        selected_skills = self._coerce_text_list(payload.get("skills"))
        command_payload = dict(payload)
        command_payload["surface"] = self._merge_agent_runtime_surface(command_payload)
        surface_file = str(command_payload.get("surface_file", "")).strip()
        if not surface_file and isinstance(command_payload.get("surface"), dict):
            surface_path = output_dir / "surface_input.json"
            try:
                surface_path.write_text(
                    json.dumps(command_payload.get("surface", {}), ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except OSError:
                pass
            else:
                surface_file = str(surface_path)
                command_payload["surface_file"] = surface_file

        record: dict[str, Any] = {
            "job_id": job_id,
            "status": "queued",
            "created_at": _utc_now(),
            "started_at": None,
            "ended_at": None,
            "last_updated_at": _utc_now(),
            "target": target,
            "mode": mode,
            "safety_grade": _normalize_agent_safety_grade(payload.get("safety_grade")),
            "report_lang": str(payload.get("report_lang", "")).strip() or "zh-CN",
            "command": self._build_command(command_payload, target=target, mode=mode, output_dir=output_dir),
            "tools": selected_tools,
            "skills": selected_skills,
            "surface_file": surface_file or None,
            "output_dir": str(output_dir),
            "resume": str(payload.get("resume", "")).strip() or None,
            "llm_config": str(payload.get("llm_config", "")).strip() or None,
            "return_code": None,
            "pid": None,
            "error": None,
            "cancel_requested": False,
            "log_line_count": 0,
            "logs": [],
            "artifacts": [],
        }

        with self._lock:
            self._jobs[job_id] = record

        self._persist_job(job_id)
        self._store.add_audit_event(
            created_at=_utc_now(),
            actor=str(actor or "web"),
            event_type="job_submitted",
            resource_type="job",
            resource_id=job_id,
            detail={
                "target": target,
                "mode": mode,
                "safety_grade": record["safety_grade"],
            },
        )
        worker = threading.Thread(target=self._run_job, args=(job_id,), daemon=True, name=f"webjob-{job_id}")
        worker.start()
        return self.get_job(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        """Return all jobs ordered by creation time descending."""
        with self._lock:
            items = [self._serialize_job(v) for v in self._jobs.values()]
        items.sort(key=lambda item: item["created_at"], reverse=True)
        return items

    def get_job(self, job_id: str) -> dict[str, Any]:
        """Return one job."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                raise KeyError(job_id)
            return self._serialize_job(record)

    def get_logs(self, job_id: str, *, offset: int = 0, limit: int = 500) -> dict[str, Any]:
        """Return incremental logs."""
        return self._store.get_logs(
            job_id,
            offset=max(0, int(offset)),
            limit=_to_int(limit, 500, minimum=1, maximum=5000),
        )

    def list_artifacts(self, job_id: str) -> list[dict[str, Any]]:
        """Return artifact list for a job."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                raise KeyError(job_id)
            return list(record.get("artifacts", []))

    def cancel(self, job_id: str, *, actor: str = "web") -> dict[str, Any]:
        """Request cancellation of a running job."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                raise KeyError(job_id)
            record["cancel_requested"] = True
            proc = record.get("_process")
            status = record.get("status")
        self._persist_job(job_id)
        if status in {"queued", "running"} and proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        self._store.add_audit_event(
            created_at=_utc_now(),
            actor=str(actor or "web"),
            event_type="job_cancel_requested",
            resource_type="job",
            resource_id=job_id,
            detail={"status": status},
        )
        self._append_log(job_id, "[web] cancel requested")
        return self.get_job(job_id)

    def resolve_file(self, job_id: str, relative_path: str) -> Path:
        """Resolve artifact file path safely under job output directory."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                raise KeyError(job_id)
            base_dir = Path(record["output_dir"]).resolve()
        candidate = (base_dir / relative_path).resolve()
        if not candidate.is_relative_to(base_dir):
            raise PermissionError("path traversal blocked")
        if not candidate.is_file():
            raise FileNotFoundError(relative_path)
        return candidate

    def get_stream_snapshot(self, job_id: str, *, offset: int = 0, limit: int = 500) -> dict[str, Any]:
        """Return stream-friendly job + log snapshot."""
        job = self.get_job(job_id)
        logs = self.get_logs(job_id, offset=offset, limit=limit)
        return {
            **logs,
            "job": job,
            "terminal": _is_terminal_job_status(str(job.get("status", ""))),
        }

    def wait_for_job_update(self, job_id: str, *, offset: int, status: str, timeout: float) -> bool:
        """Block until a job gets a new log line or status update."""
        deadline = time.monotonic() + max(0.1, float(timeout))
        with self._updates:
            while True:
                record = self._jobs.get(job_id)
                if record is None:
                    raise KeyError(job_id)
                current_total = int(record.get("log_line_count", 0))
                current_status = str(record.get("status", ""))
                if current_total > offset or current_status != status or _is_terminal_job_status(current_status):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._updates.wait(timeout=remaining)

    def _build_command(self, payload: dict[str, Any], *, target: str, mode: str, output_dir: Path) -> list[str]:
        """Construct CLI subprocess command."""
        cmd = [
            self._python_executable,
            "-m",
            "autosecaudit.cli",
            "--target",
            target,
            "--mode",
            mode,
            "--output",
            str(output_dir),
        ]
        scope = str(payload.get("scope", "")).strip()
        if scope:
            cmd.extend(["--scope", scope])
        payload = dict(payload)
        payload["surface"] = self._merge_agent_runtime_surface(payload)
        surface_file = str(payload.get("surface_file", "")).strip()
        if not surface_file and isinstance(payload.get("surface"), dict):
            candidate = output_dir / "surface_input.json"
            try:
                candidate.write_text(
                    json.dumps(payload.get("surface", {}), ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except OSError:
                surface_file = ""
            else:
                surface_file = str(candidate)
        if surface_file:
            cmd.extend(["--surface-file", surface_file])

        if mode == "plugins":
            plugins = str(payload.get("plugins", "")).strip()
            if plugins:
                cmd.extend(["--plugins", plugins])
            for plugin_dir in self._resolve_plugin_dirs(self._plugin_settings.get("plugin_dirs", [])):
                cmd.extend(["--plugin-dir", str(plugin_dir)])
            timeout = _to_float(payload.get("timeout"), 15.0, minimum=1.0, maximum=3600.0)
            cmd.extend(["--timeout", str(timeout)])
            return cmd

        budget = _to_int(payload.get("budget"), 50, minimum=1, maximum=100000)
        max_iterations = _to_int(payload.get("max_iterations"), 3, minimum=1, maximum=100)
        global_timeout = _to_float(payload.get("global_timeout"), 300.0, minimum=10.0, maximum=86400.0)

        # Auto-upgrade defaults when the Web UI sends its baseline values.
        grade = _normalize_agent_safety_grade(payload.get("safety_grade"))
        grade_defaults = SAFETY_GRADE_DEFAULTS.get(grade, {})
        if max_iterations == 3 and grade_defaults.get("max_iterations", 3) != 3:
            max_iterations = int(grade_defaults["max_iterations"])
        if abs(global_timeout - 300.0) < 0.1 and grade_defaults.get("global_timeout_seconds", 300.0) != 300.0:
            global_timeout = float(grade_defaults["global_timeout_seconds"])

        cmd.extend(["--budget", str(budget), "--max-iterations", str(max_iterations), "--global-timeout", str(global_timeout)])
        cmd.extend(["--agent-safety-grade", _normalize_agent_safety_grade(payload.get("safety_grade"))])
        self._append_cli_str(cmd, "--report-lang", payload.get("report_lang") or "zh-CN")
        tools = self._coerce_text_list(payload.get("tools"))
        skills = self._coerce_text_list(payload.get("skills"))
        resolved_tools = self._resolve_selected_tools(tools=tools, skills=skills)
        if tools:
            cmd.extend(["--tools", ",".join(tools)])
        if skills:
            cmd.extend(["--skills", ",".join(skills)])
        if resolved_tools and not tools:
            cmd.extend(["--tools", ",".join(resolved_tools)])

        if bool(payload.get("no_llm_hints", False)):
            cmd.append("--no-llm-hints")
        if bool(payload.get("multi_agent", False)):
            cmd.append("--multi-agent")
            cmd.extend(
                [
                    "--multi-agent-rounds",
                    str(_to_int(payload.get("multi_agent_rounds"), 1, minimum=1, maximum=8)),
                ]
            )

        approval_granted = payload.get("approval_granted")
        if approval_granted is True:
            cmd.append("--approval-granted")
        elif approval_granted is False:
            cmd.append("--no-approval-granted")

        llm_config = str(payload.get("llm_config", "")).strip()
        if llm_config:
            cmd.extend(["--llm-config", llm_config])
        elif not str(payload.get("llm_model", "")).strip():
            # Auto-inject saved/env LLM params if no explicit config given.
            cmd.extend(self.get_llm_cli_args())

        # Optional direct LLM router/model parameters (Web UI pass-through).
        self._append_cli_str(cmd, "--llm-model", payload.get("llm_model"))
        self._append_cli_repeat(cmd, "--llm-fallback", self._coerce_text_list(payload.get("llm_fallback")))
        self._append_cli_str(cmd, "--llm-provider", payload.get("llm_provider"))
        provider_type = str(payload.get("llm_provider_type", "")).strip()
        if provider_type in {"openai_sdk", "openai_compatible", "codex_oauth"}:
            cmd.extend(["--llm-provider-type", provider_type])
        self._append_cli_str(cmd, "--llm-base-url", payload.get("llm_base_url"))
        self._append_cli_str(cmd, "--llm-api-key-env", payload.get("llm_api_key_env"))

        # Codex OAuth / OpenClaw-style options (safe text and bounded numerics only).
        self._append_cli_str(cmd, "--llm-oauth-token-env", payload.get("llm_oauth_token_env"))
        self._append_cli_str(cmd, "--llm-oauth-token-file", payload.get("llm_oauth_token_file"))
        self._append_cli_str(cmd, "--llm-oauth-command-json", payload.get("llm_oauth_command_json"))
        if bool(payload.get("llm_oauth_browser_login", False)):
            cmd.append("--llm-oauth-browser-login")
        self._append_cli_str(cmd, "--llm-oauth-authorize-url", payload.get("llm_oauth_authorize_url"))
        self._append_cli_str(cmd, "--llm-oauth-token-url", payload.get("llm_oauth_token_url"))
        self._append_cli_str(cmd, "--llm-oauth-client-id", payload.get("llm_oauth_client_id"))
        self._append_cli_repeat(cmd, "--llm-oauth-scope", self._coerce_text_list(payload.get("llm_oauth_scopes")))
        self._append_cli_str(cmd, "--llm-oauth-redirect-host", payload.get("llm_oauth_redirect_host"))
        oauth_redirect_port = payload.get("llm_oauth_redirect_port")
        if oauth_redirect_port not in (None, ""):
            cmd.extend(["--llm-oauth-redirect-port", str(_to_int(oauth_redirect_port, 8765, minimum=1, maximum=65535))])
        self._append_cli_str(cmd, "--llm-oauth-redirect-path", payload.get("llm_oauth_redirect_path"))
        self._append_cli_str(cmd, "--llm-oauth-cache-file", payload.get("llm_oauth_cache_file"))
        self._append_cli_str(cmd, "--llm-oauth-profile-id", payload.get("llm_oauth_profile_id"))
        self._append_cli_str(cmd, "--llm-oauth-profiles-file", payload.get("llm_oauth_profiles_file"))
        if bool(payload.get("llm_oauth_no_auto_refresh", False)):
            cmd.append("--llm-oauth-no-auto-refresh")
        oauth_login_timeout = payload.get("llm_oauth_login_timeout")
        if oauth_login_timeout not in (None, ""):
            cmd.extend(
                [
                    "--llm-oauth-login-timeout",
                    str(_to_float(oauth_login_timeout, 180.0, minimum=10.0, maximum=3600.0)),
                ]
            )

        llm_timeout = payload.get("llm_timeout")
        if llm_timeout not in (None, ""):
            cmd.extend(["--llm-timeout", str(_to_float(llm_timeout, 300.0, minimum=1.0, maximum=600.0))])
        llm_temperature = payload.get("llm_temperature")
        if llm_temperature not in (None, ""):
            cmd.extend(["--llm-temperature", str(_to_float(llm_temperature, 0.0, minimum=0.0, maximum=2.0))])
        llm_max_tokens = payload.get("llm_max_output_tokens")
        if llm_max_tokens not in (None, ""):
            cmd.extend(
                [
                    "--llm-max-output-tokens",
                    str(_to_int(llm_max_tokens, 1200, minimum=1, maximum=65536)),
                ]
            )

        resume = str(payload.get("resume", "")).strip()
        if resume:
            cmd.extend(["--resume", resume])

        if mode == "plan":
            plan_filename = str(payload.get("plan_filename", "")).strip()
            if plan_filename:
                cmd.extend(["--plan-filename", plan_filename])

        return cmd

    def _merge_agent_runtime_surface(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Keep runtime control flags available via surface-file based agent runs."""
        surface = dict(payload.get("surface", {})) if isinstance(payload.get("surface", {}), dict) else {}
        autonomy_mode = str(payload.get("autonomy_mode", "")).strip().lower()
        if autonomy_mode:
            surface["autonomy_mode"] = autonomy_mode
        if "approval_granted" in payload and payload.get("approval_granted") is not None:
            surface["approval_granted"] = bool(payload.get("approval_granted"))
        return surface

    def _append_cli_str(self, cmd: list[str], flag: str, value: Any) -> None:
        """Append one string CLI arg if present and free of control chars."""
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        if any(ord(ch) < 32 for ch in text):
            return
        cmd.extend([flag, text])

    def _append_cli_repeat(self, cmd: list[str], flag: str, values: list[str]) -> None:
        """Append repeatable CLI args."""
        for item in values:
            self._append_cli_str(cmd, flag, item)

    def _coerce_text_list(self, value: Any) -> list[str]:
        """Convert list/csv field to string list with simple sanitation."""
        if value is None:
            return []
        if isinstance(value, list):
            raw_items = [str(item).strip() for item in value if str(item).strip()]
        else:
            raw_items = [item.strip() for item in str(value).split(",") if item.strip()]
        output: list[str] = []
        for item in raw_items:
            if any(ord(ch) < 32 for ch in item):
                continue
            output.append(item)
        return output

    def _resolve_selected_tools(self, *, tools: list[str], skills: list[str]) -> list[str]:
        """Resolve explicit tools plus selected skills into one effective tool allowlist."""
        resolved: list[str] = []
        seen: set[str] = set()
        for item in tools:
            normalized = str(item).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                resolved.append(normalized)
        if skills:
            registry = load_builtin_skill_registry()
            for item in skills:
                skill = registry.get(str(item).strip())
                if skill is None:
                    continue
                if skill.tool not in seen:
                    seen.add(skill.tool)
                    resolved.append(skill.tool)
        return resolved

    def get_planner_catalog(self) -> dict[str, Any]:
        """Return planner-facing tool and skill catalog for the web UI."""
        load_builtin_agent_tools()
        skill_registry = load_builtin_skill_registry()

        tools: list[dict[str, Any]] = []
        for tool_name in sorted(list_tools()):
            try:
                tool = get_tool(tool_name)
            except Exception:  # noqa: BLE001
                continue
            available, message = tool.check_availability()
            skill = skill_registry.for_tool(tool_name)
            tools.append(
                {
                    "name": tool_name,
                    "category": str(getattr(tool, "category", "generic")),
                    "description": str(getattr(tool, "description", "")).strip(),
                    "risk_level": str(getattr(tool, "risk_level", "safe")).strip() or "safe",
                    "phase_affinity": list(getattr(tool, "phase_affinity", []) or []),
                    "target_types": list(getattr(tool, "target_types", []) or []),
                    "depends_on": list(getattr(tool, "depends_on", []) or []),
                    "available": bool(available),
                    "availability_message": str(message or "").strip(),
                    "skill": skill.name if skill is not None else None,
                }
            )

        skills: list[dict[str, Any]] = []
        for skill in skill_registry.list():
            skills.append(
                {
                    "name": skill.name,
                    "tool": skill.tool,
                    "category": skill.category,
                    "description": skill.description.strip(),
                    "phases": list(skill.triggers.phase),
                    "target_source": skill.triggers.target_source,
                    "target_type": skill.triggers.target_type,
                    "risk_level": skill.risk.level,
                    "cost": int(skill.risk.cost),
                    "priority": int(skill.risk.priority),
                    "runtime": skill.dependencies.runtime,
                    "depends_on_tools": list(skill.dependencies.tools),
                }
            )

        return {"tools": tools, "skills": skills}

    def _run_job(self, job_id: str) -> None:
        """Execute one CLI process and stream logs."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return
            record["status"] = "running"
            record["started_at"] = _utc_now()
            record["last_updated_at"] = _utc_now()
            command = list(record["command"])
        self._persist_job(job_id)
        self._notify_updates()

        self._append_log(job_id, "[web] starting process")
        self._append_log(job_id, "$ " + " ".join(self._command_preview(command)))

        process: subprocess.Popen[str] | None = None
        try:
            env_overlay = dict(os.environ)
            env_overlay.update(self._get_saved_llm_env())
            process = subprocess.Popen(
                command,
                cwd=str(self._workspace_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
                env=env_overlay,
            )
            with self._lock:
                if job_id in self._jobs:
                    self._jobs[job_id]["_process"] = process
                    self._jobs[job_id]["pid"] = process.pid
                    self._jobs[job_id]["last_updated_at"] = _utc_now()
            self._persist_job(job_id)
            self._notify_updates()

            if process.stdout is not None:
                for line in process.stdout:
                    self._append_log(job_id, line.rstrip("\r\n"))

            rc = process.wait()
            self._append_log(job_id, f"[web] process exited rc={rc}")
            with self._lock:
                record = self._jobs.get(job_id)
                if record is not None:
                    record["return_code"] = rc
                    record["status"] = "canceled" if record.get("cancel_requested") else ("completed" if rc == 0 else "failed")
                    record["ended_at"] = _utc_now()
                    record["last_updated_at"] = _utc_now()
                    record["pid"] = None
                    record.pop("_process", None)
            self._persist_job(job_id)
            self._notify_updates()
        except Exception as exc:  # noqa: BLE001
            self._append_log(job_id, f"[web] execution error: {exc}")
            with self._lock:
                record = self._jobs.get(job_id)
                if record is not None:
                    record["status"] = "error"
                    record["error"] = str(exc)
                    record["ended_at"] = _utc_now()
                    record["last_updated_at"] = _utc_now()
                    record["pid"] = None
                    record.pop("_process", None)
            self._persist_job(job_id)
            self._notify_updates()
        finally:
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            self._refresh_artifacts(job_id)
            self._dispatch_notifications(job_id)

    def _append_log(self, job_id: str, line: str) -> None:
        """Append one log line."""
        entry = {"ts": _utc_now(), "line": str(line)}
        with self._updates:
            record = self._jobs.get(job_id)
            if record is None:
                return
            line_no = int(record.get("log_line_count", 0))
            record["logs"].append(entry)
            record["log_line_count"] = line_no + 1
            if len(record["logs"]) > 5000:
                overflow = len(record["logs"]) - 5000
                record["logs"] = record["logs"][overflow:]
            record["last_updated_at"] = _utc_now()
            self._updates.notify_all()
        if not self._closed:
            self._store.append_log(job_id, line_no=line_no, entry=entry)
        self._persist_job(job_id)

    def _refresh_artifacts(self, job_id: str) -> None:
        """Scan output directory and cache artifacts."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return
            output_dir = Path(record["output_dir"]).resolve()

        artifacts: list[dict[str, Any]] = []
        if output_dir.exists():
            for path in sorted(output_dir.rglob("*")):
                if not path.is_file():
                    continue
                try:
                    rel = path.relative_to(output_dir).as_posix()
                except ValueError:
                    continue
                stat = path.stat()
                artifacts.append({"path": rel, "size": stat.st_size, "mtime": int(stat.st_mtime)})

        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["artifacts"] = artifacts
                self._jobs[job_id]["last_updated_at"] = _utc_now()
        if not self._closed:
            self._store.replace_artifacts(job_id, artifacts)
        self._persist_job(job_id)
        self._notify_updates()

    def _serialize_job(self, record: dict[str, Any]) -> dict[str, Any]:
        """Build JSON-safe job summary."""
        return {
            "job_id": record["job_id"],
            "status": record["status"],
            "created_at": record.get("created_at"),
            "started_at": record.get("started_at"),
            "ended_at": record.get("ended_at"),
            "last_updated_at": record.get("last_updated_at"),
            "target": record.get("target"),
            "mode": record.get("mode"),
            "safety_grade": record.get("safety_grade"),
            "report_lang": record.get("report_lang", "zh-CN"),
            "pid": record.get("pid"),
            "return_code": record.get("return_code"),
            "output_dir": record.get("output_dir"),
            "resume": record.get("resume"),
            "llm_config": record.get("llm_config"),
            "tools": list(record.get("tools", []) or []),
            "skills": list(record.get("skills", []) or []),
            "surface_file": record.get("surface_file"),
            "error": record.get("error"),
            "cancel_requested": bool(record.get("cancel_requested", False)),
            "log_line_count": int(record.get("log_line_count", 0)),
            "artifact_count": len(record.get("artifacts", [])),
            "command_preview": self._command_preview(list(record.get("command", []))),
        }

    @staticmethod
    def _command_preview(command: list[str]) -> list[str]:
        """Return CLI args preview."""
        return [str(item) for item in command]

    def _restore_persisted_jobs(self) -> None:
        """Load persisted jobs from SQLite and mark in-flight items as interrupted."""
        restored = self._store.list_jobs()
        for record in restored:
            record["logs"] = []
            record["artifacts"] = self._store.list_artifacts(record["job_id"])
            record["pid"] = None
            total = int(record.get("log_line_count", 0))
            if total > 0:
                tail = self._store.get_logs(record["job_id"], offset=max(0, total - 5000), limit=5000)
                record["logs"] = list(tail.get("items", []))
            with self._lock:
                self._jobs[record["job_id"]] = record

            if str(record.get("status", "")) in {"queued", "running"}:
                with self._lock:
                    current = self._jobs.get(record["job_id"])
                    if current is None:
                        continue
                    current["status"] = "error"
                    current["ended_at"] = _utc_now()
                    current["last_updated_at"] = _utc_now()
                    current["error"] = current.get("error") or "web_service_restarted"
                self._persist_job(record["job_id"])
                self._append_log(record["job_id"], "[web] job marked interrupted after web service restart")

    def _persist_job(self, job_id: str) -> None:
        """Persist current in-memory job state."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return
            snapshot = dict(record)
        if self._closed:
            return
        self._store.upsert_job(snapshot)

    def _next_job_id_locked(self) -> str:
        """Generate a process-local unique job id while holding the lock."""
        while True:
            self._counter += 1
            candidate = f"job-{time.strftime('%Y%m%d-%H%M%S')}-{self._counter:03d}"
            if candidate not in self._jobs:
                return candidate

    def _notify_updates(self) -> None:
        """Wake long-poll/SSE waiters."""
        with self._updates:
            self._updates.notify_all()

    def _build_notifier(self, config: dict[str, Any]) -> BaseNotifier:
        built = build_notifier_from_config(config if isinstance(config, dict) else {})
        if built is None:
            return NoopNotifier()
        return built

    def _normalize_plugin_settings(self, config: Any) -> dict[str, Any]:
        raw_dirs = []
        if isinstance(config, dict):
            raw_dirs = config.get("plugin_dirs", [])
        elif isinstance(config, list):
            raw_dirs = config
        elif config not in (None, ""):
            raw_dirs = str(config).splitlines()

        if not isinstance(raw_dirs, list):
            raw_dirs = [raw_dirs]

        plugin_dirs: list[str] = []
        seen: set[str] = set()
        for item in raw_dirs:
            text = str(item).strip()
            if not text or any(ord(ch) < 32 for ch in text):
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            plugin_dirs.append(text)
        return {"plugin_dirs": plugin_dirs}

    def _resolve_plugin_dirs(self, plugin_dirs: list[str]) -> list[Path]:
        resolved: list[Path] = []
        for item in plugin_dirs:
            raw = str(item).strip()
            if not raw:
                continue
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = (self._workspace_dir / candidate).resolve()
            else:
                candidate = candidate.resolve()
            resolved.append(candidate)
        return resolved

    def _reload_plugin_runtime(self) -> dict[str, Any]:
        resolved_dirs = self._resolve_plugin_dirs(self._plugin_settings.get("plugin_dirs", []))
        result = self._plugin_loader.load_from_directories(resolved_dirs)
        self._plugin_runtime = {
            "last_loaded_at": _utc_now(),
            "resolved_dirs": [str(path) for path in resolved_dirs],
            "loaded_plugin_ids": list(result.get("loaded_plugin_ids", [])),
            "errors": list(result.get("errors", [])),
        }
        return dict(self._plugin_runtime)

    def _dispatch_notifications(self, job_id: str) -> None:
        """Emit runtime notifications for terminal jobs."""
        if self._closed:
            return
        settings = self.get_notification_settings()
        enabled_events = settings.get("events", []) if isinstance(settings, dict) else []
        if not isinstance(enabled_events, list):
            enabled_events = []
        if not enabled_events:
            return

        try:
            job = self.get_job(job_id)
        except KeyError:
            return
        status = str(job.get("status", ""))
        report_summary = self._load_report_summary(job_id)
        severity_counts = report_summary.get("severity_counts", {})
        finding_total = int(report_summary.get("finding_total", 0) or 0)

        base_context = {
            "job_id": job_id,
            "target": job.get("target"),
            "mode": job.get("mode"),
            "status": status,
            "finding_total": finding_total,
            "severity_counts": severity_counts,
        }

        if status in {"completed", "failed", "error", "canceled"} and status in enabled_events:
            self._notifier.notify(
                NotificationEvent(
                    event_type=status,
                    severity="info" if status == "completed" else "warning",
                    title=f"AutoSecAudit job {status}",
                    message=f"{job.get('target')} finished with status={status}",
                    context=base_context,
                )
            )

        if int(severity_counts.get("critical", 0) or 0) > 0 and "finding_critical" in enabled_events:
            self._notifier.notify(
                NotificationEvent(
                    event_type="finding_critical",
                    severity="critical",
                    title="Critical findings detected",
                    message=f"{job.get('target')} produced critical findings.",
                    context=base_context,
                )
            )
        if int(severity_counts.get("high", 0) or 0) > 0 and "finding_high" in enabled_events:
            self._notifier.notify(
                NotificationEvent(
                    event_type="finding_high",
                    severity="high",
                    title="High-risk findings detected",
                    message=f"{job.get('target')} produced high-severity findings.",
                    context=base_context,
                )
            )
        try:
            self._notifier.flush(timeout_seconds=0.5)
        except Exception:  # noqa: BLE001
            pass

    def _load_report_summary(self, job_id: str) -> dict[str, Any]:
        """Extract minimal finding summary from persisted reports."""
        candidates = ["agent/audit_report.json", "audit_report.json"]
        for candidate in candidates:
            try:
                path = self.resolve_file(job_id, candidate)
            except (KeyError, FileNotFoundError, PermissionError):
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            summary = payload.get("summary", {})
            if not isinstance(summary, dict):
                summary = {}
            severity_counts = summary.get("severity_counts", {})
            if not isinstance(severity_counts, dict):
                severity_counts = {}
            return {
                "finding_total": int(
                    summary.get("total_findings")
                    or summary.get("vulnerability_findings")
                    or 0
                ),
                "severity_counts": {
                    "critical": int(severity_counts.get("critical", 0) or 0),
                    "high": int(severity_counts.get("high", 0) or 0),
                    "medium": int(severity_counts.get("medium", 0) or 0),
                    "low": int(severity_counts.get("low", 0) or 0),
                    "info": int(severity_counts.get("info", 0) or 0),
                },
            }
        return {
            "finding_total": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    # ------------------------------------------------------------------
    # LLM settings
    # ------------------------------------------------------------------

    LLM_PRESETS: list[dict[str, str]] = [
        {"id": "openai", "label": "OpenAI", "base_url": "https://api.openai.com/v1", "default_model": "gpt-4.1-mini", "note": "需要 OpenAI API Key"},
        {"id": "qwen", "label": "通义千问 (Qwen)", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "default_model": "qwen-plus", "note": "阿里云，支付宝注册即用"},
        {"id": "deepseek", "label": "DeepSeek", "base_url": "https://api.deepseek.com/v1", "default_model": "deepseek-chat", "note": "高性价比，手机号注册即用"},
        {"id": "glm", "label": "智谱 (GLM)", "base_url": "https://open.bigmodel.cn/api/paas/v4", "default_model": "glm-4-flash", "note": "手机号注册即用"},
        {"id": "kimi", "label": "月之暗面 (Kimi)", "base_url": "https://api.moonshot.cn/v1", "default_model": "moonshot-v1-8k", "note": "手机号注册即用"},
        {"id": "siliconflow", "label": "SiliconFlow", "base_url": "https://api.siliconflow.cn/v1", "default_model": "Qwen/Qwen2.5-7B-Instruct", "note": "聚合多家开源模型"},
        {"id": "ollama", "label": "本地 Ollama", "base_url": "http://host.docker.internal:11434/v1", "default_model": "qwen2.5:14b", "note": "本地部署，完全免费，需 16GB+ 内存"},
        {"id": "custom", "label": "自定义 (Custom)", "base_url": "", "default_model": "", "note": "手动填写 Base URL 和模型名"},
    ]

    def get_llm_settings(self) -> dict[str, Any]:
        """Return current LLM configuration with source detection."""
        import os

        saved = self._store.get_setting("llm_config", default={}).get("value") or {}
        if isinstance(saved, dict) and saved.get("model"):
            return {
                "configured": True,
                "preset_id": saved.get("preset_id"),
                "provider_type": saved.get("provider_type", "openai_compatible"),
                "base_url": saved.get("base_url", ""),
                "model": saved.get("model", ""),
                "api_key_configured": bool(saved.get("api_key")),
                "temperature": float(saved.get("temperature", 0.0)),
                "max_output_tokens": int(saved.get("max_output_tokens", 1200)),
                "timeout_seconds": _normalize_llm_timeout(saved.get("timeout_seconds")),
                "source": "web",
                "presets": self.LLM_PRESETS,
            }

        env_model = os.getenv("AUTOSECAUDIT_LLM_MODEL", "").strip()
        env_base_url = os.getenv("AUTOSECAUDIT_LLM_BASE_URL", "").strip()
        env_provider = os.getenv("AUTOSECAUDIT_LLM_PROVIDER", "openai_compatible").strip()
        env_api_key = os.getenv("AUTOSECAUDIT_LLM_API_KEY", "").strip()
        if env_model:
            return {
                "configured": True,
                "preset_id": None,
                "provider_type": env_provider,
                "base_url": env_base_url or "https://api.openai.com/v1",
                "model": env_model,
                "api_key_configured": bool(env_api_key),
                "temperature": 0.0,
                "max_output_tokens": 1200,
                "timeout_seconds": DEFAULT_LLM_TIMEOUT_SECONDS,
                "source": "env",
                "presets": self.LLM_PRESETS,
            }

        return {
            "configured": False,
            "preset_id": None,
            "provider_type": None,
            "base_url": None,
            "model": None,
            "api_key_configured": False,
            "temperature": 0.0,
            "max_output_tokens": 1200,
            "timeout_seconds": DEFAULT_LLM_TIMEOUT_SECONDS,
            "source": "none",
            "presets": self.LLM_PRESETS,
        }

    def save_llm_settings(self, config: dict[str, Any]) -> dict[str, Any]:
        """Persist LLM configuration from the web UI."""
        normalized = dict(config)
        normalized["timeout_seconds"] = _normalize_llm_timeout(config.get("timeout_seconds"))
        self._store.set_setting("llm_config", normalized, updated_at=_utc_now())
        return self.get_llm_settings()

    def test_llm_connection(self, config: dict[str, Any]) -> dict[str, Any]:
        """Send a trivial prompt to verify LLM connectivity."""
        import time as _time
        import urllib.error
        import urllib.request

        model = str(config.get("model", "")).strip()
        base_url = str(config.get("base_url", "")).strip().rstrip("/")
        api_key = str(config.get("api_key", "")).strip()
        timeout = _normalize_llm_timeout(config.get("timeout_seconds"))

        if not model or not base_url:
            return {"ok": False, "model": model, "error": "model and base_url are required"}

        url = f"{base_url}/chat/completions"
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "Respond with exactly: OK"}],
            "max_tokens": 10,
            "temperature": 0,
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        start = _time.monotonic()
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                body = json.loads(resp.read().decode("utf-8"))
            latency = int((_time.monotonic() - start) * 1000)
            reply = ""
            if isinstance(body, dict):
                choices = body.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {})
                    reply = str(msg.get("content", ""))[:200]
            return {"ok": True, "model": model, "latency_ms": latency, "reply_preview": reply}
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            return {"ok": False, "model": model, "error": f"HTTP {exc.code}: {detail}"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "model": model, "error": str(exc)[:300]}

    def get_mission_llm_completion(self) -> Any | None:
        """Return a prompt->text callable for mission parsing, or None when no LLM is configured."""
        router = self.build_runtime_llm_router()
        if router is None:
            return None

        def _complete(prompt: str) -> str:
            return router.complete(prompt)

        return _complete

    def build_runtime_llm_router(self) -> LLMRouter | None:
        """Build an in-process LLM router from saved or environment settings."""
        settings = self.get_llm_settings()
        if not settings.get("configured"):
            return None

        source = str(settings.get("source", "none")).strip().lower()
        try:
            if source == "web":
                saved = self._store.get_setting("llm_config", default={}).get("value") or {}
                model = str(saved.get("model", "")).strip()
                if not model:
                    return None
                provider_type = str(saved.get("provider_type", "openai_compatible")).strip() or "openai_compatible"
                provider_name = str(saved.get("preset_id", "")).strip() or "openai"
                base_url = str(saved.get("base_url", "")).strip() or None
                api_key = str(saved.get("api_key", "")).strip()
                api_key_env = "OPENAI_API_KEY"
                if api_key:
                    os.environ[WEB_RUNTIME_LLM_API_KEY_ENV] = api_key
                    api_key_env = WEB_RUNTIME_LLM_API_KEY_ENV
                return LLMRouter.from_cli_args(
                    llm_model=model,
                    llm_provider=provider_name,
                    llm_provider_type=provider_type,
                    llm_fallbacks=self._coerce_text_list(saved.get("fallback_models")),
                    llm_base_url=base_url,
                    llm_api_key_env=api_key_env,
                    llm_oauth_token_env=None,
                    llm_oauth_token_file=None,
                    llm_oauth_command_json=None,
                    llm_oauth_browser_login=False,
                    llm_oauth_authorize_url=None,
                    llm_oauth_token_url=None,
                    llm_oauth_client_id=None,
                    llm_oauth_scopes=[],
                    llm_oauth_redirect_host="127.0.0.1",
                    llm_oauth_redirect_port=8765,
                    llm_oauth_redirect_path="/callback",
                    llm_oauth_cache_file=None,
                    llm_oauth_login_timeout=180.0,
                    llm_oauth_profile_id=None,
                    llm_oauth_profiles_file=None,
                    llm_oauth_auto_refresh=True,
                    llm_timeout=_normalize_llm_timeout(saved.get("timeout_seconds")),
                    llm_temperature=_to_float(saved.get("temperature"), 0.0, minimum=0.0, maximum=2.0),
                    llm_max_output_tokens=_to_int(saved.get("max_output_tokens"), 1200, minimum=1, maximum=65536),
                )

            if source == "env":
                env_model = os.getenv("AUTOSECAUDIT_LLM_MODEL", "").strip()
                if not env_model:
                    return None
                return LLMRouter.from_cli_args(
                    llm_model=env_model,
                    llm_provider="openai",
                    llm_provider_type=(os.getenv("AUTOSECAUDIT_LLM_PROVIDER", "openai_compatible").strip() or "openai_compatible"),
                    llm_fallbacks=[],
                    llm_base_url=(os.getenv("AUTOSECAUDIT_LLM_BASE_URL", "").strip() or None),
                    llm_api_key_env="AUTOSECAUDIT_LLM_API_KEY",
                    llm_oauth_token_env=None,
                    llm_oauth_token_file=None,
                    llm_oauth_command_json=None,
                    llm_oauth_browser_login=False,
                    llm_oauth_authorize_url=None,
                    llm_oauth_token_url=None,
                    llm_oauth_client_id=None,
                    llm_oauth_scopes=[],
                    llm_oauth_redirect_host="127.0.0.1",
                    llm_oauth_redirect_port=8765,
                    llm_oauth_redirect_path="/callback",
                    llm_oauth_cache_file=None,
                    llm_oauth_login_timeout=180.0,
                    llm_oauth_profile_id=None,
                    llm_oauth_profiles_file=None,
                    llm_oauth_auto_refresh=True,
                    llm_timeout=_normalize_llm_timeout(settings.get("timeout_seconds")),
                    llm_temperature=_to_float(settings.get("temperature"), 0.0, minimum=0.0, maximum=2.0),
                    llm_max_output_tokens=_to_int(settings.get("max_output_tokens"), 1200, minimum=1, maximum=65536),
                )
        except LLMRouterError:
            return None
        return None

    def get_llm_cli_args(self) -> list[str]:
        """Build CLI args from saved/env LLM config for auto-injection."""
        settings = self.get_llm_settings()
        if not settings.get("configured"):
            return []
        source = settings.get("source", "none")
        args: list[str] = []
        if source == "web":
            saved = self._store.get_setting("llm_config", default={}).get("value") or {}
            model = str(saved.get("model", "")).strip()
            provider_type = str(saved.get("provider_type", "openai_compatible")).strip()
            base_url = str(saved.get("base_url", "")).strip()
            temperature = _to_float(saved.get("temperature"), 0.0, minimum=0.0, maximum=2.0)
            max_output_tokens = _to_int(saved.get("max_output_tokens"), 1200, minimum=1, maximum=65536)
            timeout_seconds = _normalize_llm_timeout(saved.get("timeout_seconds"))
            if model:
                args.extend(["--llm-model", model])
            if provider_type:
                args.extend(["--llm-provider-type", provider_type])
            if base_url:
                args.extend(["--llm-base-url", base_url])
            args.extend(["--llm-temperature", str(temperature)])
            args.extend(["--llm-max-output-tokens", str(max_output_tokens)])
            args.extend(["--llm-timeout", str(timeout_seconds)])
        elif source == "env":
            import os
            env_model = os.getenv("AUTOSECAUDIT_LLM_MODEL", "").strip()
            env_base_url = os.getenv("AUTOSECAUDIT_LLM_BASE_URL", "").strip()
            env_provider = os.getenv("AUTOSECAUDIT_LLM_PROVIDER", "").strip()
            if env_model:
                args.extend(["--llm-model", env_model])
            if env_provider:
                args.extend(["--llm-provider-type", env_provider])
            if env_base_url:
                args.extend(["--llm-base-url", env_base_url])
        return args

    def _get_saved_llm_env(self) -> dict[str, str]:
        """Return env vars to inject into subprocess from saved LLM config."""
        saved = self._store.get_setting("llm_config", default={}).get("value") or {}
        api_key = str(saved.get("api_key", "")).strip()
        if api_key:
            return {"OPENAI_API_KEY": api_key}
        return {}
