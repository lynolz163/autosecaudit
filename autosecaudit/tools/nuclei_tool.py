"""Nuclei-based vulnerability scanning tool for agent mode."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any

from autosecaudit.agent_core.tool_registry import register_tool
from autosecaudit.agent_core.tools import BaseAgentTool
from autosecaudit.core.models import Finding
from autosecaudit.tools.base_tool import ToolExecutionResult


@register_tool
class NucleiTool(BaseAgentTool):
    """Run nuclei in safe mode and parse JSONL findings."""

    name = "nuclei_exploit_check"
    description = "Template-based non-destructive vulnerability checks via nuclei."
    cost = 20
    priority = 40
    category = "validation"
    target_types = ["nuclei_target"]
    phase_affinity = ["verification"]
    depends_on = ["tech_stack_fingerprint"]
    risk_level = "medium"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.5}
    default_options = {"severity": ["medium"]}
    input_schema = {
        "target_mode": "http_url",
        "properties": {
            "templates": {
                "type": "array",
                "items": {
                    "type": "string",
                    "format": "safe_shell_text",
                    "error": "nuclei_option_contains_dangerous_chars",
                },
                "error": "nuclei_option_invalid_type",
            },
            "severity": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "error": "nuclei_invalid_severity",
                },
                "error": "nuclei_invalid_severity",
            },
            "template_id": {
                "type": "array",
                "items": {
                    "type": "string",
                    "format": "safe_shell_text",
                    "error": "nuclei_option_contains_dangerous_chars",
                },
                "error": "nuclei_option_invalid_type",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 900,
                "error": "nuclei_timeout_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "nuclei_options_invalid_keys",
    }

    _ALLOWED_OPTION_KEYS = {"templates", "severity", "template_id", "timeout_seconds"}
    _BLOCKED_OPTION_KEYS = {"cmd", "o", "output", "config", "proxy"}
    _DANGEROUS_PATTERN = re.compile(r"[;\r\n]|&&|\|\||\||`|\$\(")
    _SEVERITY_ALLOWED = {"info", "low", "medium", "high", "critical"}
    _DEFAULT_TIMEOUT_SECONDS = 300.0
    _MAX_TIMEOUT_SECONDS = 900.0
    _JSON_OUTPUT_FLAGS = ("-j", "-json")

    def check_availability(self) -> tuple[bool, str | None]:
        """Check nuclei executable availability before scheduling."""
        if self.resolve_executable():
            return True, None
        return False, "nuclei binary not found in PATH, AUTOSECAUDIT_NUCLEI_BIN, or .tools/nuclei"

    @classmethod
    def resolve_executable(cls) -> str | None:
        for candidate in cls._candidate_binaries():
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
            if Path(candidate).exists():
                return str(Path(candidate).resolve())
        return None

    @classmethod
    def _candidate_binaries(cls) -> list[str]:
        candidates: list[str] = []
        env_bin = os.getenv("AUTOSECAUDIT_NUCLEI_BIN", "").strip()
        if env_bin:
            candidates.append(env_bin)
        candidates.append("nuclei")

        repo_root = Path(__file__).resolve().parents[2]
        repo_local_dir = repo_root / ".tools" / "nuclei"
        for binary_name in ("nuclei.exe", "nuclei"):
            repo_local_bin = repo_local_dir / binary_name
            if repo_local_bin.exists():
                candidates.append(str(repo_local_bin))
        return candidates

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()

        try:
            validated_options = self._validate_options(options)
            validated_target = self._validate_safe_text(target, "target")
            timeout_seconds = self._coerce_timeout(validated_options.get("timeout_seconds"))
        except ValueError as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={
                    "status": "error",
                    "payload": {"error": str(exc)},
                    "findings": [],
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                error=str(exc),
                duration_ms=self._elapsed_ms(started),
            )

        command, completed = self._run_with_compatible_json_flag(
            target=validated_target,
            options=validated_options,
            timeout_seconds=timeout_seconds,
            started=started,
        )
        if isinstance(completed, ToolExecutionResult):
            return completed

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        findings, parse_errors = self._parse_jsonl_findings(stdout, validated_target)

        status = "completed" if completed.returncode == 0 else "failed"
        error = None
        if completed.returncode != 0:
            error = stderr[:1000] or f"nuclei exited with code {completed.returncode}"

        payload = {
            "command": command,
            "return_code": completed.returncode,
            "parse_errors": parse_errors,
            "finding_count": len(findings),
            "stderr": stderr[:1000] if stderr else "",
        }

        return ToolExecutionResult(
            ok=(completed.returncode == 0),
            tool_name=self.name,
            target=validated_target,
            data={
                "status": status,
                "payload": payload,
                "findings": findings,
                "breadcrumbs_delta": [],
                "surface_delta": {"nuclei_finding_count": len(findings)},
            },
            error=error,
            raw_output=stdout[:20000] if stdout else None,
            duration_ms=self._elapsed_ms(started),
        )

    def _run_with_compatible_json_flag(
        self,
        *,
        target: str,
        options: dict[str, Any],
        timeout_seconds: float,
        started: float,
    ) -> tuple[list[str], subprocess.CompletedProcess[str] | ToolExecutionResult]:
        last_completed: subprocess.CompletedProcess[str] | None = None
        last_command: list[str] | None = None
        for json_flag in self._JSON_OUTPUT_FLAGS:
            command = self._build_command(target, options, json_flag=json_flag)
            completed_or_error = self._execute_command(
                command=command,
                target=target,
                timeout_seconds=timeout_seconds,
                started=started,
            )
            if isinstance(completed_or_error, ToolExecutionResult):
                return command, completed_or_error
            last_completed = completed_or_error
            last_command = command
            if not self._is_unsupported_json_flag(last_completed, json_flag):
                return command, last_completed

        assert last_completed is not None and last_command is not None
        return last_command, last_completed

    def _execute_command(
        self,
        *,
        command: list[str],
        target: str,
        timeout_seconds: float,
        started: float,
    ) -> subprocess.CompletedProcess[str] | ToolExecutionResult:
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
        except FileNotFoundError:
            message = "nuclei binary not found in PATH, AUTOSECAUDIT_NUCLEI_BIN, or .tools/nuclei"
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={
                    "status": "error",
                    "payload": {"error": message},
                    "findings": [],
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                error=message,
                duration_ms=self._elapsed_ms(started),
            )
        except subprocess.TimeoutExpired:
            message = f"nuclei scan timed out after {timeout_seconds:.1f}s"
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={
                    "status": "error",
                    "payload": {"error": message},
                    "findings": [],
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                error=message,
                duration_ms=self._elapsed_ms(started),
            )
        except OSError as exc:
            message = f"failed to execute nuclei: {exc}"
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={
                    "status": "error",
                    "payload": {"error": message},
                    "findings": [],
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                error=message,
                duration_ms=self._elapsed_ms(started),
            )

    @staticmethod
    def _is_unsupported_json_flag(completed: subprocess.CompletedProcess[str], json_flag: str) -> bool:
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        combined = f"{stdout}\n{stderr}".lower()
        return f"flag provided but not defined: {json_flag}".lower() in combined

    def _build_command(self, target: str, options: dict[str, Any], *, json_flag: str = "-j") -> list[str]:
        executable = self.resolve_executable() or "nuclei"
        command = [
            executable,
            "-u",
            target,
            json_flag,
            "-silent",
            "-H",
            "User-Agent: AutoSecAudit",
        ]

        templates = self._coerce_text_list(options.get("templates"))
        for template in templates:
            command.extend(["-t", template])

        severities = self._coerce_severity_list(options.get("severity"))
        if severities:
            command.extend(["-s", ",".join(severities)])

        template_ids = self._coerce_text_list(options.get("template_id"))
        if template_ids:
            command.extend(["-id", ",".join(template_ids)])

        return command

    def _validate_options(self, options: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(options, dict):
            raise ValueError("options must be a dict")

        validated: dict[str, Any] = {}
        for key, value in options.items():
            key_text = str(key).strip().lower()
            if key_text in self._BLOCKED_OPTION_KEYS:
                raise ValueError(f"dangerous nuclei option is blocked: {key_text}")
            if key_text not in self._ALLOWED_OPTION_KEYS:
                raise ValueError(f"unsupported nuclei option: {key_text}")
            if key_text == "timeout_seconds":
                validated[key_text] = value
            else:
                self._validate_option_value_safety(value, key_text)
                validated[key_text] = value
        return validated

    def _validate_option_value_safety(self, value: Any, field_name: str) -> None:
        if isinstance(value, list):
            for item in value:
                self._validate_safe_text(str(item), field_name)
            return
        self._validate_safe_text(str(value), field_name)

    def _validate_safe_text(self, text: str, field_name: str) -> str:
        normalized = text.strip()
        if not normalized:
            raise ValueError(f"{field_name} must not be empty")
        if self._DANGEROUS_PATTERN.search(normalized):
            raise ValueError(f"{field_name} contains disallowed characters")
        return normalized

    def _coerce_text_list(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [self._validate_safe_text(str(item), "option_item") for item in value if str(item).strip()]
        return [self._validate_safe_text(str(value), "option_item")]

    def _coerce_severity_list(self, value: Any) -> list[str]:
        raw_values = self._coerce_text_list(value)
        if not raw_values:
            return []
        normalized = [item.lower() for item in raw_values]
        invalid = [item for item in normalized if item not in self._SEVERITY_ALLOWED]
        if invalid:
            raise ValueError(f"invalid severity value(s): {', '.join(invalid)}")
        return normalized

    def _coerce_timeout(self, value: Any) -> float:
        if value is None:
            return self._DEFAULT_TIMEOUT_SECONDS
        try:
            timeout_value = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout_seconds must be a number") from exc
        if timeout_value <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if timeout_value > self._MAX_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout_seconds exceeds max allowed ({self._MAX_TIMEOUT_SECONDS:.0f}s)"
            )
        return timeout_value

    def _parse_jsonl_findings(self, output: str, target: str) -> tuple[list[dict[str, Any]], int]:
        findings: list[dict[str, Any]] = []
        parse_errors = 0
        if not output:
            return findings, parse_errors

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError:
                parse_errors += 1
                continue

            info = item.get("info", {}) if isinstance(item, dict) else {}
            name = str(info.get("name") or item.get("template-id") or "Nuclei Match").strip()
            severity = self._normalize_severity(str(info.get("severity", "medium")).strip().lower())
            matcher_status = str(item.get("matcher-status", "")).strip().lower()
            matched_at = str(item.get("matched-at", "")).strip()
            template_id = str(item.get("template-id", "")).strip()

            model = Finding(
                finding_id=self._build_finding_id(template_id or name),
                title=name,
                description=f"Nuclei template match on {matched_at or target}.",
                severity=severity,
                evidence={
                    "target": target,
                    "matched_at": matched_at,
                    "template_id": template_id,
                    "matcher_status": matcher_status,
                    "nuclei_result": item,
                },
                recommendation="Review affected component and apply vendor/security patch guidance.",
            )

            findings.append(
                {
                    "type": "vuln",
                    "name": model.title,
                    "severity": model.severity,
                    "evidence": json.dumps(model.evidence, ensure_ascii=False),
                    "model": asdict(model),
                    "reproduction_steps": [
                        f"Run nuclei against target: {target}",
                        f"Template matched: {template_id or name}",
                    ],
                }
            )
        return findings, parse_errors

    @staticmethod
    def _normalize_severity(value: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        if value in allowed:
            return value
        return "medium"

    @staticmethod
    def _build_finding_id(raw_value: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", raw_value).strip("_").upper()
        normalized = normalized or "NUCLEI_MATCH"
        return f"NUCLEI_{normalized[:80]}"

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)
