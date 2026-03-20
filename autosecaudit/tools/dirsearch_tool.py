"""Dirsearch-based content discovery tool for agent mode."""

from __future__ import annotations

from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from autosecaudit.agent_core.tool_registry import register_tool
from autosecaudit.agent_core.tools import BaseAgentTool
from autosecaudit.core.models import Finding
from autosecaudit.tools.base_tool import ToolExecutionResult


@register_tool
class DirsearchTool(BaseAgentTool):
    """
    Safe dirsearch wrapper for read-only content discovery.

    Design constraints:
    - URL-only targets
    - conservative defaults (low threads)
    - subprocess list arguments (`shell=False`)
    - JSON report parsing with tolerant fallback
    """

    name = "dirsearch_scan"
    description = "Read-only web content discovery via dirsearch (directory/file enumeration)."
    cost = 10
    priority = 25
    category = "discovery"
    target_types = ["origin_url"]
    phase_affinity = ["active_discovery"]
    risk_level = "low"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.0}
    default_options = {"threads": 4, "max_results": 200}
    input_schema = {
        "target_mode": "origin_http",
        "properties": {
            "wordlist": {
                "type": "string",
                "format": "safe_shell_text",
                "error": "dirsearch_option_contains_dangerous_chars",
            },
            "extensions": {
                "type": "array",
                "items": {
                    "type": "string",
                    "format": "extension_token",
                    "error": "dirsearch_extensions_invalid_format",
                },
                "error": "dirsearch_option_invalid_type",
            },
            "threads": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10,
                "error": "dirsearch_threads_out_of_bounds",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 900,
                "error": "dirsearch_timeout_out_of_bounds",
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2000,
                "error": "dirsearch_max_results_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "dirsearch_options_invalid_keys",
    }

    _ALLOWED_OPTION_KEYS = {"wordlist", "extensions", "threads", "timeout_seconds", "max_results"}
    _DANGEROUS_PATTERN = re.compile(r"[;\r\n]|&&|\|\||\||`|\$\(")
    _DEFAULT_THREADS = 4
    _MAX_THREADS = 10
    _DEFAULT_TIMEOUT_SECONDS = 90.0
    _MAX_TIMEOUT_SECONDS = 900.0
    _DEFAULT_MAX_RESULTS = 300
    _MAX_MAX_RESULTS = 2000
    _DEFAULT_WORDLIST_ENTRIES: tuple[str, ...] = (
        "",
        "admin",
        "administrator",
        "login",
        "logout",
        "dashboard",
        "panel",
        "console",
        "api",
        "api/docs",
        "swagger",
        "swagger.json",
        "openapi.json",
        "robots.txt",
        "sitemap.xml",
        ".env",
        ".git/config",
        ".git/HEAD",
        ".gitignore",
        ".well-known/security.txt",
        "server-status",
        "server-info",
        "health",
        "status",
        "debug",
        "phpinfo.php",
        "actuator/health",
        "actuator/env",
        "graphql",
        "uploads",
    )

    def check_availability(self) -> tuple[bool, str | None]:
        """Check dirsearch executable/module availability before scheduling."""
        if shutil.which("dirsearch") or shutil.which("dirsearch.py"):
            return True, None
        if Path("/opt/dirsearch/dirsearch.py").exists():
            return True, None
        if importlib.util.find_spec("dirsearch") is not None:
            return True, None
        return False, "dirsearch is not available (install dirsearch or use the provided container image)"

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()

        try:
            validated_target = self._validate_target(target)
            validated_options = self._validate_options(options)
            timeout_seconds = self._coerce_timeout(validated_options.get("timeout_seconds"))
            max_results = self._coerce_max_results(validated_options.get("max_results"))
        except ValueError as exc:
            return self._error_result(
                target=target,
                message=str(exc),
                duration_ms=self._elapsed_ms(started),
            )

        with tempfile.TemporaryDirectory(prefix="autosecaudit-dirsearch-") as temp_dir:
            report_path = Path(temp_dir) / "dirsearch_report.json"
            command_args = self._build_command_args(
                target=validated_target,
                options=validated_options,
                report_path=report_path,
            )

            completed: subprocess.CompletedProcess[str] | None = None
            executed_command: list[str] | None = None
            last_os_error: OSError | None = None
            for command_prefix in self._candidate_commands():
                command = [*command_prefix, *command_args]
                try:
                    completed = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                        check=False,
                        shell=False,
                    )
                    executed_command = command
                    break
                except FileNotFoundError as exc:
                    last_os_error = exc
                    continue
                except subprocess.TimeoutExpired as exc:
                    parsed_report, parse_errors = self._load_report(report_path, validated_target)
                    entries = self._extract_entries(parsed_report, validated_target)
                    entries = self._dedupe_entries(entries)[:max_results]
                    warning = f"dirsearch scan timed out after {timeout_seconds:.1f}s"
                    return ToolExecutionResult(
                        ok=True,
                        tool_name=self.name,
                        target=validated_target,
                        data={
                            "status": "completed",
                            "payload": {
                                "command": command,
                                "return_code": None,
                                "stdout_preview": self._stringify_process_output(exc.stdout, limit=2000),
                                "stderr_preview": self._stringify_process_output(exc.stderr, limit=1000),
                                "parse_errors": parse_errors,
                                "entry_count": len(entries),
                                "timed_out": True,
                                "warning": warning,
                            },
                            "findings": self._build_findings(entries),
                            "breadcrumbs_delta": [
                                {"type": "endpoint", "data": item["url"]}
                                for item in entries
                                if item.get("url")
                            ],
                            "surface_delta": {
                                "dirsearch_results": entries,
                                "discovered_urls": [item["url"] for item in entries if item.get("url")],
                                "dirsearch_entry_count": len(entries),
                                "dirsearch_timed_out": True,
                            },
                            "metadata": {"timed_out": True},
                        },
                        duration_ms=self._elapsed_ms(started),
                    )
                except OSError as exc:
                    last_os_error = exc
                    continue

            if completed is None or executed_command is None:
                message = "dirsearch binary not found in PATH"
                if last_os_error is not None:
                    message = f"failed to execute dirsearch: {last_os_error}"
                return self._error_result(
                    target=validated_target,
                    message=message,
                    duration_ms=self._elapsed_ms(started),
                )

            stdout = (completed.stdout or "").strip()
            stderr = (completed.stderr or "").strip()

            parsed_report, parse_errors = self._load_report(report_path, validated_target)
            entries = self._extract_entries(parsed_report, validated_target)
            entries = self._dedupe_entries(entries)[:max_results]

            breadcrumbs_delta = [
                {"type": "endpoint", "data": item["url"]}
                for item in entries
                if item.get("url")
            ]
            surface_delta = {
                "dirsearch_results": entries,
                "discovered_urls": [item["url"] for item in entries if item.get("url")],
                "dirsearch_entry_count": len(entries),
            }

            findings = self._build_findings(entries)
            payload = {
                "command": executed_command,
                "return_code": int(completed.returncode),
                "stdout_preview": stdout[:2000],
                "stderr_preview": stderr[:1000],
                "parse_errors": parse_errors,
                "entry_count": len(entries),
            }

            status = "completed"
            error = None
            # dirsearch may return non-zero on interruptions/errors. Preserve discovery if any.
            if completed.returncode != 0 and not entries:
                status = "failed"
                error = stderr[:1000] or f"dirsearch exited with code {completed.returncode}"
            elif completed.returncode != 0:
                status = "completed"
                if stderr:
                    payload["warning"] = stderr[:1000]

            return ToolExecutionResult(
                ok=(status == "completed"),
                tool_name=self.name,
                target=validated_target,
                data={
                    "status": status,
                    "payload": payload,
                    "findings": findings,
                    "breadcrumbs_delta": breadcrumbs_delta,
                    "surface_delta": surface_delta,
                },
                error=error,
                raw_output=stdout[:20000] if stdout else None,
                duration_ms=self._elapsed_ms(started),
            )

    def _candidate_commands(self) -> list[list[str]]:
        """Return command prefixes to try in order."""
        candidates: list[list[str]] = [["dirsearch"]]

        # Common container/source-install fallback.
        dirsearch_py = Path("/opt/dirsearch/dirsearch.py")
        if dirsearch_py.exists():
            candidates.append([sys.executable, str(dirsearch_py)])

        # Python module fallback (if packaged as module).
        candidates.append([sys.executable, "-m", "dirsearch"])
        return candidates

    def _build_command_args(self, *, target: str, options: dict[str, Any], report_path: Path) -> list[str]:
        """Build dirsearch arguments (without executable prefix)."""
        args = [
            "-u",
            target,
            "-O",
            "json",
            "-o",
            str(report_path),
            "-t",
            str(self._coerce_threads(options.get("threads"))),
        ]

        args.extend(["-w", self._resolve_wordlist_path(options=options, workspace_dir=report_path.parent)])

        extensions = self._coerce_extensions(options.get("extensions"))
        if extensions:
            args.extend(["-e", ",".join(extensions)])

        return args

    def _resolve_wordlist_path(self, *, options: dict[str, Any], workspace_dir: Path) -> str:
        wordlist = options.get("wordlist")
        if isinstance(wordlist, str) and wordlist.strip():
            return wordlist.strip()
        wordlist_path = Path(workspace_dir) / "autosecaudit-dirsearch-quick.txt"
        if not wordlist_path.exists():
            wordlist_path.write_text("\n".join(self._DEFAULT_WORDLIST_ENTRIES) + "\n", encoding="utf-8")
        return str(wordlist_path)

    def _validate_target(self, target: str) -> str:
        parsed = urlparse(str(target).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("dirsearch target must be an HTTP(S) URL")
        # Restrict to base origin/path for safer, deterministic scans.
        if parsed.fragment:
            raise ValueError("dirsearch target must not include fragment")
        if parsed.query:
            raise ValueError("dirsearch target must not include query string")
        path = parsed.path or "/"
        if path not in {"", "/"}:
            raise ValueError("dirsearch target must be a base origin URL (scheme://host[:port]/)")
        return f"{parsed.scheme.lower()}://{parsed.netloc}/"

    def _validate_options(self, options: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(options, dict):
            raise ValueError("options must be a dict")

        validated: dict[str, Any] = {}
        for key, value in options.items():
            key_text = str(key).strip()
            if key_text not in self._ALLOWED_OPTION_KEYS:
                raise ValueError(f"unsupported dirsearch option: {key_text}")

            if key_text in {"wordlist", "extensions"}:
                self._validate_safe_text_payload(value, key_text)
            validated[key_text] = value
        return validated

    def _validate_safe_text_payload(self, value: Any, field_name: str) -> None:
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

    def _coerce_threads(self, value: Any) -> int:
        if value is None:
            return self._DEFAULT_THREADS
        try:
            threads = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("threads must be an integer") from exc
        if threads < 1 or threads > self._MAX_THREADS:
            raise ValueError(f"threads must be between 1 and {self._MAX_THREADS}")
        return threads

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

    def _coerce_max_results(self, value: Any) -> int:
        if value is None:
            return self._DEFAULT_MAX_RESULTS
        try:
            max_results = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_results must be an integer") from exc
        if max_results < 1 or max_results > self._MAX_MAX_RESULTS:
            raise ValueError(
                f"max_results must be between 1 and {self._MAX_MAX_RESULTS}"
            )
        return max_results

    def _coerce_extensions(self, value: Any) -> list[str]:
        if value is None:
            return []
        raw_items: list[str]
        if isinstance(value, list):
            raw_items = [str(item).strip() for item in value if str(item).strip()]
        else:
            raw_items = [item.strip() for item in str(value).split(",") if item.strip()]
        cleaned: list[str] = []
        for item in raw_items:
            if not re.fullmatch(r"[A-Za-z0-9]{1,10}", item):
                raise ValueError("extensions must contain only alphanumeric values up to 10 chars")
            cleaned.append(item.lower())
        return cleaned

    @staticmethod
    def _stringify_process_output(value: str | bytes | None, *, limit: int) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = str(value)
        return text.strip()[:limit]

    def _load_report(self, report_path: Path, target: str) -> tuple[dict[str, Any] | list[Any], int]:
        """Load dirsearch JSON report file. Returns payload + parse error count."""
        if not report_path.exists():
            return {}, 1
        try:
            raw = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}, 1
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {}, 1
        if isinstance(payload, (dict, list)):
            return payload, 0
        return {"target": target, "raw": payload}, 0

    def _extract_entries(
        self,
        payload: dict[str, Any] | list[Any],
        target: str,
    ) -> list[dict[str, Any]]:
        """
        Extract normalized discovery entries from dirsearch JSON payload.

        Supports different schema variants by recursively scanning for result-like dicts.
        """
        parsed_target = urlparse(target)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        entries: list[dict[str, Any]] = []

        def visit(node: Any) -> None:
            if isinstance(node, list):
                for item in node:
                    visit(item)
                return
            if not isinstance(node, dict):
                return

            if any(key in node for key in ("url", "path")) and any(
                key in node for key in ("status", "status_code", "content-length", "content_length")
            ):
                normalized = self._normalize_entry(node, target_origin)
                if normalized is not None:
                    entries.append(normalized)

            for value in node.values():
                if isinstance(value, (list, dict)):
                    visit(value)

        visit(payload)
        return entries

    def _normalize_entry(self, raw: dict[str, Any], target_origin: str) -> dict[str, Any] | None:
        """Normalize one dirsearch result row."""
        raw_url = raw.get("url")
        raw_path = raw.get("path")

        url_text = str(raw_url).strip() if raw_url is not None else ""
        if not url_text and raw_path is not None:
            path_text = str(raw_path).strip()
            if path_text:
                if not path_text.startswith("/"):
                    path_text = "/" + path_text
                url_text = urljoin(target_origin + "/", path_text.lstrip("/"))
        if not url_text:
            return None

        parsed = urlparse(url_text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None

        status_value = raw.get("status", raw.get("status_code"))
        try:
            status_code = int(status_value) if status_value is not None else None
        except (TypeError, ValueError):
            status_code = None

        size_value = raw.get("content-length", raw.get("content_length", raw.get("size")))
        try:
            content_length = int(size_value) if size_value is not None else None
        except (TypeError, ValueError):
            content_length = None

        redirect = raw.get("redirect")
        redirect_text = str(redirect).strip() if redirect is not None else None

        return {
            "url": url_text,
            "path": parsed.path or "/",
            "status": status_code,
            "content_length": content_length,
            "redirect": redirect_text or None,
        }

    def _dedupe_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate by URL while preserving order."""
        seen: set[str] = set()
        output: list[dict[str, Any]] = []
        for item in entries:
            url_text = str(item.get("url", "")).strip()
            if not url_text or url_text in seen:
                continue
            seen.add(url_text)
            output.append(item)
        return output

    def _build_findings(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate low-noise findings for clearly sensitive discovered paths."""
        findings: list[dict[str, Any]] = []
        for item in entries:
            path = str(item.get("path", "")).lower()
            status = item.get("status")
            if status not in {200, 206}:
                continue
            finding = self._sensitive_path_finding(item)
            if finding is not None:
                findings.append(finding)
        return findings

    def _sensitive_path_finding(self, item: dict[str, Any]) -> dict[str, Any] | None:
        """Map sensitive path patterns to findings."""
        path = str(item.get("path", "")).lower()
        url = str(item.get("url", "")).strip()
        patterns: list[tuple[tuple[str, ...], str, str, str]] = [
            ((".env",), "Sensitive File Exposure: .env", "high", "Remove public access and rotate leaked secrets."),
            ((".git/config",), "Sensitive File Exposure: .git/config", "high", "Restrict repository metadata exposure and review repository history for secrets."),
            ((".bak", ".backup", ".old"), "Backup File Exposure", "medium", "Remove backup artifacts from web root and enforce deployment artifact controls."),
        ]
        for suffixes, title, severity, recommendation in patterns:
            if any(path.endswith(suffix) for suffix in suffixes):
                model = Finding(
                    finding_id=f"DIRSEARCH_{re.sub(r'[^A-Za-z0-9]+', '_', path).strip('_').upper()[:80] or 'EXPOSURE'}",
                    title=title,
                    description=f"dirsearch discovered a potentially sensitive path: {path}",
                    severity=severity,
                    evidence={"url": url, "path": path, "status": item.get("status"), "content_length": item.get("content_length")},
                    recommendation=recommendation,
                )
                return {
                    "type": "vuln",
                    "name": model.title,
                    "severity": model.severity,
                    "evidence": json.dumps(model.evidence, ensure_ascii=False),
                    "model": asdict(model),
                    "reproduction_steps": [
                        f"Send GET request to {url}.",
                        "Confirm HTTP 200 and inspect response content carefully in authorized scope.",
                    ],
                    "recommendation": recommendation,
                }
        return None

    def _error_result(self, *, target: str, message: str, duration_ms: int) -> ToolExecutionResult:
        """Build standardized error result."""
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
            duration_ms=duration_ms,
        )

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)
