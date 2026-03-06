"""Built-in agent tool adapters registered through ToolRegistry."""

from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import datetime, timezone
from functools import lru_cache
from html.parser import HTMLParser
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import socket
import ssl
import shutil
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import ParseResult, parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from autosecaudit.auditors import SQLSanitizationAuditor, XSSProtectionAuditor
from autosecaudit.crawlers import DynamicWebCrawler
from autosecaudit.agent_safety import normalize_safety_grade
from autosecaudit.core.models import Asset, ServiceAsset
from autosecaudit.integrations.openai_compatible_extract import (
    extract_text_from_openai_compatible_response,
)
from autosecaudit.tools import NmapTool, ToolExecutionResult
from autosecaudit.tools.nuclei_tool import NucleiTool

from . import builtin_tool_schemas
from .cve_service import CveServiceError, NvdCveService
from .rag_service import RagIntelService
from .sandbox_runner import SandboxRunner
from .template_capability_index import TemplateCapabilityIndex
from .tool_registry import list_tools, register_tool
from .tool_output_schema import DiscoveredAsset, StandardFinding, StandardToolOutput
from .tools import BaseAgentTool


class _HTMLSurfaceParser(HTMLParser):
    """Minimal HTML parser for forms and script references."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_sources: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        tag_name = tag.lower()
        if tag_name == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.script_sources.append(src)
            return
        if tag_name == "form":
            self._current_form = {
                "action": attr_map.get("action", "").strip(),
                "method": (attr_map.get("method", "get") or "get").strip().upper(),
                "inputs": [],
            }
            return
        if self._current_form is None:
            return
        if tag_name not in {"input", "textarea", "select", "button"}:
            return
        self._current_form["inputs"].append(
            {
                "tag": tag_name,
                "name": attr_map.get("name", "").strip(),
                "type": (attr_map.get("type", "text") or "text").strip().lower(),
                "value": attr_map.get("value", ""),
            }
        )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


@lru_cache(maxsize=1)
def _check_playwright_runtime_availability() -> tuple[bool, str | None]:
    """Verify both the Playwright package and Chromium runtime are present."""
    try:
        spec = importlib.util.find_spec("playwright.sync_api")
    except ModuleNotFoundError:
        spec = None
    if spec is None:
        return (
            False,
            "playwright is required. Install with `pip install playwright` and run `playwright install chromium`.",
        )

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            executable_path = str(getattr(playwright.chromium, "executable_path", "") or "").strip()
    except Exception as exc:  # noqa: BLE001
        return False, f"playwright browser runtime unavailable: {type(exc).__name__}: {exc}"

    if not executable_path or not os.path.exists(executable_path):
        return False, "playwright browser runtime is missing. Run `playwright install chromium`."
    return True, None


def _http_fetch_text(
    url: str,
    *,
    accept: str = "text/html,application/json,*/*;q=0.8",
    timeout: float = 8.0,
    max_bytes: int = 500_000,
) -> tuple[int, dict[str, str], str, str]:
    """Fetch text content with small bounded reads."""
    request = Request(
        url=url,
        method="GET",
        headers={
            "User-Agent": "AutoSecAudit-Agent/0.1",
            "Accept": accept,
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = (response.read(max_bytes) or b"").decode("utf-8", errors="replace")
            final_url = getattr(response, "url", url)
            return int(response.status), {key.lower(): value for key, value in response.headers.items()}, body, str(final_url)
    except HTTPError as exc:
        body = (exc.read(max_bytes) or b"").decode("utf-8", errors="replace")
        final_url = getattr(exc, "url", url)
        return int(exc.code), {key.lower(): value for key, value in exc.headers.items()}, body, str(final_url)


def _normalize_base_origin(target: str) -> str:
    """Normalize a target to scheme+netloc origin."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return urlunparse((parsed.scheme or "https", parsed.netloc, "", "", "", ""))


def _same_origin(base_url: str, candidate: str) -> bool:
    """Return whether candidate belongs to the same HTTP origin."""
    base = urlparse(base_url)
    parsed = urlparse(candidate)
    return (
        parsed.scheme.lower() == base.scheme.lower()
        and parsed.hostname == base.hostname
        and (parsed.port or (443 if parsed.scheme == "https" else 80))
        == (base.port or (443 if base.scheme == "https" else 80))
    )


def _normalize_http_url(url: str) -> str:
    """Normalize an HTTP URL while retaining its query string."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True), key=lambda item: item[0]), doseq=True)
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def _tech_stack_from_headers_and_body(headers: dict[str, str], body: str) -> list[str]:
    """Infer a lightweight technology stack from passive signals."""
    detected: set[str] = set()
    server = str(headers.get("server", "")).lower()
    powered_by = str(headers.get("x-powered-by", "")).lower()
    body_lower = body.lower()
    combined = "\n".join([server, powered_by, body_lower[:200_000]])
    signatures = {
        "wordpress": ("wp-content", "wp-includes", "wordpress"),
        "drupal": ("drupal-settings-json", "/sites/default/", "drupal"),
        "joomla": ("joomla!", "/media/system/js/", "com_content"),
        "grafana": ("grafana", "grafana-app"),
        "jenkins": ("jenkins", "x-jenkins"),
        "spring": ("whitelabel error page", "spring boot", "actuator"),
        "struts": ("struts", "x-work"),
        "nginx": ("nginx",),
        "apache": ("apache",),
        "php": ("php",),
        "aspnet": ("asp.net", "__viewstate"),
        "react": ("react", "__next"),
        "vue": ("vue", "__nuxt"),
    }
    for tech, markers in signatures.items():
        if any(marker in combined for marker in markers):
            detected.add(tech)
    return sorted(detected)


def _extract_parameter_names(url: str) -> dict[str, str]:
    """Return URL query parameter names mapped to observed values."""
    parsed = urlparse(url)
    return {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key}


def _standard_tool_result(
    *,
    ok: bool,
    tool_name: str,
    target: str,
    output: StandardToolOutput,
    error: str | None = None,
    raw_output: str | None = None,
    duration_ms: int = 0,
) -> ToolExecutionResult:
    """Convert standardized output dataclass into legacy ToolExecutionResult."""
    return ToolExecutionResult(
        ok=ok,
        tool_name=tool_name,
        target=target,
        data=output,
        error=error,
        raw_output=raw_output,
        duration_ms=duration_ms,
    )


def _origin_no_options_schema(*, target_mode: str = "origin_http") -> dict[str, Any]:
    """Backward-compatible wrapper around extracted schema helper."""
    return builtin_tool_schemas.origin_no_options_schema(target_mode=target_mode)


def _parameter_probe_schema(tool_name: str, *, max_params: int, max_value_length: int) -> dict[str, Any]:
    """Backward-compatible wrapper around extracted schema helper."""
    return builtin_tool_schemas.parameter_probe_schema(
        tool_name,
        max_params=max_params,
        max_value_length=max_value_length,
    )


def _service_asset_id(host: str, port: int, service: str, *, proto: str = "tcp") -> str:
    normalized_host = str(host).strip().lower()
    normalized_service = str(service).strip().lower() or "unknown"
    return f"service:{proto.lower()}:{normalized_host}:{int(port)}:{normalized_service}"


def _make_service_asset(
    *,
    tool_name: str,
    host: str,
    port: int,
    service: str,
    proto: str = "tcp",
    banner: str = "",
    tls: bool = False,
    auth_required: bool | None = None,
    scheme: str = "",
    evidence: dict[str, Any] | None = None,
) -> ServiceAsset:
    asset_id = _service_asset_id(host, port, service, proto=proto)
    return ServiceAsset(
        kind="service",
        id=asset_id,
        attributes={
            "host": str(host).strip().lower(),
            "port": int(port),
            "proto": str(proto).strip().lower() or "tcp",
            "service": str(service).strip().lower(),
            "banner": str(banner).strip(),
            "tls": bool(tls),
            "auth_required": auth_required,
            "scheme": str(scheme).strip().lower(),
        },
        evidence=dict(evidence or {}),
        source_tool=tool_name,
        host=str(host).strip().lower(),
        port=int(port),
        proto=str(proto).strip().lower() or "tcp",
        service=str(service).strip().lower(),
        banner=str(banner).strip(),
        tls=bool(tls),
        auth_required=auth_required,
    )


def _dedupe_json_rows(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate small JSON-like row objects deterministically."""
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in values:
        if not isinstance(item, dict):
            continue
        marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(item)
    return deduped


def _extract_version_token(value: Any) -> str | None:
    """Extract a compact version token from banner-like text."""
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"(?i)\b[v]?\d+(?:\.\d+){1,4}(?:[-._][0-9A-Za-z]+)*\b", text)
    if match is None:
        return None
    token = match.group(0).strip()
    if token.lower().startswith("v") and len(token) > 1 and token[1].isdigit():
        token = token[1:]
    return token[:64] or None


def _make_tech_component_row(
    *,
    component: str,
    version: str | None = None,
    target: str = "",
    source_tool: str = "",
    service: str = "",
    host: str = "",
    port: int | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build one normalized technology component row for planner follow-up."""
    normalized_component = str(component or "").strip().lower()
    normalized_target = str(target or "").strip()
    normalized_host = str(host or "").strip().lower()
    normalized_service = str(service or "").strip().lower()
    if not normalized_component:
        return None
    row: dict[str, Any] = {
        "component": normalized_component,
        "version": str(version).strip() if str(version or "").strip() else None,
        "target": normalized_target or normalized_host,
        "source_tool": str(source_tool or "").strip() or None,
        "service": normalized_service or None,
        "host": normalized_host or None,
        "evidence": dict(evidence or {}),
    }
    if port is not None:
        row["port"] = int(port)
    return row


def _infer_smtp_component_version(banner: str, ehlo_response: str) -> tuple[str, str | None]:
    """Infer mail-stack component/version from SMTP banner material."""
    combined = " ".join(part for part in (banner, ehlo_response) if str(part).strip())
    lowered = combined.lower()
    patterns = (
        ("postfix", r"postfix(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("exim", r"exim(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("opensmtpd", r"opensmtpd(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("sendmail", r"sendmail(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("exchange", r"(?:microsoft\s+exchange|exchange(?:\s+server)?)(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("haraka", r"haraka(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("qmail", r"qmail(?:[ /-]?)(\d[\w.\-+]*)?"),
        ("courier", r"courier(?:[ /-]?)(\d[\w.\-+]*)?"),
    )
    for component, pattern in patterns:
        match = re.search(pattern, lowered, flags=re.IGNORECASE)
        if match is None:
            continue
        version = _extract_version_token(match.group(1) or combined)
        return component, version
    return "smtp", _extract_version_token(combined)


def _infer_mysql_component(version_string: str) -> tuple[str, str | None]:
    """Infer the database family from MySQL handshake metadata."""
    lowered = str(version_string or "").strip().lower()
    if "mariadb" in lowered:
        component = "mariadb"
    elif "percona" in lowered:
        component = "percona-server"
    else:
        component = "mysql"
    return component, _extract_version_token(version_string)


def _infer_postgres_component_version(message_text: str) -> tuple[str, str | None]:
    """Infer PostgreSQL version when the server includes it in textual replies."""
    return "postgresql", _extract_version_token(message_text)


def _infer_ssh_component_version(banner: str) -> tuple[str, str | None]:
    """Infer SSH implementation/version from server identification banner."""
    lowered = str(banner or "").strip().lower()
    patterns = (
        ("openssh", r"openssh[_ /-]?([\w.\-+]+)?"),
        ("dropbear", r"dropbear[_ /-]?([\w.\-+]+)?"),
        ("libssh", r"libssh[_ /-]?([\w.\-+]+)?"),
        ("bitvise", r"bitvise[_ /-]?([\w.\-+]+)?"),
        ("tectia", r"tectia[_ /-]?([\w.\-+]+)?"),
    )
    for component, pattern in patterns:
        match = re.search(pattern, lowered, flags=re.IGNORECASE)
        if match is None:
            continue
        version = _extract_version_token(match.group(1) or lowered)
        return component, version
    return "ssh", _extract_version_token(lowered)


def _infer_redis_component_version(ping_response: str, info_response: str) -> tuple[str, str | None]:
    """Infer Redis family/version from INFO/bounded banner responses."""
    version = AgentRedisExposureCheckTool._parse_redis_info(info_response, "redis_version")
    combined = " ".join(part for part in (version, ping_response, info_response) if str(part).strip())
    return "redis", version or _extract_version_token(combined)


def _infer_memcached_component_version(version_response: str, stats_response: str) -> tuple[str, str | None]:
    """Infer memcached version from bounded version/stats responses."""
    version = ""
    if " " in str(version_response):
        version = str(version_response).split(" ", 1)[1].strip()
    combined = " ".join(part for part in (version_response, stats_response) if str(part).strip())
    return "memcached", version or _extract_version_token(combined)


def _infer_tls_component_version(metadata: dict[str, Any]) -> tuple[str, str | None]:
    """Emit protocol-level TLS component metadata when implementation is unknown."""
    tls_version = str(metadata.get("tls_version", "")).strip() or None
    return "tls", tls_version


@register_tool
class AgentNmapTool(BaseAgentTool):
    """Agent adapter for safe nmap discovery."""

    name = "nmap_scan"
    description = "Conservative service discovery with nmap."
    cost = 15
    priority = 15
    category = "recon"
    target_types = ["host_seed"]
    phase_affinity = ["passive_recon"]
    risk_level = "low"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.0}
    default_options = {
        "scan_profile": "conservative_service_discovery",
        "ports": "top-100",
        "version_detection": False,
        "timeout_seconds": 90,
    }
    input_schema = {
        "target_mode": "host",
        "properties": {
            "ports": {
                "type": "string",
                "pattern": r"(top-100|top-1000|[0-9,\-]+)",
                "error": "nmap_scan_ports_invalid_format",
            },
            "scan_profile": {
                "type": "string",
                "enum": ["default", "conservative_service_discovery"],
                "error": "nmap_scan_invalid_scan_profile",
            },
            "version_detection": {
                "type": "boolean",
                "error": "nmap_scan_version_detection_must_be_bool",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 600,
                "error": "nmap_scan_timeout_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "nmap_scan_options_invalid_keys",
    }

    def check_availability(self) -> tuple[bool, str | None]:
        """Check that `nmap` executable is present."""
        if shutil.which("nmap"):
            return True, None
        return False, "nmap executable is not available in PATH"

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        ports = str(options.get("ports", "top-1000")).strip().lower() or "top-1000"
        scan_profile = str(options.get("scan_profile", "default")).strip().lower() or "default"
        version_detection = bool(options.get("version_detection", True))
        timeout_default = 90.0 if scan_profile == "conservative_service_discovery" else NmapTool.DEFAULT_TIMEOUT_SECONDS
        timeout_seconds = float(options.get("timeout_seconds", timeout_default))

        tool = NmapTool(
            timeout_seconds=timeout_seconds,
            scan_profile=scan_profile,
            version_detection=version_detection,
        )
        result = tool.run(target=target, options={"ports": ports})

        findings: list[dict[str, Any]] = []
        breadcrumbs_delta: list[dict[str, str]] = []
        surface_delta: dict[str, Any] = {}
        nmap_services: list[dict[str, Any]] = []
        nmap_http_origins: list[str] = []
        nmap_https_origins: list[str] = []
        nmap_service_origins: list[str] = []
        graph_assets: list[Asset] = []
        status = "completed"

        if not result.ok:
            status = "failed"
            if result.error and "failed to execute nmap" in result.error.lower():
                status = "error"
        else:
            data = result.data if isinstance(result.data, dict) else {}
            hosts = data.get("hosts", [])
            surface_delta["nmap_hosts"] = hosts
            for host in hosts:
                host_token = self._resolve_host_token(host, fallback=target)
                for port_entry in host.get("open_ports", []):
                    port = int(port_entry.get("port", 0))
                    service = str(port_entry.get("service", "")).lower()
                    scheme: str | None = None
                    service_row: dict[str, Any] = {
                        "host": host_token,
                        "port": port,
                        "service": service,
                    }
                    if "https" in service or port in {443, 8443}:
                        scheme = "https"
                    elif "http" in service or port in {80, 8080, 8000, 8888}:
                        scheme = "http"
                    if scheme and host_token:
                        origin = f"{scheme}://{host_token}:{port}"
                        breadcrumbs_delta.append(
                            {"type": "service", "data": origin}
                        )
                        service_row["scheme"] = scheme
                        service_row["origin"] = origin
                        nmap_service_origins.append(origin)
                        if scheme == "https":
                            nmap_https_origins.append(origin)
                        else:
                            nmap_http_origins.append(origin)
                    nmap_services.append(service_row)
                    graph_assets.append(
                        _make_service_asset(
                            tool_name=self.name,
                            host=host_token,
                            port=port,
                            service=service,
                            tls=scheme == "https",
                            scheme=scheme or "",
                            evidence={"nmap": {"host": host_token, "port": port, "service": service}},
                        )
                    )
            surface_delta["nmap_services"] = self._dedupe_json_rows(nmap_services)
            surface_delta["nmap_http_origins"] = self._dedupe_strings(nmap_http_origins)
            surface_delta["nmap_https_origins"] = self._dedupe_strings(nmap_https_origins)
            surface_delta["nmap_service_origins"] = self._dedupe_strings(nmap_service_origins)

        payload = asdict(result)
        return ToolExecutionResult(
            ok=(status == "completed"),
            tool_name=self.name,
            target=target,
            data={
                "status": status,
                "payload": payload,
                "findings": findings,
                "breadcrumbs_delta": breadcrumbs_delta,
                "assets_delta": [asdict(item) for item in graph_assets],
                "surface_delta": surface_delta,
            },
            error=result.error,
            raw_output=result.raw_output,
            duration_ms=result.duration_ms,
        )

    @staticmethod
    def _resolve_host_token(host_entry: dict[str, Any], fallback: str) -> str:
        hostnames = host_entry.get("hostnames", [])
        if isinstance(hostnames, list) and hostnames:
            return str(hostnames[0]).strip()

        addresses = host_entry.get("addresses", [])
        if isinstance(addresses, list) and addresses:
            first = addresses[0]
            if isinstance(first, dict) and first.get("addr"):
                return str(first.get("addr")).strip()
        return fallback

    @staticmethod
    def _dedupe_strings(values: list[str]) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for item in values:
            normalized = str(item).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    @staticmethod
    def _dedupe_json_rows(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in values:
            marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped


@register_tool
class AgentServiceBannerProbeTool(BaseAgentTool):
    """Safely capture TCP service banners for non-HTTP ports discovered by nmap."""

    name = "service_banner_probe"
    description = "Safely capture TCP banners from nmap-discovered non-HTTP services."
    cost = 4
    priority = 15
    category = "recon"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "active_discovery"]
    depends_on = ["nmap_scan"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 4,
        "read_bytes": 512,
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535,
                "error": "service_banner_probe_port_out_of_bounds",
            },
            "service": {
                "type": "string",
                "allow_blank": True,
                "max_length": 64,
                "pattern": r"[A-Za-z0-9+_.\-]*",
                "error": "service_banner_probe_service_invalid",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 15,
                "error": "service_banner_probe_timeout_out_of_bounds",
            },
            "read_bytes": {
                "type": "integer",
                "minimum": 64,
                "maximum": 2048,
                "error": "service_banner_probe_read_bytes_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "service_banner_probe_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        service_hint = str(options.get("service", "")).strip().lower()
        try:
            port = int(options.get("port", 0) or 0)
        except (TypeError, ValueError):
            return self._error_result(target=host, started=started, message="invalid_port")
        if port < 1 or port > 65535:
            return self._error_result(target=host, started=started, message="invalid_port")

        timeout_seconds = max(1.0, min(15.0, float(options.get("timeout_seconds", 4) or 4)))
        read_bytes = max(64, min(2048, int(options.get("read_bytes", 512) or 512)))

        try:
            probe_result = self._probe_banner(
                host=host,
                port=port,
                service_hint=service_hint,
                timeout_seconds=timeout_seconds,
                read_bytes=read_bytes,
            )
        except TimeoutError:
            output = StandardToolOutput(
                status="failed",
                surface_updates={
                    "service_banners": [
                        {
                            "host": host,
                            "port": port,
                            "service": service_hint,
                            "banner": "",
                            "probe_command": "",
                            "status": "timeout",
                        }
                    ]
                },
                metadata={
                    "host": host,
                    "port": port,
                    "service": service_hint,
                    "timeout_seconds": timeout_seconds,
                },
            )
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=host,
                output=output,
                error="service_banner_probe_timeout",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except OSError as exc:
            output = StandardToolOutput(
                status="failed",
                surface_updates={
                    "service_banners": [
                        {
                            "host": host,
                            "port": port,
                            "service": service_hint,
                            "banner": "",
                            "probe_command": "",
                            "status": "connection_failed",
                        }
                    ]
                },
                metadata={
                    "host": host,
                    "port": port,
                    "service": service_hint,
                    "timeout_seconds": timeout_seconds,
                },
            )
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=host,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        banner_text = probe_result["banner"]
        detected_service = probe_result["detected_service"]
        findings: list[StandardFinding] = []
        if banner_text:
            banner_preview = banner_text[:240]
            finding_id = hashlib.sha256(f"{host}:{port}:{banner_preview}".encode("utf-8")).hexdigest()[:16]
            findings.append(
                StandardFinding(
                    id=finding_id,
                    tool=self.name,
                    severity="info",
                    category="inventory",
                    title=f"Observed service banner on {host}:{port}",
                    description=(
                        f"Captured banner data from the {detected_service or service_hint or 'tcp'} service "
                        f"listening on {host}:{port}."
                    ),
                    evidence={
                        "host": host,
                        "port": port,
                        "service": detected_service or service_hint,
                        "banner": banner_preview,
                    },
                    remediation="Review exposed services and restrict unnecessary network exposure.",
                )
            )

        output = StandardToolOutput(
            status="completed",
            findings=findings,
            graph_assets=[
                _make_service_asset(
                    tool_name=self.name,
                    host=host,
                    port=port,
                    service=detected_service or service_hint or "unknown",
                    banner=banner_text,
                    evidence={
                        "banner": banner_text[:240],
                        "probe_command": probe_result["probe_command"],
                    },
                )
            ],
            surface_updates={
                "service_banners": [
                    {
                        "host": host,
                        "port": port,
                        "service": detected_service or service_hint,
                        "banner": banner_text,
                        "probe_command": probe_result["probe_command"],
                        "status": "banner_captured" if banner_text else "no_banner",
                    }
                ]
            },
            metadata={
                "host": host,
                "port": port,
                "service": detected_service or service_hint,
                "timeout_seconds": timeout_seconds,
                "read_bytes": read_bytes,
                "probe_command": probe_result["probe_command"],
                "banner_length": len(banner_text),
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _probe_banner(
        self,
        *,
        host: str,
        port: int,
        service_hint: str,
        timeout_seconds: float,
        read_bytes: int,
    ) -> dict[str, str]:
        probe_command = self._safe_probe_command(service_hint=service_hint, port=port)
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            try:
                banner_bytes = self._recv_banner(sock, read_bytes)
            except TimeoutError:
                banner_bytes = b""
            if not banner_bytes and probe_command:
                sock.sendall(probe_command)
                banner_bytes = self._recv_banner(sock, read_bytes)
        banner = self._sanitize_banner(banner_bytes)
        return {
            "banner": banner,
            "detected_service": self._classify_banner(banner, service_hint),
            "probe_command": probe_command.decode("ascii", errors="ignore").strip(),
        }

    @staticmethod
    def _safe_probe_command(*, service_hint: str, port: int) -> bytes:
        normalized = str(service_hint).strip().lower()
        if normalized == "redis" or port == 6379:
            return b"PING\r\n"
        if normalized == "memcached" or port == 11211:
            return b"version\r\n"
        return b""

    @staticmethod
    def _recv_banner(sock: socket.socket, read_bytes: int) -> bytes:
        try:
            return sock.recv(read_bytes)
        except socket.timeout as exc:
            raise TimeoutError from exc

    @staticmethod
    def _sanitize_banner(payload: bytes) -> str:
        text = (payload or b"").decode("utf-8", errors="replace")
        text = re.sub(r"[^\x09\x0A\x0D\x20-\x7E]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:512]

    @staticmethod
    def _classify_banner(banner: str, service_hint: str) -> str:
        lowered = banner.lower()
        if lowered.startswith("ssh-"):
            return "ssh"
        if lowered.startswith("+pong"):
            return "redis"
        if "smtp" in lowered:
            return "smtp"
        if "ftp" in lowered:
            return "ftp"
        if "imap" in lowered:
            return "imap"
        if "pop3" in lowered:
            return "pop3"
        return service_hint

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentSSHAuthAuditTool(BaseAgentTool):
    """Low-risk SSH surface audit based on protocol identification banner."""

    name = "ssh_auth_audit"
    description = "Validate SSH authentication surface and collect the server banner."
    cost = 5
    priority = 16
    category = "validation"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan", "service_banner_probe"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 4,
        "read_bytes": 256,
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "ssh_auth_audit_port_invalid"},
            "service": {"type": "string", "allow_blank": True, "max_length": 32, "error": "ssh_auth_audit_service_invalid"},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 15, "error": "ssh_auth_audit_timeout_invalid"},
            "read_bytes": {"type": "integer", "minimum": 64, "maximum": 1024, "error": "ssh_auth_audit_read_bytes_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "ssh_auth_audit_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        port = int(options.get("port", 22) or 22)
        timeout_seconds = max(1.0, min(15.0, float(options.get("timeout_seconds", 4) or 4)))
        read_bytes = max(64, min(1024, int(options.get("read_bytes", 256) or 256)))

        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
                sock.settimeout(timeout_seconds)
                try:
                    banner_bytes = sock.recv(read_bytes)
                except socket.timeout:
                    banner_bytes = b""
                if not banner_bytes:
                    sock.sendall(b"SSH-2.0-AutoSecAudit\r\n")
                    try:
                        banner_bytes = sock.recv(read_bytes)
                    except socket.timeout:
                        banner_bytes = b""
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        banner = AgentServiceBannerProbeTool._sanitize_banner(banner_bytes)
        component, component_version = _infer_ssh_component_version(banner)
        tech_component_row = _make_tech_component_row(
            component=component,
            version=component_version,
            target=host,
            source_tool=self.name,
            service="ssh",
            host=host,
            port=port,
            evidence={"banner": banner[:240]},
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="ssh",
            banner=banner,
            auth_required=True,
            evidence={"banner": banner[:240]},
        )
        severity = "low" if self._looks_legacy_banner(banner) else "info"
        finding = StandardFinding(
            id=hashlib.sha256(f"ssh:{host}:{port}:{banner}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity=severity,
            category="auth_surface",
            title=f"SSH authentication surface exposed on {host}:{port}",
            description="The target exposes an SSH login surface and discloses a protocol banner.",
            evidence={"host": host, "port": port, "banner": banner},
            remediation="Restrict SSH exposure to trusted administrators and review access controls.",
            reproduction_steps=[
                f"Connect to {host}:{port} over TCP.",
                "Read the SSH identification string returned by the server.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "ssh_auth_surfaces": [
                    {
                        "host": host,
                        "port": port,
                        "banner": banner,
                        "auth_required": True,
                    }
                ],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=(
                ["rag_intel_lookup", "cve_lookup"]
                if component and (component != "ssh" or component_version)
                else ["rag_intel_lookup"] if component else []
            ),
            metadata={"host": host, "port": port, "banner": banner},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _looks_legacy_banner(banner: str) -> bool:
        match = re.search(r"openssh[_-](\d+)", banner.lower())
        if match is None:
            return False
        try:
            return int(match.group(1)) < 7
        except ValueError:
            return False

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentRedisExposureCheckTool(BaseAgentTool):
    """Read-only Redis exposure audit."""

    name = "redis_exposure_check"
    description = "Safely verify whether Redis responds without authentication."
    cost = 5
    priority = 17
    category = "validation"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan", "service_banner_probe"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 4,
        "read_bytes": 1024,
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "redis_exposure_check_port_invalid"},
            "service": {"type": "string", "allow_blank": True, "max_length": 32, "error": "redis_exposure_check_service_invalid"},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 15, "error": "redis_exposure_check_timeout_invalid"},
            "read_bytes": {"type": "integer", "minimum": 128, "maximum": 4096, "error": "redis_exposure_check_read_bytes_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "redis_exposure_check_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        port = int(options.get("port", 6379) or 6379)
        timeout_seconds = max(1.0, min(15.0, float(options.get("timeout_seconds", 4) or 4)))
        read_bytes = max(128, min(4096, int(options.get("read_bytes", 1024) or 1024)))

        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
                sock.settimeout(timeout_seconds)
                sock.sendall(b"PING\r\n")
                ping_response = AgentServiceBannerProbeTool._sanitize_banner(sock.recv(read_bytes))
                info_response = ""
                if ping_response.startswith("+PONG"):
                    sock.sendall(b"INFO server\r\n")
                    try:
                        info_response = AgentServiceBannerProbeTool._sanitize_banner(sock.recv(read_bytes))
                    except socket.timeout:
                        info_response = ""
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        unauthenticated = ping_response.startswith("+PONG")
        auth_required = "NOAUTH" in ping_response.upper()
        component, component_version = _infer_redis_component_version(ping_response, info_response)
        version = component_version or self._parse_redis_info(info_response, "redis_version")
        banner = ping_response if ping_response else info_response
        tech_component_row = _make_tech_component_row(
            component=component,
            version=version,
            target=host,
            source_tool=self.name,
            service="redis",
            host=host,
            port=port,
            evidence={"ping_response": ping_response, "info_response": info_response[:240]},
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="redis",
            banner=banner,
            auth_required=(False if unauthenticated else True if auth_required else None),
            evidence={"ping_response": ping_response, "info_response": info_response[:240]},
        )
        severity = "high" if unauthenticated else "info"
        title = (
            f"Unauthenticated Redis service exposed on {host}:{port}"
            if unauthenticated
            else f"Redis service requires authentication on {host}:{port}"
        )
        description = (
            "Redis accepted a read-only probe without authentication."
            if unauthenticated
            else "Redis responded but indicated that authentication is required."
        )
        finding = StandardFinding(
            id=hashlib.sha256(f"redis:{host}:{port}:{ping_response}:{info_response}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity=severity,
            category="service_exposure",
            title=title,
            description=description,
            evidence={
                "host": host,
                "port": port,
                "ping_response": ping_response,
                "redis_version": version,
            },
            remediation="Bind Redis to trusted interfaces and require authentication with network ACLs.",
            reproduction_steps=[
                f"Connect to {host}:{port} over TCP.",
                "Send `PING` and observe whether the server replies without authentication.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "redis_exposure_checks": [
                    {
                        "host": host,
                        "port": port,
                        "ping_response": ping_response,
                        "redis_version": version,
                        "auth_required": False if unauthenticated else True if auth_required else None,
                    }
                ],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=["rag_intel_lookup", "cve_lookup"] if component else [],
            metadata={"host": host, "port": port, "redis_version": version, "component": component},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _parse_redis_info(payload: str, key: str) -> str:
        match = re.search(rf"{re.escape(key)}:([^\s]+)", payload)
        return str(match.group(1)).strip() if match else ""

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentMemcachedExposureCheckTool(BaseAgentTool):
    """Read-only memcached exposure audit."""

    name = "memcached_exposure_check"
    description = "Safely verify whether memcached is reachable and responds to stats queries."
    cost = 5
    priority = 18
    category = "validation"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan", "service_banner_probe"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 4,
        "read_bytes": 1024,
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "memcached_exposure_check_port_invalid"},
            "service": {"type": "string", "allow_blank": True, "max_length": 32, "error": "memcached_exposure_check_service_invalid"},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 15, "error": "memcached_exposure_check_timeout_invalid"},
            "read_bytes": {"type": "integer", "minimum": 128, "maximum": 4096, "error": "memcached_exposure_check_read_bytes_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "memcached_exposure_check_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        port = int(options.get("port", 11211) or 11211)
        timeout_seconds = max(1.0, min(15.0, float(options.get("timeout_seconds", 4) or 4)))
        read_bytes = max(128, min(4096, int(options.get("read_bytes", 1024) or 1024)))

        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
                sock.settimeout(timeout_seconds)
                sock.sendall(b"version\r\n")
                version_response = AgentServiceBannerProbeTool._sanitize_banner(sock.recv(read_bytes))
                stats_response = ""
                if version_response.upper().startswith("VERSION"):
                    sock.sendall(b"stats\r\n")
                    try:
                        stats_response = AgentServiceBannerProbeTool._sanitize_banner(sock.recv(read_bytes))
                    except socket.timeout:
                        stats_response = ""
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        unauthenticated = version_response.upper().startswith("VERSION")
        component, component_version = _infer_memcached_component_version(version_response, stats_response)
        version = component_version or (version_response.split(" ", 1)[1].strip() if " " in version_response else "")
        tech_component_row = _make_tech_component_row(
            component=component,
            version=version,
            target=host,
            source_tool=self.name,
            service="memcached",
            host=host,
            port=port,
            evidence={"version_response": version_response, "stats_response": stats_response[:240]},
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="memcached",
            banner=version_response,
            auth_required=False if unauthenticated else None,
            evidence={"version_response": version_response, "stats_response": stats_response[:240]},
        )
        finding = StandardFinding(
            id=hashlib.sha256(f"memcached:{host}:{port}:{version_response}:{stats_response}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity="high" if unauthenticated else "info",
            category="service_exposure",
            title=(
                f"Unauthenticated memcached service exposed on {host}:{port}"
                if unauthenticated
                else f"Memcached probe inconclusive on {host}:{port}"
            ),
            description=(
                "Memcached responded to version/statistics probes without authentication."
                if unauthenticated
                else "Memcached did not provide a conclusive response to bounded probes."
            ),
            evidence={"host": host, "port": port, "version": version, "version_response": version_response},
            remediation="Restrict memcached to internal interfaces and remove unauthenticated public exposure.",
            reproduction_steps=[
                f"Connect to {host}:{port} over TCP.",
                "Send `version` and optionally `stats` to verify whether the service is openly reachable.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "memcached_exposure_checks": [
                    {
                        "host": host,
                        "port": port,
                        "version": version,
                        "unauthenticated": unauthenticated,
                    }
                ],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=["rag_intel_lookup", "cve_lookup"] if component else [],
            metadata={"host": host, "port": port, "version": version, "component": component},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentSmtpSecurityCheckTool(BaseAgentTool):
    """Collect bounded SMTP metadata and transport-security signals."""

    name = "smtp_security_check"
    description = "Collect SMTP banner, EHLO capabilities, and STARTTLS exposure safely."
    cost = 5
    priority = 19
    category = "validation"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan", "service_banner_probe"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 5,
        "read_bytes": 2048,
        "ehlo_domain": "autosecaudit.local",
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "smtp_security_check_port_invalid"},
            "service": {"type": "string", "allow_blank": True, "max_length": 32, "error": "smtp_security_check_service_invalid"},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 20, "error": "smtp_security_check_timeout_invalid"},
            "read_bytes": {"type": "integer", "minimum": 128, "maximum": 4096, "error": "smtp_security_check_read_bytes_invalid"},
            "ehlo_domain": {"type": "string", "min_length": 1, "max_length": 128, "error": "smtp_security_check_ehlo_domain_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "smtp_security_check_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        port = int(options.get("port", 25) or 25)
        timeout_seconds = max(1.0, min(20.0, float(options.get("timeout_seconds", 5) or 5)))
        read_bytes = max(128, min(4096, int(options.get("read_bytes", 2048) or 2048)))
        ehlo_domain = str(options.get("ehlo_domain", "autosecaudit.local")).strip() or "autosecaudit.local"
        service_hint = str(options.get("service", "smtp")).strip().lower() or "smtp"

        try:
            banner, ehlo_response, tls_mode = self._probe_smtp(
                host=host,
                port=port,
                timeout_seconds=timeout_seconds,
                read_bytes=read_bytes,
                ehlo_domain=ehlo_domain,
                implicit_tls=(port == 465 or service_hint == "smtps"),
            )
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))
        except ssl.SSLError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        starttls_supported = "STARTTLS" in ehlo_response.upper()
        auth_mechanisms = self._parse_smtp_auth_mechanisms(ehlo_response)
        component, component_version = _infer_smtp_component_version(banner, ehlo_response)
        tech_component_row = _make_tech_component_row(
            component=component,
            version=component_version,
            target=host,
            source_tool=self.name,
            service="smtp",
            host=host,
            port=port,
            evidence={
                "banner": banner[:240],
                "ehlo_response": ehlo_response[:240],
                "tls_mode": tls_mode,
            },
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="smtp",
            banner=banner or ehlo_response,
            tls=(tls_mode == "implicit_tls"),
            auth_required=True if auth_mechanisms else None,
            evidence={
                "banner": banner[:240],
                "ehlo_response": ehlo_response[:400],
                "tls_mode": tls_mode,
            },
        )
        severity = "low" if tls_mode == "plain" and not starttls_supported else "info"
        title = (
            f"SMTP service on {host}:{port} does not advertise STARTTLS"
            if severity == "low"
            else f"Observed SMTP service metadata on {host}:{port}"
        )
        description = (
            "The SMTP service responded to a bounded EHLO probe but did not advertise STARTTLS."
            if severity == "low"
            else "Collected SMTP banner and EHLO capabilities for the exposed mail service."
        )
        finding = StandardFinding(
            id=hashlib.sha256(f"smtp:{host}:{port}:{banner}:{ehlo_response}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity=severity,
            category="transport_security" if severity == "low" else "service_exposure",
            title=title,
            description=description,
            evidence={
                "host": host,
                "port": port,
                "banner": banner,
                "ehlo_response": ehlo_response[:600],
                "starttls_supported": starttls_supported,
                "auth_mechanisms": auth_mechanisms,
                "tls_mode": tls_mode,
            },
            remediation="Require STARTTLS or implicit TLS for exposed SMTP services and review advertised authentication mechanisms.",
            reproduction_steps=[
                f"Connect to {host}:{port} over TCP.",
                f"Read the SMTP banner and send `EHLO {ehlo_domain}`.",
                "Inspect advertised extensions such as STARTTLS and AUTH.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "smtp_security_checks": [
                    {
                        "host": host,
                        "port": port,
                        "banner": banner,
                        "ehlo_response": ehlo_response[:600],
                        "starttls_supported": starttls_supported,
                        "auth_mechanisms": auth_mechanisms,
                        "tls_mode": tls_mode,
                    }
                ],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=["rag_intel_lookup", "cve_lookup"] if component else [],
            metadata={
                "host": host,
                "port": port,
                "starttls_supported": starttls_supported,
                "auth_mechanisms": auth_mechanisms,
                "tls_mode": tls_mode,
                "component": component,
                "component_version": component_version,
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _probe_smtp(
        self,
        *,
        host: str,
        port: int,
        timeout_seconds: float,
        read_bytes: int,
        ehlo_domain: str,
        implicit_tls: bool,
    ) -> tuple[str, str, str]:
        with socket.create_connection((host, port), timeout=timeout_seconds) as raw_sock:
            raw_sock.settimeout(timeout_seconds)
            tls_mode = "implicit_tls" if implicit_tls else "plain"
            if implicit_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    tls_sock.settimeout(timeout_seconds)
                    return self._smtp_dialog(
                        sock=tls_sock,
                        read_bytes=read_bytes,
                        ehlo_domain=ehlo_domain,
                        tls_mode=tls_mode,
                    )
            return self._smtp_dialog(
                sock=raw_sock,
                read_bytes=read_bytes,
                ehlo_domain=ehlo_domain,
                tls_mode=tls_mode,
            )

    def _smtp_dialog(
        self,
        *,
        sock: socket.socket,
        read_bytes: int,
        ehlo_domain: str,
        tls_mode: str,
    ) -> tuple[str, str, str]:
        banner = self._read_available(sock, read_bytes)
        sock.sendall(f"EHLO {ehlo_domain}\r\n".encode("ascii", errors="ignore"))
        ehlo_response = self._read_available(sock, read_bytes)
        return banner, ehlo_response, tls_mode

    @staticmethod
    def _read_available(sock: socket.socket, read_bytes: int) -> str:
        chunks: list[str] = []
        for _ in range(4):
            try:
                payload = sock.recv(read_bytes)
            except socket.timeout:
                break
            if not payload:
                break
            chunks.append(AgentServiceBannerProbeTool._sanitize_banner(payload))
            if len(payload) < read_bytes:
                break
        return " ".join(item for item in chunks if item).strip()

    @staticmethod
    def _parse_smtp_auth_mechanisms(payload: str) -> list[str]:
        match = re.search(r"AUTH(?:=|\s+)([A-Z0-9\-\s]+)", payload.upper())
        if match is None:
            return []
        return [token for token in match.group(1).split() if token]

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentMysqlHandshakeProbeTool(BaseAgentTool):
    """Collect a bounded MySQL handshake banner and version string."""

    name = "mysql_handshake_probe"
    description = "Collect MySQL handshake metadata without attempting authentication."
    cost = 4
    priority = 20
    category = "validation"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan", "service_banner_probe"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 4,
        "read_bytes": 512,
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "mysql_handshake_probe_port_invalid"},
            "service": {"type": "string", "allow_blank": True, "max_length": 32, "error": "mysql_handshake_probe_service_invalid"},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 15, "error": "mysql_handshake_probe_timeout_invalid"},
            "read_bytes": {"type": "integer", "minimum": 64, "maximum": 2048, "error": "mysql_handshake_probe_read_bytes_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "mysql_handshake_probe_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        port = int(options.get("port", 3306) or 3306)
        timeout_seconds = max(1.0, min(15.0, float(options.get("timeout_seconds", 4) or 4)))
        read_bytes = max(64, min(2048, int(options.get("read_bytes", 512) or 512)))

        try:
            packet = self._probe_mysql_handshake(host=host, port=port, timeout_seconds=timeout_seconds, read_bytes=read_bytes)
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        protocol_version, version_string = self._parse_mysql_handshake(packet)
        component, component_version = _infer_mysql_component(version_string)
        tech_component_row = _make_tech_component_row(
            component=component,
            version=component_version or version_string or None,
            target=host,
            source_tool=self.name,
            service="mysql",
            host=host,
            port=port,
            evidence={
                "protocol_version": protocol_version,
                "version_string": version_string,
            },
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="mysql",
            banner=version_string,
            auth_required=True,
            evidence={
                "protocol_version": protocol_version,
                "version_string": version_string,
            },
        )
        finding = StandardFinding(
            id=hashlib.sha256(f"mysql:{host}:{port}:{protocol_version}:{version_string}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity="info",
            category="inventory",
            title=f"Observed MySQL handshake on {host}:{port}",
            description="The server exposed a MySQL-compatible handshake banner without completing authentication.",
            evidence={
                "host": host,
                "port": port,
                "protocol_version": protocol_version,
                "version": version_string,
            },
            remediation="Review MySQL exposure and restrict database listeners to trusted networks.",
            reproduction_steps=[
                f"Connect to {host}:{port} over TCP.",
                "Read the initial MySQL handshake packet returned by the server.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "mysql_handshakes": [
                    {
                        "host": host,
                        "port": port,
                        "protocol_version": protocol_version,
                        "version": version_string,
                    }
                ],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=["rag_intel_lookup", "cve_lookup"] if component else [],
            metadata={
                "host": host,
                "port": port,
                "protocol_version": protocol_version,
                "version": version_string,
                "component": component,
                "component_version": component_version,
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _probe_mysql_handshake(*, host: str, port: int, timeout_seconds: float, read_bytes: int) -> bytes:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            return sock.recv(read_bytes)

    @staticmethod
    def _parse_mysql_handshake(packet: bytes) -> tuple[int | None, str]:
        if len(packet) < 6:
            return None, ""
        protocol_version = int(packet[4])
        version_bytes = packet[5:].split(b"\x00", 1)[0]
        version_string = version_bytes.decode("utf-8", errors="replace").strip()
        return protocol_version, version_string[:128]

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentPostgresHandshakeProbeTool(BaseAgentTool):
    """Collect a bounded PostgreSQL startup/authentication response."""

    name = "postgres_handshake_probe"
    description = "Collect PostgreSQL startup metadata and TLS support without authenticating."
    cost = 4
    priority = 21
    category = "validation"
    target_types = ["service_port"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan", "service_banner_probe"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "port": "$port",
        "service": "$service",
        "timeout_seconds": 4,
    }
    input_schema = {
        "target_mode": "host",
        "required": ["port"],
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "postgres_handshake_probe_port_invalid"},
            "service": {"type": "string", "allow_blank": True, "max_length": 32, "error": "postgres_handshake_probe_service_invalid"},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 15, "error": "postgres_handshake_probe_timeout_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "postgres_handshake_probe_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host = str(target).strip()
        port = int(options.get("port", 5432) or 5432)
        timeout_seconds = max(1.0, min(15.0, float(options.get("timeout_seconds", 4) or 4)))

        try:
            ssl_supported = self._probe_postgres_ssl(host=host, port=port, timeout_seconds=timeout_seconds)
            startup = self._probe_postgres_startup(host=host, port=port, timeout_seconds=timeout_seconds)
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        auth_code = startup.get("auth_code")
        auth_required = auth_code not in {None, 0}
        component, component_version = _infer_postgres_component_version(str(startup.get("message_text", "")))
        tech_component_row = _make_tech_component_row(
            component=component,
            version=component_version,
            target=host,
            source_tool=self.name,
            service="postgresql",
            host=host,
            port=port,
            evidence={
                "ssl_supported": ssl_supported,
                "message_type": startup.get("message_type"),
                "auth_code": auth_code,
                "auth_name": startup.get("auth_name"),
            },
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="postgresql",
            auth_required=auth_required if auth_code is not None else None,
            tls=ssl_supported,
            evidence={
                "ssl_supported": ssl_supported,
                "message_type": startup.get("message_type"),
                "auth_code": auth_code,
            },
        )
        severity = "low" if not ssl_supported else "info"
        finding = StandardFinding(
            id=hashlib.sha256(f"postgres:{host}:{port}:{ssl_supported}:{auth_code}:{startup.get('message_type')}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity=severity,
            category="transport_security" if severity == "low" else "inventory",
            title=(
                f"PostgreSQL service on {host}:{port} does not acknowledge SSL negotiation"
                if severity == "low"
                else f"Observed PostgreSQL startup response on {host}:{port}"
            ),
            description=(
                "The PostgreSQL service responded to a startup probe but did not confirm SSL support."
                if severity == "low"
                else "Collected PostgreSQL startup/authentication metadata from the exposed service."
            ),
            evidence={
                "host": host,
                "port": port,
                "ssl_supported": ssl_supported,
                "message_type": startup.get("message_type"),
                "auth_code": auth_code,
                "auth_name": startup.get("auth_name"),
                "message_text": startup.get("message_text"),
            },
            remediation="Restrict PostgreSQL exposure and prefer TLS-enabled deployments for remotely reachable services.",
            reproduction_steps=[
                f"Connect to {host}:{port} over TCP.",
                "Send a PostgreSQL SSLRequest followed by a minimal StartupMessage.",
                "Record the server response type and advertised authentication mode.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "postgres_handshakes": [
                    {
                        "host": host,
                        "port": port,
                        "ssl_supported": ssl_supported,
                        "message_type": startup.get("message_type"),
                        "auth_code": auth_code,
                        "auth_name": startup.get("auth_name"),
                    }
                ],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=["rag_intel_lookup", "cve_lookup"] if component else [],
            metadata={
                "host": host,
                "port": port,
                "ssl_supported": ssl_supported,
                "message_type": startup.get("message_type"),
                "auth_code": auth_code,
                "auth_name": startup.get("auth_name"),
                "component": component,
                "component_version": component_version,
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _recv_exact(sock: socket.socket, length: int) -> bytes:
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _probe_postgres_ssl(self, *, host: str, port: int, timeout_seconds: float) -> bool:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            sock.sendall((8).to_bytes(4, "big") + (80877103).to_bytes(4, "big"))
            try:
                response = sock.recv(1)
            except socket.timeout:
                response = b""
        return response == b"S"

    def _probe_postgres_startup(self, *, host: str, port: int, timeout_seconds: float) -> dict[str, Any]:
        payload = (
            (196608).to_bytes(4, "big")
            + b"user\x00autosecaudit\x00"
            + b"database\x00postgres\x00"
            + b"application_name\x00autosecaudit\x00"
            + b"\x00"
        )
        packet = (len(payload) + 4).to_bytes(4, "big") + payload
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            sock.sendall(packet)
            header = self._recv_exact(sock, 5)
            if len(header) < 5:
                return {"message_type": "", "auth_code": None, "auth_name": None, "message_text": ""}
            message_type = chr(header[0])
            length = int.from_bytes(header[1:5], "big")
            body = self._recv_exact(sock, max(0, length - 4))
        auth_code = None
        auth_name = None
        message_text = AgentServiceBannerProbeTool._sanitize_banner(body)
        if message_type == "R" and len(body) >= 4:
            auth_code = int.from_bytes(body[:4], "big")
            auth_name = self._postgres_auth_name(auth_code)
        return {
            "message_type": message_type,
            "auth_code": auth_code,
            "auth_name": auth_name,
            "message_text": message_text[:240],
        }

    @staticmethod
    def _postgres_auth_name(code: int) -> str:
        mapping = {
            0: "ok",
            2: "kerberos_v5",
            3: "cleartext_password",
            5: "md5_password",
            7: "gss",
            10: "sasl",
            11: "sasl_continue",
            12: "sasl_final",
        }
        return mapping.get(int(code), f"code_{int(code)}")

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentDnsZoneAuditTool(BaseAgentTool):
    """Resolve authoritative DNS metadata and attempt bounded AXFR checks."""

    name = "dns_zone_audit"
    description = "Resolve NS/MX/TXT/SOA records and test whether AXFR is exposed."
    cost = 4
    priority = 10
    category = "recon"
    target_types = ["domain"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = []
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "timeout_seconds": 5,
        "max_nameservers": 3,
    }
    input_schema = {
        "target_mode": "domain",
        "properties": {
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 20, "error": "dns_zone_audit_timeout_invalid"},
            "max_nameservers": {"type": "integer", "minimum": 1, "maximum": 10, "error": "dns_zone_audit_max_nameservers_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "dns_zone_audit_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        domain = str(target).strip().lower().rstrip(".")
        timeout_seconds = max(1.0, min(20.0, float(options.get("timeout_seconds", 5) or 5)))
        max_nameservers = max(1, min(10, int(options.get("max_nameservers", 3) or 3)))
        if not domain:
            return self._error_result(target=target, started=started, message="invalid_target")

        records = self._resolve_dns_records(domain=domain, timeout_seconds=timeout_seconds)
        zone_transfer = self._attempt_zone_transfer(
            domain=domain,
            nameservers=records.get("NS", []),
            timeout_seconds=timeout_seconds,
            max_nameservers=max_nameservers,
        )
        asset = Asset(
            kind="domain",
            id=f"domain:{domain}",
            attributes={"domain": domain, "has_zone_transfer": bool(zone_transfer.get("success", False))},
            evidence={"dns_records": records, "zone_transfer": zone_transfer},
            source_tool=self.name,
        )
        severity = "high" if zone_transfer.get("success", False) else "info"
        title = (
            f"DNS zone transfer exposed for {domain}"
            if severity == "high"
            else f"Observed DNS authority metadata for {domain}"
        )
        description = (
            "An authoritative nameserver allowed a bounded AXFR request."
            if severity == "high"
            else "Collected authoritative DNS metadata and bounded AXFR probe results."
        )
        related_subdomains = zone_transfer.get("subdomains", []) if isinstance(zone_transfer.get("subdomains", []), list) else []
        finding = StandardFinding(
            id=hashlib.sha256(f"dns-zone:{domain}:{zone_transfer.get('success', False)}:{records}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity=severity,
            category="misconfig" if severity == "high" else "inventory",
            title=title,
            description=description,
            evidence={
                "domain": domain,
                "records": records,
                "zone_transfer": zone_transfer,
            },
            remediation="Restrict AXFR to trusted DNS management hosts and review externally visible DNS metadata.",
            reproduction_steps=[
                f"Query NS/MX/TXT/SOA records for {domain}.",
                "Attempt a bounded AXFR request against a limited set of authoritative nameservers.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "dns_records": {domain: records},
                "dns_zone_audit": [
                    {
                        "domain": domain,
                        "records": records,
                        "zone_transfer": zone_transfer,
                    }
                ],
                "discovered_subdomains": related_subdomains,
                "dns_follow_up_signals": [
                    *(
                        ["authoritative_records"]
                        if any(isinstance(value, list) and value for value in records.values())
                        else []
                    ),
                    *(["zone_transfer"] if bool(zone_transfer.get("success", False)) else []),
                    *(["discovered_subdomains"] if related_subdomains else []),
                ],
            },
            follow_up_hints=(
                ["subdomain_enum_passive", "reverse_dns_probe"]
                if related_subdomains or any(isinstance(value, list) and value for value in records.values())
                else []
            ),
            metadata={
                "domain": domain,
                "record_types": sorted(records),
                "zone_transfer_success": bool(zone_transfer.get("success", False)),
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=domain,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _resolve_dns_records(self, *, domain: str, timeout_seconds: float) -> dict[str, list[str]]:
        records: dict[str, list[str]] = {}
        modules = self._load_dnspython_modules()
        if modules is not None:
            resolver_mod, _query_mod, _zone_mod = modules
            resolver = resolver_mod.Resolver()
            resolver.lifetime = timeout_seconds
            resolver.timeout = timeout_seconds
            for record_type in ("NS", "MX", "TXT", "SOA"):
                try:
                    answers = resolver.resolve(domain, record_type)
                except Exception:  # noqa: BLE001
                    continue
                values = [str(answer).strip().rstrip(".") for answer in answers if str(answer).strip()]
                if values:
                    records[record_type] = values
        if "A" not in records or "AAAA" not in records:
            try:
                infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
            except OSError:
                infos = []
            ipv4 = sorted({entry[4][0] for entry in infos if entry and entry[0] == socket.AF_INET and entry[4]})
            ipv6 = sorted({entry[4][0] for entry in infos if entry and entry[0] == socket.AF_INET6 and entry[4]})
            if ipv4:
                records.setdefault("A", ipv4)
            if ipv6:
                records.setdefault("AAAA", ipv6)
        return records

    def _attempt_zone_transfer(
        self,
        *,
        domain: str,
        nameservers: list[str],
        timeout_seconds: float,
        max_nameservers: int,
    ) -> dict[str, Any]:
        modules = self._load_dnspython_modules()
        if modules is None or not nameservers:
            return {"attempted": False, "success": False, "server": None, "subdomains": []}
        _resolver_mod, query_mod, zone_mod = modules
        for raw_server in nameservers[:max_nameservers]:
            server = str(raw_server).strip().rstrip(".")
            if not server:
                continue
            try:
                zone_xfr = query_mod.xfr(server, domain, lifetime=timeout_seconds)
                zone = zone_mod.from_xfr(zone_xfr, relativize=False)
            except Exception:  # noqa: BLE001
                continue
            if zone is None:
                continue
            subdomains = sorted(
                {
                    str(name).strip().rstrip(".")
                    for name in zone.nodes.keys()
                    if str(name).strip()
                }
            )
            return {
                "attempted": True,
                "success": True,
                "server": server,
                "record_count": len(zone.nodes),
                "subdomains": subdomains[:200],
            }
        return {"attempted": True, "success": False, "server": None, "subdomains": []}

    @staticmethod
    def _load_dnspython_modules() -> tuple[Any, Any, Any] | None:
        try:
            if importlib.util.find_spec("dns.resolver") is None:
                return None
            resolver_mod = __import__("dns.resolver", fromlist=["Resolver"])
            query_mod = __import__("dns.query", fromlist=["xfr"])
            zone_mod = __import__("dns.zone", fromlist=["from_xfr"])
            return resolver_mod, query_mod, zone_mod
        except Exception:  # noqa: BLE001
            return None

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentReverseDnsProbeTool(BaseAgentTool):
    """Resolve PTR records for in-scope IPs or resolved host addresses."""

    name = "reverse_dns_probe"
    description = "Resolve reverse-DNS names for scoped IPs and discovered host addresses."
    cost = 2
    priority = 16
    category = "recon"
    target_types = ["scope_host"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "timeout_seconds": 4,
        "max_addresses": 6,
    }
    input_schema = {
        "target_mode": "host",
        "properties": {
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 15, "error": "reverse_dns_probe_timeout_invalid"},
            "max_addresses": {"type": "integer", "minimum": 1, "maximum": 20, "error": "reverse_dns_probe_max_addresses_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "reverse_dns_probe_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        host_or_ip = str(target).strip()
        max_addresses = max(1, min(20, int(options.get("max_addresses", 6) or 6)))
        if not host_or_ip:
            return self._error_result(target=target, started=started, message="invalid_target")

        addresses = self._resolve_addresses(host_or_ip)[:max_addresses]
        reverse_rows: list[dict[str, Any]] = []
        assets: list[Asset] = []
        findings: list[StandardFinding] = []
        for address in addresses:
            ptr_names = self._reverse_lookup(address)
            asset = Asset(
                kind="ip",
                id=f"ip:{address}",
                attributes={"address": address, "ptr_names": ptr_names},
                evidence={"target": host_or_ip, "ptr_names": ptr_names},
                source_tool=self.name,
            )
            assets.append(asset)
            reverse_rows.append({"address": address, "ptr_names": ptr_names})
            if ptr_names:
                findings.append(
                    StandardFinding(
                        id=hashlib.sha256(f"ptr:{host_or_ip}:{address}:{ptr_names}".encode("utf-8")).hexdigest()[:16],
                        tool=self.name,
                        severity="info",
                        category="inventory",
                        title=f"Reverse DNS names resolved for {address}",
                        description="PTR records disclosed reverse-DNS hostnames for an in-scope address.",
                        evidence={"address": address, "ptr_names": ptr_names, "target": host_or_ip},
                        remediation="Review whether PTR hostnames expose internal naming conventions or sensitive labels.",
                        reproduction_steps=[
                            f"Resolve IP addresses for {host_or_ip} if needed.",
                            f"Run a PTR lookup for {address}.",
                        ],
                        related_asset_ids=[asset.id],
                    )
                )

        output = StandardToolOutput(
            status="completed",
            findings=findings,
            graph_assets=assets,
            surface_updates={"reverse_dns_records": reverse_rows},
            metadata={"target": host_or_ip, "address_count": len(addresses)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=host_or_ip,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _resolve_addresses(host_or_ip: str) -> list[str]:
        try:
            ipaddress.ip_address(host_or_ip)
        except ValueError:
            pass
        else:
            return [host_or_ip]
        try:
            infos = socket.getaddrinfo(host_or_ip, None, type=socket.SOCK_STREAM)
        except OSError:
            return []
        return sorted({entry[4][0] for entry in infos if entry and entry[4]})

    @staticmethod
    def _reverse_lookup(address: str) -> list[str]:
        try:
            primary, aliases, _addresses = socket.gethostbyaddr(address)
        except OSError:
            return []
        output = [str(primary).strip().rstrip(".")] + [str(item).strip().rstrip(".") for item in aliases if str(item).strip()]
        seen: set[str] = set()
        deduped: list[str] = []
        for item in output:
            lowered = item.lower()
            if not lowered or lowered in seen:
                continue
            seen.add(lowered)
            deduped.append(item)
        return deduped

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentTLSServiceProbeTool(BaseAgentTool):
    """Collect bounded TLS handshake metadata for HTTPS services."""

    name = "tls_service_probe"
    description = "Collect TLS version, cipher, and certificate metadata from HTTPS services."
    cost = 4
    priority = 12
    category = "recon"
    target_types = ["https_origin"]
    phase_affinity = ["passive_recon", "verification"]
    depends_on = ["nmap_scan"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "timeout_seconds": 5,
        "server_name": "$target_host",
    }
    input_schema = {
        "target_mode": "https_origin_or_host",
        "properties": {
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 20, "error": "tls_service_probe_timeout_invalid"},
            "server_name": {"type": "string", "allow_blank": True, "max_length": 255, "error": "tls_service_probe_server_name_invalid"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "error": "tls_service_probe_port_invalid"},
        },
        "additional_properties": False,
        "additional_properties_error": "tls_service_probe_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = str(parsed.hostname or target).strip().lower()
        if not host:
            return self._error_result(target=target, started=started, message="invalid_target")
        port = int(options.get("port", parsed.port or 443) or 443)
        timeout_seconds = max(1.0, min(20.0, float(options.get("timeout_seconds", 5) or 5)))
        server_name = str(options.get("server_name", parsed.hostname or host)).strip() or host

        try:
            metadata = self._probe_tls_metadata(
                host=host,
                port=port,
                server_name=server_name,
                timeout_seconds=timeout_seconds,
            )
        except OSError as exc:
            return self._error_result(target=host, started=started, message=str(exc))
        except ssl.SSLError as exc:
            return self._error_result(target=host, started=started, message=str(exc))

        component, component_version = _infer_tls_component_version(metadata)
        tech_target = self._canonical_tls_target(parsed=parsed, host=host, port=port)
        tech_component_row = _make_tech_component_row(
            component=component,
            version=component_version,
            target=tech_target,
            source_tool=self.name,
            service="tls",
            host=host,
            port=port,
            evidence={
                "tls_version": metadata.get("tls_version"),
                "cipher": metadata.get("cipher"),
                "server_name": metadata.get("server_name"),
            },
        )
        asset = _make_service_asset(
            tool_name=self.name,
            host=host,
            port=port,
            service="tls",
            tls=True,
            scheme="https",
            evidence={"tls_version": metadata.get("tls_version"), "cipher": metadata.get("cipher")},
        )
        severity = "medium" if metadata.get("tls_version") in {"TLSv1", "TLSv1.1"} else "info"
        finding = StandardFinding(
            id=hashlib.sha256(f"tls:{host}:{port}:{metadata.get('tls_version')}:{metadata.get('fingerprint_sha256')}".encode("utf-8")).hexdigest()[:16],
            tool=self.name,
            severity=severity,
            category="transport_security",
            title=f"Observed TLS service metadata on {host}:{port}",
            description="Collected TLS handshake metadata for the HTTPS service.",
            evidence=metadata,
            remediation="Review TLS version and certificate lifecycle to keep transport security current.",
            reproduction_steps=[
                f"Open a TLS connection to {host}:{port}.",
                "Record the negotiated protocol version, cipher, and presented certificate metadata.",
            ],
            related_asset_ids=[asset.id],
        )
        output = StandardToolOutput(
            status="completed",
            findings=[finding],
            graph_assets=[asset],
            surface_updates={
                "tls_service_metadata": [metadata],
                "tech_components": _dedupe_json_rows([tech_component_row] if tech_component_row else []),
                "tech_component_names": [component] if component else [],
            },
            follow_up_hints=["rag_intel_lookup"] if component else [],
            metadata=metadata,
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _probe_tls_metadata(
        self,
        *,
        host: str,
        port: int,
        server_name: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout_seconds) as raw_sock:
            raw_sock.settimeout(timeout_seconds)
            with context.wrap_socket(raw_sock, server_hostname=server_name) as tls_sock:
                cipher = tls_sock.cipher()
                der_cert = tls_sock.getpeercert(binary_form=True)
                cert_details = self._decode_certificate(der_cert)
                not_after = str(cert_details.get("notAfter", "")).strip()
                expires_at = ""
                days_remaining: int | None = None
                if not_after:
                    try:
                        expires_epoch = ssl.cert_time_to_seconds(not_after)
                        expires_at = datetime.fromtimestamp(expires_epoch, tz=timezone.utc).isoformat()
                        days_remaining = int((expires_epoch - time.time()) // 86400)
                    except (ValueError, OSError):
                        expires_at = not_after
                san = cert_details.get("subjectAltName", [])
                san_values = [
                    str(value).strip()
                    for item in san
                    if isinstance(item, tuple) and len(item) == 2
                    for value in [item[1]]
                    if str(value).strip()
                ]
                return {
                    "host": host,
                    "port": port,
                    "server_name": server_name,
                    "tls_version": str(tls_sock.version() or "").strip(),
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": int(cipher[2]) if cipher and len(cipher) > 2 else 0,
                    "subject": cert_details.get("subject", []),
                    "issuer": cert_details.get("issuer", []),
                    "subject_alt_names": san_values,
                    "not_after": expires_at,
                    "days_remaining": days_remaining,
                    "fingerprint_sha256": hashlib.sha256(der_cert or b"").hexdigest() if der_cert else "",
                }

    @staticmethod
    def _decode_certificate(der_cert: bytes) -> dict[str, Any]:
        if not der_cert:
            return {}
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".pem", delete=False) as handle:
            handle.write(pem_cert)
            temp_path = handle.name
        try:
            return ssl._ssl._test_decode_cert(temp_path)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return {}
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    @staticmethod
    def _canonical_tls_target(*, parsed: ParseResult, host: str, port: int) -> str:
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            normalized_port = parsed.port or port
            if parsed.scheme == "https" and normalized_port == 443:
                return f"https://{host}"
            return f"{parsed.scheme}://{host}:{normalized_port}"
        if port == 443:
            return f"https://{host}"
        return f"https://{host}:{port}"

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentCrawlerTool(BaseAgentTool):
    """Agent adapter for dynamic crawler."""

    name = "dynamic_crawl"
    description = "Playwright-based in-scope dynamic crawling."
    cost = 12
    priority = 20
    category = "discovery"
    target_types = ["origin_url"]
    phase_affinity = ["active_discovery"]
    depends_on = ["tech_stack_fingerprint"]
    risk_level = "low"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.0}
    default_options = {"max_depth": 2, "allow_domain": ["$target_host"]}
    input_schema = {
        "target_mode": "origin_http",
        "required": ["max_depth", "allow_domain"],
        "properties": {
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5,
                "error": "dynamic_crawl_max_depth_out_of_bounds",
            },
            "allow_domain": {
                "type": "array",
                "min_items": 1,
                "items": {
                    "type": "string",
                    "format": "scope_domain",
                    "error": "dynamic_crawl_allow_domain_out_of_scope",
                },
                "error": "dynamic_crawl_allow_domain_required",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "dynamic_crawl_options_invalid_keys",
    }

    def check_availability(self) -> tuple[bool, str | None]:
        """Check Playwright package and Chromium runtime before scheduling."""
        return _check_playwright_runtime_availability()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        max_depth = int(options.get("max_depth", 2))
        allow_domain = [str(item).strip() for item in options.get("allow_domain", []) if str(item).strip()]

        try:
            crawler = DynamicWebCrawler(allowed_domains=allow_domain)
            result = crawler.crawl(start_url=target, max_depth=max_depth)
            payload = {
                "start_url": result.start_url,
                "max_depth": result.max_depth,
                "visited_pages": result.visited_pages,
                "discovered_urls": result.discovered_urls,
                "api_endpoints": [asdict(item) for item in result.api_endpoints],
                "url_parameters": result.url_parameters,
                "parameter_origins": result.parameter_origins,
                "tech_stack": result.tech_stack,
                "errors": result.errors,
            }
            return ToolExecutionResult(
                ok=True,
                tool_name=self.name,
                target=target,
                data={
                    "status": "completed",
                    "payload": payload,
                    "findings": [],
                    "breadcrumbs_delta": [
                        {"type": "endpoint", "data": url} for url in result.discovered_urls
                    ],
                    "surface_delta": {
                        "discovered_urls": result.discovered_urls,
                        "api_endpoints": [asdict(item) for item in result.api_endpoints],
                        "url_parameters": result.url_parameters,
                        "parameter_origins": result.parameter_origins,
                        "tech_stack": result.tech_stack,
                    },
                },
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
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
                duration_ms=int((time.perf_counter() - started) * 1000),
            )


@register_tool
class AgentActiveWebCrawlerTool(BaseAgentTool):
    """Bounded interactive crawler with explicit page-limit control."""

    name = "active_web_crawler"
    description = "Bounded active crawling with limit-aware DynamicWebCrawler settings."
    cost = 12
    priority = 21
    category = "discovery"
    target_types = ["origin_url"]
    phase_affinity = ["active_discovery"]
    depends_on = ["dynamic_crawl"]
    risk_level = "low"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.0}
    default_options = {"max_depth": 2, "limit": 50, "allow_domain": ["$target_host"]}
    input_schema = {
        "target_mode": "origin_http",
        "required": ["max_depth", "allow_domain", "limit"],
        "properties": {
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5,
                "error": "active_web_crawler_max_depth_out_of_bounds",
            },
            "allow_domain": {
                "type": "array",
                "min_items": 1,
                "items": {
                    "type": "string",
                    "format": "scope_domain",
                    "error": "active_web_crawler_allow_domain_out_of_scope",
                },
                "error": "active_web_crawler_allow_domain_required",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
                "error": "active_web_crawler_limit_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "active_web_crawler_options_invalid_keys",
    }

    def check_availability(self) -> tuple[bool, str | None]:
        return AgentCrawlerTool().check_availability()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        max_depth = int(options.get("max_depth", 2))
        limit = max(1, min(int(options.get("limit", 50) or 50), 200))
        allow_domain = [str(item).strip() for item in options.get("allow_domain", []) if str(item).strip()]

        try:
            crawler = DynamicWebCrawler(allowed_domains=allow_domain, max_pages=limit)
            result = crawler.crawl(start_url=target, max_depth=max_depth)
            payload = {
                "start_url": result.start_url,
                "max_depth": result.max_depth,
                "page_limit": limit,
                "visited_pages": result.visited_pages,
                "discovered_urls": result.discovered_urls,
                "api_endpoints": [asdict(item) for item in result.api_endpoints],
                "url_parameters": result.url_parameters,
                "parameter_origins": result.parameter_origins,
                "tech_stack": result.tech_stack,
                "errors": result.errors,
            }
            return ToolExecutionResult(
                ok=True,
                tool_name=self.name,
                target=target,
                data={
                    "status": "completed",
                    "payload": payload,
                    "findings": [],
                    "breadcrumbs_delta": [{"type": "endpoint", "data": url} for url in result.discovered_urls[:50]],
                    "surface_delta": {
                        "discovered_urls": result.discovered_urls,
                        "api_endpoints": [asdict(item) for item in result.api_endpoints],
                        "url_parameters": result.url_parameters,
                        "parameter_origins": result.parameter_origins,
                        "tech_stack": result.tech_stack,
                    },
                },
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={
                    "status": "error",
                    "payload": {"error": str(exc), "page_limit": limit},
                    "findings": [],
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )


@register_tool
class AgentRagIntelLookupTool(BaseAgentTool):
    """Retrieve security-testing intelligence from local RAG corpus."""

    name = "rag_intel_lookup"
    description = "Retrieve attack and validation hints from local security knowledge corpus."
    cost = 3
    priority = 28
    category = "validation"
    target_types = ["tech_component"]
    phase_affinity = ["deep_testing", "verification"]
    depends_on = ["tech_stack_fingerprint"]
    risk_level = "safe"
    default_options = {
        "component": "$component",
        "version": "$version",
        "query": "$component $version security weaknesses",
        "max_results": 6,
    }
    input_schema = {
        "target_mode": "https_origin_or_host",
        "properties": {
            "component": {
                "type": "string",
                "min_length": 1,
                "max_length": 80,
                "error": "rag_intel_lookup_component_invalid",
            },
            "version": {
                "type": "string",
                "max_length": 80,
                "error": "rag_intel_lookup_version_invalid",
            },
            "query": {
                "type": "string",
                "max_length": 300,
                "error": "rag_intel_lookup_query_invalid",
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "error": "rag_intel_lookup_max_results_out_of_bounds",
            },
            "tech_stack": {
                "type": "array",
                "max_items": 40,
                "items": {"type": "string"},
                "error": "rag_intel_lookup_tech_stack_invalid",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "rag_intel_lookup_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        component = str(options.get("component", "")).strip().lower()
        version = str(options.get("version", "")).strip() or None
        query = str(options.get("query", "")).strip()
        max_results = max(1, min(int(options.get("max_results", 6) or 6), 20))
        tech_stack = [
            str(item).strip().lower()
            for item in options.get("tech_stack", [])
            if str(item).strip()
        ] if isinstance(options.get("tech_stack", []), list) else []

        if not query:
            query = " ".join(part for part in (component, version or "") if part).strip()
        if not query:
            query = str(urlparse(target if "://" in target else f"https://{target}").hostname or "").strip()

        service = RagIntelService()
        hits = service.search(
            query=query,
            component=component or None,
            version=version,
            tech_stack=tech_stack,
            max_results=max_results,
        )

        recommended_tools: list[str] = []
        seen_tools: set[str] = set()
        for item in hits:
            raw_tools = item.get("recommended_tools", [])
            if not isinstance(raw_tools, list):
                continue
            for tool_name in raw_tools:
                normalized = str(tool_name).strip()
                if not normalized or normalized in seen_tools or normalized == self.name:
                    continue
                seen_tools.add(normalized)
                recommended_tools.append(normalized)

        recommendation_contexts = [
            {
                "tool": tool_name,
                "target": target,
                "component": component or None,
                "version": version,
            }
            for tool_name in recommended_tools
        ]

        findings: list[StandardFinding] = []
        for item in hits[:3]:
            doc_id = str(item.get("doc_id", "")).strip() or "unknown"
            title = str(item.get("title", "")).strip() or "RAG intel"
            severity_hint = str(item.get("severity_hint", "info")).strip().lower() or "info"
            findings.append(
                StandardFinding(
                    id=f"{self.name}:{doc_id}",
                    tool=self.name,
                    severity=severity_hint if severity_hint in {"info", "low", "medium", "high", "critical"} else "info",
                    category="info_leak",
                    title=f"RAG Intel: {title}",
                    description=str(item.get("snippet", "")).strip() or str(item.get("summary", "")).strip(),
                    evidence={
                        "target": target,
                        "doc_id": doc_id,
                        "source": item.get("source"),
                        "references": item.get("references", []),
                    },
                    remediation="Prioritize follow-up checks from recommended_tools and confirm exploitability safely.",
                )
            )

        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={
                "rag_intel_hits": hits,
                "rag_recommended_tools": recommended_tools,
                "rag_recommendation_contexts": recommendation_contexts,
                "rag_last_query": query,
            },
            follow_up_hints=recommended_tools[:8],
            metadata={
                "component": component or None,
                "version": version,
                "query": query,
                "result_count": len(hits),
                "corpus_path": str(service.corpus_path),
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentPageVisionAnalyzerTool(BaseAgentTool):
    """Capture rendered page screenshot and derive UI-level risk signals."""

    name = "page_vision_analyzer"
    description = "Capture rendered page screenshot and analyze UI cues for security testing guidance."
    cost = 7
    priority = 19
    category = "discovery"
    target_types = ["origin_url"]
    phase_affinity = ["active_discovery", "verification"]
    depends_on = ["dynamic_crawl"]
    risk_level = "low"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.0}
    default_options = {
        "timeout_seconds": 20,
        "wait_until": "networkidle",
        "full_page": True,
        "enable_vision_llm": True,
        "max_vision_image_bytes": 2000000,
        "analysis_prompt": (
            "Identify login panels, admin/debug interfaces, sensitive operational clues, "
            "and suggest safe follow-up security checks."
        ),
    }
    input_schema = {
        "target_mode": "origin_http",
        "required": ["timeout_seconds", "wait_until", "full_page"],
        "properties": {
            "timeout_seconds": {
                "type": "number",
                "minimum": 3,
                "maximum": 120,
                "error": "page_vision_analyzer_timeout_out_of_bounds",
            },
            "wait_until": {
                "type": "string",
                "enum": ["domcontentloaded", "load", "networkidle"],
                "error": "page_vision_analyzer_wait_until_invalid",
            },
            "full_page": {
                "type": "boolean",
                "error": "page_vision_analyzer_full_page_must_be_bool",
            },
            "enable_vision_llm": {
                "type": "boolean",
                "error": "page_vision_analyzer_enable_vision_llm_must_be_bool",
            },
            "max_vision_image_bytes": {
                "type": "integer",
                "minimum": 100000,
                "maximum": 5000000,
                "error": "page_vision_analyzer_max_vision_image_bytes_out_of_bounds",
            },
            "analysis_prompt": {
                "type": "string",
                "max_length": 1200,
                "error": "page_vision_analyzer_analysis_prompt_invalid",
            },
            "vision_base_url": {
                "type": "string",
                "max_length": 300,
                "error": "page_vision_analyzer_vision_base_url_invalid",
            },
            "vision_model": {
                "type": "string",
                "max_length": 150,
                "error": "page_vision_analyzer_vision_model_invalid",
            },
            "vision_api_key": {
                "type": "string",
                "max_length": 400,
                "error": "page_vision_analyzer_vision_api_key_invalid",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "page_vision_analyzer_options_invalid_keys",
    }

    def check_availability(self) -> tuple[bool, str | None]:
        return _check_playwright_runtime_availability()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        timeout_seconds = float(options.get("timeout_seconds", 20) or 20)
        wait_until = str(options.get("wait_until", "networkidle")).strip().lower() or "networkidle"
        full_page = self._as_bool(options.get("full_page"), default=True)
        enable_vision_llm = self._as_bool(options.get("enable_vision_llm"), default=True)
        max_vision_image_bytes = max(
            100000,
            min(int(options.get("max_vision_image_bytes", 2000000) or 2000000), 5000000),
        )
        analysis_prompt = str(options.get("analysis_prompt", self.default_options["analysis_prompt"])).strip()

        snapshot = self._capture_snapshot(
            target=target,
            timeout_seconds=timeout_seconds,
            wait_until=wait_until,
            full_page=full_page,
        )
        if snapshot.get("error"):
            output = StandardToolOutput(
                status="error",
                metadata={"error": str(snapshot.get("error"))},
            )
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(snapshot.get("error")),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        screenshot_bytes = snapshot.get("screenshot_bytes", b"")
        llm_text = ""
        llm_meta: dict[str, Any] = {}
        if enable_vision_llm and isinstance(screenshot_bytes, (bytes, bytearray)):
            llm_text, llm_meta = self._analyze_with_vision_llm(
                screenshot_bytes=bytes(screenshot_bytes),
                prompt=analysis_prompt,
                timeout_seconds=timeout_seconds,
                max_vision_image_bytes=max_vision_image_bytes,
                options=options,
            )

        heuristic_text = self._heuristic_observation(snapshot)
        analysis_text = llm_text.strip() or heuristic_text
        analysis_source = "vision_llm" if llm_text.strip() else "heuristic"
        signals = self._derive_signals(
            title=str(snapshot.get("title", "")),
            dom_text=str(snapshot.get("dom_text", "")),
            analysis_text=analysis_text,
        )
        follow_up_hints = self._follow_up_hints_from_signals(signals)

        findings: list[StandardFinding] = []
        if analysis_text:
            findings.append(
                StandardFinding(
                    id=f"{self.name}:analysis",
                    tool=self.name,
                    severity="info",
                    category="info_leak",
                    title="Rendered UI Visual Analysis",
                    description=analysis_text[:1200],
                    evidence={
                        "target": snapshot.get("final_url") or target,
                        "title": snapshot.get("title"),
                        "analysis_source": analysis_source,
                    },
                    remediation="Review suggested follow-ups and validate findings with dedicated tools.",
                )
            )
        for signal in signals:
            severity = "low" if signal in {"admin_surface", "debug_surface"} else "info"
            findings.append(
                StandardFinding(
                    id=f"{self.name}:signal:{signal}",
                    tool=self.name,
                    severity=severity,
                    category="misconfig",
                    title=f"UI signal detected: {signal}",
                    description=f"The rendered page contains visual/UI indicators for `{signal}`.",
                    evidence={
                        "target": snapshot.get("final_url") or target,
                        "signal": signal,
                    },
                    remediation="Run focused follow-up checks for the signaled UI surface.",
                )
            )

        snapshot_row = {
            "url": snapshot.get("final_url") or target,
            "title": snapshot.get("title", ""),
            "screenshot_sha256": snapshot.get("screenshot_sha256"),
            "screenshot_bytes": snapshot.get("screenshot_size", 0),
            "analysis_source": analysis_source,
            "analysis": analysis_text[:1200],
            "signals": signals,
        }
        if llm_meta:
            snapshot_row["llm_meta"] = llm_meta

        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={
                "vision_snapshots": [snapshot_row],
                "vision_signals": signals,
            },
            follow_up_hints=follow_up_hints,
            metadata={
                "analysis_source": analysis_source,
                "signals": signals,
                "final_url": snapshot.get("final_url") or target,
                "title": snapshot.get("title", ""),
                "screenshot_sha256": snapshot.get("screenshot_sha256"),
                "screenshot_bytes": snapshot.get("screenshot_size", 0),
                "llm_meta": llm_meta,
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _capture_snapshot(
        self,
        *,
        target: str,
        timeout_seconds: float,
        wait_until: str,
        full_page: bool,
    ) -> dict[str, Any]:
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}

        navigation_timeout_ms = int(max(3.0, float(timeout_seconds)) * 1000)
        normalized_target = target if "://" in target else f"https://{target}"
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                context.set_default_navigation_timeout(navigation_timeout_ms)
                page = context.new_page()
                page.goto(normalized_target, wait_until=wait_until, timeout=navigation_timeout_ms)
                title = page.title()
                final_url = page.url
                dom_text = page.evaluate(
                    """() => {
                        const text = (document.body && document.body.innerText) || "";
                        return String(text).replace(/\\s+/g, " ").trim().slice(0, 5000);
                    }"""
                )
                screenshot_bytes = page.screenshot(type="png", full_page=bool(full_page))
                context.close()
                browser.close()
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}

        return {
            "final_url": str(final_url),
            "title": str(title),
            "dom_text": str(dom_text),
            "screenshot_bytes": screenshot_bytes,
            "screenshot_size": len(screenshot_bytes),
            "screenshot_sha256": hashlib.sha256(screenshot_bytes).hexdigest(),
        }

    def _analyze_with_vision_llm(
        self,
        *,
        screenshot_bytes: bytes,
        prompt: str,
        timeout_seconds: float,
        max_vision_image_bytes: int,
        options: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        if len(screenshot_bytes) > max_vision_image_bytes:
            return "", {"skipped": "image_too_large"}
        base_url = str(
            options.get("vision_base_url")
            or os.getenv("AUTOSECAUDIT_VISION_BASE_URL", "")
        ).strip()
        model = str(
            options.get("vision_model")
            or os.getenv("AUTOSECAUDIT_VISION_MODEL", "")
        ).strip()
        api_key = str(
            options.get("vision_api_key")
            or os.getenv("AUTOSECAUDIT_VISION_API_KEY", "")
        ).strip()
        if not base_url or not model or not api_key:
            return "", {"skipped": "vision_provider_not_configured"}

        image_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
        payload = {
            "model": model,
            "temperature": 0.1,
            "max_tokens": 600,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}},
                    ],
                }
            ],
        }
        endpoint = f"{base_url.rstrip('/')}/chat/completions"
        request = Request(
            endpoint,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        try:
            with urlopen(request, timeout=max(3.0, float(timeout_seconds) + 10.0)) as response:
                raw = response.read() or b"{}"
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            if not isinstance(parsed, dict):
                return "", {"error": "vision_response_invalid_json"}
            text, extract_meta = extract_text_from_openai_compatible_response(parsed)
            if not text.strip():
                return "", {"error": "vision_empty_response", "extract_meta": extract_meta}
            return text.strip(), {
                "provider_type": "openai_compatible",
                "model": model,
                "extract_meta": extract_meta,
            }
        except Exception as exc:  # noqa: BLE001
            return "", {"error": f"vision_request_failed:{exc}"}

    def _heuristic_observation(self, snapshot: dict[str, Any]) -> str:
        title = str(snapshot.get("title", "")).strip()
        dom_text = str(snapshot.get("dom_text", "")).strip().lower()
        hints: list[str] = []
        if any(token in dom_text for token in ("login", "sign in", "password", "username")):
            hints.append("Detected login-oriented UI cues in rendered content.")
        if any(token in dom_text for token in ("admin", "dashboard", "control panel")):
            hints.append("Detected admin/dashboard-oriented UI cues.")
        if any(token in dom_text for token in ("traceback", "exception", "stack trace", "debug")):
            hints.append("Detected potential debug/error disclosure cues.")
        base = f"Rendered page title: {title}." if title else "Rendered page captured."
        if hints:
            return f"{base} {' '.join(hints)}"
        return base

    def _derive_signals(self, *, title: str, dom_text: str, analysis_text: str) -> list[str]:
        haystack = "\n".join([title, dom_text, analysis_text]).lower()
        signals: list[str] = []
        if any(token in haystack for token in ("login", "sign in", "password", "username")):
            signals.append("login_interface")
        if any(token in haystack for token in ("admin", "dashboard", "control panel")):
            signals.append("admin_surface")
        if any(token in haystack for token in ("debug", "traceback", "stack trace", "exception")):
            signals.append("debug_surface")
        if any(token in haystack for token in ("upload", "import", "execute", "console")):
            signals.append("high_interaction_surface")
        deduped: list[str] = []
        seen: set[str] = set()
        for item in signals:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _follow_up_hints_from_signals(self, signals: list[str]) -> list[str]:
        mapping = {
            "login_interface": ("login_form_detector", "cookie_security_audit"),
            "admin_surface": ("passive_config_audit", "nuclei_exploit_check"),
            "debug_surface": ("error_page_analyzer", "passive_config_audit"),
            "high_interaction_surface": ("active_web_crawler", "param_fuzzer"),
        }
        hints: list[str] = []
        seen: set[str] = set()
        for signal in signals:
            for tool_name in mapping.get(signal, ()):
                if tool_name in seen:
                    continue
                seen.add(tool_name)
                hints.append(tool_name)
        return hints

    @staticmethod
    def _as_bool(value: Any, *, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return bool(default)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
            return bool(default)
        return bool(value)


@register_tool
class AgentTechStackFingerprintTool(BaseAgentTool):
    """Passive tech-stack fingerprinting using headers and page signatures."""

    name = "tech_stack_fingerprint"
    description = "Passively fingerprint technologies from headers and page signatures."
    cost = 2
    priority = 1
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        try:
            status_code, headers, body, final_url = _http_fetch_text(origin, timeout=8.0, max_bytes=300_000)
        except (URLError, TimeoutError, OSError) as exc:
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=StandardToolOutput(status="error", metadata={"error": str(exc)}),
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        tech_stack = _tech_stack_from_headers_and_body(headers, body)
        output = StandardToolOutput(
            status="completed",
            findings=[
                StandardFinding(
                    id=f"{self.name}:fingerprint",
                    tool=self.name,
                    severity="info",
                    category="info_leak",
                    title="Passive Technology Fingerprint",
                    description="Passive fingerprinting identified stack indicators from headers or page content.",
                    evidence={"url": final_url, "status_code": status_code, "tech_stack": tech_stack, "server": headers.get("server", "")},
                    remediation="Review exposed technology markers and minimize unnecessary fingerprinting signals where practical.",
                )
            ],
            surface_updates={"tech_stack": tech_stack},
            follow_up_hints=["nuclei_exploit_check"] if tech_stack else [],
            metadata={"url": final_url, "status_code": status_code, "headers": headers, "tech_stack": tech_stack},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentLoginFormDetectorTool(BaseAgentTool):
    """Detect password-bearing forms and derive low-risk auth endpoint metadata."""

    name = "login_form_detector"
    description = "Detect login/auth forms and extract likely request paths and parameter names."
    cost = 3
    priority = 4
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        try:
            status_code, headers, body, final_url = _http_fetch_text(origin, timeout=8.0, max_bytes=400_000)
        except (URLError, TimeoutError, OSError) as exc:
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=StandardToolOutput(status="error", metadata={"error": str(exc)}),
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        parser = _HTMLSurfaceParser()
        parser.feed(body)
        login_forms: list[dict[str, Any]] = []
        breadcrumbs_delta: list[dict[str, str]] = []
        api_endpoints: list[dict[str, str]] = []
        url_parameters: dict[str, list[str]] = {}
        parameter_origins: dict[str, list[str]] = {}
        for form in parser.forms:
            inputs = form.get("inputs", [])
            if not any(str(item.get("type", "")).lower() == "password" for item in inputs):
                continue
            action_url = urljoin(final_url, str(form.get("action", "")).strip() or final_url)
            normalized_action = _normalize_http_url(action_url)
            if not normalized_action:
                continue
            params = {str(item.get("name", "")).strip(): str(item.get("value", "")) for item in inputs if str(item.get("name", "")).strip()}
            login_forms.append(
                {
                    "action": normalized_action,
                    "method": str(form.get("method", "GET")).upper(),
                    "params": params,
                }
            )
            breadcrumbs_delta.append({"type": "endpoint", "data": normalized_action})
            api_endpoints.append({"url": normalized_action, "method": str(form.get("method", "GET")).upper(), "source": "login_form"})
            for param_name, value in params.items():
                url_parameters.setdefault(param_name, []).append(value)
                parameter_origins.setdefault(param_name, []).append(normalized_action)

        output = StandardToolOutput(
            status="completed",
            findings=[
                StandardFinding(
                    id=f"{self.name}:forms",
                    tool=self.name,
                    severity="info",
                    category="info_leak",
                    title="Login Form Detection",
                    description="Password-bearing forms were identified on the target origin.",
                    evidence={"status_code": status_code, "forms": login_forms, "url": final_url},
                    remediation="Use the discovered auth surface to drive low-risk validation of cookie and session controls.",
                )
            ],
            discovered_assets=[DiscoveredAsset(type=item["type"], data=item["data"]) for item in breadcrumbs_delta],
            surface_updates={
                "login_forms": login_forms,
                "api_endpoints": api_endpoints,
                "url_parameters": {key: sorted(set(values)) for key, values in url_parameters.items()},
                "parameter_origins": {key: sorted(set(values)) for key, values in parameter_origins.items()},
            },
            follow_up_hints=["cookie_security_audit"] if login_forms else [],
            metadata={"url": final_url, "status_code": status_code, "forms": login_forms, "headers": headers},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentJSEndpointExtractorTool(BaseAgentTool):
    """Extract hidden endpoints from same-origin JavaScript and HTML."""

    name = "js_endpoint_extractor"
    description = "Statically inspect same-origin HTML/JS for hidden API endpoints."
    cost = 4
    priority = 8
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon", "active_discovery"]
    input_schema = _origin_no_options_schema()

    _ENDPOINT_PATTERN = re.compile(
        r"""(?:"|')((?:https?://[^"'\\s]+|/[A-Za-z0-9_./?=&%-]*(?:api|graphql|auth|login|v1|v2)[A-Za-z0-9_./?=&%-]*))(?:"|')""",
        flags=re.IGNORECASE,
    )

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        try:
            status_code, headers, body, final_url = _http_fetch_text(origin, timeout=8.0, max_bytes=400_000)
        except (URLError, TimeoutError, OSError) as exc:
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=StandardToolOutput(status="error", metadata={"error": str(exc)}),
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        parser = _HTMLSurfaceParser()
        parser.feed(body)
        script_urls: list[str] = []
        for src in parser.script_sources[:8]:
            candidate = _normalize_http_url(urljoin(final_url, src))
            if candidate and _same_origin(final_url, candidate):
                script_urls.append(candidate)

        sources: list[tuple[str, str]] = [("html", body)]
        for script_url in script_urls:
            try:
                _script_status, _script_headers, script_body, _script_final = _http_fetch_text(
                    script_url,
                    accept="application/javascript,text/javascript,text/plain,*/*;q=0.8",
                    timeout=8.0,
                    max_bytes=350_000,
                )
            except (URLError, TimeoutError, OSError):
                continue
            sources.append((script_url, script_body))

        discovered_urls: set[str] = set()
        api_endpoints: list[dict[str, str]] = []
        url_parameters: dict[str, list[str]] = {}
        parameter_origins: dict[str, list[str]] = {}

        for source_name, text in sources:
            for match in self._ENDPOINT_PATTERN.findall(text):
                resolved = _normalize_http_url(urljoin(final_url, match))
                if not resolved or not _same_origin(final_url, resolved):
                    continue
                discovered_urls.add(resolved)
                params = _extract_parameter_names(resolved)
                if params:
                    for param_name, value in params.items():
                        values = url_parameters.setdefault(param_name, [])
                        if value not in values:
                            values.append(value)
                        parameter_origins.setdefault(param_name, []).append(source_name)
                api_endpoints.append({"url": resolved, "method": "GET", "source": source_name})

        output = StandardToolOutput(
            status="completed",
            findings=[
                StandardFinding(
                    id=f"{self.name}:discovery",
                    tool=self.name,
                    severity="info",
                    category="info_leak",
                    title="JavaScript Endpoint Extraction",
                    description="Static analysis of same-origin HTML/JS revealed candidate API or hidden endpoints.",
                    evidence={"url": final_url, "count": len(discovered_urls), "scripts": script_urls},
                    remediation="Review exposed client-side endpoints and ensure undocumented APIs are properly scoped and protected.",
                )
            ],
            discovered_assets=[DiscoveredAsset(type="endpoint", data=item) for item in sorted(discovered_urls)],
            surface_updates={
                "discovered_urls": sorted(discovered_urls),
                "api_endpoints": api_endpoints,
                "url_parameters": {key: sorted(values) for key, values in url_parameters.items()},
                "parameter_origins": {key: sorted(set(values)) for key, values in parameter_origins.items()},
            },
            follow_up_hints=["api_schema_discovery"] if api_endpoints else [],
            metadata={
                "url": final_url,
                "status_code": status_code,
                "headers": headers,
                "scripts": script_urls,
                "discovered_urls": sorted(discovered_urls),
                "api_endpoints": api_endpoints,
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentSQLSanitizationTool(BaseAgentTool):
    """Agent adapter for SQL sanitization auditing."""

    name = "sql_sanitization_audit"
    description = "Low-risk SQL injection sanitization probes."
    cost = 8
    priority = 30
    category = "testing"
    target_types = ["parameterized_endpoint"]
    phase_affinity = ["deep_testing", "verification"]
    depends_on = ["dynamic_crawl"]
    risk_level = "medium"
    default_options = {"method": "GET", "params": "$params"}
    input_schema = _parameter_probe_schema("sql_sanitization_audit", max_params=30, max_value_length=2048)

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        try:
            params = options.get("params", {})
            auditor = SQLSanitizationAuditor()
            result = auditor.audit_url(url=target, params=params)
            findings: list[dict[str, Any]] = []
            if result.is_vulnerable and result.finding is not None:
                findings.append(
                    {
                        "type": "vuln",
                        "name": "SQL Injection Sanitization Weakness",
                        "severity": "high",
                        "evidence": result.finding.evidence,
                        "reproduction_steps": [
                            f"Send GET request to {target}.",
                            f"Inject probe payload in `{result.finding.parameter}`: {result.finding.payload}",
                            f"Observe indicator: {result.finding.evidence}",
                        ],
                    }
                )
            return ToolExecutionResult(
                ok=True,
                tool_name=self.name,
                target=target,
                data={
                    "status": "completed",
                    "payload": asdict(result),
                    "findings": findings,
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
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
                duration_ms=int((time.perf_counter() - started) * 1000),
            )


@register_tool
class AgentXSSProtectionTool(BaseAgentTool):
    """Agent adapter for XSS output encoding auditing."""

    name = "xss_protection_audit"
    description = "Low-risk reflection and encoding checks."
    cost = 8
    priority = 30
    category = "testing"
    target_types = ["parameterized_endpoint"]
    phase_affinity = ["deep_testing", "verification"]
    depends_on = ["dynamic_crawl"]
    risk_level = "medium"
    default_options = {"method": "GET", "params": "$params"}
    input_schema = _parameter_probe_schema("xss_protection_audit", max_params=30, max_value_length=2048)

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        try:
            params = options.get("params", {})
            auditor = XSSProtectionAuditor()
            result = auditor.audit_url(url=target, params=params, verify_in_browser=False)
            findings: list[dict[str, Any]] = []
            if result.is_reflected and result.reflection_points:
                point = result.reflection_points[0]
                findings.append(
                    {
                        "type": "vuln",
                        "name": "Potential XSS Reflection / Encoding Weakness",
                        "severity": "high",
                        "evidence": f"context={point.context}; snippet={point.snippet}",
                        "reproduction_steps": [
                            f"Request endpoint with canary input: {target}",
                            f"Observe raw reflection at position {point.position} in {point.context} context.",
                            "Verify output encoding for this context.",
                        ],
                    }
                )
            return ToolExecutionResult(
                ok=True,
                tool_name=self.name,
                target=target,
                data={
                    "status": "completed",
                    "payload": asdict(result),
                    "findings": findings,
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
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
                duration_ms=int((time.perf_counter() - started) * 1000),
            )


@register_tool
class AgentParamFuzzerTool(BaseAgentTool):
    """Lightweight GET-only parameter anomaly checks."""

    name = "param_fuzzer"
    description = "Lightweight parameter fuzzing with bounded benign probes."
    cost = 6
    priority = 32
    category = "testing"
    target_types = ["parameterized_endpoint"]
    phase_affinity = ["deep_testing"]
    depends_on = ["dynamic_crawl"]
    risk_level = "medium"
    default_options = {"method": "GET", "mode": "lightweight", "max_probes": 6, "params": "$params"}
    input_schema = {
        "target_mode": "http_url",
        "required": ["method", "params", "mode", "max_probes"],
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET"],
                "error": "param_fuzzer_method_must_be_get",
            },
            "params": {
                "type": "object",
                "min_properties": 1,
                "max_properties": 20,
                "key_schema": {
                    "type": "string",
                    "min_length": 1,
                    "max_length": 128,
                    "error": "param_fuzzer_invalid_param_key",
                },
                "value_schema": {
                    "type": "scalar",
                    "max_length": 1024,
                    "error": "param_fuzzer_param_value_too_long",
                },
                "error": "param_fuzzer_params_must_be_non_empty_dict",
            },
            "mode": {
                "type": "string",
                "enum": ["lightweight"],
                "error": "param_fuzzer_mode_invalid",
            },
            "max_probes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "error": "param_fuzzer_max_probes_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "param_fuzzer_options_invalid_keys",
    }

    _PROBE_VALUES = ("'", "\"", "<asa-canary>", "999999999")

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        params = options.get("params", {})
        max_probes = max(1, min(int(options.get("max_probes", 6) or 6), 20))
        if not isinstance(params, dict) or not params:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": "params missing"}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error="params missing",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            baseline_status, baseline_headers, baseline_body, baseline_url = _http_fetch_text(
                self._build_url(target, params),
                accept="text/html,application/json,*/*;q=0.8",
                timeout=8.0,
                max_bytes=250_000,
            )
        except (URLError, TimeoutError, OSError) as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": str(exc)}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        probes: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        budgeted_targets = list(params.items())[:max_probes]
        for index, (param_name, original_value) in enumerate(budgeted_targets):
            probe_value = self._PROBE_VALUES[index % len(self._PROBE_VALUES)]
            mutated_params = dict(params)
            mutated_params[param_name] = probe_value
            probe_url = self._build_url(target, mutated_params)
            try:
                status_code, headers, body, final_url = _http_fetch_text(
                    probe_url,
                    accept="text/html,application/json,*/*;q=0.8",
                    timeout=8.0,
                    max_bytes=250_000,
                )
            except (URLError, TimeoutError, OSError) as exc:
                probes.append({"param": param_name, "probe_value": probe_value, "error": str(exc)})
                continue
            reflected = probe_value.lower() in body.lower()
            anomaly = status_code >= 500 or abs(len(body) - len(baseline_body)) > 1200
            probe_record = {
                "param": param_name,
                "original_value": str(original_value),
                "probe_value": probe_value,
                "status_code": status_code,
                "baseline_status_code": baseline_status,
                "content_length_delta": len(body) - len(baseline_body),
                "reflected": reflected,
                "url": final_url,
                "server": headers.get("server", ""),
            }
            probes.append(probe_record)
            if status_code >= 500:
                findings.append(
                    {
                        "type": "vuln",
                        "name": "Parameter Fuzzing Triggered Server Error",
                        "severity": "medium",
                        "evidence": json.dumps(probe_record, ensure_ascii=False),
                        "reproduction_steps": [
                            f"Request {final_url}.",
                            f"Mutate `{param_name}` with `{probe_value}` and observe HTTP {status_code}.",
                        ],
                    }
                )
            elif anomaly or reflected:
                findings.append(
                    {
                        "type": "info",
                        "name": "Parameter Fuzzing Observed Notable Response Change",
                        "severity": "info",
                        "evidence": json.dumps(probe_record, ensure_ascii=False),
                        "reproduction_steps": [
                            f"Request {baseline_url} as baseline.",
                            f"Mutate `{param_name}` with `{probe_value}` and compare response behavior.",
                        ],
                    }
                )

        if not findings:
            findings.append(
                {
                    "type": "info",
                    "name": "Lightweight Parameter Fuzzing Completed",
                    "severity": "info",
                    "evidence": json.dumps({"baseline_status_code": baseline_status, "probes": probes}, ensure_ascii=False),
                    "reproduction_steps": [f"Replay GET probes against {baseline_url} and compare responses."],
                }
            )

        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": {
                    "baseline_status_code": baseline_status,
                    "baseline_headers": baseline_headers,
                    "baseline_url": baseline_url,
                    "probes": probes,
                },
                "findings": findings,
                "breadcrumbs_delta": [],
                "surface_delta": {"fuzz_probes": probes},
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _build_url(target: str, params: dict[str, Any]) -> str:
        parsed = urlparse(target)
        query = urlencode([(str(key), str(value)) for key, value in params.items()], doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))


@register_tool
class AgentPassiveConfigAuditTool(BaseAgentTool):
    """Passive GET-only check for common sensitive files."""

    name = "passive_config_audit"
    description = "Read-only exposure checks for sensitive config artifacts."
    cost = 3
    priority = 0
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    default_options = {
        "request_timeout_seconds": 3,
        "max_total_seconds": 18,
        "max_paths": 10,
    }
    input_schema = {
        "target_mode": "origin_http",
        "properties": {
            "request_timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 8,
                "error": "passive_config_request_timeout_out_of_bounds",
            },
            "max_total_seconds": {
                "type": "number",
                "minimum": 3,
                "maximum": 60,
                "error": "passive_config_total_timeout_out_of_bounds",
            },
            "max_paths": {
                "type": "integer",
                "minimum": 1,
                "maximum": 15,
                "error": "passive_config_max_paths_out_of_bounds",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "passive_config_options_invalid_keys",
    }
    _CHECK_PATHS = [
        ".env",
        ".env.prod",
        ".env.local",
        ".env.backup",
        ".git/config",
        "wp-config.php.bak",
        "database.yml",
        ".htpasswd",
        "api/swagger.json",
        "swagger.json",
        "v1/swagger.json",
        "api/v1/swagger.json",
        "actuator/env",
        "actuator/health",
        "config.php.bak",
    ]
    _DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0
    _DEFAULT_MAX_TOTAL_SECONDS = 30.0

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        request_timeout_seconds = self._bounded_float(
            options.get("request_timeout_seconds"),
            default=self._DEFAULT_REQUEST_TIMEOUT_SECONDS,
            minimum=1.0,
            maximum=6.0,
        )
        max_paths = self._bounded_int(
            options.get("max_paths"),
            default=len(self._CHECK_PATHS),
            minimum=1,
            maximum=len(self._CHECK_PATHS),
        )
        max_total_seconds = self._bounded_float(
            options.get("max_total_seconds"),
            default=self._DEFAULT_MAX_TOTAL_SECONDS,
            minimum=3.0,
            maximum=60.0,
        )
        check_paths = list(self._CHECK_PATHS[:max_paths])
        keywords_map = {
            ".git/config": ["[core]", "repositoryformatversion", "remote \"origin\""],
            ".env": ["db_password", "secret_key", "api_key", "database_url"],
            ".env.backup": ["db_password", "secret_key", "api_key", "database_url"],
            ".env.prod": ["db_password", "secret_key", "api_key", "database_url"],
            ".env.local": ["db_password", "secret_key", "api_key", "database_url"],
            "config.php.bak": ["<?php", "define(", "password", "$db"],
            "wp-config.php.bak": ["db_name", "db_user", "db_password", "auth_key"],
            "database.yml": ["adapter:", "database:", "username:", "password:"],
            ".htpasswd": ["$apr1$", "$2y$", "$2b$", "$argon2"],
            "api/swagger.json": ["\"openapi\"", "\"swagger\"", "\"paths\""],
            "swagger.json": ["\"openapi\"", "\"swagger\"", "\"paths\""],
            "v1/swagger.json": ["\"openapi\"", "\"swagger\"", "\"paths\""],
            "api/v1/swagger.json": ["\"openapi\"", "\"swagger\"", "\"paths\""],
            "actuator/env": ["\"propertySources\"", "\"activeProfiles\"", "\"systemProperties\""],
            "actuator/health": ["\"status\"", "\"components\"", "\"diskSpace\""],
        }

        exposures: list[dict[str, Any]] = []
        for path in check_paths:
            if (time.perf_counter() - started) >= max_total_seconds:
                break
            url = f"{target.rstrip('/')}/{path}"
            request = Request(
                url=url,
                method="GET",
                headers={
                    "User-Agent": "AutoSecAudit-AgentPassiveConfig/0.1",
                    "Accept": "text/plain,text/html,*/*;q=0.8",
                },
            )
            try:
                with urlopen(request, timeout=request_timeout_seconds) as response:
                    if response.status != 200:
                        continue
                    body = (response.read(200_000) or b"").decode("utf-8", errors="replace")
            except (HTTPError, URLError, TimeoutError, OSError):
                continue

            lower_body = body.lower()
            matched = [token for token in keywords_map[path] if token.lower() in lower_body]
            if not matched:
                continue

            exposures.append(
                {
                    "path": path,
                    "url": url,
                    "matched_keywords": matched,
                    "snippet": self._snippet(body, matched[0], radius=100),
                }
            )

        findings: list[dict[str, Any]] = []
        for item in exposures:
            severity = "high" if item["path"] in {".git/config", ".env", ".env.backup", ".env.prod", ".env.local", "wp-config.php.bak", "database.yml", ".htpasswd", "actuator/env"} else "medium"
            findings.append(
                {
                    "type": "vuln",
                    "name": f"Sensitive File Exposure: {item['path']}",
                    "severity": severity,
                    "evidence": f"keywords={item['matched_keywords']}; snippet={item['snippet']}",
                    "reproduction_steps": [
                        f"Send GET request to {item['url']}.",
                        f"Confirm HTTP 200 and sensitive marker(s): {', '.join(item['matched_keywords'])}.",
                    ],
                }
            )

        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": {
                    "origin": target,
                    "checked_paths": check_paths,
                    "request_timeout_seconds": request_timeout_seconds,
                    "max_total_seconds": max_total_seconds,
                    "exposures": exposures,
                },
                "findings": findings,
                "breadcrumbs_delta": [],
                "surface_delta": {"config_exposures": exposures},
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _snippet(body: str, keyword: str, radius: int = 80) -> str:
        lower_body = body.lower()
        lower_keyword = keyword.lower()
        index = lower_body.find(lower_keyword)
        if index < 0:
            snippet = body[: radius * 2]
        else:
            start = max(0, index - radius)
            end = min(len(body), index + len(keyword) + radius)
            snippet = body[start:end]
        return " ".join(snippet.replace("\n", " ").replace("\r", " ").split())

    @staticmethod
    def _bounded_float(
        value: Any,
        *,
        default: float,
        minimum: float,
        maximum: float,
    ) -> float:
        try:
            numeric = float(value if value is not None else default)
        except (TypeError, ValueError):
            numeric = default
        return max(minimum, min(maximum, numeric))

    @staticmethod
    def _bounded_int(
        value: Any,
        *,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        try:
            numeric = int(value if value is not None else default)
        except (TypeError, ValueError):
            numeric = default
        return max(minimum, min(maximum, numeric))


@register_tool
class AgentHTTPSecurityHeadersTool(BaseAgentTool):
    """Read-only HTTP security header validation."""

    name = "http_security_headers"
    description = "Validate common baseline HTTP security headers."
    cost = 3
    priority = 5
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        url = self._normalize_target_url(target)

        try:
            request = Request(
                url=url,
                method="GET",
                headers={
                    "User-Agent": "AutoSecAudit-HTTPHeaders/0.1",
                    "Accept": "text/html,application/json,*/*;q=0.8",
                },
            )
            with urlopen(request, timeout=8) as response:
                status_code = int(response.status)
                headers = {key.lower(): value for key, value in response.headers.items()}
        except HTTPError as exc:
            status_code = int(exc.code)
            headers = {key.lower(): value for key, value in exc.headers.items()}
        except (URLError, TimeoutError, OSError) as exc:
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=StandardToolOutput(status="error", metadata={"error": str(exc)}),
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        expectations = {
            "strict-transport-security": ("HSTS Missing", "Add Strict-Transport-Security on HTTPS responses.", "medium"),
            "content-security-policy": ("CSP Missing", "Add a Content-Security-Policy to reduce XSS impact.", "medium"),
            "x-frame-options": ("X-Frame-Options Missing", "Set X-Frame-Options or CSP frame-ancestors.", "low"),
            "x-content-type-options": ("X-Content-Type-Options Missing", "Set X-Content-Type-Options: nosniff.", "low"),
            "referrer-policy": ("Referrer-Policy Missing", "Set Referrer-Policy to reduce cross-origin leakage.", "low"),
        }
        findings: list[StandardFinding] = []
        for header_name, (title, recommendation, severity) in expectations.items():
            if str(headers.get(header_name, "")).strip():
                continue
            findings.append(
                StandardFinding(
                    id=f"{self.name}:{header_name}",
                    tool=self.name,
                    severity=severity,
                    category="misconfig",
                    title=title,
                    description=f"Response is missing the expected security header `{header_name}`.",
                    evidence={"status_code": status_code, "missing_header": header_name, "url": url},
                    remediation=recommendation,
                )
            )
        if not findings:
            findings.append(
                StandardFinding(
                    id=f"{self.name}:baseline",
                    tool=self.name,
                    severity="info",
                    category="compliance",
                    title="Baseline Security Headers Present",
                    description="The origin returned the expected baseline HTTP security headers.",
                    evidence={"status_code": status_code, "headers": headers, "url": url},
                    remediation="Keep header baselines monitored to prevent regressions.",
                )
            )
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={"http_security_headers": headers},
            follow_up_hints=["csp_evaluator"] if "content-security-policy" in headers else [],
            metadata={"url": url, "status_code": status_code, "headers": headers},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _normalize_target_url(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        path = parsed.path if parsed.path not in {"", "/"} else ""
        return f"{parsed.scheme}://{parsed.netloc}{path}"


@register_tool
class AgentSSLExpiryCheckTool(BaseAgentTool):
    """TLS certificate expiry validation for agent workflows."""

    name = "ssl_expiry_check"
    description = "Check TLS certificate expiry using stdlib ssl."
    cost = 3
    priority = 6
    category = "recon"
    target_types = ["https_origin"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema(target_mode="https_origin_or_host")

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        parsed = self._parse_target(target)
        host = parsed.hostname
        port = parsed.port or 443
        if parsed.scheme.lower() == "http":
            return ToolExecutionResult(
                ok=True,
                tool_name=self.name,
                target=target,
                data={
                    "status": "skipped",
                    "payload": {"reason": "http_target"},
                    "findings": [],
                    "breadcrumbs_delta": [],
                    "surface_delta": {},
                },
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        if not host:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": "hostname missing"}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error="hostname missing",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        try:
            cert, tls_version = self._fetch_certificate(host, port)
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": str(exc)}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        not_after = cert.get("notAfter")
        expires_at = self._parse_not_after(str(not_after)) if not_after else None
        if expires_at is None:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": f"unable to parse expiry: {not_after}"}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error=f"unable to parse expiry: {not_after}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        now = datetime.now(timezone.utc)
        days_left = int((expires_at - now).total_seconds() // 86400)
        metadata = {
            "host": host,
            "port": port,
            "days_left": days_left,
            "expires_at": expires_at.isoformat(),
            "tls_version": tls_version,
            "subject_alt_name": cert.get("subjectAltName"),
        }
        findings: list[dict[str, Any]] = []
        if days_left < 0:
            findings.append({"type": "vuln", "name": "TLS Certificate Expired", "severity": "high", "evidence": json.dumps(metadata, ensure_ascii=False), "reproduction_steps": [f"Open TLS connection to {host}:{port}.", "Observe expired certificate metadata."]})
        elif days_left <= 7:
            findings.append({"type": "vuln", "name": "TLS Certificate Expiring Within 7 Days", "severity": "high", "evidence": json.dumps(metadata, ensure_ascii=False), "reproduction_steps": [f"Open TLS connection to {host}:{port}.", "Observe imminent certificate expiry."]})
        elif days_left <= 30:
            findings.append({"type": "vuln", "name": "TLS Certificate Expiring Soon", "severity": "medium", "evidence": json.dumps(metadata, ensure_ascii=False), "reproduction_steps": [f"Open TLS connection to {host}:{port}.", "Observe expiry window below 30 days."]})
        else:
            findings.append({"type": "info", "name": "TLS Certificate Expiry Healthy", "severity": "info", "evidence": json.dumps(metadata, ensure_ascii=False), "reproduction_steps": [f"Open TLS connection to {host}:{port}.", "Observe certificate validity and remaining lifetime."]})

        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": metadata,
                "findings": findings,
                "breadcrumbs_delta": [],
                "surface_delta": {"tls_metadata": metadata},
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _parse_target(target: str) -> ParseResult:
        normalized = target if "://" in target else f"https://{target}"
        return urlparse(normalized)

    @staticmethod
    def _fetch_certificate(host: str, port: int) -> tuple[dict[str, object], str | None]:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert(), tls_sock.version()

    @staticmethod
    def _parse_not_after(value: str) -> datetime | None:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


@register_tool
class AgentCORSMisconfigurationTool(BaseAgentTool):
    """Safe CORS misconfiguration probing."""

    name = "cors_misconfiguration"
    description = "Probe for arbitrary Origin reflection and credentialed wildcard CORS."
    cost = 5
    priority = 22
    category = "testing"
    target_types = ["origin_url"]
    phase_affinity = ["deep_testing"]
    risk_level = "medium"
    input_schema = _origin_no_options_schema()

    _TEST_ORIGINS = (
        "https://evil.example.com",
        "null",
    )

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        parsed = urlparse(target if "://" in target else f"https://{target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        test_origins = [*self._TEST_ORIGINS, f"https://{(parsed.hostname or 'target')}.evil.invalid"]
        findings: list[dict[str, Any]] = []
        probes: list[dict[str, Any]] = []
        for candidate in test_origins:
            try:
                headers, status_code, method = self._collect_headers(origin, candidate)
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                probes.append({"origin": candidate, "error": str(exc)})
                continue
            probes.append(
                {
                    "origin": candidate,
                    "status_code": status_code,
                    "probe_method": method,
                    "allow_origin": headers.get("access-control-allow-origin"),
                    "allow_credentials": headers.get("access-control-allow-credentials"),
                }
            )
            acao = str(headers.get("access-control-allow-origin", "")).strip()
            acac = str(headers.get("access-control-allow-credentials", "")).strip().lower()
            if acao == "*" and acac == "true":
                findings.append({"type": "vuln", "name": "CORS Allows Any Origin With Credentials", "severity": "high", "evidence": json.dumps(probes[-1], ensure_ascii=False), "reproduction_steps": [f"Send OPTIONS/GET request to {origin} with Origin: {candidate}.", "Observe wildcard ACAO plus credentials."]})
            elif acao == candidate and acac == "true":
                findings.append({"type": "vuln", "name": "CORS Reflects Arbitrary Origin With Credentials", "severity": "high", "evidence": json.dumps(probes[-1], ensure_ascii=False), "reproduction_steps": [f"Send OPTIONS/GET request to {origin} with Origin: {candidate}.", "Observe reflected ACAO plus credentials."]})
            elif acao in {candidate, "*"}:
                findings.append({"type": "vuln", "name": "CORS Allows Untrusted Origin", "severity": "medium", "evidence": json.dumps(probes[-1], ensure_ascii=False), "reproduction_steps": [f"Send OPTIONS/GET request to {origin} with Origin: {candidate}.", "Observe permissive ACAO value."]})
        if not findings:
            findings.append({"type": "info", "name": "No Obvious CORS Misconfiguration", "severity": "info", "evidence": json.dumps(probes, ensure_ascii=False), "reproduction_steps": [f"Probe {origin} with untrusted Origin headers and inspect response."]})
        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": {"origin": origin, "probes": probes},
                "findings": findings,
                "breadcrumbs_delta": [],
                "surface_delta": {"cors_probes": probes},
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _collect_headers(url: str, test_origin: str) -> tuple[dict[str, str], int, str]:
        for method in ("OPTIONS", "GET"):
            request = Request(
                url=url,
                method=method,
                headers={
                    "Origin": test_origin,
                    "Access-Control-Request-Method": "GET",
                    "User-Agent": "AutoSecAudit-CORS/0.1",
                },
            )
            try:
                with urlopen(request, timeout=8) as response:
                    return {k.lower(): v for k, v in response.headers.items()}, int(response.status), method
            except HTTPError as exc:
                if exc.code in {403, 404, 405}:
                    return {k.lower(): v for k, v in exc.headers.items()}, exc.code, method
                raise
        return {}, 0, "GET"


@register_tool
class AgentSubdomainEnumPassiveTool(BaseAgentTool):
    """Passive certificate-transparency-based subdomain enumeration."""

    name = "subdomain_enum_passive"
    description = "Enumerate likely subdomains via crt.sh JSON feed."
    cost = 5
    priority = 12
    category = "recon"
    target_types = ["domain"]
    phase_affinity = ["passive_recon"]
    default_options = {"max_results": 100}
    input_schema = {
        "target_mode": "domain",
        "properties": {
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "error": "subdomain_enum_passive_max_results_out_of_bounds",
            }
        },
        "additional_properties": False,
        "additional_properties_error": "subdomain_enum_passive_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        max_results = int(options.get("max_results", 100) or 100)
        domain = self._normalize_domain(target)
        if not domain:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": "invalid domain"}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error="invalid domain",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            request = Request(url=url, headers={"User-Agent": "AutoSecAudit-SubdomainPassive/0.1", "Accept": "application/json"})
            with urlopen(request, timeout=12) as response:
                payload = json.loads((response.read(2_000_000) or b"[]").decode("utf-8", errors="replace"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                data={"status": "error", "payload": {"error": str(exc)}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        discovered: set[str] = set()
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                raw_names = str(item.get("name_value", "")).splitlines()
                for raw_name in raw_names:
                    candidate = raw_name.strip().lower().lstrip("*.").strip(".")
                    if not candidate:
                        continue
                    if candidate == domain or candidate.endswith(f".{domain}"):
                        discovered.add(candidate)
        ordered = sorted(discovered)[: max(1, min(max_results, 500))]
        findings = [
            {
                "type": "info",
                "name": "Passive Subdomain Enumeration Results",
                "severity": "info",
                "evidence": json.dumps({"domain": domain, "count": len(ordered), "subdomains": ordered}, ensure_ascii=False),
                "reproduction_steps": [f"Query crt.sh for %.{domain} and review returned SAN/CN values."],
            }
        ]
        breadcrumbs_delta = [{"type": "service", "data": f"https://{item}"} for item in ordered[:20]]
        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": {"domain": domain, "subdomains": ordered},
                "findings": findings,
                "breadcrumbs_delta": breadcrumbs_delta,
                "surface_delta": {"discovered_subdomains": ordered},
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _normalize_domain(target: str) -> str:
        token = str(target).strip().lower()
        if "://" in token:
            token = (urlparse(token).hostname or "").strip().lower()
        token = token.strip(".")
        if not token:
            return ""
        try:
            ipaddress.ip_address(token)
            return ""
        except ValueError:
            return token


@register_tool
class AgentGitExposureCheckTool(BaseAgentTool):
    """Check common VCS exposure paths."""

    name = "git_exposure_check"
    description = "Detect exposed VCS metadata such as .git and .svn."
    cost = 2
    priority = 2
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    _PATHS = {
        ".git/HEAD": "git_head",
        ".git/config": "git_config",
        ".svn/entries": "svn_entries",
        ".hg/requires": "hg_requires",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        findings: list[StandardFinding] = []
        assets: list[DiscoveredAsset] = []
        exposures: list[dict[str, Any]] = []
        for path, exposure_type in self._PATHS.items():
            probe_url = urljoin(f"{origin}/", path)
            try:
                status_code, headers, body, final_url = _http_fetch_text(probe_url, timeout=6.0, max_bytes=25_000)
            except (HTTPError, URLError, TimeoutError, OSError):
                continue
            body_lower = body.lower()
            exposed = (
                status_code == 200
                and (
                    "refs/" in body_lower
                    or "[core]" in body_lower
                    or "<?xml" in body_lower
                    or "store" in body_lower
                )
            )
            if not exposed:
                continue
            exposures.append({"url": final_url, "status_code": status_code, "type": exposure_type})
            assets.append(DiscoveredAsset(type="endpoint", data=final_url))
            findings.append(
                StandardFinding(
                    id=f"{self.name}:{exposure_type}",
                    tool=self.name,
                    severity="high",
                    category="info_leak",
                    title="Exposed Version Control Metadata",
                    description=f"Sensitive repository metadata is reachable at {path}.",
                    evidence={"url": final_url, "status_code": status_code, "server": headers.get("server", "")},
                    remediation="Block direct access to repository metadata and rotate any exposed secrets.",
                )
            )
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            discovered_assets=assets,
            surface_updates={"git_exposures": exposures},
            follow_up_hints=["passive_config_audit"] if exposures else [],
            metadata={"origin": origin, "exposure_count": len(exposures)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentSourceMapDetectorTool(BaseAgentTool):
    """Detect exposed JavaScript source maps."""

    name = "source_map_detector"
    description = "Detect exposed JavaScript source map files."
    cost = 2
    priority = 7
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    _SOURCE_MAP_PATTERN = re.compile(r"sourceMappingURL=([^\s*]+)")

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        try:
            _status_code, _headers, body, final_url = _http_fetch_text(origin, timeout=8.0, max_bytes=400_000)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            output = StandardToolOutput(status="error", metadata={"error": str(exc)})
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        parser = _HTMLSurfaceParser()
        parser.feed(body)
        script_urls = {
            _normalize_http_url(urljoin(final_url, src))
            for src in parser.script_sources[:12]
            if _normalize_http_url(urljoin(final_url, src))
        }
        findings: list[StandardFinding] = []
        assets: list[DiscoveredAsset] = []
        detected_maps: list[str] = []
        for script_url in sorted(script_urls):
            candidates = {_normalize_http_url(f"{script_url}.map")}
            try:
                _script_status, _script_headers, script_body, _script_final = _http_fetch_text(
                    script_url,
                    accept="application/javascript,text/javascript,text/plain,*/*;q=0.8",
                    timeout=8.0,
                    max_bytes=250_000,
                )
                for match in self._SOURCE_MAP_PATTERN.findall(script_body):
                    candidates.add(_normalize_http_url(urljoin(script_url, match.strip())))
            except (HTTPError, URLError, TimeoutError, OSError):
                pass
            for candidate in {item for item in candidates if item}:
                try:
                    status_code, _headers, map_body, final_map = _http_fetch_text(
                        candidate,
                        accept="application/json,text/plain,*/*;q=0.8",
                        timeout=8.0,
                        max_bytes=250_000,
                    )
                except (HTTPError, URLError, TimeoutError, OSError):
                    continue
                if status_code != 200 or '"version"' not in map_body[:200]:
                    continue
                detected_maps.append(final_map)
                assets.append(DiscoveredAsset(type="endpoint", data=final_map))
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:{len(detected_maps)}",
                        tool=self.name,
                        severity="medium",
                        category="info_leak",
                        title="Exposed JavaScript Source Map",
                        description="A source map is publicly accessible and may reveal application source paths or code.",
                        evidence={"url": final_map, "script_url": script_url},
                        remediation="Disable public source map exposure in production or gate access to build artifacts.",
                    )
                )
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            discovered_assets=assets,
            surface_updates={"source_maps": detected_maps},
            follow_up_hints=["js_endpoint_extractor"] if detected_maps else [],
            metadata={"origin": origin, "source_map_count": len(detected_maps)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentErrorPageAnalyzerTool(BaseAgentTool):
    """Analyze framework/debug information leaked by error pages."""

    name = "error_page_analyzer"
    description = "Analyze verbose error pages for stack traces and debug markers."
    cost = 3
    priority = 11
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    _MARKERS = (
        "traceback",
        "stack trace",
        "exception",
        "whitelabel error page",
        "php fatal error",
        "debug",
        "nullreferenceexception",
        "sqlstate",
    )

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        probe_url = urljoin(f"{origin}/", "__autosecaudit_error_probe__?debug=1")
        try:
            status_code, headers, body, final_url = _http_fetch_text(probe_url, timeout=8.0, max_bytes=250_000)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            output = StandardToolOutput(status="error", metadata={"error": str(exc)})
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        body_lower = body.lower()
        matched_markers = [marker for marker in self._MARKERS if marker in body_lower]
        findings: list[StandardFinding] = []
        if matched_markers:
            findings.append(
                StandardFinding(
                    id=f"{self.name}:debug_page",
                    tool=self.name,
                    severity="medium",
                    category="info_leak",
                    title="Verbose Error Page Detected",
                    description="The application error response exposes debugging details or stack trace markers.",
                    evidence={"url": final_url, "status_code": status_code, "markers": matched_markers, "server": headers.get("server", "")},
                    remediation="Disable verbose error pages in production and replace with generic error handling.",
                )
            )
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={"error_page_markers": matched_markers},
            metadata={"origin": origin, "status_code": status_code},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentAPISchemaDiscoveryTool(BaseAgentTool):
    """Discover common API schema endpoints."""

    name = "api_schema_discovery"
    description = "Discover OpenAPI, Swagger, and GraphQL schema endpoints."
    cost = 4
    priority = 18
    category = "discovery"
    target_types = ["origin_url"]
    phase_affinity = ["active_discovery"]
    input_schema = _origin_no_options_schema()

    _PATHS = (
        "openapi.json",
        "swagger.json",
        "swagger/v1/swagger.json",
        "v3/api-docs",
        "api-docs",
        "graphql",
        "api/graphql",
    )

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        findings: list[StandardFinding] = []
        assets: list[DiscoveredAsset] = []
        schemas: list[dict[str, Any]] = []
        for path in self._PATHS:
            probe_url = urljoin(f"{origin}/", path)
            try:
                status_code, headers, body, final_url = _http_fetch_text(probe_url, timeout=8.0, max_bytes=300_000)
            except (HTTPError, URLError, TimeoutError, OSError):
                continue
            content_type = headers.get("content-type", "").lower()
            body_lower = body.lower()
            discovered = False
            schema_kind = ""
            if status_code == 200 and ("openapi" in body_lower or "swagger" in body_lower):
                discovered = True
                schema_kind = "openapi"
            elif status_code in {200, 400, 405} and "graphql" in path and any(
                marker in body_lower for marker in ("graphql", "__schema", "query")
            ):
                discovered = True
                schema_kind = "graphql"
            elif status_code == 200 and "application/json" in content_type and path.endswith(".json"):
                discovered = True
                schema_kind = "json_schema"
            if not discovered:
                continue
            schemas.append({"url": final_url, "kind": schema_kind, "status_code": status_code})
            assets.append(DiscoveredAsset(type="endpoint", data=final_url))
            findings.append(
                StandardFinding(
                    id=f"{self.name}:{schema_kind}:{len(schemas)}",
                    tool=self.name,
                    severity="info",
                    category="info_leak",
                    title="API Schema Endpoint Discovered",
                    description=f"Publicly reachable {schema_kind} metadata was identified.",
                    evidence={"url": final_url, "status_code": status_code, "content_type": content_type},
                    remediation="Restrict schema exposure in production or ensure it contains no sensitive metadata.",
                )
            )
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            discovered_assets=assets,
            surface_updates={
                "api_endpoints": [{"url": item["url"], "method": "GET", "source": self.name} for item in schemas],
                "api_schemas": schemas,
            },
            follow_up_hints=["param_fuzzer"] if schemas else [],
            metadata={"origin": origin, "schema_count": len(schemas)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentWAFDetectorTool(BaseAgentTool):
    """Detect common WAF/CDN fingerprints from response metadata."""

    name = "waf_detector"
    description = "Identify common WAF and CDN protection layers."
    cost = 3
    priority = 13
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    _VENDOR_MARKERS = {
        "cloudflare": ("cf-ray", "__cf_bm", "cf-cache-status", "attention required"),
        "akamai": ("akamai", "ghost", "akamaighost"),
        "aws_waf": ("x-amzn-requestid", "awsalb", "aws"),
        "incapsula": ("incap_ses", "visid_incap", "incapsula"),
        "sucuri": ("x-sucuri-id", "x-sucuri-cache"),
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        try:
            status_code, headers, body, final_url = _http_fetch_text(origin, timeout=8.0, max_bytes=120_000)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            output = StandardToolOutput(status="error", metadata={"error": str(exc)})
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        header_text = "\n".join(f"{key}:{value}" for key, value in headers.items()).lower()
        combined = f"{header_text}\n{body[:4000].lower()}"
        vendors = [
            vendor
            for vendor, markers in self._VENDOR_MARKERS.items()
            if any(marker in combined for marker in markers)
        ]
        findings = [
            StandardFinding(
                id=f"{self.name}:{vendor}",
                tool=self.name,
                severity="info",
                category="misconfig",
                title="Potential WAF/CDN Identified",
                description=f"Response metadata suggests {vendor} is protecting the target.",
                evidence={"url": final_url, "status_code": status_code, "vendor": vendor},
                remediation="Account for upstream WAF/CDN behavior when validating false positives or tuning scans.",
            )
            for vendor in vendors
        ]
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={"waf_vendors": vendors},
            metadata={"origin": origin, "status_code": status_code},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentSecurityTxtCheckTool(BaseAgentTool):
    """Check security.txt presence and basic fields."""

    name = "security_txt_check"
    description = "Check /.well-known/security.txt compliance."
    cost = 1
    priority = 3
    category = "recon"
    target_types = ["origin_url"]
    phase_affinity = ["passive_recon"]
    input_schema = _origin_no_options_schema()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        probe_url = urljoin(f"{origin}/", ".well-known/security.txt")
        try:
            status_code, headers, body, final_url = _http_fetch_text(
                probe_url,
                accept="text/plain,*/*;q=0.8",
                timeout=8.0,
                max_bytes=32_000,
            )
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            output = StandardToolOutput(status="error", metadata={"error": str(exc)})
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        has_contact = any(line.lower().startswith("contact:") for line in lines)
        has_expires = any(line.lower().startswith("expires:") for line in lines)
        findings: list[StandardFinding] = []
        if status_code != 200:
            findings.append(
                StandardFinding(
                    id=f"{self.name}:missing",
                    tool=self.name,
                    severity="low",
                    category="compliance",
                    title="security.txt Missing",
                    description="No security.txt file was found under /.well-known/security.txt.",
                    evidence={"url": final_url, "status_code": status_code},
                    remediation="Publish a valid security.txt file with contact and expiry metadata.",
                )
            )
        elif not has_contact or not has_expires:
            findings.append(
                StandardFinding(
                    id=f"{self.name}:incomplete",
                    tool=self.name,
                    severity="low",
                    category="compliance",
                    title="security.txt Incomplete",
                    description="security.txt is present but missing required contact or expiry fields.",
                    evidence={"url": final_url, "status_code": status_code, "has_contact": has_contact, "has_expires": has_expires},
                    remediation="Ensure security.txt includes at least Contact and Expires fields.",
                )
            )
        security_txt_data: dict[str, Any] = {
            "present": status_code == 200,
            "status_code": status_code,
            "url": final_url,
            "has_contact": has_contact,
            "has_expires": has_expires,
            "line_count": len(lines),
            "content_preview": "\n".join(lines[:20]) if status_code == 200 else None,
        }
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            discovered_assets=[DiscoveredAsset(type="endpoint", data=final_url)] if status_code == 200 else [],
            surface_updates={"security_txt": security_txt_data},
            metadata={"origin": origin, "status_code": status_code, "line_count": len(lines)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentCookieSecurityAuditTool(BaseAgentTool):
    """Audit cookie flags from response headers."""

    name = "cookie_security_audit"
    description = "Audit Secure, HttpOnly, and SameSite cookie attributes."
    cost = 3
    priority = 24
    category = "testing"
    target_types = ["origin_url"]
    phase_affinity = ["deep_testing", "verification"]
    risk_level = "low"
    input_schema = _origin_no_options_schema()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        url = _normalize_base_origin(target)
        request = Request(
            url=url,
            method="GET",
            headers={
                "User-Agent": "AutoSecAudit-CookieAudit/0.1",
                "Accept": "text/html,application/json,*/*;q=0.8",
            },
        )
        try:
            with urlopen(request, timeout=8.0) as response:
                status_code = int(response.status)
                cookies = response.headers.get_all("Set-Cookie") or []
        except HTTPError as exc:
            status_code = int(exc.code)
            cookies = exc.headers.get_all("Set-Cookie") or []
        except (URLError, TimeoutError, OSError) as exc:
            output = StandardToolOutput(status="error", metadata={"error": str(exc)})
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        findings: list[StandardFinding] = []
        parsed_cookies: list[dict[str, Any]] = []
        is_https = urlparse(url).scheme == "https"
        for raw_cookie in cookies:
            segments = [segment.strip() for segment in raw_cookie.split(";") if segment.strip()]
            if not segments:
                continue
            cookie_name = segments[0].split("=", maxsplit=1)[0].strip()
            attribute_set = {segment.split("=", maxsplit=1)[0].strip().lower() for segment in segments[1:]}
            parsed_cookie = {
                "name": cookie_name,
                "secure": "secure" in attribute_set,
                "httponly": "httponly" in attribute_set,
                "samesite": any(segment.lower().startswith("samesite=") for segment in segments[1:]),
            }
            parsed_cookies.append(parsed_cookie)
            if is_https and not parsed_cookie["secure"]:
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:{cookie_name}:secure",
                        tool=self.name,
                        severity="medium",
                        category="misconfig",
                        title="Cookie Missing Secure Attribute",
                        description=f"Cookie {cookie_name} is set over HTTPS without the Secure attribute.",
                        evidence={"cookie": parsed_cookie, "status_code": status_code},
                        remediation="Mark sensitive cookies as Secure on HTTPS origins.",
                    )
                )
            if not parsed_cookie["httponly"]:
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:{cookie_name}:httponly",
                        tool=self.name,
                        severity="low",
                        category="misconfig",
                        title="Cookie Missing HttpOnly Attribute",
                        description=f"Cookie {cookie_name} is accessible to client-side scripts.",
                        evidence={"cookie": parsed_cookie, "status_code": status_code},
                        remediation="Use HttpOnly for session and sensitive cookies whenever possible.",
                    )
                )
            if not parsed_cookie["samesite"]:
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:{cookie_name}:samesite",
                        tool=self.name,
                        severity="low",
                        category="misconfig",
                        title="Cookie Missing SameSite Attribute",
                        description=f"Cookie {cookie_name} does not declare SameSite.",
                        evidence={"cookie": parsed_cookie, "status_code": status_code},
                        remediation="Set SameSite=Lax or SameSite=Strict unless cross-site behavior is required.",
                    )
                )
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={"cookies": parsed_cookies},
            metadata={"url": url, "cookie_count": len(parsed_cookies)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentCSPEvaluatorTool(BaseAgentTool):
    """Evaluate CSP quality rather than mere presence."""

    name = "csp_evaluator"
    description = "Evaluate Content-Security-Policy quality and risky directives."
    cost = 4
    priority = 23
    category = "testing"
    target_types = ["origin_url"]
    phase_affinity = ["deep_testing", "verification"]
    risk_level = "low"
    input_schema = _origin_no_options_schema()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        del options
        started = time.perf_counter()
        origin = _normalize_base_origin(target)
        try:
            status_code, headers, _body, final_url = _http_fetch_text(origin, timeout=8.0, max_bytes=200_000)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            output = StandardToolOutput(status="error", metadata={"error": str(exc)})
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        csp = str(headers.get("content-security-policy", "")).strip()
        findings: list[StandardFinding] = []
        if not csp:
            findings.append(
                StandardFinding(
                    id=f"{self.name}:missing",
                    tool=self.name,
                    severity="medium",
                    category="misconfig",
                    title="Content-Security-Policy Missing",
                    description="No CSP header was observed on the target origin.",
                    evidence={"url": final_url, "status_code": status_code},
                    remediation="Deploy a restrictive Content-Security-Policy tailored to the application.",
                )
            )
        else:
            lowered = csp.lower()
            risky_tokens = [token for token in ("'unsafe-inline'", "'unsafe-eval'", " data:", " http:", " *") if token in lowered]
            if risky_tokens:
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:risky",
                        tool=self.name,
                        severity="medium",
                        category="misconfig",
                        title="Risky CSP Directives Present",
                        description="The CSP header contains directives that materially weaken protection.",
                        evidence={"url": final_url, "csp": csp, "risky_tokens": risky_tokens},
                        remediation="Remove unsafe or overly broad sources from script/style/object directives.",
                    )
                )
            if "script-src" not in lowered and "default-src" not in lowered:
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:no_script_control",
                        tool=self.name,
                        severity="low",
                        category="misconfig",
                        title="CSP Lacks Script Source Restrictions",
                        description="The CSP header does not define script-src or default-src.",
                        evidence={"url": final_url, "csp": csp},
                        remediation="Declare explicit script-src or default-src directives.",
                    )
                )
        csp_data: dict[str, Any] = {
            "present": bool(csp),
            "url": final_url,
            "policy": csp or None,
            "risky_tokens": risky_tokens if csp else [],
            "has_script_src": "script-src" in (csp or "").lower() if csp else False,
            "has_default_src": "default-src" in (csp or "").lower() if csp else False,
        }
        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={"csp_evaluation": csp_data},
            follow_up_hints=["http_security_headers"] if findings else [],
            metadata={"url": final_url, "csp_present": bool(csp)},
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentCveLookupTool(BaseAgentTool):
    """Query NVD CVE data for one detected technology component."""

    name = "cve_lookup"
    description = "Query NVD for known CVEs based on detected technology stack."
    cost = 5
    priority = 35
    category = "validation"
    target_types = ["tech_component"]
    phase_affinity = ["verification"]
    depends_on = ["tech_stack_fingerprint"]
    risk_level = "safe"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.5}
    default_options = {
        "component": "$component",
        "version": "$version",
        "service": "$service",
        "rag_intel_hits": "$rag_intel_hits",
        "rag_recommended_tools": "$rag_recommended_tools",
        "max_results": 10,
        "severity": "medium",
    }
    input_schema = {
        "target_mode": "https_origin_or_host",
        "required": ["component"],
        "properties": {
            "component": {
                "type": "string",
                "min_length": 1,
                "max_length": 128,
                "error": "cve_lookup_component_invalid",
            },
            "version": {
                "type": "string",
                "min_length": 1,
                "max_length": 64,
                "allow_blank": True,
                "error": "cve_lookup_version_invalid",
            },
            "service": {
                "type": "string",
                "allow_blank": True,
                "max_length": 64,
                "error": "cve_lookup_service_invalid",
            },
            "rag_intel_hits": {
                "type": "array",
                "max_items": 20,
                "items": {"type": "object"},
                "error": "cve_lookup_rag_hits_invalid",
            },
            "rag_recommended_tools": {
                "type": "array",
                "max_items": 20,
                "items": {"type": "string"},
                "error": "cve_lookup_rag_tools_invalid",
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "error": "cve_lookup_max_results_invalid",
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "error": "cve_lookup_severity_invalid",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "cve_lookup_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        component = str(options.get("component", "")).strip()
        version = str(options.get("version", "")).strip() or None
        service_name = str(options.get("service", "")).strip().lower() or None
        rag_hits = [item for item in options.get("rag_intel_hits", []) if isinstance(item, dict)] if isinstance(options.get("rag_intel_hits", []), list) else []
        rag_recommended_tools = [
            str(item).strip()
            for item in options.get("rag_recommended_tools", [])
            if str(item).strip()
        ] if isinstance(options.get("rag_recommended_tools", []), list) else []
        if not component or component.startswith("$"):
            parsed = urlparse(target if "://" in target else f"https://{target}")
            component = (parsed.hostname or "").strip().lower()
        if not component:
            output = StandardToolOutput(
                status="error",
                metadata={"error": "cve_lookup_component_missing"},
            )
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error="cve_lookup_component_missing",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        max_results = max(1, min(int(options.get("max_results", 10) or 10), 50))
        severity = str(options.get("severity", "medium")).strip().lower() or None
        component_text = f"{component}/{version}" if version else component

        try:
            service = NvdCveService()
            results = service.lookup_components(
                [component_text],
                severity=severity,
                max_results_per_component=max_results,
                service=service_name,
                rag_hits=rag_hits,
                rag_recommended_tools=rag_recommended_tools,
            )
        except CveServiceError as exc:
            output = StandardToolOutput(
                status="error",
                metadata={
                    "error": str(exc),
                    "component": component,
                    "version": version,
                    "service": service_name,
                },
            )
            return _standard_tool_result(
                ok=False,
                tool_name=self.name,
                target=target,
                output=output,
                error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        findings: list[StandardFinding] = []
        candidates: list[dict[str, Any]] = []
        template_capability_index: dict[str, dict[str, Any]] = {}
        for item in results:
            cve_id = str(item.get("cve_id", "")).strip().upper()
            if not cve_id:
                continue
            cvss_score = item.get("cvss_score")
            normalized_cvss = float(cvss_score) if isinstance(cvss_score, (int, float)) else None
            severity_text = str(item.get("severity", "medium")).strip().lower() or "medium"
            has_template = bool(item.get("has_nuclei_template", False))
            template_capability = item.get("template_capability", {})
            if isinstance(template_capability, dict):
                template_capability_index[cve_id] = template_capability
            description = str(item.get("description", "")).strip() or "Potentially affected CVE entry from NVD."
            findings.append(
                StandardFinding(
                    id=f"{self.name}:{component}:{cve_id}",
                    tool=self.name,
                    severity=severity_text,
                    category="vuln",
                    title=f"{cve_id} Potential Exposure",
                    description=description,
                    evidence={
                        "target": target,
                        "component": component,
                        "version": version,
                        "service": service_name,
                        "cve_id": cve_id,
                        "cvss_score": normalized_cvss,
                        "rank": item.get("rank"),
                        "template_capability": template_capability,
                    },
                    remediation="Confirm deployed version and apply vendor patch guidance if vulnerable.",
                    cvss_score=normalized_cvss,
                )
            )
            candidates.append(
                {
                    "cve_id": cve_id,
                    "target": target,
                    "component": component,
                    "version": version,
                    "service": service_name,
                    "cvss_score": normalized_cvss,
                    "severity": severity_text,
                    "has_nuclei_template": has_template,
                    "template_capability": template_capability,
                    "rank": int(item.get("rank", 0) or 0),
                    "safe_only": True,
                    "allow_high_risk": False,
                    "authorization_confirmed": False,
                }
            )

        follow_up_hints: list[str] = []
        if any(item.get("has_nuclei_template", False) for item in candidates):
            follow_up_hints.append("cve_verify")
        if "poc_sandbox_exec" in {item.lower() for item in rag_recommended_tools}:
            follow_up_hints.append("poc_sandbox_exec")

        output = StandardToolOutput(
            status="completed",
            findings=findings,
            surface_updates={
                "cve_lookup_results": results,
                "cve_candidates": [item for item in candidates if item.get("has_nuclei_template", False)],
                "template_capability_index": template_capability_index,
            },
            follow_up_hints=follow_up_hints,
            metadata={
                "component": component,
                "version": version,
                "service": service_name,
                "result_count": len(results),
                "rag_context_applied": bool(rag_hits or rag_recommended_tools),
            },
        )
        return _standard_tool_result(
            ok=True,
            tool_name=self.name,
            target=target,
            output=output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


@register_tool
class AgentCveVerifyTool(BaseAgentTool):
    """Verify selected CVE IDs using nuclei CVE templates."""

    name = "cve_verify"
    description = "Verify specific CVE IDs using nuclei CVE templates."
    cost = 25
    priority = 45
    category = "validation"
    target_types = ["cve_candidate"]
    phase_affinity = ["verification"]
    depends_on = ["cve_lookup"]
    risk_level = "high"
    retry_policy = {"max_retries": 1, "backoff_seconds": 1.5}
    default_options = {
        "cve_ids": "$cve_ids",
        "component": "$component",
        "version": "$version",
        "service": "$service",
        "rag_intel_hits": "$rag_intel_hits",
        "rag_recommended_tools": "$rag_recommended_tools",
        "safe_only": "$safe_only",
        "authorization_confirmed": "$authorization_confirmed",
        "allow_high_risk": "$allow_high_risk",
        "timeout_seconds": 180,
        "safety_grade": "$safety_grade",
    }
    input_schema = {
        "target_mode": "https_origin_or_host",
        "required": ["cve_ids", "authorization_confirmed", "safe_only", "allow_high_risk"],
        "properties": {
            "cve_ids": {
                "type": "array",
                "min_items": 1,
                "max_items": 20,
                "items": {
                    "type": "string",
                    "pattern": r"CVE-\d{4}-\d{4,8}",
                    "error": "cve_verify_invalid_cve_id",
                },
                "error": "cve_verify_invalid_cve_id",
            },
            "component": {
                "type": "string",
                "allow_blank": True,
                "max_length": 128,
                "error": "cve_verify_component_invalid",
            },
            "version": {
                "type": "string",
                "allow_blank": True,
                "max_length": 80,
                "error": "cve_verify_version_invalid",
            },
            "service": {
                "type": "string",
                "allow_blank": True,
                "max_length": 64,
                "error": "cve_verify_service_invalid",
            },
            "rag_intel_hits": {
                "type": "array",
                "max_items": 20,
                "items": {"type": "object"},
                "error": "cve_verify_rag_hits_invalid",
            },
            "rag_recommended_tools": {
                "type": "array",
                "max_items": 20,
                "items": {"type": "string"},
                "error": "cve_verify_rag_tools_invalid",
            },
            "safe_only": {
                "type": "boolean",
                "error": "cve_verify_safe_only_must_be_bool",
            },
            "authorization_confirmed": {
                "type": "boolean",
                "error": "cve_verify_authorization_confirmed_must_be_bool",
            },
            "allow_high_risk": {
                "type": "boolean",
                "error": "cve_verify_allow_high_risk_must_be_bool",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 900,
                "error": "cve_verify_timeout_out_of_bounds",
            },
            "safety_grade": {
                "type": "string",
                "enum": ["conservative", "balanced", "aggressive"],
                "error": "cve_verify_safety_grade_invalid",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "cve_verify_options_invalid_keys",
    }

    def check_availability(self) -> tuple[bool, str | None]:
        """Mirror nuclei runtime availability check."""
        return NucleiTool().check_availability()

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        cve_ids = self._coerce_cve_ids(options.get("cve_ids"))
        component = str(options.get("component", "")).strip().lower() or None
        version = str(options.get("version", "")).strip() or None
        service_name = str(options.get("service", "")).strip().lower() or None
        rag_hits = [item for item in options.get("rag_intel_hits", []) if isinstance(item, dict)] if isinstance(options.get("rag_intel_hits", []), list) else []
        rag_recommended_tools = [
            str(item).strip()
            for item in options.get("rag_recommended_tools", [])
            if str(item).strip()
        ] if isinstance(options.get("rag_recommended_tools", []), list) else []
        safe_only = self._as_bool(options.get("safe_only"), True)
        authorization_confirmed = self._as_bool(options.get("authorization_confirmed"), False)
        allow_high_risk = self._as_bool(options.get("allow_high_risk"), False)
        safety_grade = normalize_safety_grade(options.get("safety_grade", "balanced"))

        if safety_grade == "conservative":
            return self._error_result(
                target=target,
                started=started,
                message="cve_verify_denied_in_conservative_grade",
            )
        if not authorization_confirmed:
            return self._error_result(
                target=target,
                started=started,
                message="authorization_confirmed_required_for_cve_verify",
            )
        if allow_high_risk and safety_grade != "aggressive":
            return self._error_result(
                target=target,
                started=started,
                message="allow_high_risk_requires_aggressive_grade",
            )
        if not safe_only and not allow_high_risk:
            return self._error_result(
                target=target,
                started=started,
                message="unsafe_verification_requires_allow_high_risk",
            )
        if not cve_ids:
            return self._error_result(
                target=target,
                started=started,
                message="cve_verify_requires_at_least_one_cve_id",
            )

        timeout_seconds = float(options.get("timeout_seconds", 180.0) or 180.0)
        severities = ["info", "low", "medium"] if safe_only else ["info", "low", "medium", "high", "critical"]
        verification_order, template_capabilities, selected_templates = self._build_verification_plan(
            cve_ids=cve_ids,
            component=component,
            service=service_name,
            rag_hits=rag_hits,
            rag_recommended_tools=rag_recommended_tools,
        )

        nuclei = NucleiTool()
        nuclei_result = nuclei.run(
            target=target,
            options={
                "templates": selected_templates or ["cves/"],
                "template_id": verification_order,
                "severity": severities,
                "timeout_seconds": timeout_seconds,
            },
        )
        nuclei_data = nuclei_result.data if isinstance(nuclei_result.data, dict) else {}
        nuclei_findings = nuclei_data.get("findings", []) if isinstance(nuclei_data.get("findings", []), list) else []

        verified_by_cve: dict[str, dict[str, Any]] = {}
        for finding in nuclei_findings:
            if not isinstance(finding, dict):
                continue
            cve_id = self._extract_cve_id(finding)
            if not cve_id:
                continue
            verified_by_cve.setdefault(cve_id, finding)

        verification_rows: list[dict[str, Any]] = []
        findings: list[StandardFinding] = []
        for cve_id in verification_order:
            matched = verified_by_cve.get(cve_id)
            verified = matched is not None
            capability = template_capabilities.get(cve_id, {})
            if verified and isinstance(matched, dict):
                severity_text = str(matched.get("severity", "medium")).strip().lower() or "medium"
                evidence = matched.get("model", {}).get("evidence", {}) if isinstance(matched.get("model", {}), dict) else {}
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:{cve_id}",
                        tool=self.name,
                        severity=severity_text,
                        category="vuln",
                        title=f"{cve_id} Verified",
                        description=f"Nuclei template matched for {cve_id}.",
                        evidence=(
                            (evidence if isinstance(evidence, dict) else {"raw": matched})
                            | {
                                "component": component,
                                "version": version,
                                "service": service_name,
                                "template_capability": capability,
                            }
                        ),
                        remediation="Apply vendor patch or mitigation for the verified CVE.",
                        cvss_score=None,
                        cve_id=cve_id,
                        cve_verified=True,
                    )
                )
            else:
                findings.append(
                    StandardFinding(
                        id=f"{self.name}:{cve_id}:not_verified",
                        tool=self.name,
                        severity="info",
                        category="validation",
                        title=f"{cve_id} Not Verified",
                        description=f"No positive nuclei match was observed for {cve_id}.",
                        evidence={
                            "target": target,
                            "cve_id": cve_id,
                            "component": component,
                            "version": version,
                            "service": service_name,
                            "template_capability": capability,
                        },
                        remediation="Perform manual validation if exposure is still suspected.",
                        cve_id=cve_id,
                        cve_verified=False,
                    )
                )
            verification_rows.append(
                {
                    "cve_id": cve_id,
                    "verified": verified,
                    "target": target,
                    "component": component,
                    "version": version,
                    "service": service_name,
                    "template_capability": capability,
                }
            )

        status = "completed" if nuclei_result.ok else "failed"
        if nuclei_result.error and status == "completed":
            status = "error"
        output = StandardToolOutput(
            status=status,
            findings=findings,
            surface_updates={
                "cve_verification": verification_rows,
                "template_capability_index": template_capabilities,
            },
            metadata={
                "requested_cve_ids": cve_ids,
                "verification_order": verification_order,
                "selected_templates": selected_templates or ["cves/"],
                "component": component,
                "version": version,
                "service": service_name,
                "rag_recommended_tools": rag_recommended_tools,
                "safe_only": safe_only,
                "allow_high_risk": allow_high_risk,
                "safety_grade": safety_grade,
                "nuclei_error": nuclei_result.error,
                "nuclei_payload": nuclei_data.get("payload", {}),
            },
        )
        return _standard_tool_result(
            ok=(status == "completed"),
            tool_name=self.name,
            target=target,
            output=output,
            error=nuclei_result.error,
            raw_output=nuclei_result.raw_output,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _as_bool(value: Any, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        return bool(default)

    @staticmethod
    def _coerce_cve_ids(value: Any) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        values: list[str]
        if isinstance(value, list):
            values = [str(item).strip() for item in value if str(item).strip()]
        elif isinstance(value, str):
            values = [item.strip() for item in value.split(",") if item.strip()]
        else:
            values = []
        for item in values:
            normalized = item.upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,8}", normalized):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)
        return output

    @staticmethod
    def _extract_cve_id(finding: dict[str, Any]) -> str:
        for candidate in (
            str(finding.get("name", "")),
            str(finding.get("evidence", "")),
            str((finding.get("model", {}) if isinstance(finding.get("model", {}), dict) else {}).get("evidence", {})),
        ):
            match = re.search(r"(CVE-\d{4}-\d{4,8})", candidate, flags=re.IGNORECASE)
            if match:
                return match.group(1).upper()
        return ""

    @staticmethod
    def _build_verification_plan(
        *,
        cve_ids: list[str],
        component: str | None,
        service: str | None,
        rag_hits: list[dict[str, Any]] | None = None,
        rag_recommended_tools: list[str] | None = None,
    ) -> tuple[list[str], dict[str, dict[str, Any]], list[str]]:
        ranked_rows = NvdCveService.rank_cve_candidates(
            [{"cve_id": cve_id} for cve_id in cve_ids if str(cve_id).strip()],
            component=component,
            version=None,
            service=service,
            rag_hits=rag_hits or [],
            rag_recommended_tools=rag_recommended_tools or [],
        )
        ordered = [str(item.get("cve_id", "")).strip().upper() for item in ranked_rows if str(item.get("cve_id", "")).strip()]
        capabilities = {
            cve_id: item.get("template_capability", {}) if isinstance(item.get("template_capability", {}), dict) else {}
            for cve_id, item in ((str(row.get("cve_id", "")).strip().upper(), row) for row in ranked_rows)
            if cve_id
        }
        selected_templates: list[str] = []
        seen_templates: set[str] = set()
        for cve_id in ordered:
            capability = capabilities.get(cve_id) or {}
            paths = capability.get("template_paths", [])
            if not isinstance(paths, list):
                continue
            for path in paths:
                normalized = str(path).strip()
                if not normalized or normalized in seen_templates:
                    continue
                seen_templates.add(normalized)
                selected_templates.append(normalized)
        return ordered, capabilities, selected_templates[:20]


@register_tool
class AgentPocSandboxExecTool(BaseAgentTool):
    """Execute controlled PoC code in sandbox and return evidence."""

    name = "poc_sandbox_exec"
    description = "Execute approved PoC code in an isolated Python sandbox for evidence collection."
    cost = 18
    priority = 42
    category = "validation"
    target_types = ["tech_component"]
    phase_affinity = ["verification"]
    depends_on = ["cve_lookup"]
    risk_level = "high"
    retry_policy = {"max_retries": 0, "backoff_seconds": 0.0}
    default_options = {
        "code_template": "$poc_template",
        "code": "",
        "cve_id": "$cve_id",
        "cve_ids": "$cve_ids",
        "component": "$component",
        "version": "$version",
        "service": "$service",
        "port": "$port",
        "rag_intel_hits": "$rag_intel_hits",
        "rag_recommended_tools": "$rag_recommended_tools",
        "approval_granted": "$approval_granted",
        "authorization_confirmed": "$authorization_confirmed",
        "timeout_seconds": 25,
        "safe_mode": True,
        "safety_grade": "$safety_grade",
    }
    input_schema = {
        "target_mode": "https_origin_or_host",
        "required": ["approval_granted", "authorization_confirmed", "timeout_seconds", "safe_mode"],
        "properties": {
            "code_template": {
                "type": "string",
                "enum": [
                    "auto",
                    "http_probe",
                    "tcp_banner_probe",
                    "redis_ping_info_probe",
                    "memcached_stats_probe",
                    "ssh_banner_probe",
                    "tls_handshake_probe",
                    "none",
                ],
                "error": "poc_sandbox_exec_invalid_template",
            },
            "code": {
                "type": "string",
                "max_length": 12000,
                "error": "poc_sandbox_exec_code_invalid",
            },
            "cve_id": {
                "type": "string",
                "pattern": r"CVE-\d{4}-\d{4,8}",
                "allow_blank": True,
                "error": "poc_sandbox_exec_invalid_cve_id",
            },
            "cve_ids": {
                "type": "array",
                "max_items": 20,
                "items": {
                    "type": "string",
                    "pattern": r"CVE-\d{4}-\d{4,8}",
                    "error": "poc_sandbox_exec_invalid_cve_id",
                },
                "error": "poc_sandbox_exec_invalid_cve_ids",
            },
            "component": {
                "type": "string",
                "allow_blank": True,
                "max_length": 128,
                "error": "poc_sandbox_exec_component_invalid",
            },
            "version": {
                "type": "string",
                "allow_blank": True,
                "max_length": 80,
                "error": "poc_sandbox_exec_version_invalid",
            },
            "service": {
                "type": "string",
                "allow_blank": True,
                "max_length": 64,
                "error": "poc_sandbox_exec_service_invalid",
            },
            "port": {
                "type": "integer",
                "minimum": 0,
                "maximum": 65535,
                "error": "poc_sandbox_exec_port_invalid",
            },
            "rag_intel_hits": {
                "type": "array",
                "max_items": 20,
                "items": {"type": "object"},
                "error": "poc_sandbox_exec_rag_hits_invalid",
            },
            "rag_recommended_tools": {
                "type": "array",
                "max_items": 20,
                "items": {"type": "string"},
                "error": "poc_sandbox_exec_rag_tools_invalid",
            },
            "approval_granted": {
                "type": "boolean",
                "error": "poc_sandbox_exec_approval_granted_must_be_bool",
            },
            "authorization_confirmed": {
                "type": "boolean",
                "error": "poc_sandbox_exec_authorization_confirmed_must_be_bool",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 120,
                "error": "poc_sandbox_exec_timeout_out_of_bounds",
            },
            "safe_mode": {
                "type": "boolean",
                "error": "poc_sandbox_exec_safe_mode_must_be_bool",
            },
            "safety_grade": {
                "type": "string",
                "enum": ["conservative", "balanced", "aggressive"],
                "error": "poc_sandbox_exec_safety_grade_invalid",
            },
        },
        "additional_properties": False,
        "additional_properties_error": "poc_sandbox_exec_options_invalid_keys",
    }

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        started = time.perf_counter()
        approval_granted = self._as_bool(options.get("approval_granted"), default=False)
        authorization_confirmed = self._as_bool(options.get("authorization_confirmed"), default=False)
        safe_mode = self._as_bool(options.get("safe_mode"), default=True)
        timeout_seconds = float(options.get("timeout_seconds", 25) or 25)
        safety_grade = normalize_safety_grade(options.get("safety_grade", "balanced"))
        cve_id = str(options.get("cve_id", "")).strip().upper()
        cve_ids = AgentCveVerifyTool._coerce_cve_ids(options.get("cve_ids"))
        code_template = str(options.get("code_template", "auto")).strip().lower() or "auto"
        code = str(options.get("code", "")).strip()
        service = str(options.get("service", "")).strip().lower()
        component = str(options.get("component", "")).strip().lower()
        version = str(options.get("version", "")).strip() or None
        rag_hits = [item for item in options.get("rag_intel_hits", []) if isinstance(item, dict)] if isinstance(options.get("rag_intel_hits", []), list) else []
        rag_recommended_tools = [
            str(item).strip()
            for item in options.get("rag_recommended_tools", [])
            if str(item).strip()
        ] if isinstance(options.get("rag_recommended_tools", []), list) else []
        try:
            port = int(options.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0

        if cve_id and cve_id not in cve_ids:
            cve_ids = [cve_id, *cve_ids]
        ranked_cve_candidates = NvdCveService.rank_cve_candidates(
            [{"cve_id": candidate} for candidate in cve_ids if candidate],
            component=component or None,
            version=version,
            service=service or None,
            rag_hits=rag_hits,
            rag_recommended_tools=rag_recommended_tools,
        )
        candidate_order = [
            str(item.get("cve_id", "")).strip().upper()
            for item in ranked_cve_candidates
            if str(item.get("cve_id", "")).strip()
        ]
        if not cve_id and candidate_order:
            cve_id = candidate_order[0]
        selected_capability = next(
            (
                item.get("template_capability", {})
                for item in ranked_cve_candidates
                if str(item.get("cve_id", "")).strip().upper() == cve_id and isinstance(item.get("template_capability", {}), dict)
            ),
            {},
        )

        if not authorization_confirmed:
            return self._error_result(
                target=target,
                started=started,
                message="authorization_confirmed_required_for_poc_sandbox_exec",
            )
        if not approval_granted:
            return self._error_result(
                target=target,
                started=started,
                message="approval_required_for_poc_sandbox_exec",
            )
        if safety_grade != "aggressive":
            return self._error_result(
                target=target,
                started=started,
                message="poc_sandbox_exec_requires_aggressive_grade",
            )
        if not safe_mode:
            return self._error_result(
                target=target,
                started=started,
                message="poc_sandbox_exec_safe_mode_must_be_true",
            )
        if cve_id and not re.fullmatch(r"CVE-\d{4}-\d{4,8}", cve_id):
            return self._error_result(
                target=target,
                started=started,
                message="poc_sandbox_exec_invalid_cve_id",
            )
        effective_template = code_template
        if not code:
            effective_template = self._resolve_template_name(
                target=target,
                template=code_template,
                service=service,
                component=component,
                port=port,
                template_capability=selected_capability if isinstance(selected_capability, dict) else None,
            )
            code = self._template_code(
                target=target,
                cve_id=cve_id,
                template=effective_template,
                service=service,
                component=component,
                version=version,
                port=port,
            )
        elif code_template == "auto":
            effective_template = "custom"

        runner = SandboxRunner()
        execution = runner.run_python(
            code=code,
            timeout_seconds=timeout_seconds,
            max_output_bytes=120000,
        )
        stdout = str(execution.stdout or "")
        stderr = str(execution.stderr or "")
        vulnerable_signal = ("VULNERABLE" in stdout.upper()) or ("VULNERABLE" in stderr.upper())
        protocol_evidence = self._extract_protocol_evidence(
            stdout=stdout,
            stderr=stderr,
            template=effective_template,
            target=target,
            cve_id=cve_id,
            component=component,
            version=version,
            service=service,
            port=port,
        )
        primary_protocol_evidence = protocol_evidence[0] if protocol_evidence else {}
        severity = "high" if vulnerable_signal else ("medium" if execution.ok else "info")
        finding_title = (
            f"PoC sandbox execution signaled vulnerability {cve_id}".strip()
            if vulnerable_signal
            else "PoC sandbox execution completed"
        )
        finding_desc = (
            "Sandbox PoC emitted explicit vulnerability signal."
            if vulnerable_signal
            else "Sandbox PoC completed without explicit vulnerability signal."
        )
        findings = [
            StandardFinding(
                id=f"{self.name}:{cve_id or 'generic'}",
                tool=self.name,
                severity=severity,
                category="validation",
                title=finding_title,
                description=finding_desc,
                evidence={
                    "target": target,
                    "cve_id": cve_id or None,
                    "template": effective_template,
                    "component": component or None,
                    "version": version,
                    "service": service or None,
                    "port": port or None,
                    "protocol_evidence": primary_protocol_evidence if isinstance(primary_protocol_evidence, dict) else {},
                    "exit_code": execution.exit_code,
                    "timed_out": execution.timed_out,
                    "stdout_preview": stdout[:2000],
                    "stderr_preview": stderr[:2000],
                },
                remediation=(
                    "Validate exploitability manually and apply patch/mitigation immediately."
                    if vulnerable_signal
                    else "Review PoC output and adjust probes for deterministic reproduction."
                ),
                cve_id=cve_id or None,
                cve_verified=bool(vulnerable_signal),
            )
        ]
        output_status = "completed" if execution.ok else "failed"
        if execution.timed_out:
            output_status = "error"
        output = StandardToolOutput(
            status=output_status,
            findings=findings,
            surface_updates={
                "poc_sandbox_runs": [
                    {
                        "target": target,
                        "cve_id": cve_id or None,
                        "ok": execution.ok,
                        "exit_code": execution.exit_code,
                        "timed_out": execution.timed_out,
                        "vulnerability_signal": vulnerable_signal,
                        "template": effective_template,
                        "protocol_evidence_count": len(protocol_evidence),
                        "effective_cve_id": cve_id or None,
                    }
                ],
                "poc_protocol_evidence": protocol_evidence,
                "poc_candidate_order": candidate_order,
                "template_capability_index": {
                    str(item.get("cve_id", "")).strip().upper(): item.get("template_capability", {})
                    for item in ranked_cve_candidates
                    if str(item.get("cve_id", "")).strip()
                },
            },
            metadata={
                "execution": execution.to_dict(),
                "template": effective_template,
                "safe_mode": safe_mode,
                "safety_grade": safety_grade,
                "component": component or None,
                "version": version,
                "service": service or None,
                "port": port or None,
                "protocol_evidence_count": len(protocol_evidence),
                "candidate_order": candidate_order,
                "rag_recommended_tools": rag_recommended_tools,
            },
        )
        return _standard_tool_result(
            ok=(output_status == "completed"),
            tool_name=self.name,
            target=target,
            output=output,
            error="sandbox_timeout" if execution.timed_out else None,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _error_result(self, *, target: str, started: float, message: str) -> ToolExecutionResult:
        output = StandardToolOutput(status="error", metadata={"error": message})
        return _standard_tool_result(
            ok=False,
            tool_name=self.name,
            target=target,
            output=output,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _template_code(
        *,
        target: str,
        cve_id: str,
        template: str,
        service: str,
        component: str,
        version: str | None,
        port: int,
    ) -> str:
        template = AgentPocSandboxExecTool._resolve_template_name(
            target=target,
            template=template,
            service=service,
            component=component,
            port=port,
        )
        if template == "none":
            return (
                "print('No template selected. Provide explicit code for sandbox execution.')\n"
                "raise SystemExit(1)\n"
            )
        marker = cve_id or "CVE-UNSPECIFIED"
        if template == "redis_ping_info_probe":
            return (
                "import json, socket\n"
                f"TARGET = {target!r}\n"
                f"PORT = {port!r}\n"
                f"CVE = {marker!r}\n"
                "host = TARGET\n"
                "if '://' in TARGET:\n"
                "    raise SystemExit('redis_ping_info_probe expects host target')\n"
                "with socket.create_connection((host, PORT or 6379), timeout=8) as sock:\n"
                "    sock.settimeout(8)\n"
                "    sock.sendall(b'PING\\r\\n')\n"
                "    pong = sock.recv(256).decode('utf-8', errors='replace').strip()\n"
                "    sock.sendall(b'INFO server\\r\\n')\n"
                "    info = sock.recv(2048).decode('utf-8', errors='replace').strip()\n"
                "version = ''\n"
                "for line in info.splitlines():\n"
                "    if line.lower().startswith('redis_version:'):\n"
                "        version = line.split(':', 1)[1].strip()\n"
                "        break\n"
                "print('AUTOSECAUDIT_EVIDENCE ' + json.dumps({'protocol':'redis','host':host,'port':PORT or 6379,'ping_response':pong,'redis_version':version,'unauthenticated':pong.startswith('+PONG')}, sort_keys=True))\n"
                "print(f'REDIS probe target={host}:{PORT} pong={pong[:80]} version={version} cve={CVE}')\n"
                "if pong.startswith('+PONG') or 'redis_version:' in info.lower():\n"
                "    print(f'VULNERABLE_SIGNAL {CVE} {host}:{PORT}')\n"
            )
        if template == "memcached_stats_probe":
            return (
                "import json, socket\n"
                f"TARGET = {target!r}\n"
                f"PORT = {port!r}\n"
                f"CVE = {marker!r}\n"
                "host = TARGET\n"
                "if '://' in TARGET:\n"
                "    raise SystemExit('memcached_stats_probe expects host target')\n"
                "with socket.create_connection((host, PORT or 11211), timeout=8) as sock:\n"
                "    sock.settimeout(8)\n"
                "    sock.sendall(b'version\\r\\n')\n"
                "    version_line = sock.recv(256).decode('utf-8', errors='replace').strip()\n"
                "    sock.sendall(b'stats\\r\\n')\n"
                "    stats = sock.recv(2048).decode('utf-8', errors='replace').strip()\n"
                "version_value = version_line.split(' ', 1)[1].strip() if version_line.startswith('VERSION ') else ''\n"
                "print('AUTOSECAUDIT_EVIDENCE ' + json.dumps({'protocol':'memcached','host':host,'port':PORT or 11211,'version':version_value,'stats_preview':stats[:240],'unauthenticated':version_line.startswith('VERSION')}, sort_keys=True))\n"
                "print(f'MEMCACHED probe target={host}:{PORT} version={version_line[:120]} stats={stats[:200]} cve={CVE}')\n"
                "if version_line.startswith('VERSION') or 'STAT ' in stats:\n"
                "    print(f'VULNERABLE_SIGNAL {CVE} {host}:{PORT}')\n"
            )
        if template == "ssh_banner_probe":
            return (
                "import json, socket\n"
                f"TARGET = {target!r}\n"
                f"PORT = {port!r}\n"
                f"VERSION = {version!r}\n"
                f"CVE = {marker!r}\n"
                "host = TARGET\n"
                "if '://' in TARGET:\n"
                "    raise SystemExit('ssh_banner_probe expects host target')\n"
                "with socket.create_connection((host, PORT or 22), timeout=8) as sock:\n"
                "    sock.settimeout(8)\n"
                "    banner = sock.recv(1024).decode('utf-8', errors='replace').strip()\n"
                "    if not banner:\n"
                "        sock.sendall(b'SSH-2.0-AutoSecAudit\\r\\n')\n"
                "        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()\n"
                "print('AUTOSECAUDIT_EVIDENCE ' + json.dumps({'protocol':'ssh','host':host,'port':PORT or 22,'banner':banner[:240],'reported_version':VERSION or ''}, sort_keys=True))\n"
                "print(f'SSH probe target={host}:{PORT} banner={banner[:240]} version={VERSION or \"\"} cve={CVE}')\n"
                "lowered = banner.lower()\n"
                "if 'openssh_5' in lowered or 'openssh_6' in lowered or 'dropbear_201' in lowered:\n"
                "    print(f'VULNERABLE_SIGNAL {CVE} {host}:{PORT}')\n"
            )
        if template == "tcp_banner_probe":
            return (
                "import socket\n"
                f"TARGET = {target!r}\n"
                f"SERVICE = {service!r}\n"
                f"COMPONENT = {component!r}\n"
                f"VERSION = {version!r}\n"
                f"PORT = {port!r}\n"
                f"CVE = {marker!r}\n"
                "probe = b''\n"
                "if SERVICE == 'redis' or PORT == 6379:\n"
                "    probe = b'PING\\r\\n'\n"
                "elif SERVICE == 'memcached' or PORT == 11211:\n"
                "    probe = b'version\\r\\n'\n"
                "elif SERVICE == 'ssh' or PORT == 22:\n"
                "    probe = b'SSH-2.0-AutoSecAudit\\r\\n'\n"
                "host = TARGET\n"
                "if '://' in TARGET:\n"
                "    raise SystemExit('tcp_banner_probe expects host target')\n"
                "with socket.create_connection((host, PORT or 0), timeout=8) as sock:\n"
                "    sock.settimeout(8)\n"
                "    banner = b''\n"
                "    try:\n"
                "        banner = sock.recv(1024)\n"
                "    except TimeoutError:\n"
                "        banner = b''\n"
                "    except socket.timeout:\n"
                "        banner = b''\n"
                "    if not banner and probe:\n"
                "        sock.sendall(probe)\n"
                "        try:\n"
                "            banner = sock.recv(1024)\n"
                "        except socket.timeout:\n"
                "            banner = b''\n"
                "text = banner.decode('utf-8', errors='replace').strip()\n"
                "print(f'TCP probe service={SERVICE or COMPONENT} target={host}:{PORT} version={VERSION or \"\"} banner={text[:240]} cve={CVE}')\n"
                "lowered = text.lower()\n"
                "if (SERVICE == 'redis' and lowered.startswith('+pong')) or (SERVICE == 'memcached' and lowered.startswith('version')):\n"
                "    print(f'VULNERABLE_SIGNAL {CVE} {host}:{PORT}')\n"
                "if SERVICE == 'ssh' and ('openssh_5' in lowered or 'openssh_6' in lowered):\n"
                "    print(f'VULNERABLE_SIGNAL {CVE} {host}:{PORT}')\n"
            )
        if template == "tls_handshake_probe":
            return (
                "import json, socket, ssl\n"
                f"TARGET = {target!r}\n"
                f"PORT = {port!r}\n"
                f"CVE = {marker!r}\n"
                "host = TARGET\n"
                "if '://' in TARGET:\n"
                "    from urllib.parse import urlparse\n"
                "    parsed = urlparse(TARGET)\n"
                "    host = parsed.hostname or TARGET\n"
                "    PORT = parsed.port or PORT or 443\n"
                "context = ssl.create_default_context()\n"
                "context.check_hostname = False\n"
                "context.verify_mode = ssl.CERT_NONE\n"
                "with socket.create_connection((host, PORT or 443), timeout=8) as raw_sock:\n"
                "    raw_sock.settimeout(8)\n"
                "    with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:\n"
                "        version = tls_sock.version() or ''\n"
                "        cipher = tls_sock.cipher()\n"
                "cipher_name = (cipher[0] if cipher else '').upper()\n"
                "weak_tls = version in {'TLSv1', 'TLSv1.1'} or any(token in cipher_name for token in {'RC4', '3DES', 'DES', 'NULL', 'MD5'})\n"
                "print('AUTOSECAUDIT_EVIDENCE ' + json.dumps({'protocol':'tls','host':host,'port':PORT or 443,'tls_version':version,'cipher':cipher[0] if cipher else '', 'weak_tls':weak_tls}, sort_keys=True))\n"
                "print(f'TLS probe target={host}:{PORT} version={version} cipher={cipher[0] if cipher else \"\"} cve={CVE}')\n"
                "if version in {'TLSv1', 'TLSv1.1'} or any(token in cipher_name for token in {'RC4', '3DES', 'DES', 'NULL', 'MD5'}):\n"
                "    print(f'VULNERABLE_SIGNAL {CVE} {host}:{PORT}')\n"
            )
        return (
            "from urllib.request import Request, urlopen\n"
            "from urllib.error import URLError, HTTPError\n"
            f"TARGET = {target!r}\n"
            f"CVE = {marker!r}\n"
            "try:\n"
            "    req = Request(TARGET, method='GET', headers={'User-Agent':'AutoSecAudit-PoC/0.1'})\n"
            "    with urlopen(req, timeout=8) as resp:\n"
            "        status = int(getattr(resp, 'status', 0) or 0)\n"
            "        body = (resp.read(120000) or b'').decode('utf-8', errors='replace')\n"
            "    print(f'PoC probe status={status} target={TARGET} cve={CVE}')\n"
            "    if status in {500, 502, 503} and ('traceback' in body.lower() or 'exception' in body.lower()):\n"
            "        print(f'VULNERABLE_SIGNAL {CVE} {TARGET}')\n"
            "except HTTPError as exc:\n"
            "    print(f'PoC HTTPError code={exc.code} target={TARGET} cve={CVE}')\n"
            "except URLError as exc:\n"
            "    print(f'PoC URLError target={TARGET} reason={exc}')\n"
            "\n"
        )

    @staticmethod
    def _resolve_template_name(
        *,
        target: str,
        template: str,
        service: str,
        component: str,
        port: int,
        template_capability: dict[str, Any] | None = None,
    ) -> str:
        normalized_template = str(template or "").strip().lower() or "auto"
        if normalized_template != "auto":
            return normalized_template
        normalized_service = str(service or component).strip().lower()
        capability_tags = {
            str(item).strip().lower()
            for item in ((template_capability or {}).get("protocol_tags", []) if isinstance(template_capability, dict) else [])
            if str(item).strip()
        }
        parsed = urlparse(target if "://" in target else "")
        if capability_tags.intersection({"redis"}) or normalized_service == "redis" or port == 6379:
            return "redis_ping_info_probe"
        if capability_tags.intersection({"memcached"}) or normalized_service == "memcached" or port == 11211:
            return "memcached_stats_probe"
        if capability_tags.intersection({"ssh", "openssh", "dropbear"}) or normalized_service in {"ssh", "openssh", "dropbear"} or port == 22:
            return "ssh_banner_probe"
        if capability_tags.intersection({"tls", "ssl", "https"}) or normalized_service in {"tls", "ssl", "https"} or parsed.scheme == "https" or port in {443, 8443, 9443}:
            return "tls_handshake_probe"
        if parsed.scheme in {"http", "https"}:
            return "http_probe"
        return "tcp_banner_probe"

    @staticmethod
    def _extract_protocol_evidence(
        *,
        stdout: str,
        stderr: str,
        template: str,
        target: str,
        cve_id: str,
        component: str,
        version: str | None,
        service: str,
        port: int,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for raw_line in f"{stdout}\n{stderr}".splitlines():
            line = str(raw_line).strip()
            if not line.startswith("AUTOSECAUDIT_EVIDENCE "):
                continue
            payload = line.removeprefix("AUTOSECAUDIT_EVIDENCE ").strip()
            try:
                item = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            normalized = dict(item)
            normalized.setdefault("template", template)
            normalized.setdefault("target", target)
            normalized.setdefault("cve_id", cve_id or None)
            normalized.setdefault("component", component or None)
            normalized.setdefault("version", version)
            normalized.setdefault("service", service or None)
            normalized.setdefault("port", port or None)
            records.append(normalized)
        return records

    @staticmethod
    def _as_bool(value: Any, *, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return bool(default)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
            return bool(default)
        return bool(value)


def load_builtin_agent_tools() -> list[str]:
    """
    Ensure all built-in tools are registered.

    Notes:
    - Classes in this module are registered by import side-effect.
    - Nuclei/Dirsearch tools live in `autosecaudit.tools.*` and are imported
      here for registration side-effect as well.
    """
    from autosecaudit.tools import dirsearch_tool as _dirsearch_tool  # noqa: F401
    from autosecaudit.tools import nuclei_tool as _nuclei_tool  # noqa: F401

    return list_tools()
