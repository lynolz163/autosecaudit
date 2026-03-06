"""HTTP security header validation plugin."""

from __future__ import annotations

import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from autosecaudit.core.models import AuditContext, Finding, PluginResult, Severity, utc_now_iso
from autosecaudit.core.plugin import AuditPlugin
from autosecaudit.core.registry import registry


@registry.register
class HTTPHeaderValidationPlugin(AuditPlugin):
    """Validate common HTTP security headers using safe read-only requests."""

    plugin_id = "http_headers_validation"
    name = "HTTP Header Validation"
    category = "validation"
    read_only = True

    REQUIRED_HEADERS: dict[str, tuple[Severity, str]] = {
        "strict-transport-security": (
            "high",
            "Enable HSTS to enforce secure transport in browsers.",
        ),
        "content-security-policy": (
            "medium",
            "Define a restrictive CSP to reduce XSS and content injection risks.",
        ),
        "x-content-type-options": (
            "low",
            "Set X-Content-Type-Options to 'nosniff'.",
        ),
        "x-frame-options": (
            "low",
            "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
        ),
        "referrer-policy": (
            "low",
            "Set Referrer-Policy (e.g. 'strict-origin-when-cross-origin') to reduce cross-origin URL leakage.",
        ),
        "permissions-policy": (
            "low",
            "Set Permissions-Policy to restrict browser feature access (camera, microphone, geolocation, etc.).",
        ),
    }

    def run(self, context: AuditContext) -> PluginResult:
        started_at = utc_now_iso()
        url = self._normalize_target_url(context.config.target)
        context.log_operation(
            plugin_id=self.plugin_id,
            action="http_request",
            status="info",
            detail=f"Fetching headers from: {url}",
        )

        try:
            request = Request(url, method="GET", headers={"User-Agent": "AutoSecAudit/0.1"})
            with urlopen(request, timeout=8) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                status_code = response.status
        except HTTPError as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"HTTP request failed with status {exc.code}",
            )
        except (URLError, socket.timeout, TimeoutError) as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"Network request error: {exc}",
            )
        except OSError as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"HTTP request system error: {exc}",
            )

        missing = [header for header in self.REQUIRED_HEADERS if header not in headers]
        findings: list[Finding] = []
        for header in missing:
            severity, recommendation = self.REQUIRED_HEADERS[header]
            findings.append(
                Finding(
                    finding_id=f"VAL-HTTP-{header.upper().replace('-', '_')}",
                    title=f"Missing HTTP Header: {header}",
                    description=f"Response is missing the security header `{header}`.",
                    severity=severity,
                    recommendation=recommendation,
                    evidence={"url": url, "status_code": status_code},
                )
            )

        status = "passed" if not findings else "failed"
        return PluginResult(
            plugin_id=self.plugin_id,
            plugin_name=self.name,
            category=self.category,
            status=status,
            started_at=started_at,
            ended_at=utc_now_iso(),
            findings=findings,
            metadata={"url": url, "missing_headers": missing, "status_code": status_code},
        )

    @staticmethod
    def _normalize_target_url(target: str) -> str:
        normalized = target if "://" in target else f"https://{target}"
        parsed = urlparse(normalized)
        if not parsed.scheme:
            return f"https://{target}"
        return normalized
