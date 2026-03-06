"""CORS misconfiguration validation plugin."""

from __future__ import annotations

import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from autosecaudit.core.models import AuditContext, Finding, PluginResult, utc_now_iso
from autosecaudit.core.plugin import AuditPlugin
from autosecaudit.core.registry import registry


@registry.register
class CORSMisconfigurationPlugin(AuditPlugin):
    """Probe for overly permissive CORS behavior with safe read-only requests."""

    plugin_id = "cors_misconfiguration"
    name = "CORS Misconfiguration Check"
    category = "validation"
    read_only = True

    _TEST_ORIGIN = "https://autosecaudit.invalid"

    def run(self, context: AuditContext) -> PluginResult:
        started_at = utc_now_iso()
        url = self._normalize_target_url(context.config.target)
        context.log_operation(
            plugin_id=self.plugin_id,
            action="cors_probe",
            status="info",
            detail=f"Testing CORS headers for: {url}",
        )

        try:
            headers, status_code, method = self._collect_headers(url)
        except HTTPError as exc:
            headers = {k.lower(): v for k, v in exc.headers.items()}
            status_code = exc.code
            method = "GET"
        except (URLError, socket.timeout, TimeoutError) as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"CORS probe request failed: {exc}",
            )
        except OSError as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"CORS probe system error: {exc}",
            )

        findings = self._build_findings(url=url, status_code=status_code, method=method, headers=headers)
        status = "failed" if any(item.severity != "info" for item in findings) else "passed"
        metadata = {
            "url": url,
            "status_code": status_code,
            "probe_method": method,
            "allow_origin": headers.get("access-control-allow-origin"),
            "allow_credentials": headers.get("access-control-allow-credentials"),
            "allow_methods": headers.get("access-control-allow-methods"),
            "vary": headers.get("vary"),
        }
        return PluginResult(
            plugin_id=self.plugin_id,
            plugin_name=self.name,
            category=self.category,
            status=status,
            started_at=started_at,
            ended_at=utc_now_iso(),
            findings=findings,
            metadata=metadata,
        )

    def _collect_headers(self, url: str) -> tuple[dict[str, str], int, str]:
        for method in ("OPTIONS", "GET"):
            request = Request(
                url,
                method=method,
                headers={
                    "Origin": self._TEST_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                    "User-Agent": "AutoSecAudit/0.1",
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

    def _build_findings(
        self,
        *,
        url: str,
        status_code: int,
        method: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        allow_origin = str(headers.get("access-control-allow-origin", "")).strip()
        allow_credentials = str(headers.get("access-control-allow-credentials", "")).strip().lower()
        evidence = {
            "url": url,
            "status_code": status_code,
            "probe_method": method,
            "access_control_allow_origin": allow_origin,
            "access_control_allow_credentials": allow_credentials,
        }

        findings: list[Finding] = []
        if allow_origin == "*" and allow_credentials == "true":
            findings.append(
                Finding(
                    finding_id="VAL-CORS-WILDCARD-CREDS-001",
                    title="CORS Allows Any Origin With Credentials",
                    description="The application permits credentialed cross-origin access from any origin.",
                    severity="high",
                    recommendation="Restrict allowed origins and disable credential sharing for wildcard origins.",
                    evidence=evidence,
                )
            )
        elif allow_origin == "*":
            findings.append(
                Finding(
                    finding_id="VAL-CORS-WILDCARD-001",
                    title="CORS Allows Any Origin",
                    description="The application responds with a wildcard Access-Control-Allow-Origin header.",
                    severity="medium",
                    recommendation="Restrict allowed origins to trusted frontends only.",
                    evidence=evidence,
                )
            )
        elif allow_origin == self._TEST_ORIGIN and allow_credentials == "true":
            findings.append(
                Finding(
                    finding_id="VAL-CORS-REFLECT-CREDS-001",
                    title="CORS Reflects Arbitrary Origin With Credentials",
                    description="The application reflects the supplied Origin header while also allowing credentials.",
                    severity="high",
                    recommendation="Validate Origin headers against an explicit allowlist before enabling credentials.",
                    evidence=evidence,
                )
            )
        elif allow_origin == self._TEST_ORIGIN:
            findings.append(
                Finding(
                    finding_id="VAL-CORS-REFLECT-001",
                    title="CORS Reflects Arbitrary Origin",
                    description="The application reflects the supplied Origin header without verifying trust.",
                    severity="medium",
                    recommendation="Validate Origin headers against an explicit allowlist.",
                    evidence=evidence,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    finding_id="VAL-CORS-HEALTHY-001",
                    title="CORS Policy Looks Restrictive",
                    description="No obvious overly permissive CORS behavior was detected in the probe response.",
                    severity="info",
                    evidence=evidence,
                )
            )
        return findings

    @staticmethod
    def _normalize_target_url(target: str) -> str:
        normalized = target if "://" in target else f"https://{target}"
        parsed = urlparse(normalized)
        if not parsed.scheme:
            return f"https://{target}"
        return normalized
