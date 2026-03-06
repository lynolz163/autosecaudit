"""SSL/TLS certificate expiry validation plugin."""

from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import ParseResult, urlparse

from autosecaudit.core.models import AuditContext, Finding, PluginResult, utc_now_iso
from autosecaudit.core.plugin import AuditPlugin
from autosecaudit.core.registry import registry


@registry.register
class SSLExpiryCheckPlugin(AuditPlugin):
    """Check whether the target TLS certificate is nearing expiration."""

    plugin_id = "ssl_expiry_check"
    name = "SSL Expiry Check"
    category = "validation"
    read_only = True

    def run(self, context: AuditContext) -> PluginResult:
        started_at = utc_now_iso()
        parsed = self._parse_target(context.config.target)
        host = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme.lower() == "http":
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="skipped",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error="Target uses HTTP; SSL expiry check skipped",
            )

        if not host:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error="Unable to extract hostname from target",
            )

        context.log_operation(
            plugin_id=self.plugin_id,
            action="ssl_expiry_connect",
            status="info",
            detail=f"Connecting to {host}:{port} for expiry validation",
        )

        try:
            cert = self._fetch_certificate(host, port)
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"TLS connection error: {exc}",
            )

        not_after = cert.get("notAfter")
        if not isinstance(not_after, str):
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error="Certificate notAfter field missing",
            )

        expires_at = self._parse_not_after(not_after)
        if expires_at is None:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"Unable to parse certificate expiry: {not_after}",
            )

        now = datetime.now(timezone.utc)
        days_left = int((expires_at - now).total_seconds() // 86400)
        metadata = {
            "host": host,
            "port": port,
            "days_left": days_left,
            "expires_at": expires_at.isoformat(),
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "subject_alt_name": cert.get("subjectAltName"),
        }

        findings: list[Finding] = []
        if days_left < 0:
            findings.append(
                Finding(
                    finding_id="VAL-SSL-EXPIRED-001",
                    title="SSL Certificate Expired",
                    description="The TLS certificate has already expired.",
                    severity="high",
                    recommendation="Renew and deploy a valid certificate immediately.",
                    evidence=metadata,
                )
            )
            status = "failed"
        elif days_left <= 7:
            findings.append(
                Finding(
                    finding_id="VAL-SSL-EXPIRING-CRITICAL-001",
                    title="SSL Certificate Expiring Within 7 Days",
                    description="The TLS certificate expires within the next 7 days.",
                    severity="high",
                    recommendation="Schedule an immediate certificate renewal and deployment.",
                    evidence=metadata,
                )
            )
            status = "failed"
        elif days_left <= 30:
            findings.append(
                Finding(
                    finding_id="VAL-SSL-EXPIRING-SOON-001",
                    title="SSL Certificate Expiring Soon",
                    description="The TLS certificate expires within the next 30 days.",
                    severity="medium",
                    recommendation="Plan a certificate renewal before the expiry window is reached.",
                    evidence=metadata,
                )
            )
            status = "failed"
        else:
            findings.append(
                Finding(
                    finding_id="VAL-SSL-HEALTHY-001",
                    title="SSL Certificate Expiry Healthy",
                    description="The TLS certificate is valid and not close to expiry.",
                    severity="info",
                    evidence=metadata,
                )
            )
            status = "passed"

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

    @staticmethod
    def _parse_target(target: str) -> ParseResult:
        normalized = target if "://" in target else f"https://{target}"
        return urlparse(normalized)

    @staticmethod
    def _fetch_certificate(host: str, port: int) -> dict[str, object]:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert()

    @staticmethod
    def _parse_not_after(value: str) -> datetime | None:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
