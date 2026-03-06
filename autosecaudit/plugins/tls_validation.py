"""TLS certificate validation plugin."""

from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import ParseResult, urlparse

from autosecaudit.core.models import AuditContext, Finding, PluginResult, utc_now_iso
from autosecaudit.core.plugin import AuditPlugin
from autosecaudit.core.registry import registry


@registry.register
class TLSCertificateValidationPlugin(AuditPlugin):
    """Validate TLS certificate validity period for HTTPS targets."""

    plugin_id = "tls_certificate_validation"
    name = "TLS Certificate Validation"
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
                error="Target uses HTTP; TLS certificate check skipped",
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
            action="tls_connect",
            status="info",
            detail=f"Connecting to {host}:{port} for certificate validation",
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
                error="Certificate does not contain a parseable notAfter field",
                metadata={"certificate_subject": cert.get("subject")},
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
                metadata={"certificate_subject": cert.get("subject")},
            )

        now = datetime.now(timezone.utc)
        days_left = int((expires_at - now).total_seconds() // 86400)
        findings: list[Finding] = []
        if days_left < 0:
            findings.append(
                Finding(
                    finding_id="VAL-TLS-EXPIRED-001",
                    title="TLS Certificate Expired",
                    description="The TLS certificate is expired.",
                    severity="high",
                    evidence={"host": host, "port": port, "expired_at": expires_at.isoformat()},
                    recommendation="Renew and deploy a valid TLS certificate immediately.",
                )
            )
            status = "failed"
        elif days_left <= 30:
            findings.append(
                Finding(
                    finding_id="VAL-TLS-EXPIRING-001",
                    title="TLS Certificate Expiring Soon",
                    description="The TLS certificate expires within 30 days.",
                    severity="medium",
                    evidence={"host": host, "port": port, "days_left": days_left},
                    recommendation="Plan certificate renewal before expiration.",
                )
            )
            status = "failed"
        else:
            findings.append(
                Finding(
                    finding_id="VAL-TLS-INFO-001",
                    title="TLS Certificate Validity Check Passed",
                    description="TLS certificate is valid and not near expiry.",
                    severity="info",
                    evidence={"host": host, "port": port, "days_left": days_left},
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
            metadata={"host": host, "port": port, "not_after": not_after},
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
                cert = tls_sock.getpeercert()
        return cert

    @staticmethod
    def _parse_not_after(value: str) -> datetime | None:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
