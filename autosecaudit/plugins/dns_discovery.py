"""DNS discovery plugin."""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from autosecaudit.core.models import AuditContext, Finding, PluginResult, utc_now_iso
from autosecaudit.core.plugin import AuditPlugin
from autosecaudit.core.registry import registry


@registry.register
class DNSDiscoveryPlugin(AuditPlugin):
    """Discover DNS-resolved addresses for a target hostname."""

    plugin_id = "dns_discovery"
    name = "DNS Discovery"
    category = "discovery"
    read_only = True

    def run(self, context: AuditContext) -> PluginResult:
        started_at = utc_now_iso()
        host = self._extract_host(context.config.target)
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
            action="dns_lookup",
            status="info",
            detail=f"Resolving host: {host}",
        )

        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = sorted({entry[4][0] for entry in records if entry and entry[4]})
        except socket.gaierror as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"DNS lookup failed: {exc}",
            )
        except OSError as exc:
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status="error",
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=f"System DNS error: {exc}",
            )

        findings: list[Finding] = []
        if not addresses:
            findings.append(
                Finding(
                    finding_id="DISC-DNS-001",
                    title="No DNS Address Resolved",
                    description="No IPv4/IPv6 address was resolved for the target hostname.",
                    severity="medium",
                    evidence={"host": host},
                    recommendation=(
                        "Verify DNS records and network resolver configuration for this asset."
                    ),
                )
            )
            status = "failed"
        else:
            findings.append(
                Finding(
                    finding_id="DISC-DNS-INFO-001",
                    title="DNS Addresses Discovered",
                    description="Asset discovery succeeded and DNS addresses were resolved.",
                    severity="info",
                    evidence={"host": host, "addresses": addresses},
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
            metadata={"address_count": len(addresses), "host": host},
        )

    @staticmethod
    def _extract_host(target: str) -> str:
        normalized = target if "://" in target else f"https://{target}"
        parsed = urlparse(normalized)
        return parsed.hostname or ""
