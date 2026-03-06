"""Port and service discovery plugin built on the safe Nmap wrapper."""

from __future__ import annotations

from urllib.parse import urlparse

from autosecaudit.core.models import AuditContext, Finding, PluginResult, utc_now_iso
from autosecaudit.core.plugin import AuditPlugin
from autosecaudit.core.registry import registry


@registry.register
class PortServiceScanPlugin(AuditPlugin):
    """Discover common exposed services and flag risky ports."""

    plugin_id = "port_service_scan"
    name = "Port Service Scan"
    category = "discovery"
    read_only = True

    _DEFAULT_PORTS = ",".join(
        [
            "21",
            "22",
            "25",
            "53",
            "80",
            "110",
            "111",
            "135",
            "139",
            "143",
            "389",
            "443",
            "445",
            "465",
            "587",
            "993",
            "995",
            "1433",
            "1521",
            "2049",
            "2375",
            "3306",
            "3389",
            "5432",
            "5900",
            "6379",
            "8000",
            "8080",
            "8443",
            "9200",
            "9300",
            "11211",
            "27017",
        ]
    )

    _RISKY_PORTS: dict[int, tuple[str, str]] = {
        21: ("medium", "FTP service exposed; ensure anonymous access is disabled and the service is required."),
        23: ("high", "Telnet is exposed; replace it with SSH and disable plaintext remote administration."),
        2375: ("high", "Docker remote API is exposed; bind it locally or protect it with TLS and network controls."),
        3306: ("medium", "MySQL service exposed; restrict network exposure and require strong authentication."),
        3389: ("high", "RDP service exposed; restrict access with VPN, allowlists, and MFA."),
        5432: ("medium", "PostgreSQL service exposed; restrict network access and verify authentication hardening."),
        5900: ("high", "VNC service exposed; restrict remote access and enforce strong authentication."),
        6379: ("high", "Redis service exposed; restrict access and require protected mode/authentication."),
        9200: ("high", "Elasticsearch HTTP API exposed; restrict access and require authentication."),
        9300: ("high", "Elasticsearch transport port exposed; restrict it to trusted cluster nodes."),
        11211: ("high", "Memcached service exposed; bind locally or filter access."),
        27017: ("high", "MongoDB service exposed; restrict access and require authentication."),
    }

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
                error="Unable to extract host from target",
            )

        timeout_seconds = max(5.0, min(float(context.config.plugin_timeout_seconds) - 1.0, 60.0))
        context.log_operation(
            plugin_id=self.plugin_id,
            action="nmap_service_scan",
            status="info",
            detail=f"Scanning common service ports on: {host}",
        )

        from autosecaudit.tools.nmap_tool import NmapTool

        result = NmapTool(timeout_seconds=timeout_seconds).run(
            target=host,
            options={"ports": self._DEFAULT_PORTS},
        )
        if not result.ok:
            error = str(result.error or "")
            status = "skipped" if "failed to execute nmap" in error.lower() else "error"
            return PluginResult(
                plugin_id=self.plugin_id,
                plugin_name=self.name,
                category=self.category,
                status=status,
                started_at=started_at,
                ended_at=utc_now_iso(),
                error=error or "nmap service scan failed",
            )

        payload = result.data if isinstance(result.data, dict) else {}
        hosts = payload.get("hosts", []) if isinstance(payload, dict) else []
        open_ports: list[dict[str, object]] = []
        for host_entry in hosts:
            if not isinstance(host_entry, dict):
                continue
            for port_entry in host_entry.get("open_ports", []):
                if isinstance(port_entry, dict):
                    open_ports.append(port_entry)

        findings: list[Finding] = []
        if open_ports:
            findings.append(
                Finding(
                    finding_id="DISC-PORTS-INFO-001",
                    title="Open Network Services Detected",
                    description="One or more network services are reachable on the target.",
                    severity="info",
                    evidence={
                        "host": host,
                        "open_ports": open_ports,
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    finding_id="DISC-PORTS-NONE-001",
                    title="No Common Services Detected",
                    description="No open services were detected in the curated common-port scan set.",
                    severity="info",
                    evidence={"host": host},
                )
            )

        for port_entry in open_ports:
            port = int(port_entry.get("port", 0) or 0)
            if port not in self._RISKY_PORTS:
                continue
            severity, recommendation = self._RISKY_PORTS[port]
            service_name = str(port_entry.get("service", "unknown"))
            findings.append(
                Finding(
                    finding_id=f"DISC-PORTS-RISK-{port}",
                    title=f"Potentially Risky Service Exposed: {service_name} on {port}/tcp",
                    description="A service that commonly requires strict network restriction is exposed.",
                    severity=severity,
                    recommendation=recommendation,
                    evidence={
                        "host": host,
                        "port": port,
                        "service": service_name,
                        "version": port_entry.get("version"),
                    },
                )
            )

        status = "failed" if len(findings) > 1 and any(item.severity != "info" for item in findings) else "passed"
        return PluginResult(
            plugin_id=self.plugin_id,
            plugin_name=self.name,
            category=self.category,
            status=status,
            started_at=started_at,
            ended_at=utc_now_iso(),
            findings=findings,
            metadata={
                "host": host,
                "open_port_count": len(open_ports),
                "scanned_ports": self._DEFAULT_PORTS,
            },
        )

    @staticmethod
    def _extract_host(target: str) -> str:
        normalized = target if "://" in target else f"https://{target}"
        parsed = urlparse(normalized)
        return parsed.hostname or ""
