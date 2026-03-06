"""Read-only Nmap wrapper tool."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
import subprocess
import time
from typing import Any
from xml.etree import ElementTree

from .base_tool import BaseTool, ToolExecutionResult


class NmapOutputFormat(str, Enum):
    """Supported Nmap output formats that can be parsed to JSON."""

    XML = "xml"
    GREPABLE = "grepable"


@dataclass(frozen=True)
class _PortRecord:
    """Internal normalized port record."""

    port: int
    protocol: str
    service: str
    version: str


class NmapTool(BaseTool):
    """
    Encapsulate safe Nmap scanning for agent perception.

    Notes:
    - Uses subprocess with argument list (`shell=False`) to avoid command injection.
    - Intended for authorized internal read-only discovery/validation workflows.
    """

    name = "nmap_tool"
    read_only = True
    DEFAULT_TIMEOUT_SECONDS = 300.0
    SUPPORTED_SCAN_PROFILES = {"default", "conservative_service_discovery"}

    def __init__(
        self,
        nmap_path: str = "nmap",
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        scan_profile: str = "default",
        version_detection: bool = True,
        output_format: NmapOutputFormat = NmapOutputFormat.XML,
        extra_args: list[str] | None = None,
    ) -> None:
        self._nmap_path = nmap_path
        self._timeout_seconds = timeout_seconds
        self._scan_profile = self._normalize_scan_profile(scan_profile)
        self._version_detection = bool(version_detection)
        self._output_format = output_format
        self._extra_args = list(extra_args or [])

    def run(self, target: str, options: str | dict[str, Any]) -> ToolExecutionResult:
        """
        Execute Nmap scan and return parsed structured output.

        Args:
            target: Hostname or IP.
            options: Port definition string or option dictionary.
        """
        started = time.perf_counter()
        try:
            normalized_target = self._validate_target(target)
            normalized_ports = self._coerce_ports(options)
        except ValueError as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=target,
                error=str(exc),
                duration_ms=self._elapsed_ms(started),
            )

        command = self._build_command(normalized_target, normalized_ports)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=normalized_target,
                error=f"Nmap scan timed out after {self._timeout_seconds:.1f}s",
                duration_ms=self._elapsed_ms(started),
            )
        except OSError as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=normalized_target,
                error=f"Failed to execute nmap: {exc}",
                duration_ms=self._elapsed_ms(started),
            )

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        if completed.returncode != 0:
            error = self._normalize_nmap_error(stderr or stdout)
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=normalized_target,
                error=error,
                raw_output=stdout,
                duration_ms=self._elapsed_ms(started),
            )

        if not stdout:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=normalized_target,
                error="Nmap returned empty output",
                duration_ms=self._elapsed_ms(started),
            )

        try:
            parsed = (
                self._parse_xml(stdout)
                if self._output_format == NmapOutputFormat.XML
                else self._parse_grepable(stdout)
            )
        except ValueError as exc:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=normalized_target,
                error=f"Failed to parse nmap output: {exc}",
                raw_output=stdout,
                duration_ms=self._elapsed_ms(started),
            )

        if parsed["summary"]["up_hosts"] == 0:
            return ToolExecutionResult(
                ok=False,
                tool_name=self.name,
                target=normalized_target,
                data=parsed,
                error="Target appears down or unreachable",
                raw_output=stdout,
                duration_ms=self._elapsed_ms(started),
            )

        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=normalized_target,
            data=parsed,
            raw_output=stdout,
            duration_ms=self._elapsed_ms(started),
        )

    def _coerce_ports(self, options: str | dict[str, Any]) -> str:
        if isinstance(options, dict):
            return self._validate_ports(str(options.get("ports", "top-1000")))
        return self._validate_ports(str(options))

    def _build_command(self, target: str, ports: str) -> list[str]:
        """Build a safe list-form Nmap command."""
        command = [self._nmap_path]
        if self._version_detection:
            command.append("-sV")
        command.extend(["--open", "-Pn"])

        if self._scan_profile == "conservative_service_discovery":
            host_timeout = max(15, min(int(self._timeout_seconds) - 5, 120))
            command.extend(["-T4", "--max-retries", "1", "--host-timeout", f"{host_timeout}s"])

        if ports == "top-100":
            command.extend(["--top-ports", "100"])
        elif ports == "top-1000":
            command.extend(["--top-ports", "1000"])
        else:
            command.extend(["-p", ports])

        command.extend(self._extra_args)
        if self._output_format == NmapOutputFormat.XML:
            command.extend(["-oX", "-"])
        else:
            command.extend(["-oG", "-"])
        command.append(target)
        return command

    @staticmethod
    def _validate_target(target: str) -> str:
        normalized = target.strip()
        if not normalized:
            raise ValueError("target must not be empty")
        if any(char.isspace() for char in normalized):
            raise ValueError("target must not contain spaces")
        return normalized

    @staticmethod
    def _validate_ports(ports: str) -> str:
        normalized = ports.replace(" ", "")
        if not normalized:
            raise ValueError("ports must not be empty")
        if normalized in {"top-100", "top-1000"}:
            return normalized
        if not re.fullmatch(r"[0-9,\-]+", normalized):
            raise ValueError("ports must contain only digits, commas, and dashes")

        for block in normalized.split(","):
            if "-" in block:
                parts = block.split("-", maxsplit=1)
                if len(parts) != 2 or not parts[0] or not parts[1]:
                    raise ValueError(f"invalid port range: {block}")
                start = int(parts[0])
                end = int(parts[1])
                if start > end:
                    raise ValueError(f"invalid port range: {block}")
                if start < 1 or end > 65535:
                    raise ValueError(f"port range out of bounds: {block}")
            else:
                port = int(block)
                if port < 1 or port > 65535:
                    raise ValueError(f"port out of bounds: {port}")
        return normalized

    @classmethod
    def _normalize_scan_profile(cls, value: str) -> str:
        normalized = str(value or "default").strip().lower()
        if normalized in cls.SUPPORTED_SCAN_PROFILES:
            return normalized
        return "default"

    @staticmethod
    def _parse_xml(xml_output: str) -> dict[str, Any]:
        """Parse Nmap XML output into a structured dictionary."""
        try:
            root = ElementTree.fromstring(xml_output)
        except ElementTree.ParseError as exc:
            raise ValueError(str(exc)) from exc

        hosts: list[dict[str, Any]] = []
        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

            addresses = [
                {"addr": item.get("addr", ""), "addrtype": item.get("addrtype", "")}
                for item in host_elem.findall("address")
            ]
            hostnames = [
                item.get("name", "")
                for item in host_elem.findall("./hostnames/hostname")
                if item.get("name")
            ]

            open_ports: list[dict[str, Any]] = []
            for port_elem in host_elem.findall("./ports/port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = (
                    service_elem.get("name", "unknown")
                    if service_elem is not None
                    else "unknown"
                )
                version = NmapTool._build_version_string(service_elem)
                port_record = _PortRecord(
                    port=int(port_elem.get("portid", "0")),
                    protocol=port_elem.get("protocol", ""),
                    service=service_name,
                    version=version,
                )
                open_ports.append(
                    {
                        "port": port_record.port,
                        "protocol": port_record.protocol,
                        "service": port_record.service,
                        "version": port_record.version,
                    }
                )

            hosts.append(
                {
                    "state": host_state,
                    "addresses": addresses,
                    "hostnames": hostnames,
                    "open_ports": open_ports,
                }
            )

        up_hosts = sum(1 for host in hosts if host["state"] == "up")
        open_port_count = sum(len(host["open_ports"]) for host in hosts)

        return {
            "scanner": "nmap",
            "format": "xml",
            "hosts": hosts,
            "summary": {
                "host_count": len(hosts),
                "up_hosts": up_hosts,
                "open_port_count": open_port_count,
            },
        }

    @staticmethod
    def _parse_grepable(output: str) -> dict[str, Any]:
        """Parse Nmap grepable output into a structured dictionary."""
        host_map: dict[str, dict[str, Any]] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            status_match = re.match(
                r"^Host:\s+(?P<addr>\S+)\s+\((?P<name>.*?)\)\s+Status:\s+(?P<status>\w+)",
                stripped,
            )
            if status_match:
                address = status_match.group("addr")
                host_entry = host_map.setdefault(
                    address,
                    {
                        "state": "unknown",
                        "addresses": [{"addr": address, "addrtype": "ipv4_or_hostname"}],
                        "hostnames": [],
                        "open_ports": [],
                    },
                )
                host_entry["state"] = status_match.group("status").lower()
                hostname = status_match.group("name").strip()
                if hostname:
                    host_entry["hostnames"] = [hostname]
                continue

            ports_match = re.match(
                r"^Host:\s+(?P<addr>\S+)\s+\((?P<name>.*?)\)\s+Ports:\s+(?P<ports>.+)$",
                stripped,
            )
            if not ports_match:
                continue

            address = ports_match.group("addr")
            host_entry = host_map.setdefault(
                address,
                {
                    "state": "unknown",
                    "addresses": [{"addr": address, "addrtype": "ipv4_or_hostname"}],
                    "hostnames": [],
                    "open_ports": [],
                },
            )

            hostname = ports_match.group("name").strip()
            if hostname:
                host_entry["hostnames"] = [hostname]

            port_descriptors = [item.strip() for item in ports_match.group("ports").split(",")]
            for descriptor in port_descriptors:
                if not descriptor:
                    continue

                fields = descriptor.split("/")
                if len(fields) < 7:
                    continue
                try:
                    port = int(fields[0])
                except ValueError:
                    continue
                state = fields[1].lower()
                protocol = fields[2]
                service = fields[4] or "unknown"
                version = fields[6].strip()

                if state != "open":
                    continue
                host_entry["open_ports"].append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "version": version,
                    }
                )

        hosts = list(host_map.values())
        up_hosts = sum(1 for host in hosts if host["state"] == "up")
        open_port_count = sum(len(host["open_ports"]) for host in hosts)

        return {
            "scanner": "nmap",
            "format": "grepable",
            "hosts": hosts,
            "summary": {
                "host_count": len(hosts),
                "up_hosts": up_hosts,
                "open_port_count": open_port_count,
            },
        }

    @staticmethod
    def _build_version_string(service_elem: ElementTree.Element | None) -> str:
        """Build readable service version string from Nmap service attributes."""
        if service_elem is None:
            return ""
        parts: list[str] = []
        for attr in ("product", "version", "extrainfo"):
            value = service_elem.get(attr, "").strip()
            if value:
                parts.append(value)
        return " ".join(parts)

    @staticmethod
    def _normalize_nmap_error(message: str) -> str:
        """Normalize common Nmap errors for higher-level agents."""
        lowered = message.lower()
        if "failed to resolve" in lowered:
            return "Host is unreachable: DNS resolution failed"
        if "host seems down" in lowered:
            return "Target appears down or unreachable"
        if "timed out" in lowered:
            return "Nmap scan timed out"
        return message or "Nmap execution failed"

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        """Return elapsed time in milliseconds."""
        return int((time.perf_counter() - started) * 1000)
