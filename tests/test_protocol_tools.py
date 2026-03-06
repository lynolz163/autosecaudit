from __future__ import annotations

import socket
import threading
from unittest.mock import patch

from autosecaudit.agent_core.builtin_tools import (
    AgentDnsZoneAuditTool,
    AgentMemcachedExposureCheckTool,
    AgentMysqlHandshakeProbeTool,
    AgentPostgresHandshakeProbeTool,
    AgentRedisExposureCheckTool,
    AgentReverseDnsProbeTool,
    AgentSSHAuthAuditTool,
    AgentSmtpSecurityCheckTool,
    AgentTLSServiceProbeTool,
)


def test_ssh_auth_audit_captures_banner_and_asset() -> None:
    tool = AgentSSHAuthAuditTool()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])

        def _serve() -> None:
            conn, _addr = server.accept()
            with conn:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        result = tool.run("127.0.0.1", {"port": port, "service": "ssh", "timeout_seconds": 2})
        thread.join(timeout=1)

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["title"].startswith("SSH authentication surface exposed")
    assert data["assets_delta"][0]["kind"] == "service"
    assert data["assets_delta"][0]["attributes"]["service"] == "ssh"
    assert data["surface_delta"]["tech_components"][0]["component"] == "openssh"
    assert data["surface_delta"]["tech_components"][0]["version"] == "9.6"
    assert "cve_lookup" in data["follow_up_hints"]


def test_redis_exposure_check_detects_unauthenticated_service() -> None:
    tool = AgentRedisExposureCheckTool()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])

        def _serve() -> None:
            conn, _addr = server.accept()
            with conn:
                assert conn.recv(32) == b"PING\r\n"
                conn.sendall(b"+PONG\r\n")
                assert conn.recv(64) == b"INFO server\r\n"
                conn.sendall(b"$32\r\nredis_version:7.2.1\r\nrole:master\r\n")

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        result = tool.run("127.0.0.1", {"port": port, "service": "redis", "timeout_seconds": 2})
        thread.join(timeout=1)

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["severity"] == "high"
    assert data["surface_delta"]["redis_exposure_checks"][0]["redis_version"] == "7.2.1"
    assert data["surface_delta"]["tech_components"][0]["component"] == "redis"
    assert data["surface_delta"]["tech_components"][0]["version"] == "7.2.1"
    assert "rag_intel_lookup" in data["follow_up_hints"]


def test_memcached_exposure_check_detects_open_service() -> None:
    tool = AgentMemcachedExposureCheckTool()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])

        def _serve() -> None:
            conn, _addr = server.accept()
            with conn:
                assert conn.recv(64) == b"version\r\n"
                conn.sendall(b"VERSION 1.6.22\r\n")
                assert conn.recv(64) == b"stats\r\n"
                conn.sendall(b"STAT pid 1\r\nSTAT uptime 99\r\nEND\r\n")

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        result = tool.run("127.0.0.1", {"port": port, "service": "memcached", "timeout_seconds": 2})
        thread.join(timeout=1)

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["severity"] == "high"
    assert data["surface_delta"]["memcached_exposure_checks"][0]["version"] == "1.6.22"
    assert data["surface_delta"]["tech_components"][0]["component"] == "memcached"
    assert data["surface_delta"]["tech_components"][0]["version"] == "1.6.22"
    assert "cve_lookup" in data["follow_up_hints"]


def test_tls_service_probe_emits_tls_asset_and_metadata() -> None:
    tool = AgentTLSServiceProbeTool()
    metadata = {
        "host": "example.com",
        "port": 443,
        "server_name": "example.com",
        "tls_version": "TLSv1",
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "cipher_bits": 256,
        "subject": [],
        "issuer": [],
        "subject_alt_names": ["example.com"],
        "not_after": "2026-04-01T00:00:00+00:00",
        "days_remaining": 25,
        "fingerprint_sha256": "abc123",
    }

    with patch.object(AgentTLSServiceProbeTool, "_probe_tls_metadata", return_value=metadata):
        result = tool.run("https://example.com:443", {"timeout_seconds": 2, "server_name": "example.com"})

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["severity"] == "medium"
    assert data["assets_delta"][0]["attributes"]["tls"] is True
    assert data["surface_delta"]["tls_service_metadata"][0]["tls_version"] == "TLSv1"
    assert data["surface_delta"]["tech_components"][0]["component"] == "tls"
    assert data["surface_delta"]["tech_components"][0]["version"] == "TLSv1"
    assert "rag_intel_lookup" in data["follow_up_hints"]


def test_smtp_security_check_flags_plaintext_starttls_gap() -> None:
    tool = AgentSmtpSecurityCheckTool()
    with patch.object(
        AgentSmtpSecurityCheckTool,
        "_probe_smtp",
        return_value=("220 mail.example.com ESMTP Postfix 3.8.5", "250-mail.example.com 250 AUTH PLAIN LOGIN", "plain"),
    ):
        result = tool.run("127.0.0.1", {"port": 25, "service": "smtp", "timeout_seconds": 2})

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["severity"] == "low"
    assert data["surface_delta"]["smtp_security_checks"][0]["starttls_supported"] is False
    assert data["surface_delta"]["tech_components"][0]["component"] == "postfix"
    assert data["surface_delta"]["tech_components"][0]["version"] == "3.8.5"
    assert "cve_lookup" in data["follow_up_hints"]


def test_mysql_handshake_probe_extracts_version_and_asset() -> None:
    tool = AgentMysqlHandshakeProbeTool()
    packet = b"\x1a\x00\x00\x00\x0a8.0.36-0ubuntu0\x00rest"
    with patch.object(AgentMysqlHandshakeProbeTool, "_probe_mysql_handshake", return_value=packet):
        result = tool.run("127.0.0.1", {"port": 3306, "service": "mysql", "timeout_seconds": 2})

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["surface_delta"]["mysql_handshakes"][0]["version"] == "8.0.36-0ubuntu0"
    assert data["assets_delta"][0]["attributes"]["service"] == "mysql"
    assert data["surface_delta"]["tech_components"][0]["component"] == "mysql"
    assert data["surface_delta"]["tech_components"][0]["version"] == "8.0.36-0ubuntu0"
    assert "rag_intel_lookup" in data["follow_up_hints"]


def test_postgres_handshake_probe_tracks_ssl_support_and_auth_mode() -> None:
    tool = AgentPostgresHandshakeProbeTool()
    with patch.object(AgentPostgresHandshakeProbeTool, "_probe_postgres_ssl", return_value=False), patch.object(
        AgentPostgresHandshakeProbeTool,
        "_probe_postgres_startup",
        return_value={"message_type": "R", "auth_code": 10, "auth_name": "sasl", "message_text": "AuthenticationSASL"},
    ):
        result = tool.run("127.0.0.1", {"port": 5432, "service": "postgresql", "timeout_seconds": 2})

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["severity"] == "low"
    assert data["surface_delta"]["postgres_handshakes"][0]["auth_name"] == "sasl"
    assert data["surface_delta"]["tech_components"][0]["component"] == "postgresql"
    assert "cve_lookup" in data["follow_up_hints"]


def test_dns_zone_audit_reports_zone_transfer() -> None:
    tool = AgentDnsZoneAuditTool()
    with patch.object(AgentDnsZoneAuditTool, "_resolve_dns_records", return_value={"NS": ["ns1.example.com"], "MX": ["10 mail.example.com"]}), patch.object(
        AgentDnsZoneAuditTool,
        "_attempt_zone_transfer",
        return_value={"attempted": True, "success": True, "server": "ns1.example.com", "subdomains": ["dev.example.com"]},
    ):
        result = tool.run("example.com", {"timeout_seconds": 2, "max_nameservers": 1})

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["findings"][0]["severity"] == "high"
    assert data["surface_delta"]["discovered_subdomains"] == ["dev.example.com"]
    assert "zone_transfer" in data["surface_delta"]["dns_follow_up_signals"]
    assert "reverse_dns_probe" in data["follow_up_hints"]


def test_reverse_dns_probe_links_ptr_results_to_ip_assets() -> None:
    tool = AgentReverseDnsProbeTool()
    with patch.object(AgentReverseDnsProbeTool, "_resolve_addresses", return_value=["192.0.2.10"]), patch.object(
        AgentReverseDnsProbeTool,
        "_reverse_lookup",
        return_value=["mail.example.com"],
    ):
        result = tool.run("192.0.2.10", {"max_addresses": 1})

    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert result.ok is True
    assert data["assets_delta"][0]["kind"] == "ip"
    assert data["surface_delta"]["reverse_dns_records"][0]["ptr_names"] == ["mail.example.com"]
