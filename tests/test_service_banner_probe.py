from __future__ import annotations

import socket
import threading

from autosecaudit.agent_core.builtin_tools import AgentServiceBannerProbeTool


def test_service_banner_probe_captures_passive_banner() -> None:
    tool = AgentServiceBannerProbeTool()

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
        result = tool.run(
            "127.0.0.1",
            {
                "port": port,
                "service": "ssh",
                "timeout_seconds": 2,
                "read_bytes": 128,
            },
        )
        thread.join(timeout=1)

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert data["surface_delta"]["service_banners"][0]["service"] == "ssh"
    assert "SSH-2.0-OpenSSH_9.6" in data["surface_delta"]["service_banners"][0]["banner"]
    assert data["findings"][0]["severity"] == "info"


def test_service_banner_probe_uses_safe_redis_ping_when_no_initial_banner() -> None:
    tool = AgentServiceBannerProbeTool()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])

        def _serve() -> None:
            conn, _addr = server.accept()
            with conn:
                received = conn.recv(32)
                assert received == b"PING\r\n"
                conn.sendall(b"+PONG\r\n")

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        result = tool.run(
            "127.0.0.1",
            {
                "port": port,
                "service": "redis",
                "timeout_seconds": 2,
                "read_bytes": 128,
            },
        )
        thread.join(timeout=1)

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert data["surface_delta"]["service_banners"][0]["service"] == "redis"
    assert data["surface_delta"]["service_banners"][0]["probe_command"] == "PING"
    assert data["surface_delta"]["service_banners"][0]["banner"] == "+PONG"
