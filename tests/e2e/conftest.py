from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(base_url: str, process: subprocess.Popen[str], timeout_seconds: float = 60.0) -> None:
    deadline = time.time() + max(5.0, float(timeout_seconds))
    while time.time() < deadline:
        if process.poll() is not None:
            output = ""
            if process.stdout is not None:
                try:
                    output = process.stdout.read()
                except Exception:
                    output = ""
            raise RuntimeError(f"E2E server exited before startup.\n{output}")
        try:
            with urllib.request.urlopen(f"{base_url}/healthz", timeout=2.0) as response:
                if int(getattr(response, "status", 0) or 0) == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"E2E server did not become ready within {timeout_seconds:.0f}s")


@pytest.fixture(scope="session")
def e2e_server_url(tmp_path_factory: pytest.TempPathFactory) -> str:
    output_root = tmp_path_factory.mktemp("autosecaudit-e2e-output") / "web-jobs"
    port = _find_free_port()
    env = dict(os.environ)
    env.update(
        {
            "AUTOSECAUDIT_WEB_JWT_SECRET": "AutoSecAudit-E2E-JWT-Secret-0123456789",
            "AUTOSECAUDIT_WEB_DEFAULT_ADMIN_USERNAME": "admin",
            "AUTOSECAUDIT_WEB_DEFAULT_ADMIN_PASSWORD": "AdminPass1234!",
            "AUTOSECAUDIT_WEB_DEFAULT_ADMIN_DISPLAY_NAME": "E2E Admin",
            "AUTOSECAUDIT_WEB_ENFORCE_HTTPS": "0",
        }
    )

    command = [
        sys.executable,
        "-c",
        "from autosecaudit.webapp.server import main; raise SystemExit(main())",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--workspace",
        str(REPO_ROOT),
        "--output-root",
        str(output_root),
        "--max-jobs",
        "8",
        "--max-running-jobs",
        "2",
    ]
    process = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    base_url = f"http://127.0.0.1:{port}"
    _wait_for_server(base_url, process)
    try:
        yield base_url
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)
