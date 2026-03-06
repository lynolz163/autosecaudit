from __future__ import annotations

import sys
from pathlib import Path

from autosecaudit.webapp.services.job_manager import JobManager


def _build_manager(tmp_path: Path) -> JobManager:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    output_root = workspace / "output" / "web-jobs"
    return JobManager(
        workspace_dir=workspace,
        output_root=output_root,
        python_executable=sys.executable,
        max_jobs=20,
        max_running_jobs=4,
    )


def test_llm_settings_default_timeout_is_300_seconds(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        settings = manager.get_llm_settings()
        assert settings["timeout_seconds"] == 300.0
    finally:
        manager.close()


def test_test_llm_connection_uses_requested_timeout_up_to_300_seconds(tmp_path: Path, monkeypatch) -> None:
    manager = _build_manager(tmp_path)
    captured: dict[str, float] = {}

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return b'{"choices":[{"message":{"content":"OK"}}]}'

    def _fake_urlopen(request, timeout):
        captured["timeout"] = float(timeout)
        return _FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    try:
        result = manager.test_llm_connection(
            {
                "base_url": "https://api.example.test/v1",
                "model": "demo-model",
                "timeout_seconds": 300,
            }
        )
        assert result["ok"] is True
        assert captured["timeout"] == 300.0
    finally:
        manager.close()


def test_legacy_web_llm_timeout_is_upgraded_and_forwarded_to_cli_args(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        manager.save_llm_settings(
            {
                "preset_id": "openai",
                "provider_type": "openai_compatible",
                "base_url": "https://api.example.test/v1",
                "model": "demo-model",
                "temperature": 0.2,
                "max_output_tokens": 2048,
                "timeout_seconds": 20,
            }
        )

        settings = manager.get_llm_settings()
        args = manager.get_llm_cli_args()

        assert settings["timeout_seconds"] == 300.0
        assert "--llm-timeout" in args
        assert args[args.index("--llm-timeout") + 1] == "300.0"
    finally:
        manager.close()
