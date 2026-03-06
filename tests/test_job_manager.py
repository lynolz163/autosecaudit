from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

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


def test_job_manager_propagates_safety_grade_to_cli_command(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 3,
                "global_timeout": 300,
                "safety_grade": "aggressive",
            },
            target="https://example.com",
            mode="agent",
            output_dir=tmp_path / "out",
        )

        assert "--agent-safety-grade" in command
        assert command[command.index("--agent-safety-grade") + 1] == "aggressive"
    finally:
        manager.close()


def test_job_manager_propagates_tool_selection_to_cli_command(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 3,
                "global_timeout": 300,
                "safety_grade": "balanced",
                "tools": ["git_exposure_check", "api_schema_discovery", "cookie_security_audit"],
            },
            target="https://example.com",
            mode="agent",
            output_dir=tmp_path / "out",
        )

        assert "--tools" in command
        assert command[command.index("--tools") + 1] == (
            "git_exposure_check,api_schema_discovery,cookie_security_audit"
        )
    finally:
        manager.close()


def test_job_manager_propagates_skill_selection_to_cli_command(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 3,
                "global_timeout": 300,
                "safety_grade": "balanced",
                "skills": ["git_exposure_check", "api_schema_discovery"],
            },
            target="https://example.com",
            mode="agent",
            output_dir=tmp_path / "out",
        )

        assert "--skills" in command
        assert command[command.index("--skills") + 1] == "git_exposure_check,api_schema_discovery"
        assert "--tools" in command
        assert command[command.index("--tools") + 1] == "git_exposure_check,api_schema_discovery"
    finally:
        manager.close()


def test_job_manager_returns_planner_catalog_with_tools_and_skills(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        catalog = manager.get_planner_catalog()

        assert "tools" in catalog
        assert "skills" in catalog
        assert any(item["name"] == "git_exposure_check" for item in catalog["tools"])
        assert any(item["name"] == "git_exposure_check" and item["tool"] == "git_exposure_check" for item in catalog["skills"])
    finally:
        manager.close()


def test_job_manager_builds_surface_file_arg_for_agent_jobs(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        output_dir = tmp_path / "out"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 1,
                "global_timeout": 300,
                "safety_grade": "balanced",
                "surface": {
                    "authorization_confirmed": True,
                    "cve_candidates": [{"cve_id": "CVE-2024-1111", "target": "https://example.com"}],
                },
            },
            target="https://example.com",
            mode="agent",
            output_dir=output_dir,
        )

        assert "--surface-file" in command
        surface_file = Path(command[command.index("--surface-file") + 1])
        assert surface_file.exists()
    finally:
        manager.close()


def test_job_manager_merges_autonomy_mode_into_surface_file(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        output_dir = tmp_path / "out"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 1,
                "global_timeout": 300,
                "safety_grade": "balanced",
                "autonomy_mode": "constrained",
            },
            target="https://example.com",
            mode="agent",
            output_dir=output_dir,
        )

        assert "--surface-file" in command
        surface_file = Path(command[command.index("--surface-file") + 1])
        assert '"autonomy_mode": "constrained"' in surface_file.read_text(encoding="utf-8")
    finally:
        manager.close()


def test_job_manager_propagates_multi_agent_and_approval_flags(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 2,
                "global_timeout": 300,
                "safety_grade": "aggressive",
                "multi_agent": True,
                "multi_agent_rounds": 2,
                "approval_granted": True,
            },
            target="https://example.com",
            mode="agent",
            output_dir=tmp_path / "out",
        )

        assert "--multi-agent" in command
        assert "--multi-agent-rounds" in command
        assert command[command.index("--multi-agent-rounds") + 1] == "2"
        assert "--approval-granted" in command
    finally:
        manager.close()


def test_job_manager_propagates_report_language_to_cli_command(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    try:
        command = manager._build_command(  # noqa: SLF001
            {
                "target": "https://example.com",
                "mode": "agent",
                "budget": 50,
                "max_iterations": 2,
                "global_timeout": 300,
                "safety_grade": "balanced",
                "report_lang": "zh-CN",
            },
            target="https://example.com",
            mode="agent",
            output_dir=tmp_path / "out",
        )

        assert "--report-lang" in command
        assert command[command.index("--report-lang") + 1] == "zh-CN"
    finally:
        manager.close()


def test_job_manager_build_runtime_llm_router_from_saved_web_settings(tmp_path: Path, monkeypatch) -> None:
    manager = _build_manager(tmp_path)
    captured: dict[str, object] = {}

    def _fake_from_cli_args(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(complete=lambda prompt: prompt)

    monkeypatch.setattr(
        "autosecaudit.webapp.services.job_manager.LLMRouter.from_cli_args",
        _fake_from_cli_args,
    )

    try:
        manager.save_llm_settings(
            {
                "preset_id": "deepseek",
                "provider_type": "openai_compatible",
                "base_url": "https://api.deepseek.com/v1",
                "model": "deepseek-chat",
                "api_key": "secret-key",
                "temperature": 0.1,
                "max_output_tokens": 2048,
                "timeout_seconds": 120,
            }
        )

        router = manager.build_runtime_llm_router()

        assert router is not None
        assert captured["llm_model"] == "deepseek-chat"
        assert captured["llm_provider_type"] == "openai_compatible"
        assert captured["llm_base_url"] == "https://api.deepseek.com/v1"
    finally:
        manager.close()
