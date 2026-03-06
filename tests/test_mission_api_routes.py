from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from autosecaudit.webapp.fastapi_app import create_app, resolve_runtime_paths
from autosecaudit.webapp.server import CodexWebAuthManager, JobManager


def _build_app(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    output_root = workspace / "output" / "web-jobs"
    static_dir, _frontend_dir = resolve_runtime_paths(workspace=workspace)
    manager = JobManager(
        workspace_dir=workspace,
        output_root=output_root,
        python_executable=sys.executable,
        max_jobs=20,
        max_running_jobs=4,
    )
    app = create_app(
        workspace=workspace,
        static_dir=static_dir,
        manager=manager,
        codex_auth=CodexWebAuthManager(),
        api_token="bootstrap-token",
    )
    return app, manager


def test_mission_parse_route_returns_compiled_draft_and_session(tmp_path: Path) -> None:
    app, manager = _build_app(tmp_path)
    try:
        client = TestClient(app)
        response = client.post(
            "/api/v1/mission/parse",
            headers={"x-api-token": "bootstrap-token"},
            json={"message": "对 example.com 进行信息收集"},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["session_id"]
        assert payload["draft"]["target"] == "example.com"
        assert payload["draft"]["intent"] == "recon"
        assert payload["draft"]["payload"]["mode"] == "agent"
        assert len(payload["messages"]) == 2
    finally:
        manager.close()


def test_mission_parse_route_supports_follow_up_dialogue(tmp_path: Path) -> None:
    app, manager = _build_app(tmp_path)
    try:
        client = TestClient(app)
        first = client.post(
            "/api/v1/mission/parse",
            headers={"x-api-token": "bootstrap-token"},
            json={"message": "对 example.com 进行渗透测试"},
        )
        session_id = first.json()["session_id"]

        second = client.post(
            "/api/v1/mission/parse",
            headers={"x-api-token": "bootstrap-token"},
            json={"session_id": session_id, "message": "不要跑 Playwright，继续深测 443/8443"},
        )

        assert second.status_code == 200
        payload = second.json()
        assert payload["session_id"] == session_id
        assert payload["draft"]["depth"] == "deep"
        assert 443 in payload["draft"]["payload"]["surface"]["focus_ports"]
        assert "dynamic_crawl" not in payload["draft"]["selected_tools"]
        assert len(payload["messages"]) == 4
    finally:
        manager.close()


def test_mission_execute_route_submits_job_with_compiled_payload(tmp_path: Path) -> None:
    app, manager = _build_app(tmp_path)
    captured: dict[str, object] = {}

    def fake_submit(payload, *, actor="web"):
        captured["payload"] = payload
        captured["actor"] = actor
        return {
            "job_id": "job-123",
            "status": "queued",
            "target": payload["target"],
            "mode": payload["mode"],
            "safety_grade": payload["safety_grade"],
            "report_lang": payload["report_lang"],
            "log_line_count": 0,
            "artifact_count": 0,
            "command_preview": [],
        }

    app.state.manager.submit = fake_submit
    try:
        client = TestClient(app)
        response = client.post(
            "/api/v1/mission/execute",
            headers={"x-api-token": "bootstrap-token"},
            json={"message": "对 example.com 进行渗透测试"},
        )

        assert response.status_code == 201
        payload = response.json()
        assert payload["session_id"]
        assert payload["job"]["job_id"] == "job-123"
        assert payload["draft"]["intent"] == "pentest"
        assert captured["payload"]["target"] == "example.com"
        assert captured["payload"]["mode"] == "agent"
        assert captured["payload"]["autonomy_mode"] == payload["draft"]["autonomy_mode"]
        assert captured["actor"] == "bootstrap:bootstrap-admin"
    finally:
        manager.close()


def test_mission_parse_route_uses_llm_structured_parser_when_available(tmp_path: Path) -> None:
    app, manager = _build_app(tmp_path)
    app.state.manager.get_mission_llm_completion = lambda: (
        lambda _prompt: json.dumps(
            {
                "target": "llm-route.example.com",
                "intent": "recon",
                "depth": "light",
                "surface": {"focus_ports": [443]},
            }
        )
    )
    try:
        client = TestClient(app)
        response = client.post(
            "/api/v1/mission/parse",
            headers={"x-api-token": "bootstrap-token"},
            json={"message": "帮我处理这个站"},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["draft"]["target"] == "llm-route.example.com"
        assert payload["draft"]["intent"] == "recon"
        assert payload["draft"]["payload"]["surface"]["focus_ports"] == [443]
        assert payload["draft"]["payload"]["surface"]["mission_parser_source"] == "llm"
        assert payload["draft"]["payload"]["surface"]["mission_parser_values"]["target"] == "llm-route.example.com"
    finally:
        manager.close()
