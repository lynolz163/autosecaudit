"""Tests for API router registration and versioned OpenAPI paths."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from autosecaudit.webapp.fastapi_app import _resolve_frontend_dir, create_app, resolve_runtime_paths
from autosecaudit.webapp.server import CodexWebAuthManager, JobManager


@pytest.fixture()
def web_app(tmp_path: Path):
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
    try:
        yield app
    finally:
        manager.close()


def test_versioned_auth_and_user_routes_are_registered(web_app) -> None:
    paths = {route.path for route in web_app.routes}
    assert "/api/auth/login" in paths
    assert "/api/v1/auth/login" in paths
    assert "/api/users" in paths
    assert "/api/v1/users" in paths
    assert "/api/jobs" in paths
    assert "/api/v1/jobs" in paths
    assert "/api/jobs/catalog" in paths
    assert "/api/v1/jobs/catalog" in paths
    assert "/api/reports" in paths
    assert "/api/v1/reports" in paths
    assert "/api/dashboard/summary" in paths
    assert "/api/v1/dashboard/summary" in paths
    assert "/api/assets" in paths
    assert "/api/v1/assets" in paths
    assert "/api/schedules" in paths
    assert "/api/v1/schedules" in paths
    assert "/api/plugins" in paths
    assert "/api/v1/plugins" in paths
    assert "/api/llm/codex/config" in paths
    assert "/api/v1/llm/codex/config" in paths
    assert "/api/cve/search" in paths
    assert "/api/v1/cve/search" in paths
    assert "/api/cve/job/{job_id}" in paths
    assert "/api/v1/cve/job/{job_id}" in paths
    assert "/api/cve/verify" in paths
    assert "/api/v1/cve/verify" in paths
    assert "/api/mission/parse" in paths
    assert "/api/v1/mission/parse" in paths
    assert "/api/mission/execute" in paths
    assert "/api/v1/mission/execute" in paths
    assert "/api/rag/corpus" in paths
    assert "/api/v1/rag/corpus" in paths
    assert "/api/rag/search" in paths
    assert "/api/v1/rag/search" in paths
    assert "/api/settings/notifications" in paths
    assert "/api/v1/settings/notifications" in paths
    assert "/api/audit/events" in paths
    assert "/api/v1/audit/events" in paths
    assert "/oauth/codex/callback" in paths


def test_openapi_prefers_v1_auth_and_user_routes(web_app) -> None:
    paths = set(web_app.openapi()["paths"].keys())
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/users" in paths
    assert "/api/v1/jobs" in paths
    assert "/api/v1/jobs/catalog" in paths
    assert "/api/v1/reports" in paths
    assert "/api/v1/dashboard/summary" in paths
    assert "/api/v1/assets" in paths
    assert "/api/v1/schedules" in paths
    assert "/api/v1/plugins" in paths
    assert "/api/v1/llm/codex/config" in paths
    assert "/api/v1/cve/search" in paths
    assert "/api/v1/cve/job/{job_id}" in paths
    assert "/api/v1/cve/verify" in paths
    assert "/api/v1/mission/parse" in paths
    assert "/api/v1/mission/execute" in paths
    assert "/api/v1/rag/corpus" in paths
    assert "/api/v1/rag/search" in paths
    assert "/api/v1/settings/notifications" in paths
    assert "/api/v1/audit/events" in paths
    assert "/api/auth/login" not in paths
    assert "/api/users" not in paths
    assert "/api/jobs" not in paths
    assert "/api/jobs/catalog" not in paths
    assert "/api/reports" not in paths
    assert "/api/dashboard/summary" not in paths
    assert "/api/assets" not in paths
    assert "/api/schedules" not in paths
    assert "/api/plugins" not in paths
    assert "/api/llm/codex/config" not in paths
    assert "/api/cve/search" not in paths
    assert "/api/cve/job/{job_id}" not in paths
    assert "/api/cve/verify" not in paths
    assert "/api/mission/parse" not in paths
    assert "/api/mission/execute" not in paths
    assert "/api/rag/corpus" not in paths
    assert "/api/rag/search" not in paths
    assert "/api/settings/notifications" not in paths
    assert "/api/audit/events" not in paths
    assert "/oauth/codex/callback" not in paths


def test_metrics_endpoint_is_exposed_without_openapi_registration(web_app) -> None:
    client = TestClient(web_app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "autosecaudit_http_requests" in response.text or "http_request_duration" in response.text
    assert "autosecaudit_jobs_total" in response.text
    assert "/metrics" not in set(web_app.openapi()["paths"].keys())


def test_frontend_dir_prefers_dist_by_default_and_static_by_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    static_dir = workspace / "autosecaudit" / "webapp" / "static"
    dist_dir = workspace / "autosecaudit" / "webapp" / "frontend_dist"
    static_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text("<html>static</html>", encoding="utf-8")
    (dist_dir / "index.html").write_text("<html>dist</html>", encoding="utf-8")

    monkeypatch.delenv("AUTOSECAUDIT_WEB_FRONTEND", raising=False)
    resolved_default = _resolve_frontend_dir(workspace=workspace, static_dir=static_dir)
    assert resolved_default != static_dir.resolve()
    assert resolved_default.name == "frontend_dist"

    monkeypatch.setenv("AUTOSECAUDIT_WEB_FRONTEND", "static")
    assert _resolve_frontend_dir(workspace=workspace, static_dir=static_dir) == static_dir.resolve()
