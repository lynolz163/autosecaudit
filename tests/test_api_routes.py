"""Tests for API router registration and versioned OpenAPI paths."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from autosecaudit.webapp.fastapi_app import _resolve_frontend_dir, create_app, resolve_runtime_paths
from autosecaudit.webapp.server import CodexWebAuthManager, JobManager


def _build_web_app(tmp_path: Path):
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


def _seed_realtime_job(web_app, job_id: str = "job-ws-portal"):
    manager = web_app.state.manager
    output_dir = web_app.state.workspace / "output" / "web-jobs" / f"{job_id}-portal"
    agent_dir = output_dir / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)

    state_path = agent_dir / "agent_state.json"
    report_path = agent_dir / "audit_report.json"
    state_path.write_text(
        json.dumps(
            {
                "session_status": "running",
                "pending_approval": {},
                "loop_guard": {},
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    report_path.write_text(
        json.dumps(
            {
                "meta": {
                    "target": "https://portal.example.com",
                    "decision_summary": "Initial realtime summary.",
                },
                "summary": {
                    "total_findings": 0,
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                },
                "scope": {"assets": [], "surface": {}},
                "findings": [],
                "history": [],
                "thought_stream": [],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    record = {
        "job_id": job_id,
        "status": "running",
        "session_status": "running",
        "created_at": "2026-03-16T10:00:00Z",
        "started_at": "2026-03-16T10:00:05Z",
        "ended_at": None,
        "last_updated_at": "2026-03-16T10:00:05Z",
        "target": "https://portal.example.com",
        "mode": "agent",
        "safety_grade": "balanced",
        "report_lang": "zh-CN",
        "command": [sys.executable, "-m", "autosecaudit.cli"],
        "tools": [],
        "skills": [],
        "surface_file": None,
        "output_dir": str(output_dir),
        "resume": None,
        "llm_config": None,
        "return_code": None,
        "pid": 4321,
        "error": None,
        "cancel_requested": False,
        "log_line_count": 0,
        "logs": [],
        "artifacts": [],
        "pending_approval": {},
        "loop_guard": {},
    }
    with manager._lock:
        manager._jobs[job_id] = record
    manager._persist_job(job_id)
    manager._refresh_artifacts(job_id)
    manager._append_log(job_id, "[agent] planning started")
    return job_id, output_dir, report_path


@pytest.fixture()
def web_app(tmp_path: Path):
    app, manager = _build_web_app(tmp_path)
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
    assert "/api/jobs/ws" in paths
    assert "/api/v1/jobs/ws" in paths
    assert "/api/jobs/{job_id}/ws" in paths
    assert "/api/v1/jobs/{job_id}/ws" in paths
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
    assert "/api/mission/chat" in paths
    assert "/api/v1/mission/chat" in paths
    assert "/api/rag/corpus" in paths
    assert "/api/v1/rag/corpus" in paths
    assert "/api/rag/search" in paths
    assert "/api/v1/rag/search" in paths
    assert "/api/settings/notifications" in paths
    assert "/api/v1/settings/notifications" in paths
    assert "/api/audit/events" in paths
    assert "/api/v1/audit/events" in paths
    assert "/api/search/global" in paths
    assert "/api/v1/search/global" in paths
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
    assert "/api/v1/mission/chat" in paths
    assert "/api/v1/rag/corpus" in paths
    assert "/api/v1/rag/search" in paths
    assert "/api/v1/settings/notifications" in paths
    assert "/api/v1/audit/events" in paths
    assert "/api/v1/search/global" in paths
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
    assert "/api/mission/chat" not in paths
    assert "/api/rag/corpus" not in paths
    assert "/api/rag/search" not in paths
    assert "/api/settings/notifications" not in paths
    assert "/api/audit/events" not in paths
    assert "/api/search/global" not in paths
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


def test_bootstrap_api_uses_generic_unavailable_code_after_user_exists(web_app) -> None:
    web_app.state.auth_service.create_user(username="admin", password="AdminPass1234", role="admin")
    client = TestClient(web_app)

    response = client.post(
        "/api/auth/bootstrap",
        headers={"Authorization": "Bearer bootstrap-token"},
        json={"username": "next-admin", "password": "NextAdmin1234", "display_name": "Next Admin"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "bootstrap_unavailable"


def test_user_self_protection_returns_generic_error_code(web_app) -> None:
    user = web_app.state.auth_service.create_user(username="admin", password="AdminPass1234", role="admin")
    token = web_app.state.auth_service.issue_access_token(user)
    client = TestClient(web_app)

    response = client.put(
        f"/api/v1/users/{user['user_id']}",
        headers={"Authorization": f"Bearer {token}"},
        json={"enabled": False},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "user_update_rejected"


def test_job_submit_failure_is_sanitized(web_app, monkeypatch: pytest.MonkeyPatch) -> None:
    user = web_app.state.auth_service.create_user(username="admin", password="AdminPass1234", role="admin")
    token = web_app.state.auth_service.issue_access_token(user)
    client = TestClient(web_app)

    def _broken_submit(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("sqlite is locked at C:/sensitive/path.db")

    monkeypatch.setattr(web_app.state.manager, "submit", _broken_submit)

    response = client.post(
        "/api/v1/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "https://example.com", "mode": "agent"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "job_submit_failed"


def test_codex_login_failure_is_sanitized(web_app, monkeypatch: pytest.MonkeyPatch) -> None:
    user = web_app.state.auth_service.create_user(username="admin", password="AdminPass1234", role="admin")
    token = web_app.state.auth_service.issue_access_token(user)
    client = TestClient(web_app)

    def _broken_start_login(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("oauth client secret missing from disk")

    monkeypatch.setattr(web_app.state.codex_auth, "start_login", _broken_start_login)

    response = client.post(
        "/api/v1/llm/codex/login/start",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "codex_login_failed"


def test_api_rejects_tampered_jwt_token(web_app) -> None:
    user = web_app.state.auth_service.create_user(username="admin", password="AdminPass1234", role="admin")
    token = web_app.state.auth_service.issue_access_token(user)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    client = TestClient(web_app)

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"


def test_viewer_cannot_create_assets_via_api(web_app) -> None:
    user = web_app.state.auth_service.create_user(username="viewer", password="ViewerPass1234", role="viewer")
    token = web_app.state.auth_service.issue_access_token(user)
    client = TestClient(web_app)

    response = client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Blocked Asset",
            "target": "https://blocked.example.com",
            "default_mode": "agent",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "forbidden"


def test_http_requests_redirect_to_https_when_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOSECAUDIT_WEB_ENFORCE_HTTPS", "1")
    monkeypatch.setenv("AUTOSECAUDIT_WEB_HSTS_MAX_AGE_SECONDS", "31536000")
    app, manager = _build_web_app(tmp_path)
    client = TestClient(app)
    try:
        response = client.get("/healthz?full=1", follow_redirects=False)
        assert response.status_code == 307
        assert response.headers["location"] == "https://testserver/healthz?full=1"
    finally:
        manager.close()


def test_hsts_header_is_added_for_forwarded_https_requests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOSECAUDIT_WEB_ENFORCE_HTTPS", "1")
    monkeypatch.setenv("AUTOSECAUDIT_WEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AUTOSECAUDIT_WEB_HSTS_MAX_AGE_SECONDS", "7200")
    app, manager = _build_web_app(tmp_path)
    client = TestClient(app)
    try:
        response = client.get(
            "/healthz",
            headers={
                "Host": "console.example.com",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "console.example.com",
            },
        )
        assert response.status_code == 200
        assert response.headers["strict-transport-security"] == "max-age=7200; includeSubDomains"
    finally:
        manager.close()


def test_global_search_returns_assets_jobs_reports_and_findings(web_app) -> None:
    user = web_app.state.auth_service.create_user(username="viewer", password="ViewerPass1234", role="viewer")
    token = web_app.state.auth_service.issue_access_token(user)
    client = TestClient(web_app)

    web_app.state.manager.store.create_asset(
        {
            "name": "Customer Portal",
            "target": "https://portal.example.com",
            "scope": "portal.example.com",
            "default_mode": "agent",
            "tags": ["portal", "prod"],
            "default_payload": {},
            "enabled": True,
            "created_at": "2026-03-16T10:00:00Z",
            "updated_at": "2026-03-16T10:00:00Z",
            "notes": "Portal baseline asset",
        }
    )

    job_id = "job-search-portal"
    output_dir = web_app.state.workspace / "output" / "web-jobs" / job_id / "agent"
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "audit_report.json"
    report_payload = {
        "meta": {"target": "https://portal.example.com", "decision_summary": "Portal review with login focus."},
        "summary": {"total_findings": 1, "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
        "scope": {"assets": [], "surface": {}},
        "findings": [
            {
                "id": "portal-login-risk",
                "tool": "xss_protection_audit",
                "title": "Portal login flow exposed to CVE-2026-0001 style bypass",
                "severity": "high",
                "description": "Portal login page reflects unsafe portal parameters.",
                "cve_id": "CVE-2026-0001",
                "evidence": {"path": "/login"},
            }
        ],
        "history": [],
    }
    report_path.write_text(json.dumps(report_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    web_app.state.manager.store.upsert_job(
        {
            "job_id": job_id,
            "status": "completed",
            "created_at": "2026-03-16T10:05:00Z",
            "started_at": "2026-03-16T10:05:10Z",
            "ended_at": "2026-03-16T10:10:00Z",
            "last_updated_at": "2026-03-16T10:10:00Z",
            "target": "https://portal.example.com",
            "mode": "agent",
            "safety_grade": "balanced",
            "command": ["python", "-m", "autosecaudit.cli"],
            "output_dir": str(output_dir.parent),
            "resume": None,
            "llm_config": None,
            "return_code": 0,
            "pid": None,
            "error": None,
            "cancel_requested": False,
            "log_line_count": 0,
        }
    )
    web_app.state.manager.store.replace_artifacts(
        job_id,
        [{"path": "agent/audit_report.json", "size": report_path.stat().st_size, "mtime": report_path.stat().st_mtime}],
    )

    response = client.get(
        "/api/v1/search/global",
        headers={"Authorization": f"Bearer {token}"},
        params={"q": "portal", "limit": 10},
    )

    assert response.status_code == 200
    payload = response.json()
    kinds = {item["kind"] for item in payload["items"]}
    assert {"asset", "job", "report", "finding"}.issubset(kinds)
    assert payload["groups"]["finding"] >= 1


def test_job_realtime_websocket_streams_snapshot_status_and_analysis(web_app) -> None:
    user = web_app.state.auth_service.create_user(username="viewer", password="ViewerPass1234", role="viewer")
    token = web_app.state.auth_service.issue_access_token(user)
    job_id, _output_dir, report_path = _seed_realtime_job(web_app)
    client = TestClient(web_app)

    with client.websocket_connect(f"/api/v1/jobs/{job_id}/ws?api_token={token}") as websocket:
        initial = websocket.receive_json()
        assert initial["event"] == "snapshot"
        assert initial["payload"]["job"]["job_id"] == job_id
        assert initial["payload"]["analysis_available"] is True
        assert initial["payload"]["items"][0]["line"] == "[agent] planning started"
        assert initial["payload"]["artifacts"]

        time.sleep(0.02)
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        report_payload["meta"]["decision_summary"] = "Approval branch detected and report refreshed."
        report_payload["meta"]["approval_marker"] = "waiting"
        report_path.write_text(json.dumps(report_payload, ensure_ascii=False, indent=2), encoding="utf-8")

        with web_app.state.manager._lock:
            record = web_app.state.manager._jobs[job_id]
            record["status"] = "waiting_approval"
            record["session_status"] = "waiting_approval"
            record["pending_approval"] = {
                "summary": "Need approval before the next active validation step.",
                "actions": [{"tool_name": "nuclei", "target": "https://portal.example.com/login"}],
            }
            record["last_updated_at"] = "2026-03-16T10:02:00Z"
        web_app.state.manager._persist_job(job_id)
        web_app.state.manager._notify_updates()
        web_app.state.manager._append_log(job_id, "[agent] approval required")

        received = [websocket.receive_json() for _ in range(3)]
        assert any(item["event"] == "status" and item["payload"]["job"]["status"] == "waiting_approval" for item in received)
        assert any(item["event"] == "analysis" for item in received)
        assert any(item["event"] == "log" and item["payload"]["item"]["line"] == "[agent] approval required" for item in received)


def test_jobs_realtime_websocket_pushes_waiting_approval_queue(web_app) -> None:
    user = web_app.state.auth_service.create_user(username="viewer2", password="ViewerPass1234", role="viewer")
    token = web_app.state.auth_service.issue_access_token(user)
    job_id, _output_dir, _report_path = _seed_realtime_job(web_app, job_id="job-ws-approval")
    client = TestClient(web_app)

    with client.websocket_connect(f"/api/v1/jobs/ws?api_token={token}") as websocket:
        initial = websocket.receive_json()
        assert initial["event"] == "snapshot"
        assert initial["payload"]["approval_total"] == 0

        with web_app.state.manager._lock:
            record = web_app.state.manager._jobs[job_id]
            record["status"] = "waiting_approval"
            record["session_status"] = "waiting_approval"
            record["pending_approval"] = {"summary": "Pause for approval.", "actions": []}
            record["last_updated_at"] = "2026-03-16T10:03:00Z"
        web_app.state.manager._persist_job(job_id)
        web_app.state.manager._notify_updates()

        update = websocket.receive_json()
        assert update["event"] == "jobs"
        assert update["payload"]["approval_total"] == 1
        assert update["payload"]["approval_job_ids"] == [job_id]
