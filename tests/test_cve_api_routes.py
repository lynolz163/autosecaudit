from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from autosecaudit.agent_core.cve_service import NvdCveService
from autosecaudit.webapp.fastapi_app import create_app, resolve_runtime_paths
from autosecaudit.webapp.server import CodexWebAuthManager, JobManager


@pytest.fixture()
def cve_app(tmp_path: Path):
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


def test_cve_routes_are_registered(cve_app) -> None:
    paths = {route.path for route in cve_app.routes}
    assert "/api/cve/search" in paths
    assert "/api/v1/cve/search" in paths
    assert "/api/cve/job/{job_id}" in paths
    assert "/api/v1/cve/job/{job_id}" in paths
    assert "/api/cve/verify" in paths
    assert "/api/v1/cve/verify" in paths


def test_cve_search_endpoint_returns_items(cve_app, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_search(self: NvdCveService, **_kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                "cve_id": "CVE-2024-1111",
                "severity": "high",
                "description": "Demo CVE",
                "affected_versions": [],
                "has_nuclei_template": True,
                "cvss_score": 8.7,
                "source": "nvd",
            }
        ]

    monkeypatch.setattr(NvdCveService, "search", fake_search)
    client = TestClient(cve_app)
    response = client.post(
        "/api/v1/cve/search",
        headers={"x-api-token": "bootstrap-token"},
        json={"keyword": "nginx", "max_results": 5},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["items"][0]["cve_id"] == "CVE-2024-1111"


def test_cve_verify_endpoint_submits_agent_job(cve_app, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_submit(payload: dict[str, Any], *, actor: str = "web") -> dict[str, Any]:
        captured["payload"] = payload
        captured["actor"] = actor
        return {
            "job_id": "job-cve-001",
            "status": "queued",
            "target": payload.get("target"),
            "mode": payload.get("mode"),
            "safety_grade": payload.get("safety_grade", "balanced"),
        }

    monkeypatch.setattr(cve_app.state.manager, "submit", fake_submit)
    client = TestClient(cve_app)
    response = client.post(
        "/api/v1/cve/verify",
        headers={"x-api-token": "bootstrap-token"},
        json={
            "target": "https://example.com",
            "safety_grade": "balanced",
            "authorization_confirmed": True,
            "safe_only": True,
            "allow_high_risk": False,
            "cve_ids": ["CVE-2024-1111"],
        },
    )

    assert response.status_code == 201
    assert response.json()["job"]["job_id"] == "job-cve-001"
    submitted = captured["payload"]
    assert submitted["mode"] == "agent"
    assert submitted["tools"] == ["cve_verify"]
    assert submitted["skills"] == ["cve_verify"]
    assert submitted["no_llm_hints"] is True
    assert submitted["surface"]["cve_candidates"][0]["cve_id"] == "CVE-2024-1111"
