from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from autosecaudit.webapp.fastapi_app import create_app, resolve_runtime_paths
from autosecaudit.webapp.server import CodexWebAuthManager, JobManager


@pytest.fixture()
def rag_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    output_root = workspace / "output" / "web-jobs"
    static_dir, _frontend_dir = resolve_runtime_paths(workspace=workspace)
    corpus_path = workspace / "config" / "rag" / "intel_corpus.json"
    monkeypatch.setenv("AUTOSECAUDIT_RAG_CORPUS_FILE", str(corpus_path))

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
        yield app, corpus_path
    finally:
        manager.close()


def test_rag_routes_are_registered(rag_app) -> None:
    app, _corpus_path = rag_app
    paths = {route.path for route in app.routes}
    assert "/api/rag/corpus" in paths
    assert "/api/v1/rag/corpus" in paths
    assert "/api/rag/search" in paths
    assert "/api/v1/rag/search" in paths


def test_rag_corpus_get_and_put(rag_app) -> None:
    app, corpus_path = rag_app
    client = TestClient(app)

    get_response = client.get("/api/v1/rag/corpus", headers={"x-api-token": "bootstrap-token"})
    assert get_response.status_code == 200
    assert get_response.json()["exists"] is False

    put_response = client.put(
        "/api/v1/rag/corpus",
        headers={"x-api-token": "bootstrap-token"},
        json={
            "documents": [
                {
                    "id": "flask-debug-note",
                    "title": "Flask Debug Exposure",
                    "summary": "Debug traces may leak internals.",
                    "content": "Check traceback leakage and debug toolbar exposure.",
                    "tags": ["flask", "debug"],
                    "recommended_tools": ["error_page_analyzer", "passive_config_audit"],
                    "severity_hint": "medium",
                    "references": ["https://flask.palletsprojects.com/"],
                }
            ]
        },
    )
    assert put_response.status_code == 200
    payload = put_response.json()
    assert payload["exists"] is True
    assert payload["external_document_count"] == 1
    assert payload["documents"][0]["id"] == "flask-debug-note"
    assert corpus_path.exists()

    written = json.loads(corpus_path.read_text(encoding="utf-8"))
    assert isinstance(written, dict)
    assert written["documents"][0]["id"] == "flask-debug-note"


def test_rag_search_uses_external_corpus(rag_app) -> None:
    app, corpus_path = rag_app
    corpus_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_path.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "id": "flask-debug-note",
                        "title": "Flask Debug Exposure",
                        "summary": "Debug traces may leak internals.",
                        "content": "Check traceback leakage and debug toolbar exposure.",
                        "tags": ["flask", "debug"],
                        "recommended_tools": ["error_page_analyzer"],
                        "severity_hint": "medium",
                        "references": [],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    client = TestClient(app)
    response = client.post(
        "/api/v1/rag/search",
        headers={"x-api-token": "bootstrap-token"},
        json={"query": "flask debug traceback", "component": "flask", "max_results": 5},
    )
    assert response.status_code == 200
    payload = response.json()
    assert any(item.get("doc_id") == "flask-debug-note" for item in payload["items"])
