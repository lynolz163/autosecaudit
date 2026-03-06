from __future__ import annotations

import json
from pathlib import Path

from autosecaudit.agent_core.rag_service import RagIntelService


def test_rag_service_uses_builtin_corpus_when_external_file_missing(tmp_path: Path) -> None:
    service = RagIntelService(corpus_path=tmp_path / "missing-intel.json")

    hits = service.search(query="nginx traversal misconfiguration", component="nginx", max_results=5)

    assert hits
    assert any("nuclei_exploit_check" in item.get("recommended_tools", []) for item in hits)


def test_rag_service_loads_external_corpus_and_ranks_relevant_doc_first(tmp_path: Path) -> None:
    corpus_path = tmp_path / "intel.json"
    corpus_path.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "id": "flask-debug-exposure",
                        "title": "Flask debug exposure patterns",
                        "summary": "Flask debug mode leaks stack traces and debugger endpoints.",
                        "content": "Validate DEBUG mode, traceback leaks, and hardened production config.",
                        "tags": ["flask", "debug", "traceback"],
                        "recommended_tools": ["error_page_analyzer", "passive_config_audit"],
                        "severity_hint": "medium",
                        "references": ["https://flask.palletsprojects.com/"],
                    },
                    {
                        "id": "unrelated-sample",
                        "title": "Unrelated Windows hardening note",
                        "summary": "Not relevant to flask web stack.",
                        "content": "This is intentionally unrelated.",
                        "tags": ["windows", "hardening"],
                        "recommended_tools": ["nmap_scan"],
                        "severity_hint": "low",
                        "references": [],
                    },
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    service = RagIntelService(corpus_path=corpus_path)
    hits = service.search(query="flask debug traceback", component="flask", max_results=3)

    assert hits
    assert hits[0]["doc_id"] == "flask-debug-exposure"
    assert "error_page_analyzer" in hits[0]["recommended_tools"]

