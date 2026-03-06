from __future__ import annotations

import json
from pathlib import Path

from autosecaudit.agent_core.agent_memory import AgentMemoryStore


def test_agent_memory_store_builds_compact_context_from_large_state(tmp_path: Path) -> None:
    store = AgentMemoryStore(base_dir=tmp_path / "memory")
    state = {
        "target": "https://example.com",
        "current_phase": "deep_testing",
        "budget_remaining": 42,
        "iteration_count": 3,
        "history": [
            {"tool": f"tool_{idx}", "target": f"https://example.com/{idx}", "status": "completed"}
            for idx in range(20)
        ],
        "breadcrumbs": [
            {"type": "service", "data": f"https://example.com:{443 + idx}"}
            for idx in range(20)
        ],
        "surface": {
            "tech_stack": ["nginx", "react"],
            "nmap_services": [
                {"host": "example.com", "port": 22, "service": "ssh"},
                {"host": "example.com", "port": 6379, "service": "redis"},
            ],
            "api_endpoints": [{"url": f"https://example.com/api/{idx}"} for idx in range(12)],
        },
        "feedback": {"follow_up_tools": ["service_banner_probe", "api_schema_discovery"]},
    }

    context = store.build_memory_context(
        state=state,
        findings=[{"title": "Missing HSTS", "severity": "low", "tool": "http_security_headers"}],
    )

    assert context["compression_applied"] is True
    assert context["history_total"] == 20
    assert len(context["recent_actions"]) == 8
    assert context["recon_memory"]["services"][0]["value"]["port"] == 22
    assert context["recon_memory"]["services"][0]["hit_score"] > 0
    assert context["recon_memory"]["services"][0]["freshness_score"] > 0
    assert "planning_hints" in context
    assert "service_banner_probe" in context["follow_up_tools"]


def test_agent_memory_store_persists_and_recalls_target_memory(tmp_path: Path) -> None:
    store = AgentMemoryStore(base_dir=tmp_path / "memory")
    state = {
        "target": "https://example.com",
        "current_phase": "verification",
        "budget_remaining": 10,
        "iteration_count": 2,
        "history": [{"tool": "nmap_scan", "target": "example.com", "status": "completed"}],
        "breadcrumbs": [{"type": "service", "data": "https://example.com:443"}],
        "surface": {
            "tech_stack": ["nginx"],
            "nmap_services": [{"host": "example.com", "port": 22, "service": "ssh"}],
        },
        "feedback": {"follow_up_tools": ["service_banner_probe"]},
    }

    persisted = store.persist(
        target="https://example.com",
        state=state,
        findings=[{"title": "Observed SSH banner", "severity": "info", "tool": "service_banner_probe"}],
    )
    loaded = store.load(target="https://example.com")

    assert persisted["run_count"] == 1
    assert loaded["target_key"] == store.target_key("https://example.com")
    assert loaded["recon_memory"]["items"]["services"][0]["value"]["service"] == "ssh"
    assert "service_banner_probe" in loaded["follow_up_tools"]


def test_agent_memory_store_prunes_expired_entries(tmp_path: Path) -> None:
    store = AgentMemoryStore(base_dir=tmp_path / "memory")
    path = store.path_for_target("https://example.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "target": "https://example.com",
                "target_key": store.target_key("https://example.com"),
                "updated_at": "2026-03-01T00:00:00+00:00",
                "run_count": 2,
                "recon_memory": {
                    "ttl_seconds": 3600,
                    "items": {
                        "origins": [
                            {
                                "key": "k1",
                                "value": "https://expired.example.com",
                                "weight": 1.0,
                                "hit_count": 1,
                                "first_seen_at": "2026-03-01T00:00:00+00:00",
                                "last_seen_at": "2026-03-01T00:00:00+00:00",
                                "expires_at": "2026-03-01T01:00:00+00:00",
                                "ttl_seconds": 3600,
                            }
                        ]
                    },
                },
                "exploit_memory": {"ttl_seconds": 3600, "items": {"follow_up_tools": [], "findings": [], "cve_candidates": [], "rag_intel_hits": []}},
                "report_memory": {"ttl_seconds": 3600, "items": {"run_summaries": [], "report_preferences": []}},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    loaded = store.load(target="https://example.com")

    assert loaded["recon_memory"]["items"]["origins"] == []


def test_agent_memory_store_fuses_rag_hits_into_exploit_memory(tmp_path: Path) -> None:
    corpus_path = tmp_path / "intel.json"
    corpus_path.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "id": "flask-debug-lab",
                        "title": "Flask debug lab",
                        "summary": "Flask debug exposure often needs passive config review.",
                        "content": "Use passive config audit and error page analysis carefully.",
                        "tags": ["flask", "debug", "traceback"],
                        "recommended_tools": ["passive_config_audit", "error_page_analyzer"],
                        "severity_hint": "high",
                        "references": [],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    store = AgentMemoryStore(base_dir=tmp_path / "memory", rag_corpus_path=corpus_path)
    state = {
        "target": "https://example.com",
        "current_phase": "verification",
        "budget_remaining": 30,
        "history": [],
        "breadcrumbs": [{"type": "service", "data": "https://example.com:443"}],
        "surface": {"tech_stack": ["flask/3.0"]},
        "feedback": {},
    }

    context = store.build_memory_context(state=state, findings=[])

    assert context["exploit_memory"]["rag_intel_hits"]
    assert any(
        item["value"]["doc_id"] == "flask-debug-lab"
        for item in context["exploit_memory"]["rag_intel_hits"]
    )
    assert "passive_config_audit" in context["planning_hints"]["rag_recommended_tools"]
    assert "error_page_analyzer" in context["planning_hints"]["rag_recommended_tools"]
