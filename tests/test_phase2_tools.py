from __future__ import annotations

from pathlib import Path
import pytest

from autosecaudit.agent_core.builtin_tools import (
    AgentCrawlerTool,
    AgentPageVisionAnalyzerTool,
    AgentRagIntelLookupTool,
)


def test_rag_intel_lookup_tool_emits_surface_updates_and_follow_up_hints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeService:
        corpus_path = Path("/tmp/fake-corpus.json")

        def search(self, **kwargs):  # noqa: ANN003
            assert kwargs["component"] == "nginx"
            return [
                {
                    "doc_id": "nginx-alias-traversal-patterns",
                    "title": "Nginx alias traversal misconfiguration",
                    "summary": "Alias traversal pattern.",
                    "snippet": "Test traversal edge cases safely.",
                    "source": "builtin",
                    "tags": ["nginx"],
                    "recommended_tools": ["cve_lookup", "nuclei_exploit_check"],
                    "severity_hint": "high",
                    "references": ["https://nvd.nist.gov/"],
                    "score": 7.0,
                }
            ]

    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.RagIntelService", lambda: _FakeService())

    tool = AgentRagIntelLookupTool()
    result = tool.run(
        target="https://example.com",
        options={
            "component": "nginx",
            "version": "1.18",
            "query": "nginx traversal",
            "max_results": 5,
        },
    )

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert isinstance(data, dict)
    assert data["surface_delta"]["rag_intel_hits"][0]["doc_id"] == "nginx-alias-traversal-patterns"
    assert "cve_lookup" in data["surface_delta"]["rag_recommended_tools"]
    assert "nuclei_exploit_check" in data["follow_up_hints"]


def test_page_vision_analyzer_tool_derives_signals_and_follow_ups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_capture(self, **kwargs):  # noqa: ANN001, ANN003
        del kwargs
        return {
            "final_url": "https://example.com/login",
            "title": "Admin Login",
            "dom_text": "Please sign in. Username password. Debug information hidden.",
            "screenshot_bytes": b"fake-png",
            "screenshot_size": 8,
            "screenshot_sha256": "abc123",
        }

    def _fake_llm(self, **kwargs):  # noqa: ANN001, ANN003
        del kwargs
        return "Login panel and admin dashboard elements are visible.", {"model": "fake-vision"}

    monkeypatch.setattr(AgentPageVisionAnalyzerTool, "_capture_snapshot", _fake_capture)
    monkeypatch.setattr(AgentPageVisionAnalyzerTool, "_analyze_with_vision_llm", _fake_llm)

    tool = AgentPageVisionAnalyzerTool()
    result = tool.run(
        target="https://example.com",
        options={
            "timeout_seconds": 10,
            "wait_until": "networkidle",
            "full_page": True,
            "enable_vision_llm": True,
            "max_vision_image_bytes": 1000000,
            "analysis_prompt": "Analyze security-relevant UI cues.",
        },
    )

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert isinstance(data, dict)
    assert "login_interface" in data["surface_delta"]["vision_signals"]
    assert "admin_surface" in data["surface_delta"]["vision_signals"]
    assert "login_form_detector" in data["follow_up_hints"]
    assert "passive_config_audit" in data["follow_up_hints"]


def test_playwright_tools_report_unavailable_when_browser_runtime_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "autosecaudit.agent_core.builtin_tools._check_playwright_runtime_availability",
        lambda: (False, "playwright browser runtime is missing. Run `playwright install chromium`."),
    )

    crawler_available, crawler_reason = AgentCrawlerTool().check_availability()
    vision_available, vision_reason = AgentPageVisionAnalyzerTool().check_availability()

    assert crawler_available is False
    assert "playwright install chromium" in str(crawler_reason)
    assert vision_available is False
    assert "playwright install chromium" in str(vision_reason)
