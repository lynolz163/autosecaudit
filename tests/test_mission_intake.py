from __future__ import annotations

import json

from autosecaudit.agent_core.mission_intake import (
    MissionSessionManager,
    build_mission_draft,
    continue_mission_draft,
)


def test_build_mission_draft_for_recon_infers_target_and_defaults() -> None:
    draft = build_mission_draft("对 example.com 进行信息收集")

    assert draft.target == "example.com"
    assert draft.intent == "recon"
    assert draft.depth == "standard"
    assert draft.mode == "agent"
    assert draft.report_lang == "zh-CN"
    assert draft.safety_grade == "balanced"
    assert draft.autonomy_mode == "adaptive"
    assert draft.payload["surface"]["mission_intent"] == "recon"
    assert draft.payload["surface"]["authorization_confirmed"] is False
    assert draft.selected_skills


def test_build_mission_draft_for_verify_does_not_enable_cve_verify_without_authorization() -> None:
    draft = build_mission_draft("verify https://example.com for CVE exposure")

    assert draft.target == "https://example.com"
    assert draft.intent == "verify"
    assert "cve_verify" not in draft.selected_skills
    assert draft.authorization_confirmed is False


def test_build_mission_draft_applies_overrides_and_authorization_signal() -> None:
    draft = build_mission_draft(
        "对 mysite.example.com 进行渗透测试，我自己的网站",
        overrides={"budget": 777, "tools": ["nmap_scan"], "multi_agent": True, "multi_agent_rounds": 3},
    )

    assert draft.intent == "pentest"
    assert draft.authorization_confirmed is True
    assert draft.payload["budget"] == 777
    assert draft.selected_tools == ["nmap_scan"]
    assert draft.multi_agent is True
    assert draft.multi_agent_rounds == 3


def test_continue_mission_draft_can_disable_playwright_and_focus_ports() -> None:
    draft = build_mission_draft("对 example.com 进行渗透测试")

    updated = continue_mission_draft(draft, "不要跑 Playwright，继续深测 443/8443")

    assert updated.depth == "deep"
    assert updated.autonomy_mode == "supervised"
    assert 443 in updated.payload["surface"]["focus_ports"]
    assert 8443 in updated.payload["surface"]["focus_ports"]
    assert "dynamic_crawl" not in updated.selected_tools
    assert "page_vision_analyzer" not in updated.selected_tools
    assert updated.payload["surface"]["preferred_origins"] == [
        "https://example.com:443/",
        "https://example.com:8443/",
    ]


def test_mission_session_manager_preserves_target_and_updates_follow_up() -> None:
    manager = MissionSessionManager()

    first = manager.compile_turn("对 example.com 进行渗透测试")
    second = manager.compile_turn("只做低风险验证", session_id=first.session_id)

    assert second.session_id == first.session_id
    assert second.draft.target == "example.com"
    assert second.draft.intent == "verify"
    assert second.draft.depth == "light"
    assert second.draft.autonomy_mode == "constrained"
    assert len(second.messages) == 4


def test_build_mission_draft_prefers_llm_structured_parameters() -> None:
    def _fake_llm(_prompt: str) -> str:
        return json.dumps(
            {
                "target": "llm.example.com",
                "intent": "recon",
                "depth": "light",
                "report_lang": "zh-CN",
                "tools": ["nmap_scan", "fake_tool"],
                "skills": ["git_exposure_check", "fake_skill"],
                "surface": {
                    "disabled_tools": ["dynamic_crawl"],
                    "focus_ports": [443, 8443],
                },
            }
        )

    draft = build_mission_draft("帮我看看这个站", llm_completion=_fake_llm)

    assert draft.target == "llm.example.com"
    assert draft.intent == "recon"
    assert draft.depth == "light"
    assert "fake_tool" not in draft.selected_tools
    assert "fake_skill" not in draft.selected_skills
    assert "git_exposure_check" in draft.selected_skills
    assert 443 in draft.payload["surface"]["focus_ports"]
    assert draft.payload["surface"]["mission_parser_source"] == "llm"
    assert draft.payload["surface"]["mission_parser_values"]["intent"] == "recon"
    assert draft.payload["surface"]["mission_parser_values"]["surface"]["focus_ports"] == [443, 8443]
