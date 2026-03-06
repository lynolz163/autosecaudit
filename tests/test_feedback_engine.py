from __future__ import annotations

from autosecaudit.agent_core.feedback_engine import FeedbackEngine


def test_feedback_engine_prioritizes_tools_from_surface_signals() -> None:
    engine = FeedbackEngine()

    feedback = engine.build_feedback(
        history=[],
        surface={
            "tech_stack": ["wordpress"],
            "url_parameters": {"id": ["1"]},
            "parameter_origins": {"id": ["https://example.com/api/users?id=1"]},
        },
        findings=[],
        tool_follow_up_hints=[],
    )

    assert feedback["priority_overrides"]["nuclei_exploit_check"] <= -5
    assert feedback["priority_overrides"]["sql_sanitization_audit"] <= -5
    assert feedback["priority_overrides"]["param_fuzzer"] <= -5


def test_feedback_engine_returns_pause_for_critical_findings() -> None:
    engine = FeedbackEngine()

    signal = engine.evaluate_risk_escalation(
        [
            {
                "title": "Critical exposure",
                "description": "remote code execution",
                "severity": "critical",
            }
        ]
    )

    assert signal == "pause"


def test_feedback_engine_merge_feedback_dedupes_and_preserves_stronger_signal() -> None:
    engine = FeedbackEngine()

    merged = engine.merge_feedback(
        {
            "follow_up_tools": ["api_schema_discovery"],
            "priority_overrides": {"api_schema_discovery": -4},
            "risk_signal": "tighten",
        },
        {
            "follow_up_tools": ["api_schema_discovery", "source_map_detector"],
            "priority_overrides": {"source_map_detector": -5},
            "risk_signal": "pause",
        },
    )

    assert merged["follow_up_tools"] == ["api_schema_discovery", "source_map_detector"]
    assert merged["priority_overrides"]["api_schema_discovery"] == -4
    assert merged["priority_overrides"]["source_map_detector"] == -5
    assert merged["risk_signal"] == "pause"


def test_feedback_engine_expands_frontend_stack_hints() -> None:
    engine = FeedbackEngine()

    feedback = engine.build_feedback(
        history=[],
        surface={"tech_stack": ["react"]},
        findings=[],
        tool_follow_up_hints=[],
    )

    assert feedback["priority_overrides"]["source_map_detector"] <= -5
    assert feedback["priority_overrides"]["api_schema_discovery"] <= -5


def test_feedback_engine_prioritizes_cve_tools_when_candidates_exist() -> None:
    engine = FeedbackEngine()

    feedback = engine.build_feedback(
        history=[],
        surface={
            "tech_stack": ["nginx"],
            "cve_candidates": [
                {"cve_id": "CVE-2024-1111", "target": "https://example.com"},
            ],
        },
        findings=[],
        tool_follow_up_hints=[],
    )

    assert feedback["priority_overrides"]["cve_verify"] <= -6


def test_feedback_engine_prioritizes_poc_when_authorized_and_approved() -> None:
    engine = FeedbackEngine()

    feedback = engine.build_feedback(
        history=[],
        surface={
            "authorization_confirmed": True,
            "approval_granted": True,
            "cve_candidates": [
                {"cve_id": "CVE-2024-1111", "target": "https://example.com"},
            ],
        },
        findings=[],
        tool_follow_up_hints=[],
    )

    assert feedback["priority_overrides"]["poc_sandbox_exec"] <= -3
