from __future__ import annotations

import json
from pathlib import Path

from autosecaudit.decision import MultiAgentDecisionMaker


def test_multi_agent_decision_maker_generates_session_tree_and_actions(tmp_path: Path) -> None:
    session_path = tmp_path / "multi_agent_session_tree.json"
    maker = MultiAgentDecisionMaker(
        available_tools=[
            "tech_stack_fingerprint",
            "page_vision_analyzer",
            "rag_intel_lookup",
            "cve_lookup",
        ],
        safety_grade="aggressive",
        session_tree_path=session_path,
        max_rounds=1,
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 80,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {"tech_stack": ["nginx/1.18"]},
        "history": [],
        "safety_grade": "aggressive",
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert plan.actions
    assert plan.decision_summary.startswith("[multi-agent]")
    assert session_path.exists()
    payload = json.loads(session_path.read_text(encoding="utf-8"))
    roles = {item.get("role") for item in payload if isinstance(item, dict)}
    assert {"orchestrator", "recon", "exploiter", "reviewer"}.issubset(roles)


def test_multi_agent_reviewer_blocks_poc_without_approval(tmp_path: Path) -> None:
    session_path = tmp_path / "multi_agent_session_tree.json"
    maker = MultiAgentDecisionMaker(
        available_tools=["poc_sandbox_exec"],
        safety_grade="aggressive",
        session_tree_path=session_path,
        max_rounds=1,
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 80,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {
            "authorization_confirmed": True,
            "cve_candidates": [
                {"cve_id": "CVE-2024-1111", "target": "https://example.com"},
            ],
        },
        "history": [],
        "safety_grade": "aggressive",
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert plan.actions == []

