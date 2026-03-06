"""Example usage for hardened AuditDecisionMaker planning."""

from __future__ import annotations

from dataclasses import asdict
import json

from autosecaudit.decision import AuditDecisionMaker


def mock_llm(prompt: str) -> str:
    """Mock LLM callback returning allowed tool hints."""
    _ = prompt
    return json.dumps(
        {
            "decision_summary": "Run passive checks first, then crawl.",
            "tools": ["passive_config_audit", "dynamic_crawl", "sql_sanitization_audit"],
            "reason": "Minimize risk while expanding visibility.",
        },
        ensure_ascii=False,
    )


def main() -> None:
    decision_maker = AuditDecisionMaker(llm_callable=mock_llm)

    audit_state = {
        "scope": ["example.com"],
        "breadcrumbs": [
            {"type": "service", "data": "http://example.com:80"},
            {"type": "endpoint", "data": "http://example.com/search?q=test"},
        ],
        "history": [],
        "budget_remaining": 30,
    }

    plan = decision_maker.plan_from_state(audit_state, use_llm_hints=True)
    print(json.dumps(asdict(plan), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
