from __future__ import annotations

from autosecaudit.agent_core.builtin_tools import (
    AgentCORSMisconfigurationTool,
    AgentSecurityTxtCheckTool,
    AgentServiceBannerProbeTool,
)
from autosecaudit.agent_core.policy import PolicyEngine
from autosecaudit.agent_core.scheduler import Action


def _action(tool_name: str, target: str, options: dict, *, priority: int = 10, cost: int = 5) -> Action:
    return Action(
        action_id="A1",
        tool_name=tool_name,
        target=target,
        options=options,
        priority=priority,
        cost=cost,
        capabilities=["network_read"],
        idempotency_key="key-1",
        reason="test",
        preconditions=[],
        stop_conditions=[],
    )


def test_conservative_grade_blocks_active_tools() -> None:
    engine = PolicyEngine(safety_grade="conservative")
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
        "budget_remaining": 50,
    }
    plan = {
        "actions": [
            _action(
                "dynamic_crawl",
                "https://example.com",
                {"max_depth": 2, "allow_domain": ["example.com"]},
                priority=20,
                cost=12,
            )
        ]
    }

    allowed, blocked = engine.validate_plan(plan, state)

    assert allowed == []
    assert len(blocked) == 1
    assert blocked[0].reason == "safety_grade_denied:conservative"


def test_nuclei_severity_is_limited_to_medium_or_below() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001

    invalid = _action(
        "nuclei_exploit_check",
        "https://example.com",
        {"severity": ["high"]},
    )
    valid = _action(
        "nuclei_exploit_check",
        "https://example.com",
        {"severity": ["medium"]},
    )

    assert engine.validate_options_schema(invalid, scope_model) == "nuclei_invalid_severity"
    assert engine.validate_options_schema(valid, scope_model) is None


def test_active_web_crawler_schema_accepts_bounded_limit() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "active_web_crawler",
        "https://example.com",
        {"max_depth": 2, "allow_domain": ["example.com"], "limit": 50},
        priority=21,
        cost=12,
    )

    assert engine.validate_options_schema(action, scope_model) is None


def test_nmap_schema_accepts_conservative_fast_profile() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "nmap_scan",
        "example.com",
        {
            "scan_profile": "conservative_service_discovery",
            "ports": "top-100",
            "version_detection": False,
            "timeout_seconds": 90,
        },
        priority=14,
        cost=15,
    )

    assert engine.validate_options_schema(action, scope_model) is None


def test_param_fuzzer_requires_get_and_lightweight_mode() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "param_fuzzer",
        "https://example.com/api/user",
        {"method": "GET", "params": {"id": "1"}, "mode": "lightweight", "max_probes": 6},
        priority=32,
        cost=6,
    )

    assert engine.validate_options_schema(action, scope_model) is None


def test_passive_config_schema_accepts_bounded_options() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "passive_config_audit",
        "https://example.com",
        {
            "request_timeout_seconds": 3,
            "max_total_seconds": 18,
            "max_paths": 10,
        },
        priority=0,
        cost=3,
    )

    assert engine.validate_options_schema(action, scope_model) is None


def test_policy_blocks_dependency_when_crawler_signal_is_missing() -> None:
    engine = PolicyEngine()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "feedback": {},
        "history": [],
        "budget_remaining": 50,
    }
    action = _action(
        "sql_sanitization_audit",
        "https://example.com/api/user",
        {"method": "GET", "params": {"id": "1"}},
        priority=30,
        cost=8,
    )
    action.preconditions = ["target_in_scope", "params_available", "crawler_signal_present"]

    class _Tool:
        depends_on = ["dynamic_crawl"]

    reason = engine.validate_preconditions(action, state, tool=_Tool())

    assert reason == "precondition_failed:crawler_signal_present"


def test_security_txt_metadata_schema_blocks_unexpected_options() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "security_txt_check",
        "https://example.com",
        {"timeout": 5},
        priority=3,
        cost=1,
    )

    reason = engine.validate_options_schema(action, scope_model, tool=AgentSecurityTxtCheckTool())

    assert reason == "security_txt_check_options_invalid_keys"


def test_cve_verify_schema_accepts_safe_options() -> None:
    engine = PolicyEngine()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "cve_verify",
        "https://example.com",
        {
            "cve_ids": ["CVE-2024-1111"],
            "safe_only": True,
            "authorization_confirmed": True,
            "allow_high_risk": False,
            "timeout_seconds": 180,
            "safety_grade": "balanced",
        },
        priority=45,
        cost=25,
    )

    assert engine.validate_options_schema(action, scope_model) is None


def test_service_banner_probe_schema_and_dependency_accept_nmap_backed_targets() -> None:
    engine = PolicyEngine()
    tool = AgentServiceBannerProbeTool()
    scope_model = engine._parse_scope(["example.com"])  # noqa: SLF001
    action = _action(
        "service_banner_probe",
        "example.com",
        {
            "port": 22,
            "service": "ssh",
            "timeout_seconds": 4,
            "read_bytes": 512,
        },
        priority=15,
        cost=4,
    )
    action.preconditions = ["target_in_scope", "not_already_done"]
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [],
        "surface": {"nmap_services": [{"host": "example.com", "port": 22, "service": "ssh"}]},
        "history": [
            {
                "tool": "nmap_scan",
                "target": "example.com",
                "options": {
                    "ports": "top-100",
                    "scan_profile": "conservative_service_discovery",
                    "timeout_seconds": 90,
                    "version_detection": False,
                },
                "status": "completed",
            }
        ],
        "budget_remaining": 50,
    }

    assert engine.validate_options_schema(action, scope_model, tool=tool) is None
    assert engine.validate_preconditions(action, state, tool=tool) is None


def test_cve_verify_precondition_requires_authorization() -> None:
    engine = PolicyEngine()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
        "budget_remaining": 50,
        "safety_grade": "balanced",
    }
    action = _action(
        "cve_verify",
        "https://example.com",
        {
            "cve_ids": ["CVE-2024-1111"],
            "safe_only": True,
            "authorization_confirmed": False,
            "allow_high_risk": False,
            "timeout_seconds": 180,
            "safety_grade": "balanced",
        },
        priority=45,
        cost=25,
    )
    action.preconditions = ["authorization_confirmed"]

    reason = engine.validate_preconditions(action, state)

    assert reason == "precondition_failed:authorization_confirmed"


def test_cve_verify_precondition_accepts_surface_authorization() -> None:
    engine = PolicyEngine()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {"authorization_confirmed": True},
        "history": [],
        "budget_remaining": 50,
        "safety_grade": "balanced",
    }
    action = _action(
        "cve_verify",
        "https://example.com",
        {
            "cve_ids": ["CVE-2024-1111"],
            "safe_only": True,
            "allow_high_risk": False,
            "timeout_seconds": 180,
            "safety_grade": "balanced",
        },
        priority=45,
        cost=25,
    )
    action.preconditions = ["authorization_confirmed"]

    reason = engine.validate_preconditions(action, state)

    assert reason is None


def test_constrained_autonomy_blocks_medium_risk_tools() -> None:
    engine = PolicyEngine()
    tool = AgentCORSMisconfigurationTool()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {"autonomy_mode": "constrained"},
        "history": [],
        "budget_remaining": 50,
        "safety_grade": "balanced",
    }
    plan = {
        "actions": [
            _action(
                "cors_misconfiguration",
                "https://example.com",
                {},
                priority=20,
                cost=4,
            )
        ]
    }

    allowed, blocked = engine.validate_plan(plan, state, tool_getter=lambda _name: tool)

    assert allowed == []
    assert len(blocked) == 1
    assert blocked[0].reason == "autonomy_risk_denied:constrained:medium"


def test_cve_verify_precondition_uses_surface_high_risk_flag() -> None:
    engine = PolicyEngine()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {
            "authorization_confirmed": True,
            "allow_high_risk": True,
        },
        "history": [],
        "budget_remaining": 50,
        "safety_grade": "balanced",
    }
    action = _action(
        "cve_verify",
        "https://example.com",
        {
            "cve_ids": ["CVE-2024-1111"],
            "safe_only": False,
            "timeout_seconds": 180,
            "safety_grade": "balanced",
        },
        priority=45,
        cost=25,
    )
    action.preconditions = ["authorization_confirmed"]

    reason = engine.validate_preconditions(action, state)

    assert reason == "precondition_failed:allow_high_risk_requires_aggressive_grade"


def test_poc_sandbox_precondition_requires_approval() -> None:
    engine = PolicyEngine()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {"authorization_confirmed": True, "approval_granted": False},
        "history": [],
        "budget_remaining": 80,
        "safety_grade": "aggressive",
    }
    action = _action(
        "poc_sandbox_exec",
        "https://example.com",
        {
            "cve_id": "CVE-2024-1111",
            "authorization_confirmed": True,
            "approval_granted": False,
            "safe_mode": True,
            "timeout_seconds": 10,
            "safety_grade": "aggressive",
        },
        priority=42,
        cost=18,
    )
    action.preconditions = ["authorization_confirmed", "approval_granted"]

    reason = engine.validate_preconditions(action, state)

    assert reason == "precondition_failed:approval_granted"


def test_poc_sandbox_precondition_requires_aggressive_grade() -> None:
    engine = PolicyEngine()
    state = {
        "scope": ["example.com"],
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {"authorization_confirmed": True, "approval_granted": True},
        "history": [],
        "budget_remaining": 80,
        "safety_grade": "balanced",
    }
    action = _action(
        "poc_sandbox_exec",
        "https://example.com",
        {
            "cve_id": "CVE-2024-1111",
            "authorization_confirmed": True,
            "approval_granted": True,
            "safe_mode": True,
            "timeout_seconds": 10,
            "safety_grade": "balanced",
        },
        priority=42,
        cost=18,
    )
    action.preconditions = ["authorization_confirmed", "approval_granted"]

    reason = engine.validate_preconditions(action, state)

    assert reason == "precondition_failed:poc_requires_aggressive_grade"
