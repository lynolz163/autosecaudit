from __future__ import annotations

from autosecaudit.agent_core.audit_pipeline import AuditPipeline


def test_pipeline_advances_from_passive_recon_to_active_discovery() -> None:
    pipeline = AuditPipeline()
    state = pipeline.bootstrap_state(
        {
            "budget_remaining": 100,
            "history": [{"tool": "tech_stack_fingerprint", "status": "completed"}],
            "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
            "surface": {},
            "feedback": {},
            "findings_count": 0,
        }
    )

    transition = pipeline.evaluate_transition(state, available_tools=["dynamic_crawl"])

    assert transition.changed is True
    assert transition.phase.name == "active_discovery"
    assert state["current_phase"] == "active_discovery"


def test_pipeline_falls_back_when_testing_surface_disappears() -> None:
    pipeline = AuditPipeline()
    state = pipeline.bootstrap_state(
        {
            "budget_remaining": 100,
            "current_phase": "deep_testing",
            "history": [{"tool": "dynamic_crawl", "status": "completed"}],
            "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
            "surface": {},
            "feedback": {},
            "findings_count": 0,
        }
    )

    transition = pipeline.evaluate_transition(state, available_tools=["dynamic_crawl", "param_fuzzer"])

    assert transition.changed is True
    assert transition.phase.name == "active_discovery"
    assert transition.reason == "fallback:testing_surface_missing"


def test_pipeline_advances_when_phase_budget_is_exhausted() -> None:
    pipeline = AuditPipeline()
    state = pipeline.bootstrap_state(
        {
            "budget_remaining": 100,
            "total_budget": 100,
            "current_phase": "passive_recon",
            "phase_budget_spent": {"passive_recon": 20},
            "history": [],
            "breadcrumbs": [],
            "surface": {},
            "feedback": {},
        }
    )

    transition = pipeline.evaluate_transition(state, available_tools=["dynamic_crawl"])

    assert transition.changed is True
    assert transition.reason == "budget_exhausted:passive_recon"
    assert transition.phase.name == "active_discovery"


def test_pipeline_advances_when_current_phase_has_no_available_tools() -> None:
    pipeline = AuditPipeline()
    state = pipeline.bootstrap_state(
        {
            "budget_remaining": 100,
            "current_phase": "active_discovery",
            "history": [],
            "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
            "surface": {},
            "feedback": {},
        }
    )

    transition = pipeline.evaluate_transition(state, available_tools=["cookie_security_audit"])

    assert transition.changed is True
    assert transition.reason == "no_available_tools:active_discovery"
    assert transition.phase.name == "deep_testing"


def test_verification_phase_budget_and_tool_pool_are_expanded() -> None:
    pipeline = AuditPipeline()
    verification = next(phase for phase in pipeline.PHASES if phase.name == "verification")
    passive_recon = next(phase for phase in pipeline.PHASES if phase.name == "passive_recon")
    active_discovery = next(phase for phase in pipeline.PHASES if phase.name == "active_discovery")

    assert verification.max_budget_pct == 0.20
    assert {"http_security_headers", "cors_misconfiguration", "passive_config_audit", "rag_intel_lookup", "page_vision_analyzer", "poc_sandbox_exec"}.issubset(
        set(verification.allowed_tools)
    )
    assert "service_banner_probe" in passive_recon.allowed_tools
    assert "service_banner_probe" in active_discovery.allowed_tools
    assert "page_vision_analyzer" in active_discovery.allowed_tools


def test_passive_recon_phase_budget_has_floor_for_low_default_budgets() -> None:
    pipeline = AuditPipeline()
    state = pipeline.bootstrap_state(
        {
            "budget_remaining": 50,
            "total_budget": 50,
            "current_phase": "passive_recon",
            "phase_budget_spent": {},
            "history": [],
            "breadcrumbs": [],
            "surface": {},
            "feedback": {},
        }
    )

    # 50 * 0.20 = 10, but passive_recon should reserve at least 15 so
    # host/IP-only runs can execute nmap_scan.
    assert pipeline.phase_budget_remaining(state, "passive_recon") == 15


def test_pipeline_recognizes_nmap_surface_origins_without_breadcrumbs() -> None:
    pipeline = AuditPipeline()
    state = pipeline.bootstrap_state(
        {
            "budget_remaining": 100,
            "history": [
                {"tool": "nmap_scan", "status": "completed"},
                {"tool": "tech_stack_fingerprint", "status": "completed"},
                {"tool": "http_security_headers", "status": "completed"},
            ],
            "breadcrumbs": [],
            "surface": {
                "nmap_http_origins": ["http://example.com:8080"],
            },
            "feedback": {},
            "findings_count": 0,
        }
    )

    transition = pipeline.evaluate_transition(state, available_tools=["dynamic_crawl"])

    assert transition.changed is True
    assert transition.phase.name == "active_discovery"
