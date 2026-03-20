from __future__ import annotations

import json

from autosecaudit.agent_safety import SAFETY_GRADE_ACTION_LIMITS
from autosecaudit.agent_core.skill_loader import SkillRegistry
from autosecaudit.decision import AuditDecisionMaker


def _history_entry(maker: AuditDecisionMaker, tool_name: str, target: str, options: dict) -> dict:
    normalized_target = maker._normalize_target_for_key(tool_name, target)  # noqa: SLF001
    return {
        "tool": tool_name,
        "target": normalized_target,
        "options": options,
        "status": "completed",
        "idempotency_key": maker.compute_idempotency_key(tool_name, normalized_target, options),
    }


def test_decision_maker_falls_back_when_dynamic_crawl_is_unavailable() -> None:
    maker = AuditDecisionMaker()
    origin = "https://example.com"
    state = {
        "scope": ["example.com"],
        "budget_remaining": 16,
        "breadcrumbs": [{"type": "service", "data": origin}],
        "surface": {},
        "history": [
            _history_entry(maker, "tech_stack_fingerprint", origin, {}),
            _history_entry(maker, "login_form_detector", origin, {}),
            _history_entry(maker, "js_endpoint_extractor", origin, {}),
            _history_entry(
                maker,
                "passive_config_audit",
                origin,
                {
                    "max_paths": 10,
                    "max_total_seconds": 18,
                    "request_timeout_seconds": 3,
                },
            ),
            _history_entry(maker, "http_security_headers", origin, {}),
            _history_entry(maker, "cors_misconfiguration", origin, {}),
            _history_entry(maker, "ssl_expiry_check", origin, {}),
            _history_entry(maker, "subdomain_enum_passive", "example.com", {"max_results": 100}),
        ],
    }

    default_plan = maker.plan_from_state(
        state,
        use_llm_hints=False,
        available_tools=["dynamic_crawl", "dirsearch_scan"],
    )
    fallback_plan = maker.plan_from_state(
        state,
        use_llm_hints=False,
        available_tools=[
            "nmap_scan",
            "http_security_headers",
            "ssl_expiry_check",
            "subdomain_enum_passive",
            "cors_misconfiguration",
            "sql_sanitization_audit",
            "xss_protection_audit",
            "passive_config_audit",
            "dirsearch_scan",
            "nuclei_exploit_check",
        ],
    )

    assert [action.tool_name for action in default_plan.actions] == ["dynamic_crawl"]
    assert [action.tool_name for action in fallback_plan.actions] == ["dirsearch_scan"]


def test_conservative_grade_prefers_passive_surface_enrichment() -> None:
    maker = AuditDecisionMaker(safety_grade="conservative")
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert "tech_stack_fingerprint" in tool_names
    assert "dynamic_crawl" not in tool_names
    assert "active_web_crawler" not in tool_names
    assert "dirsearch_scan" not in tool_names
    assert "nuclei_exploit_check" not in tool_names


def test_param_fuzzer_is_generated_for_parameterized_surface_endpoints() -> None:
    maker = AuditDecisionMaker(
        available_tools=["param_fuzzer"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [],
        "surface": {
            "api_endpoints": [{"url": "https://example.com/api/user?id=1", "method": "GET"}],
            "url_parameters": {"id": ["1"]},
            "parameter_origins": {"id": ["https://example.com/api/user?id=1"]},
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["param_fuzzer"]


def test_param_fuzzer_skips_edge_challenge_and_static_asset_endpoints() -> None:
    maker = AuditDecisionMaker(
        available_tools=["param_fuzzer"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [],
        "surface": {
            "api_endpoints": [{"url": "https://example.com/api/user?id=1", "method": "GET"}],
            "url_parameters": {
                "id": ["1"],
                "v": ["99"],
            },
            "parameter_origins": {
                "id": [
                    "https://example.com/api/user?id=1",
                    "https://example.com/cdn-cgi/content?id=challenge-token",
                ],
                "v": ["https://example.com/static/app.js?v=99"],
            },
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["param_fuzzer"]
    assert [action.target for action in plan.actions] == ["https://example.com:443/api/user"]


def test_decision_maker_prioritizes_passive_subdomain_before_initial_nmap() -> None:
    maker = AuditDecisionMaker()
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "breadcrumbs": [],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert tool_names[:2] == ["subdomain_enum_passive", "nmap_scan"]


def test_aggressive_plan_diversifies_tools_and_prefers_primary_web_origin() -> None:
    maker = AuditDecisionMaker(
        available_tools=[
            "passive_config_audit",
            "tech_stack_fingerprint",
            "login_form_detector",
            "js_endpoint_extractor",
            "http_security_headers",
            "ssl_expiry_check",
            "dynamic_crawl",
            "dirsearch_scan",
        ],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "breadcrumbs": [
            {"type": "service", "data": "http://example.com:3128"},
            {"type": "service", "data": "http://example.com:8008"},
            {"type": "service", "data": "http://example.com:80"},
            {"type": "service", "data": "https://example.com:443"},
        ],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]
    passive_actions = [action for action in plan.actions if action.tool_name == "passive_config_audit"]

    assert len(tool_names) <= SAFETY_GRADE_ACTION_LIMITS["aggressive"]
    assert "dynamic_crawl" in tool_names
    assert "dirsearch_scan" in tool_names
    assert 1 <= len(passive_actions) <= 2
    assert any(action.target in {"https://example.com:443", "http://example.com:80"} for action in passive_actions)
    for action in passive_actions:
        assert action.options == {
            "max_paths": 10,
            "max_total_seconds": 18,
            "request_timeout_seconds": 3,
        }


def test_decision_maker_uses_nmap_surface_to_plan_multi_port_origin_checks() -> None:
    maker = AuditDecisionMaker(
        available_tools=["http_security_headers"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [],
        "surface": {
            "nmap_hosts": [
                {
                    "hostnames": ["example.com"],
                    "open_ports": [
                        {"port": 80, "service": "http"},
                        {"port": 8080, "service": "http-proxy"},
                    ],
                }
            ]
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == [
        "http_security_headers",
        "http_security_headers",
    ]
    assert [action.target for action in plan.actions] == [
        "http://example.com:80/",
        "http://example.com:8080/",
    ]


def test_decision_maker_respects_surface_focus_ports_and_preferred_origins() -> None:
    maker = AuditDecisionMaker(
        available_tools=["http_security_headers", "service_banner_probe"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [
            {"type": "service", "data": "http://example.com:80/"},
            {"type": "service", "data": "https://example.com:443/"},
            {"type": "service", "data": "https://example.com:8443/"},
        ],
        "surface": {
            "focus_ports": [443, 8443],
            "preferred_origins": ["https://example.com:443/", "https://example.com:8443/"],
            "nmap_services": [
                {"host": "example.com", "port": 22, "service": "ssh"},
                {"host": "example.com", "port": 443, "service": "https"},
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert all(":80/" not in action.target for action in plan.actions if action.tool_name == "http_security_headers")
    assert any(action.target == "https://example.com:443/" for action in plan.actions if action.tool_name == "http_security_headers")


def test_decision_maker_renders_dynamic_crawl_placeholders() -> None:
    maker = AuditDecisionMaker(
        available_tools=["dynamic_crawl"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["dynamic_crawl"]
    assert plan.actions[0].options == {"allow_domain": ["example.com"], "max_depth": 2}


def test_conservative_plan_can_use_api_schema_discovery_in_active_phase() -> None:
    maker = AuditDecisionMaker(
        available_tools=["api_schema_discovery"],
        safety_grade="conservative",
    )
    origin = "https://example.com"
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [{"type": "service", "data": origin}],
        "surface": {},
        "history": [
            _history_entry(maker, "passive_config_audit", origin, {"max_paths": 10, "max_total_seconds": 18, "request_timeout_seconds": 3}),
        ],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False, available_tools=["api_schema_discovery"])

    assert [action.tool_name for action in plan.actions] == ["api_schema_discovery"]


def test_decision_maker_falls_back_to_legacy_logic_without_skills() -> None:
    maker = AuditDecisionMaker(
        available_tools=["dynamic_crawl"],
        safety_grade="balanced",
        skill_registry=SkillRegistry(),
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["dynamic_crawl"]
    assert plan.actions[0].options == {"allow_domain": ["example.com"], "max_depth": 2}


def test_default_available_tools_include_full_registered_core_set() -> None:
    expected = {
        "service_banner_probe",
        "git_exposure_check",
        "source_map_detector",
        "error_page_analyzer",
        "waf_detector",
        "security_txt_check",
        "api_schema_discovery",
        "cookie_security_audit",
        "csp_evaluator",
    }

    assert expected.issubset(set(AuditDecisionMaker.DEFAULT_AVAILABLE_TOOLS))


def test_decision_maker_generates_service_banner_probe_actions_from_nmap_services() -> None:
    maker = AuditDecisionMaker(
        available_tools=["service_banner_probe"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 20,
        "current_phase": "active_discovery",
        "breadcrumbs": [],
        "surface": {
            "nmap_services": [
                {"host": "example.com", "port": 22, "service": "ssh"},
                {"host": "example.com", "port": 6379, "service": "redis"},
                {"host": "example.com", "port": 80, "service": "http", "scheme": "http"},
            ]
        },
        "history": [
            _history_entry(
                maker,
                "nmap_scan",
                "example.com",
                {
                    "ports": "top-100",
                    "scan_profile": "conservative_service_discovery",
                    "timeout_seconds": 90,
                    "version_detection": False,
                },
            )
        ],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == [
        "service_banner_probe",
        "service_banner_probe",
    ]
    assert [action.target for action in plan.actions] == ["example.com", "example.com"]
    assert [action.options["port"] for action in plan.actions] == [22, 6379]
    assert [action.options["service"] for action in plan.actions] == ["ssh", "redis"]


def test_path_level_cap_limits_xss_and_sql_candidates_per_host() -> None:
    maker = AuditDecisionMaker(
        available_tools=["sql_sanitization_audit", "xss_protection_audit"],
        safety_grade="aggressive",
    )
    surface = {
        "api_endpoints": [
            {"url": "https://example.com/100?id=1", "method": "GET"},
            {"url": "https://example.com/101?id=1", "method": "GET"},
            {"url": "https://example.com/102?id=1", "method": "GET"},
            {"url": "https://example.com/103?id=1", "method": "GET"},
            {"url": "https://example.com/200?id=1", "method": "GET"},
        ],
        "url_parameters": {"id": ["1"]},
        "parameter_origins": {
            "id": [
                "https://example.com/100?id=1",
                "https://example.com/101?id=1",
                "https://example.com/102?id=1",
                "https://example.com/103?id=1",
                "https://example.com/200?id=1",
            ]
        },
    }
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": surface,
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    xss_targets = [action.target for action in plan.actions if action.tool_name == "xss_protection_audit"]
    sql_targets = [action.target for action in plan.actions if action.tool_name == "sql_sanitization_audit"]

    assert len(xss_targets) == 3
    assert len(sql_targets) == 3
    assert len(set(xss_targets)) == 3
    assert len(set(sql_targets)) == 3


def test_safety_grade_action_limits_are_raised_for_broader_tool_coverage() -> None:
    assert SAFETY_GRADE_ACTION_LIMITS == {
        "conservative": 5,
        "balanced": 8,
        "aggressive": 15,
    }


def test_decision_maker_generates_cve_lookup_and_verify_candidates() -> None:
    maker = AuditDecisionMaker(
        available_tools=["cve_lookup", "cve_verify"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {
            "tech_stack": ["nginx/1.18"],
            "authorization_confirmed": True,
            "cve_candidates": [
                {
                    "cve_id": "CVE-2024-1111",
                    "target": "https://example.com",
                    "safe_only": True,
                    "allow_high_risk": False,
                    "authorization_confirmed": True,
                }
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert "cve_lookup" in tool_names
    assert "cve_verify" in tool_names


def test_decision_maker_applies_llm_selected_cve_ids_to_verify_action() -> None:
    def _llm_callable(_prompt: str) -> str:
        return json.dumps(
            {
                "actions": [
                    {
                        "tool_name": "cve_verify",
                        "target": "https://example.com",
                        "options": {"cve_ids": ["CVE-2024-2222"]},
                    }
                ]
            }
        )

    maker = AuditDecisionMaker(
        llm_callable=_llm_callable,
        available_tools=["cve_verify"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "authorization_confirmed": True,
        "surface": {
            "authorization_confirmed": True,
            "cve_candidates": [
                {
                    "cve_id": "CVE-2024-1111",
                    "target": "https://example.com",
                    "severity": "medium",
                    "cvss_score": 6.5,
                    "has_nuclei_template": True,
                },
                {
                    "cve_id": "CVE-2024-2222",
                    "target": "https://example.com",
                    "severity": "high",
                    "cvss_score": 8.9,
                    "has_nuclei_template": True,
                },
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=True)
    cve_verify_actions = [action for action in plan.actions if action.tool_name == "cve_verify"]
    assert cve_verify_actions
    assert cve_verify_actions[0].options["cve_ids"] == ["CVE-2024-2222"]


def test_decision_maker_uses_top_level_cve_runtime_fields_for_verify() -> None:
    maker = AuditDecisionMaker(
        available_tools=["cve_verify"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "authorization_confirmed": True,
        "cve_safe_only": False,
        "cve_allow_high_risk": True,
        "cve_candidates": [
            {
                "cve_id": "CVE-2024-9999",
                "target": "https://example.com",
                "severity": "critical",
                "cvss_score": 9.8,
            }
        ],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["cve_verify"]
    options = plan.actions[0].options
    assert options["cve_ids"] == ["CVE-2024-9999"]
    assert options["authorization_confirmed"] is True
    assert options["safe_only"] is False
    assert options["allow_high_risk"] is True
    assert options["safety_grade"] == "aggressive"


def test_decision_maker_generates_rag_intel_lookup_candidates() -> None:
    maker = AuditDecisionMaker(
        available_tools=["rag_intel_lookup"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 60,
        "current_phase": "verification",
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {"tech_stack": ["nginx/1.18"]},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["rag_intel_lookup"]
    options = plan.actions[0].options
    assert options["component"] == "nginx"
    assert options["version"] == "1.18"


def test_decision_maker_generates_page_vision_analyzer_in_active_phase() -> None:
    maker = AuditDecisionMaker(
        available_tools=["page_vision_analyzer"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 60,
        "current_phase": "active_discovery",
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["page_vision_analyzer"]
    assert plan.actions[0].options["wait_until"] == "networkidle"
    assert plan.actions[0].options["full_page"] is True


def test_low_budget_active_phase_can_fall_back_to_nonzero_priority_when_needed() -> None:
    maker = AuditDecisionMaker(
        available_tools=["api_schema_discovery", "page_vision_analyzer"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 9,
        "current_phase": "active_discovery",
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["api_schema_discovery"]
    assert plan.actions[0].target == "https://example.com:443/"


def test_decision_maker_generates_poc_sandbox_exec_when_approved() -> None:
    maker = AuditDecisionMaker(
        available_tools=["poc_sandbox_exec"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "budget_remaining": 100,
        "current_phase": "verification",
        "breadcrumbs": [],
        "authorization_confirmed": True,
        "approval_granted": True,
        "surface": {
            "authorization_confirmed": True,
            "approval_granted": True,
            "rag_recommended_tools": ["poc_sandbox_exec"],
            "tech_components": [
                {
                    "component": "redis",
                    "version": "7.2.1",
                    "target": "cache.example.com",
                    "host": "cache.example.com",
                    "service": "redis",
                    "port": 6379,
                }
            ],
            "cve_candidates": [
                {
                    "cve_id": "CVE-2024-1111",
                    "target": "cache.example.com",
                    "component": "redis",
                    "version": "7.2.1",
                    "service": "redis",
                    "port": 6379,
                    "severity": "high",
                    "cvss_score": 8.9,
                }
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["poc_sandbox_exec"]
    options = plan.actions[0].options
    assert plan.actions[0].target == "cache.example.com"
    assert options["cve_id"] == "CVE-2024-1111"
    assert options["component"] == "redis"
    assert options["service"] == "redis"
    assert options["port"] == 6379
    assert options["approval_granted"] is True
    assert options["authorization_confirmed"] is True
    assert options["safety_grade"] == "aggressive"
    assert options["code_template"] == "redis_ping_info_probe"


def test_decision_maker_generates_cve_verify_for_protocol_host_candidates() -> None:
    maker = AuditDecisionMaker(
        available_tools=["cve_verify"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["cache.example.com"],
        "budget_remaining": 80,
        "current_phase": "verification",
        "authorization_confirmed": True,
        "surface": {
            "authorization_confirmed": True,
            "cve_candidates": [
                {
                    "cve_id": "CVE-2024-2222",
                    "target": "cache.example.com",
                    "component": "redis",
                    "version": "7.2.1",
                    "service": "redis",
                    "has_nuclei_template": True,
                }
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["cve_verify"]
    assert plan.actions[0].target == "cache.example.com"
    assert plan.actions[0].options["service"] == "redis"


def test_decision_maker_generates_nuclei_candidates_from_rag_recommended_tls_components() -> None:
    maker = AuditDecisionMaker(
        available_tools=["nuclei_exploit_check"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["app.example.com"],
        "target": "app.example.com",
        "budget_remaining": 80,
        "current_phase": "verification",
        "breadcrumbs": [],
        "surface": {
            "rag_recommended_tools": ["nuclei_exploit_check"],
            "tech_components": [
                {
                    "component": "tls",
                    "version": "TLSv1.0",
                    "target": "https://app.example.com",
                    "host": "app.example.com",
                    "service": "tls",
                    "port": 443,
                }
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["nuclei_exploit_check"]
    assert plan.actions[0].target == "https://app.example.com:443/"


def test_decision_maker_narrows_nuclei_templates_from_protocol_matched_cves() -> None:
    maker = AuditDecisionMaker(
        available_tools=["nuclei_exploit_check"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["app.example.com"],
        "target": "app.example.com",
        "budget_remaining": 80,
        "current_phase": "verification",
        "breadcrumbs": [],
        "surface": {
            "rag_recommended_tools": ["nuclei_exploit_check"],
            "nuclei_targets": ["https://app.example.com:443/"],
            "tech_components": [
                {
                    "component": "tls",
                    "version": "TLSv1.0",
                    "target": "https://app.example.com:443/",
                    "host": "app.example.com",
                    "service": "tls",
                    "port": 443,
                }
            ],
            "cve_candidates": [
                {
                    "cve_id": "CVE-2025-1001",
                    "target": "https://app.example.com:443/",
                    "component": "tls",
                    "service": "tls",
                    "severity": "high",
                    "has_nuclei_template": True,
                    "template_capability": {
                        "has_template": True,
                        "template_count": 2,
                        "template_paths": ["ssl/tls-version-check.yaml"],
                        "protocol_tags": ["tls", "https"],
                    },
                },
                {
                    "cve_id": "CVE-2024-0002",
                    "target": "https://app.example.com:443/",
                    "component": "generic-web",
                    "service": "http",
                    "severity": "medium",
                    "has_nuclei_template": True,
                    "template_capability": {
                        "has_template": True,
                        "template_count": 1,
                        "template_paths": ["http/generic-check.yaml"],
                        "protocol_tags": ["http"],
                    },
                },
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["nuclei_exploit_check"]
    assert plan.actions[0].options["template_id"] == ["CVE-2025-1001", "CVE-2024-0002"]
    assert plan.actions[0].options["templates"] == ["ssl/tls-version-check.yaml", "http/generic-check.yaml"]
    assert plan.actions[0].options["severity"] == ["medium", "high"]


def test_decision_maker_passes_rag_context_into_cve_lookup_for_protocol_components() -> None:
    maker = AuditDecisionMaker(
        available_tools=["cve_lookup"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["cache.example.com"],
        "target": "cache.example.com",
        "budget_remaining": 60,
        "current_phase": "verification",
        "breadcrumbs": [],
        "surface": {
            "tech_components": [
                {
                    "component": "redis",
                    "version": "7.2.1",
                    "target": "cache.example.com",
                    "host": "cache.example.com",
                    "service": "redis",
                    "port": 6379,
                }
            ],
            "rag_intel_hits": [
                {
                    "doc_id": "redis-public-exposure-patterns",
                    "title": "Redis public exposure",
                    "summary": "Redis unauthenticated access",
                    "tags": ["redis", "cache"],
                    "recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
                }
            ],
            "rag_recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
            "rag_recommendation_contexts": [
                {
                    "tool": "poc_sandbox_exec",
                    "target": "cache.example.com",
                    "component": "redis",
                    "version": "7.2.1",
                }
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["cve_lookup"]
    options = plan.actions[0].options
    assert options["service"] == "redis"
    assert options["rag_recommended_tools"] == ["cve_lookup", "poc_sandbox_exec"]
    assert options["rag_intel_hits"][0]["doc_id"] == "redis-public-exposure-patterns"


def test_build_hardened_prompt_uses_compact_prompt_state() -> None:
    maker = AuditDecisionMaker()
    state = {
        "target": "https://example.com",
        "scope": ["example.com"],
        "budget_remaining": 50,
        "current_phase": "active_discovery",
        "history": [
            {"tool": f"tool_{idx}", "target": f"https://example.com/{idx}", "status": "completed"}
            for idx in range(25)
        ],
        "breadcrumbs": [
            {"type": "endpoint", "data": f"https://example.com/path/{idx}"}
            for idx in range(25)
        ],
        "surface": {
            "tech_stack": ["nginx", "react"],
            "api_endpoints": [{"url": f"https://example.com/api/{idx}"} for idx in range(20)],
        },
        "memory_context": {
            "compression_applied": True,
            "known_origins": ["https://example.com:443"],
            "recent_actions": [{"tool": "nmap_scan", "status": "completed", "target": "example.com"}],
        },
    }

    prompt = maker.build_hardened_prompt(state)

    assert '"history_recent"' in prompt
    assert '"memory_context"' in prompt
    assert '"compression_notice"' in prompt
    assert '"history":[{' not in prompt


def test_decision_maker_uses_memory_context_to_restore_tech_stack_hints() -> None:
    maker = AuditDecisionMaker(
        available_tools=["cve_lookup", "rag_intel_lookup"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "target": "https://example.com",
        "budget_remaining": 60,
        "current_phase": "verification",
        "breadcrumbs": [{"type": "service", "data": "https://example.com"}],
        "surface": {},
        "memory_context": {
            "planning_hints": {
                "tech_stack": ["nginx/1.24"],
                "follow_up_tools": ["cve_lookup", "rag_intel_lookup"],
                "rag_recommended_tools": ["rag_intel_lookup"],
                "rag_intel_hits": [
                    {
                        "doc_id": "nginx-alias-lab",
                        "title": "Nginx alias traversal lab",
                        "severity_hint": "high",
                        "score": 6.0,
                        "recommended_tools": ["passive_config_audit", "nuclei_exploit_check"],
                    }
                ],
            }
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert "cve_lookup" in tool_names
    assert "rag_intel_lookup" in tool_names


def test_decision_maker_generates_protocol_follow_up_actions_from_discovered_services() -> None:
    maker = AuditDecisionMaker(
        available_tools=[
            "ssh_auth_audit",
            "redis_exposure_check",
            "memcached_exposure_check",
            "tls_service_probe",
        ],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "target": "https://example.com",
        "budget_remaining": 80,
        "current_phase": "passive_recon",
        "breadcrumbs": [{"type": "service", "data": "https://example.com:443"}],
        "surface": {
            "nmap_services": [
                {"host": "example.com", "port": 22, "service": "ssh"},
                {"host": "example.com", "port": 6379, "service": "redis"},
                {"host": "example.com", "port": 11211, "service": "memcached"},
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert "ssh_auth_audit" in tool_names
    assert "redis_exposure_check" in tool_names
    assert "memcached_exposure_check" in tool_names
    assert "tls_service_probe" in tool_names


def test_decision_maker_generates_mail_and_database_follow_up_actions_from_discovered_services() -> None:
    maker = AuditDecisionMaker(
        available_tools=[
            "smtp_security_check",
            "mysql_handshake_probe",
            "postgres_handshake_probe",
        ],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["example.com"],
        "target": "https://example.com",
        "budget_remaining": 80,
        "current_phase": "passive_recon",
        "breadcrumbs": [{"type": "service", "data": "https://example.com:443"}],
        "surface": {
            "nmap_services": [
                {"host": "example.com", "port": 25, "service": "smtp"},
                {"host": "example.com", "port": 3306, "service": "mysql"},
                {"host": "example.com", "port": 5432, "service": "postgresql"},
            ],
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert "smtp_security_check" in tool_names
    assert "mysql_handshake_probe" in tool_names
    assert "postgres_handshake_probe" in tool_names


def test_decision_maker_generates_scope_host_candidates_even_with_http_service_urls_present() -> None:
    maker = AuditDecisionMaker(
        available_tools=["reverse_dns_probe"],
        safety_grade="balanced",
    )
    state = {
        "scope": ["192.0.2.10"],
        "target": "https://example.com",
        "budget_remaining": 20,
        "current_phase": "passive_recon",
        "breadcrumbs": [{"type": "service", "data": "https://example.com:443"}],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)

    assert [action.tool_name for action in plan.actions] == ["reverse_dns_probe"]
    assert plan.actions[0].target == "192.0.2.10"


def test_decision_maker_generates_rag_and_cve_candidates_from_structured_tech_components() -> None:
    maker = AuditDecisionMaker(
        available_tools=["rag_intel_lookup", "cve_lookup"],
        safety_grade="aggressive",
    )
    state = {
        "scope": ["db.example.com"],
        "target": "db.example.com",
        "budget_remaining": 60,
        "current_phase": "verification",
        "breadcrumbs": [],
        "surface": {
            "tech_components": [
                {
                    "component": "mysql",
                    "version": "8.0.36-0ubuntu0",
                    "target": "db.example.com",
                    "service": "mysql",
                    "port": 3306,
                }
            ]
        },
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    tool_names = [action.tool_name for action in plan.actions]

    assert "rag_intel_lookup" in tool_names
    assert "cve_lookup" in tool_names
    rag_action = next(action for action in plan.actions if action.tool_name == "rag_intel_lookup")
    cve_action = next(action for action in plan.actions if action.tool_name == "cve_lookup")
    assert rag_action.target == "db.example.com"
    assert rag_action.options["component"] == "mysql"
    assert rag_action.options["version"] == "8.0.36-0ubuntu0"
    assert cve_action.options["component"] == "mysql"
