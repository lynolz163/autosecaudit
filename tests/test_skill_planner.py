from __future__ import annotations

from types import SimpleNamespace

from autosecaudit.agent_core.skill_loader import load_builtin_skill_registry
from autosecaudit.agent_core.skill_planner import SkillDrivenPlanner


def test_skill_planner_generates_nmap_candidates_from_skill_metadata() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("nmap_scan")
    assert skill is not None

    candidates = planner.generate_candidates_for_skill(
        skill=skill,
        tool=None,
        phase="passive_recon",
        planning_context={
            "scope_items": ["example.com"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": set(),
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(target="example.com", target_type="host_seed", context={})
            ],
        },
    )

    assert len(candidates) == 1
    assert candidates[0].tool_name == "nmap_scan"
    assert candidates[0].options["ports"] == "top-100"
    assert "initial service discovery" in str(candidates[0].reason)
    assert candidates[0].preconditions == ["target_in_scope", "not_already_done"]


def test_skill_planner_interprets_nmap_results_and_generates_follow_ups() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("nmap_scan")
    assert skill is not None

    interpreted = planner.interpret_result(
        skill,
        {
            "status": "completed",
            "error": None,
            "payload": {
                "data": {
                    "hosts": [
                        {
                            "hostnames": ["example.com"],
                            "addresses": [{"addr": "93.184.216.34"}],
                            "open_ports": [{"port": 80, "service": "http"}],
                        }
                    ]
                }
            },
            "findings": [],
            "breadcrumbs_delta": [],
            "surface_delta": {},
            "follow_up_hints": [],
            "metadata": {},
        },
    )

    assert {"type": "service", "data": "http://example.com:80"} in interpreted["breadcrumbs_delta"]
    assert "tech_stack_fingerprint" in interpreted["follow_up_hints"]
    assert interpreted["surface_delta"]["nmap_hosts"][0]["hostnames"] == ["example.com"]


def test_skill_planner_resolves_surface_follow_ups_from_skill_rules() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("tech_stack_fingerprint")
    assert skill is not None

    follow_ups = planner.resolve_surface_follow_ups(skill, {"tech_stack": ["react"]})

    assert follow_ups == ["source_map_detector", "api_schema_discovery"]


def test_skill_planner_generates_cve_lookup_candidates_from_tech_stack() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("cve_lookup")
    assert skill is not None

    candidates = planner.generate_candidates_for_skill(
        skill=skill,
        tool=None,
        phase="verification",
        planning_context={
            "scope_items": ["example.com"],
            "origins": ["https://example.com"],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": set(),
            "surface": {"tech_stack": ["nginx/1.18"]},
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(
                    target="https://example.com",
                    target_type="tech_component",
                    context={"component": "nginx", "version": "1.18"},
                )
            ],
        },
    )

    assert len(candidates) == 1
    assert candidates[0].options["component"] == "nginx"
    assert candidates[0].options["version"] == "1.18"


def test_skill_planner_generates_service_banner_probe_candidates_from_nmap_services() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("service_banner_probe")
    assert skill is not None

    candidates = planner.generate_candidates_for_skill(
        skill=skill,
        tool=None,
        phase="active_discovery",
        planning_context={
            "scope_items": ["example.com"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": {"nmap_scan"},
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(
                    target="example.com",
                    target_type="service_port",
                    context={"port": 22, "service": "ssh"},
                )
            ],
        },
    )

    assert len(candidates) == 1
    assert candidates[0].tool_name == "service_banner_probe"
    assert candidates[0].options == {
        "port": 22,
        "service": "ssh",
        "timeout_seconds": 4,
        "read_bytes": 512,
    }
    assert "ssh service port 22" in str(candidates[0].reason)


def test_skill_planner_filters_service_port_candidates_by_service_match() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("redis_exposure_check")
    assert skill is not None

    candidates = planner.generate_candidates_for_skill(
        skill=skill,
        tool=None,
        phase="verification",
        planning_context={
            "scope_items": ["example.com"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": {"nmap_scan"},
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(target="example.com", target_type="service_port", context={"port": 22, "service": "ssh"}),
                SimpleNamespace(target="example.com", target_type="service_port", context={"port": 6379, "service": "redis"}),
            ],
        },
    )

    assert len(candidates) == 1
    assert candidates[0].tool_name == "redis_exposure_check"
    assert candidates[0].options["port"] == 6379


def test_skill_planner_generates_mail_and_database_service_candidates() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    smtp_skill = registry.for_tool("smtp_security_check")
    mysql_skill = registry.for_tool("mysql_handshake_probe")
    assert smtp_skill is not None
    assert mysql_skill is not None

    smtp_candidates = planner.generate_candidates_for_skill(
        skill=smtp_skill,
        tool=None,
        phase="passive_recon",
        planning_context={
            "scope_items": ["example.com"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": {"nmap_scan"},
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(target="example.com", target_type="service_port", context={"port": 25, "service": "smtp"}),
                SimpleNamespace(target="example.com", target_type="service_port", context={"port": 3306, "service": "mysql"}),
            ],
        },
    )
    mysql_candidates = planner.generate_candidates_for_skill(
        skill=mysql_skill,
        tool=None,
        phase="verification",
        planning_context={
            "scope_items": ["example.com"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": {"nmap_scan"},
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(target="example.com", target_type="service_port", context={"port": 25, "service": "smtp"}),
                SimpleNamespace(target="example.com", target_type="service_port", context={"port": 3306, "service": "mysql"}),
            ],
        },
    )

    assert len(smtp_candidates) == 1
    assert smtp_candidates[0].options["port"] == 25
    assert len(mysql_candidates) == 1
    assert mysql_candidates[0].options["port"] == 3306


def test_skill_planner_generates_reverse_dns_probe_from_scope_host_targets() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("reverse_dns_probe")
    assert skill is not None

    candidates = planner.generate_candidates_for_skill(
        skill=skill,
        tool=None,
        phase="passive_recon",
        planning_context={
            "scope_items": ["192.0.2.10"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": set(),
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(target="192.0.2.10", target_type="scope_host", context={}),
            ],
        },
    )

    assert len(candidates) == 1
    assert candidates[0].tool_name == "reverse_dns_probe"


def test_skill_planner_resolves_protocol_surface_follow_ups_from_component_names() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    mysql_skill = registry.for_tool("mysql_handshake_probe")
    dns_skill = registry.for_tool("dns_zone_audit")
    redis_skill = registry.for_tool("redis_exposure_check")
    rag_skill = registry.for_tool("rag_intel_lookup")
    assert mysql_skill is not None
    assert dns_skill is not None
    assert redis_skill is not None
    assert rag_skill is not None

    mysql_follow_ups = planner.resolve_surface_follow_ups(
        mysql_skill,
        {"tech_component_names": ["mysql"]},
    )
    dns_follow_ups = planner.resolve_surface_follow_ups(
        dns_skill,
        {"dns_follow_up_signals": ["authoritative_records", "zone_transfer"]},
    )
    redis_follow_ups = planner.resolve_surface_follow_ups(
        redis_skill,
        {"tech_component_names": ["redis"]},
    )
    rag_follow_ups = planner.resolve_surface_follow_ups(
        rag_skill,
        {"rag_recommended_tools": ["poc_sandbox_exec"]},
    )

    assert mysql_follow_ups == ["rag_intel_lookup", "cve_lookup"]
    assert dns_follow_ups == ["subdomain_enum_passive", "reverse_dns_probe"]
    assert redis_follow_ups == ["rag_intel_lookup", "cve_lookup"]
    assert rag_follow_ups == ["poc_sandbox_exec"]


def test_skill_planner_generates_poc_candidate_from_rag_recommended_tech_component() -> None:
    planner = SkillDrivenPlanner()
    registry = load_builtin_skill_registry()
    skill = registry.for_tool("poc_sandbox_exec")
    assert skill is not None

    candidates = planner.generate_candidates_for_skill(
        skill=skill,
        tool=None,
        phase="verification",
        planning_context={
            "scope_items": ["cache.example.com"],
            "origins": [],
            "endpoint_params": {},
            "surface_confirmed_endpoints": set(),
            "nuclei_targets": [],
            "history_tools": set(),
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
                        "service": "redis",
                        "port": 6379,
                    }
                ],
            },
            "resolve_targets": lambda _target_types: [
                SimpleNamespace(
                    target="cache.example.com",
                    target_type="tech_component",
                    context={
                        "component": "redis",
                        "version": "7.2.1",
                        "service": "redis",
                        "port": 6379,
                        "authorization_confirmed": True,
                        "approval_granted": True,
                        "safety_grade": "aggressive",
                    },
                ),
            ],
        },
    )

    assert len(candidates) == 1
    assert candidates[0].tool_name == "poc_sandbox_exec"
    assert candidates[0].options["code_template"] == "auto"
    assert candidates[0].options["component"] == "redis"
