from __future__ import annotations

import json
from pathlib import Path

from autosecaudit.core.report import (
    generate_agent_json_report,
    generate_agent_visual_html_report,
    generate_markdown_report,
)


def test_generate_agent_json_report_includes_coverage_summary(tmp_path: Path) -> None:
    output_path = tmp_path / "audit_report.json"
    state = {
        "target": "https://example.com",
        "scope": ["example.com"],
        "breadcrumbs": [
            {"type": "service", "data": "https://example.com:443"},
            {"type": "service", "data": "http://example.com:80"},
        ],
        "surface": {
            "api_endpoints": [{"url": "https://example.com/api/users?id=1"}],
            "discovered_urls": ["https://example.com/login"],
            "url_parameters": {"id": ["1"]},
            "tech_stack": ["wordpress", "nginx"],
            "config_exposures": [{"path": ".env"}],
        },
        "history": [
            {"tool": "nmap_scan", "status": "completed", "action_cost": 15},
            {"tool": "dynamic_crawl", "status": "completed", "action_cost": 12},
            {"tool": "tech_stack_fingerprint", "status": "error", "action_cost": 2},
        ],
        "budget_remaining": 71,
        "iteration_count": 2,
    }

    payload = generate_agent_json_report(
        findings=[
            {
                "type": "vuln",
                "name": "Sensitive File Exposure: .env",
                "severity": "high",
                "evidence": "SECRET_KEY=example",
                "reproduction_steps": ["GET /.env"],
            }
        ],
        state=state,
        output_path=output_path,
        decision_summary="Executed discovery and surface analysis.",
    )

    coverage = payload["coverage"]
    assert coverage["unique_tools_executed"] == 3
    assert coverage["service_origins_observed"] == 2
    assert coverage["api_endpoint_count"] == 1
    assert coverage["parameter_count"] == 1
    assert coverage["config_exposure_count"] == 1
    assert coverage["completed_actions"] == 2
    assert coverage["error_actions"] == 1
    assert any(item["tool"] == "dynamic_crawl" for item in coverage["tool_stats"])
    assert payload["risk_matrix"]["total_score"] == 15
    assert payload["risk_matrix"]["categories"][0]["name"] == "configuration"
    assert payload["risk_matrix"]["categories"][0]["finding_count"] == 1


def test_recon_summary_with_full_surface(tmp_path: Path) -> None:
    """Verify that the 'recon' section aggregates all expected surface data."""
    output_path = tmp_path / "audit_report.json"
    state = {
        "target": "https://example.com",
        "scope": ["example.com"],
        "breadcrumbs": [
            {"type": "service", "data": "https://example.com"},
            {"type": "endpoint", "data": "https://example.com/api"},
        ],
        "surface": {
            "discovered_subdomains": ["sub1.example.com", "sub2.example.com"],
            "tls_metadata": {
                "host": "example.com",
                "port": 443,
                "days_left": 90,
                "expires_at": "2026-06-01T00:00:00Z",
                "tls_version": "TLSv1.3",
                "subject_alt_name": [["DNS", "example.com"], ["DNS", "*.example.com"]],
            },
            "http_security_headers": {
                "server": "nginx",
                "content-type": "text/html",
            },
            "waf": {
                "confidence": 0.92,
                "summary": "Passive response markers matched Cloudflare.",
                "signals": ["cf-cache-status", "server: cloudflare"],
            },
            "tech_stack": ["nginx", "react"],
            "waf_vendors": ["cloudflare"],
            "ports": [
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
            "services": [
                {"host": "example.com", "port": 443, "service": "https", "protocol": "tcp", "tls": True, "auth_required": False},
            ],
            "security_txt": {
                "present": True,
                "status_code": 200,
                "url": "https://example.com/.well-known/security.txt",
                "has_contact": True,
                "has_expires": False,
                "line_count": 3,
                "content_preview": "Contact: security@example.com",
            },
            "csp_evaluation": {
                "present": True,
                "url": "https://example.com",
                "policy": "default-src 'self'",
                "risky_tokens": [],
                "has_script_src": False,
                "has_default_src": True,
            },
            "cookies": [
                {"name": "session", "secure": True, "httponly": True, "samesite": True},
                {"name": "prefs", "secure": False, "httponly": False, "samesite": False},
            ],
            "login_forms": [
                {"action": "https://example.com/login", "method": "POST", "params": {"username": "", "password": ""}},
            ],
            "api_schemas": [
                {"url": "https://example.com/openapi.json", "kind": "openapi", "status_code": 200},
            ],
            "git_exposures": [
                {"url": "https://example.com/.git/HEAD", "status_code": 200, "type": "git_head"},
            ],
            "source_maps": ["https://example.com/app.js.map"],
            "api_endpoints": [{"url": "https://example.com/api/users", "method": "GET", "source": "crawl"}],
            "discovered_urls": ["https://example.com/", "https://example.com/about"],
            "url_parameters": {"id": ["1", "2"], "page": ["1"]},
            "config_exposures": [{"path": ".env", "status_code": 200}],
            "error_page_markers": ["traceback", "debug"],
        },
        "history": [
            {"tool": "ssl_expiry_check", "status": "completed", "target": "https://example.com"},
        ],
    }

    payload = generate_agent_json_report(
        findings=[],
        state=state,
        output_path=output_path,
        decision_summary="Full recon test.",
    )

    recon = payload["recon"]

    # target info
    assert recon["target_info"]["target"] == "https://example.com"
    assert recon["target_info"]["scope"] == ["example.com"]
    assert "https://example.com" in recon["target_info"]["service_origins"]

    # subdomains
    assert "sub1.example.com" in recon["subdomains"]
    assert "sub2.example.com" in recon["subdomains"]

    # TLS
    assert recon["tls_certificate"]["tls_version"] == "TLSv1.3"
    assert recon["tls_certificate"]["days_left"] == 90

    # HTTP headers
    assert recon["http_headers"]["server"] == "nginx"

    # Tech stack
    assert "nginx" in recon["tech_stack"]
    assert "react" in recon["tech_stack"]

    # WAF
    assert "cloudflare" in recon["waf_cdn"]

    # Security policies
    assert recon["security_policies"]["security_txt"]["present"] is True
    assert recon["security_policies"]["csp_evaluation"]["present"] is True
    assert recon["security_policies"]["csp_evaluation"]["has_default_src"] is True
    assert len(recon["security_policies"]["cookies"]) == 2

    # Login forms
    assert len(recon["login_forms"]) == 1
    assert recon["login_forms"][0]["action"] == "https://example.com/login"

    # API schemas
    assert len(recon["api_schemas"]) == 1
    assert recon["api_schemas"][0]["kind"] == "openapi"

    # Git exposures
    assert len(recon["git_exposures"]) == 1

    # Source maps
    assert "https://example.com/app.js.map" in recon["source_maps"]

    # URLs & endpoints
    assert len(recon["discovered_urls"]) == 2
    assert len(recon["api_endpoints"]) == 1

    # Parameters
    assert "id" in recon["url_parameters"]

    # Error markers
    assert "traceback" in recon["error_page_markers"]

    # Tools executed
    assert len(recon["tools_executed"]) == 1
    infrastructure = payload["infrastructure"]
    assert infrastructure["ports"][0]["port"] == 443
    assert infrastructure["waf"]["detected"] is True
    assert any(item["name"] == "nginx" for item in infrastructure["middleware"])
    assert infrastructure["certificates"][0]["tls_version"] == "TLSv1.3"

    attack_surface = payload["attack_surface"]
    assert any(item["type"] == "login_form" for item in attack_surface["entry_points"])
    assert any(item["type"] == "api_endpoint" for item in attack_surface["entry_points"])
    assert any(item["type"] == "config_exposure" for item in attack_surface["sensitive_paths"])
    assert any(item["type"] == "source_map" for item in attack_surface["sensitive_paths"])


def test_recon_summary_with_empty_surface(tmp_path: Path) -> None:
    """Ensure _build_recon_summary handles empty / minimal state without errors."""
    output_path = tmp_path / "audit_report.json"
    state = {
        "target": "https://empty.example.com",
        "scope": [],
        "breadcrumbs": [],
        "surface": {},
        "history": [],
    }

    payload = generate_agent_json_report(
        findings=[], state=state, output_path=output_path,
    )

    recon = payload["recon"]
    assert recon["target_info"]["target"] == "https://empty.example.com"
    assert recon["subdomains"] == []
    assert recon["tls_certificate"] == {}
    assert recon["waf_cdn"] == []
    assert recon["tech_stack"] == []
    assert recon["login_forms"] == []
    assert recon["api_schemas"] == []
    assert recon["git_exposures"] == []
    assert recon["source_maps"] == []
    assert recon["discovered_urls"] == []
    assert recon["api_endpoints"] == []
    assert recon["url_parameters"] == {}
    assert recon["error_page_markers"] == []
    assert recon["tools_executed"] == []


def test_markdown_report_includes_recon(tmp_path: Path) -> None:
    """Verify recon_data sections appear in the generated Markdown."""
    output_file = tmp_path / "report.md"
    recon_data = {
        "target_info": {"target": "https://example.com", "scope": ["example.com"], "service_origins": []},
        "subdomains": ["sub1.example.com"],
        "dns_records": {},
        "ports_services": {"ports": [], "services": []},
        "tls_certificate": {"host": "example.com", "port": 443, "tls_version": "TLSv1.3", "days_left": 90, "expires_at": "2026-06-01"},
        "http_headers": {"server": "nginx"},
        "tech_stack": ["nginx"],
        "waf_cdn": ["cloudflare"],
        "security_policies": {"security_txt": {}, "csp_evaluation": {}, "cookies": []},
        "login_forms": [],
        "api_schemas": [],
        "config_exposures": [],
        "git_exposures": [],
        "source_maps": [],
        "discovered_urls": [],
        "api_endpoints": [],
        "url_parameters": {},
        "error_page_markers": [],
        "tools_executed": [],
    }

    content = generate_markdown_report([], str(output_file), recon_data=recon_data)

    assert "## Reconnaissance & Information Gathering" in content
    assert "### Target Overview" in content
    assert "### Subdomain Enumeration" in content
    assert "sub1.example.com" in content
    assert "### SSL/TLS Certificate" in content
    assert "TLSv1.3" in content
    assert "### HTTP Security Headers" in content
    assert "nginx" in content
    assert "### Technology Stack" in content
    assert "### WAF / CDN Detection" in content
    assert "cloudflare" in content


def test_markdown_report_supports_chinese_and_detailed_sections(tmp_path: Path) -> None:
    output_file = tmp_path / "report_zh.md"
    findings = [
        {
            "type": "vuln",
            "name": "SQL Injection",
            "severity": "high",
            "evidence": {"url": "https://example.com?id=1'"},
            "reproduction_steps": ["GET /?id=1%27", "Observe SQL error"],
            "recommendation": "Use parameterized queries.",
            "cve_id": "CVE-2024-9999",
            "cvss_score": 9.1,
            "cve_verified": True,
        }
    ]
    content = generate_markdown_report(
        findings,
        str(output_file),
        report_lang="zh-CN",
        coverage_data={
            "unique_tools_executed": 2,
            "completed_actions": 1,
            "failed_actions": 0,
            "error_actions": 1,
            "service_origins_observed": 1,
            "api_endpoint_count": 1,
            "parameter_count": 1,
            "tool_stats": [
                {"tool": "sql_sanitization_audit", "total": 1, "completed": 1, "failed": 0, "error": 0},
            ],
            "highlights": ["Detected SQLi signal."],
        },
        history_data=[
            {
                "tool": "sql_sanitization_audit",
                "target": "https://example.com",
                "status": "completed",
                "action_cost": 8,
                "budget_before": 50,
                "budget_after": 42,
                "ranking_explanation": {
                    "selected_candidate": "SQLI-signal",
                    "candidate_order": ["SQLI-signal", "XSS-signal"],
                    "selected_templates": ["web/sqli/basic.yaml"],
                    "reasons": ["Parameterized endpoint discovered during crawl."],
                },
            }
        ],
        blocked_actions=[
            {
                "action": {
                    "tool_name": "nuclei_exploit_check",
                    "target": "https://example.com",
                    "preconditions": ["authorization_confirmed"],
                },
                "reason": "missing_precondition:authorization_confirmed",
            }
        ],
        state_data={
            "target": "https://example.com",
            "safety_grade": "balanced",
            "iteration_count": 1,
            "budget_remaining": 42,
            "scope": ["example.com"],
            "breadcrumbs": [],
            "surface": {},
        },
        decision_summary="执行了SQL注入检查。",
    )

    assert "# 安全审计报告" in content
    assert "## 决策摘要" in content
    assert "## 执行覆盖" in content
    assert "## 被阻断动作" in content
    assert "## 详细证据" in content
    assert "SQLI-signal" in content
    assert "web/sqli/basic.yaml" in content
    assert "CVE-2024-9999" in content


def test_agent_json_report_includes_runtime_and_blocked_actions(tmp_path: Path) -> None:
    output_path = tmp_path / "audit_report.json"
    payload = generate_agent_json_report(
        findings=[{"type": "vuln", "name": "XSS", "severity": "high", "evidence": "<script>alert(1)</script>"}],
        state={
            "target": "https://example.com",
            "scope": ["example.com"],
            "breadcrumbs": [],
            "surface": {},
            "history": [{"tool": "xss_protection_audit", "status": "error", "action_cost": 6}],
            "budget_remaining": 44,
            "total_budget": 50,
            "iteration_count": 1,
            "safety_grade": "aggressive",
        },
        output_path=output_path,
        report_lang="zh-CN",
        blocked_actions=[
            {
                "action": {"tool_name": "nuclei_exploit_check", "target": "https://example.com"},
                "reason": "insufficient_budget",
            }
        ],
    )

    assert payload["meta"]["report_lang"] == "zh-CN"
    assert payload["summary"]["blocked_actions_count"] == 1
    assert payload["summary"]["failed_actions_count"] == 1
    assert payload["execution"]["runtime"]["safety_grade"] == "aggressive"
    assert payload["execution"]["blocked_actions"][0]["reason"] == "insufficient_budget"


def test_agent_json_report_preserves_phase_and_metadata_summary(tmp_path: Path) -> None:
    output_path = tmp_path / "audit_report.json"
    payload = generate_agent_json_report(
        findings=[],
        state={
            "target": "redis.example.com",
            "scope": ["redis.example.com"],
            "breadcrumbs": [],
            "surface": {},
            "current_phase": "verification",
            "phase_history": [{"phase": "verification", "reason": "advance:deep_testing"}],
            "history": [
                {
                    "tool": "cve_verify",
                    "target": "redis.example.com",
                    "status": "completed",
                    "phase": "verification",
                    "ranking_explanation": {
                        "component": "redis",
                        "selected_candidate": "CVE-2025-0001",
                    },
                    "metadata_summary": {
                        "component": "redis",
                        "candidate_order": ["CVE-2025-0001"],
                    },
                }
            ],
        },
        output_path=output_path,
    )

    assert payload["meta"]["current_phase"] == "verification"
    assert payload["execution"]["phase_history"][0]["phase"] == "verification"
    assert payload["history"][0]["phase"] == "verification"
    assert payload["history"][0]["metadata_summary"]["component"] == "redis"
    assert payload["history"][0]["ranking_explanation"]["selected_candidate"] == "CVE-2025-0001"


def test_agent_visual_html_report_includes_asset_topology_section(tmp_path: Path) -> None:
    json_report = tmp_path / "audit_report.json"
    state_path = tmp_path / "agent_state.json"
    html_path = tmp_path / "agent_report.html"

    generate_agent_json_report(
        findings=[
            {
                "type": "vuln",
                "name": "SMTP service on mail.example.com:25 does not advertise STARTTLS",
                "severity": "low",
                "evidence": {"host": "mail.example.com", "port": 25},
                "related_asset_ids": ["service:tcp:mail.example.com:25:smtp"],
            }
        ],
        state={
            "target": "mail.example.com",
            "scope": ["example.com"],
            "breadcrumbs": [],
            "surface": {
                "poc_protocol_evidence": [
                    {
                        "protocol": "smtp",
                        "service": "smtp",
                        "host": "mail.example.com",
                        "port": 25,
                        "template": "smtp_probe",
                        "tls_supported": False,
                        "banner": "220 mail.example.com ESMTP Postfix 3.8.5",
                    }
                ]
            },
            "assets": [
                {
                    "kind": "service",
                    "id": "service:tcp:mail.example.com:25:smtp",
                    "source_tool": "smtp_security_check",
                    "attributes": {
                        "host": "mail.example.com",
                        "port": 25,
                        "proto": "tcp",
                        "service": "smtp",
                        "banner": "220 mail.example.com ESMTP Postfix 3.8.5",
                        "tls": False,
                        "auth_required": True,
                    },
                    "evidence": {"banner": "220 mail.example.com ESMTP Postfix 3.8.5"},
                }
            ],
            "history": [],
        },
        output_path=json_report,
    )
    state_path.write_text(
        json.dumps(
            {
                "target": "mail.example.com",
                "scope": ["example.com"],
                "breadcrumbs": [],
                "surface": {
                    "poc_protocol_evidence": [
                        {
                            "protocol": "smtp",
                            "service": "smtp",
                            "host": "mail.example.com",
                            "port": 25,
                            "template": "smtp_probe",
                            "tls_supported": False,
                            "banner": "220 mail.example.com ESMTP Postfix 3.8.5",
                        }
                    ]
                },
                "assets": [
                    {
                        "kind": "service",
                        "id": "service:tcp:mail.example.com:25:smtp",
                        "source_tool": "smtp_security_check",
                        "attributes": {
                            "host": "mail.example.com",
                            "port": 25,
                            "proto": "tcp",
                            "service": "smtp",
                            "banner": "220 mail.example.com ESMTP Postfix 3.8.5",
                            "tls": False,
                            "auth_required": True,
                        },
                        "evidence": {"banner": "220 mail.example.com ESMTP Postfix 3.8.5"},
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    html = generate_agent_visual_html_report(
        audit_report_json_path=json_report,
        agent_state_json_path=state_path,
        output_html_path=html_path,
    )

    assert "Asset Topology" in html
    assert "Asset Trends" in html
    assert "service:tcp:mail.example.com:25:smtp" in html
    assert "220 mail.example.com ESMTP Postfix 3.8.5" in html
    assert "SMTP service on mail.example.com:25 does not advertise STARTTLS" in html
    assert "Structured Validation" in html
    assert "smtp_probe" in html
    assert "tls_supported" in html
    assert "Redis Version" in html


def test_agent_visual_html_report_includes_verification_ranking_and_batch_trends(tmp_path: Path) -> None:
    output_root = tmp_path / "web-jobs"
    previous_agent_dir = output_root / "job-previous-redis-example" / "agent"
    current_agent_dir = output_root / "job-current-redis-example" / "agent"
    previous_agent_dir.mkdir(parents=True, exist_ok=True)
    current_agent_dir.mkdir(parents=True, exist_ok=True)

    previous_json = previous_agent_dir / "audit_report.json"
    generate_agent_json_report(
        findings=[],
        state={
            "target": "redis.example.com",
            "scope": ["redis.example.com"],
            "breadcrumbs": [],
            "surface": {},
            "assets": [
                {
                    "kind": "service",
                    "id": "service:tcp:redis.example.com:6379:redis",
                    "source_tool": "redis_exposure_check",
                    "attributes": {
                        "host": "redis.example.com",
                        "port": 6379,
                        "proto": "tcp",
                        "service": "redis",
                    },
                }
            ],
            "history": [],
        },
        output_path=previous_json,
    )

    current_json = current_agent_dir / "audit_report.json"
    state_path = current_agent_dir / "agent_state.json"
    html_path = current_agent_dir / "agent_report.html"

    generate_agent_json_report(
        findings=[
            {
                "type": "vuln",
                "name": "Redis unauthenticated access",
                "severity": "high",
                "related_asset_ids": ["service:tcp:redis.example.com:6379:redis"],
                "evidence": {"host": "redis.example.com", "port": 6379},
            }
        ],
        state={
            "target": "redis.example.com",
            "scope": ["redis.example.com"],
            "current_phase": "verification",
            "phase_history": [{"phase": "verification", "reason": "advance:deep_testing"}],
            "breadcrumbs": [],
            "surface": {
                "cve_lookup_results": [
                    {
                        "target": "redis.example.com",
                        "component": "redis",
                        "service": "redis",
                        "version": "7.2.1",
                        "cve_id": "CVE-2025-0001",
                        "rank": 1,
                        "severity": "high",
                        "cvss_score": 8.8,
                        "has_nuclei_template": True,
                        "ranking_context": {
                            "component": "redis",
                            "service": "redis",
                            "version": "7.2.1",
                            "rag_recommended_tools": ["cve_verify", "poc_sandbox_exec"],
                            "rag_tags": ["redis", "unauthenticated"],
                        },
                        "template_capability": {
                            "template_count": 2,
                            "protocol_tags": ["redis", "tcp"],
                        },
                    }
                ],
                "cve_verification": [{"cve_id": "CVE-2025-0001", "verified": True}],
                "template_capability_index": {
                    "CVE-2025-0001": {
                        "template_count": 2,
                        "protocol_tags": ["redis", "tcp"],
                    }
                },
            },
            "assets": [
                {
                    "kind": "service",
                    "id": "service:tcp:redis.example.com:6379:redis",
                    "source_tool": "redis_exposure_check",
                    "attributes": {
                        "host": "redis.example.com",
                        "port": 6379,
                        "proto": "tcp",
                        "service": "redis",
                    },
                },
                {
                    "kind": "host",
                    "id": "host:redis.example.com",
                    "source_tool": "nmap_scan",
                    "attributes": {"host": "redis.example.com"},
                },
            ],
            "history": [
                {
                    "tool": "cve_verify",
                    "target": "redis.example.com",
                    "status": "completed",
                    "phase": "verification",
                    "ranking_explanation": {
                        "selected_candidate": "CVE-2025-0001",
                        "candidate_order": ["CVE-2025-0001", "CVE-2024-9999"],
                        "selected_templates": ["network/redis/cve-2025-0001.yaml"],
                        "reasons": ["RAG recommended cve_verify", "Protocol tags: redis, tcp"],
                    },
                    "metadata_summary": {
                        "component": "redis",
                        "service": "redis",
                        "version": "7.2.1",
                        "verification_order": ["CVE-2025-0001"],
                        "selected_templates": ["network/redis/cve-2025-0001.yaml"],
                    },
                }
            ],
        },
        output_path=current_json,
    )

    state_path.write_text(
        json.dumps(
            {
                "target": "redis.example.com",
                "scope": ["redis.example.com"],
                "current_phase": "verification",
                "phase_history": [{"phase": "verification", "reason": "advance:deep_testing"}],
                "surface": {},
                "assets": [],
                "history": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    html = generate_agent_visual_html_report(
        audit_report_json_path=current_json,
        agent_state_json_path=state_path,
        output_html_path=html_path,
    )

    assert "Verification Ranking" in html
    assert "CVE-2025-0001" in html
    assert "Run Batch Trends" in html
    assert "Phase Trends" in html
    assert "New / Resolved Since Previous Batch" in html
    assert "Asset Inventory Changes" in html
    assert "Service Changes" in html
    assert "Executed Actions and Selection Rationale" in html
    assert "Asset Severity Breakdown" in html
    assert "Service Protocol Breakdown" in html
    assert "redis/tcp" in html
    assert "redis.example.com" in html
    assert "Redis unauthenticated access" in html
    assert "job-previous-redis-example" in html
    assert "job-current-redis-example" in html
