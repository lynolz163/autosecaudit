from __future__ import annotations

import json
from html import escape as html_escape
from pathlib import Path

from autosecaudit.webapp.reporting import (
    build_report_analysis,
    enrich_report_assets,
    extract_report_assets,
    extract_report_findings,
    render_generated_report_html,
    summarize_report_assets,
)


def test_reporting_links_assets_to_findings_via_related_asset_ids() -> None:
    payload = {
        "scope": {
            "assets": [
                {
                    "id": "service:tcp:example.com:25:smtp",
                    "kind": "service",
                    "source_tool": "smtp_security_check",
                    "attributes": {"host": "example.com", "port": 25, "service": "smtp", "proto": "tcp"},
                    "evidence": {},
                },
                {
                    "id": "domain:example.com",
                    "kind": "domain",
                    "source_tool": "dns_zone_audit",
                    "attributes": {"domain": "example.com"},
                    "evidence": {},
                },
            ]
        },
        "findings": [
            {
                "id": "smtp-starttls",
                "tool": "smtp_security_check",
                "title": "SMTP service on example.com:25 does not advertise STARTTLS",
                "severity": "low",
                "evidence": {"host": "example.com", "port": 25},
                "related_asset_ids": ["service:tcp:example.com:25:smtp"],
            },
            {
                "id": "zone-transfer",
                "tool": "dns_zone_audit",
                "title": "DNS zone transfer exposed for example.com",
                "severity": "high",
                "evidence": {"domain": "example.com"},
                "related_asset_ids": ["domain:example.com"],
            },
        ],
    }

    findings = extract_report_findings(payload)
    assets = enrich_report_assets(extract_report_assets(payload), findings)
    summary = summarize_report_assets(assets)

    assert findings[0]["related_asset_ids"]
    smtp_asset = next(item for item in assets if item["id"] == "service:tcp:example.com:25:smtp")
    assert smtp_asset["finding_count"] == 1
    assert smtp_asset["display_name"] == "example.com:25 (smtp)"
    assert summary["total_assets"] == 2
    assert summary["service_assets"] == 1
    assert summary["assets_by_kind"]["domain"] == 1


class _FakeReportManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._jobs: list[dict[str, object]] = []
        self._artifacts: dict[str, list[dict[str, object]]] = {}

    def list_jobs(self) -> list[dict[str, object]]:
        return list(self._jobs)

    def list_artifacts(self, job_id: str) -> list[dict[str, object]]:
        return list(self._artifacts.get(job_id, []))

    def resolve_file(self, job_id: str, relative_path: str) -> Path:
        path = self.root / job_id / relative_path
        if not path.exists():
            raise FileNotFoundError(relative_path)
        return path


def _write_job_payload(
    manager: _FakeReportManager,
    *,
    job_id: str,
    target: str,
    payload: dict[str, object],
    updated_at: str,
) -> None:
    job_dir = manager.root / job_id / "agent"
    job_dir.mkdir(parents=True, exist_ok=True)
    report_path = job_dir / "audit_report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    artifacts = [{"path": "agent/audit_report.json", "size": report_path.stat().st_size}]
    artifact_dir = job_dir / "artifacts"
    if artifact_dir.exists():
        for item in artifact_dir.glob("*.json"):
            artifacts.append({"path": f"agent/artifacts/{item.name}", "size": item.stat().st_size})
    manager._jobs.append(
        {
            "job_id": job_id,
            "target": target,
            "mode": "agent",
            "status": "completed",
            "last_updated_at": updated_at,
        }
    )
    manager._artifacts[job_id] = artifacts


def test_build_report_analysis_includes_ranking_and_asset_trends(tmp_path: Path) -> None:
    manager = _FakeReportManager(tmp_path)

    baseline_payload = {
        "meta": {"target": "redis.example.com", "decision_summary": "baseline"},
        "summary": {"total_findings": 0, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
        "scope": {
            "assets": [
                {
                    "id": "service:tcp:redis.example.com:6379:redis",
                    "kind": "service",
                    "source_tool": "redis_exposure_check",
                    "attributes": {"host": "redis.example.com", "port": 6379, "service": "redis", "proto": "tcp"},
                    "evidence": {},
                }
            ],
            "surface": {},
        },
        "findings": [],
        "history": [],
        "execution": {"current_phase": "verification", "phase_history": []},
    }
    _write_job_payload(
        manager,
        job_id="job-baseline",
        target="redis.example.com",
        payload=baseline_payload,
        updated_at="2026-03-05T10:00:00Z",
    )

    current_job_dir = tmp_path / "job-current" / "agent" / "artifacts"
    current_job_dir.mkdir(parents=True, exist_ok=True)
    artifact_payload = {
        "action": {
            "tool_name": "cve_verify",
            "target": "redis.example.com",
            "options": {"cve_ids": ["CVE-2025-0001", "CVE-2024-9999"]},
        },
        "metadata": {
            "component": "redis",
            "service": "redis",
            "version": "7.2.0",
            "verification_order": ["CVE-2025-0001", "CVE-2024-9999"],
            "selected_templates": ["network/redis/CVE-2025-0001.yaml"],
        },
    }
    (current_job_dir / "A1_cve_verify.json").write_text(
        json.dumps(artifact_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    current_payload = {
        "meta": {"target": "redis.example.com", "decision_summary": "verification run"},
        "summary": {"total_findings": 1, "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
        "infrastructure": {
            "ports": [{"host": "redis.example.com", "port": 6379, "protocol": "tcp", "service": "redis", "tls": False}],
            "middleware": [],
            "waf": {"detected": False, "vendors": []},
            "tech_stack": ["redis"],
            "certificates": [],
            "dns": {"records": {}, "subdomains": []},
        },
        "risk_matrix": {
            "total_score": 15,
            "categories": [{"name": "network", "score": 15, "finding_count": 1, "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}}],
        },
        "attack_surface": {
            "entry_points": [{"type": "origin", "url": "redis://redis.example.com:6379", "method": "CONNECT", "source": "service_origin"}],
            "exposed_services": [{"host": "redis.example.com", "port": 6379, "service": "redis", "protocol": "tcp"}],
            "sensitive_paths": [],
        },
        "scope": {
            "assets": [
                {
                    "id": "service:tcp:redis.example.com:6379:redis",
                    "kind": "service",
                    "source_tool": "redis_exposure_check",
                    "attributes": {"host": "redis.example.com", "port": 6379, "service": "redis", "proto": "tcp"},
                    "evidence": {},
                },
                {
                    "id": "domain:redis.example.com",
                    "kind": "domain",
                    "source_tool": "reverse_dns_probe",
                    "attributes": {"domain": "redis.example.com"},
                    "evidence": {},
                },
            ],
            "surface": {
                "cve_lookup_results": [
                    {
                        "cve_id": "CVE-2025-0001",
                        "target": "redis.example.com",
                        "component": "redis",
                        "service": "redis",
                        "version": "7.2.0",
                        "rank": 1,
                        "severity": "high",
                        "cvss_score": 9.1,
                        "has_nuclei_template": True,
                        "ranking_context": {
                            "component": "redis",
                            "service": "redis",
                            "version": "7.2.0",
                            "rag_recommended_tools": ["cve_verify"],
                            "rag_tags": ["redis", "unauth"],
                            "protocol_aliases": ["redis"],
                        },
                        "template_capability": {"template_count": 2, "protocol_tags": ["redis"]},
                    },
                    {
                        "cve_id": "CVE-2024-9999",
                        "target": "redis.example.com",
                        "component": "redis",
                        "service": "redis",
                        "version": "7.2.0",
                        "rank": 2,
                        "severity": "medium",
                        "cvss_score": 6.5,
                        "has_nuclei_template": False,
                        "ranking_context": {
                            "component": "redis",
                            "service": "redis",
                            "version": "7.2.0",
                            "rag_recommended_tools": ["cve_verify"],
                            "rag_tags": ["redis"],
                            "protocol_aliases": ["redis"],
                        },
                        "template_capability": {"template_count": 0, "protocol_tags": []},
                    },
                ],
                "cve_verification": [{"cve_id": "CVE-2025-0001", "verified": True}],
                "template_capability_index": {
                    "CVE-2025-0001": {"template_count": 2, "protocol_tags": ["redis"]},
                },
            },
        },
        "findings": [
            {
                "tool": "cve_verify",
                "title": "CVE-2025-0001 Verified",
                "severity": "high",
                "evidence": {"target": "redis.example.com"},
                "related_asset_ids": ["service:tcp:redis.example.com:6379:redis"],
            }
        ],
        "history": [
            {"tool": "redis_exposure_check", "phase": "active_discovery", "status": "completed"},
            {
                "tool": "cve_verify",
                "target": "redis.example.com",
                "phase": "verification",
                "status": "completed",
                "ranking_explanation": {
                    "component": "redis",
                    "selected_candidate": "CVE-2025-0001",
                    "reasons": ["RAG recommended cve_verify"],
                },
                "metadata_summary": {
                    "component": "redis",
                    "candidate_order": ["CVE-2025-0001", "CVE-2024-9999"],
                },
            },
        ],
        "execution": {
            "current_phase": "verification",
            "phase_history": [
                {"phase": "active_discovery", "reason": "advance:passive_recon"},
                {"phase": "verification", "reason": "advance:deep_testing"},
            ],
        },
    }
    _write_job_payload(
        manager,
        job_id="job-current",
        target="redis.example.com",
        payload=current_payload,
        updated_at="2026-03-06T10:00:00Z",
    )

    analysis = build_report_analysis(manager, job_id="job-current")

    assert analysis["verification_ranking"]
    assert analysis["verification_ranking"][1]["tool"] == "cve_verify"
    assert analysis["verification_ranking"][1]["items"][0]["cve_id"] == "CVE-2025-0001"
    assert "Matched 2 template(s)" in analysis["verification_ranking"][1]["items"][0]["reasons"]

    assert analysis["asset_phase_trends"]
    verification_phase = next(item for item in analysis["asset_phase_trends"] if item["phase"] == "verification")
    assert verification_phase["finding_count"] == 1

    assert analysis["asset_batch_trends"]
    current_batch = next(item for item in analysis["asset_batch_trends"] if item["is_current"])
    assert current_batch["delta_assets"] == 1
    assert analysis["execution_history"][1]["ranking_explanation"]["selected_candidate"] == "CVE-2025-0001"
    assert analysis["diff"]["new_assets_count"] == 1
    assert analysis["diff"]["new_assets"][0]["display_name"] == "redis.example.com"
    assert analysis["diff"]["new_asset_severity_counts"]["info"] == 1
    assert analysis["diff"]["persistent_service_protocol_counts"][0]["label"] == "redis/tcp"
    assert analysis["infrastructure"]["ports"][0]["port"] == 6379
    assert analysis["risk_matrix"]["total_score"] == 15
    assert analysis["attack_surface"]["entry_points"][0]["type"] == "origin"

    html = render_generated_report_html(
        item={"job_id": "job-current", "target": "redis.example.com", "status": "completed", "updated_at": "2026-03-06T10:00:00Z", "finding_total": 1, "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
        analysis=analysis,
    )
    assert "Verification Ranking" in html
    assert "Execution History" in html
    assert "Why Executed" in html
    assert "Asset Trends by Phase" in html
    assert "Asset Trends by Run Batch" in html
    assert "Baseline Asset / Service Diff" in html
    assert "New Asset Severity" in html
    assert "Persistent Service Protocols" in html
    assert "Infrastructure Summary" in html
    assert "Risk Matrix" in html
    assert "Attack Surface" in html
    assert "redis/tcp" in html
    assert "redis.example.com" in html


def test_build_report_analysis_backfills_execution_history_reason_from_artifact(tmp_path: Path) -> None:
    manager = _FakeReportManager(tmp_path)
    artifact_dir = tmp_path / "job-exec-history" / "agent" / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "A1_subdomain_enum_passive.json").write_text(
        json.dumps(
            {
                "action": {
                    "tool_name": "subdomain_enum_passive",
                    "target": "example.com",
                    "reason": "Enumerate likely subdomains through passive certificate transparency sources.",
                    "preconditions": ["target_in_scope", "not_already_done", "domain_scope_declared"],
                    "options": {"max_results": 100},
                }
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    payload = {
        "meta": {"target": "example.com", "decision_summary": "passive recon"},
        "summary": {"total_findings": 0, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
        "scope": {"assets": [], "surface": {}},
        "findings": [],
        "history": [
            {
                "tool": "subdomain_enum_passive",
                "target": "example.com",
                "phase": "passive_recon",
                "status": "completed",
                "artifacts": ["/workspace/output/web-jobs/job-exec-history/agent/artifacts/A1_subdomain_enum_passive.json"],
            }
        ],
        "execution": {"current_phase": "passive_recon", "phase_history": []},
    }
    _write_job_payload(
        manager,
        job_id="job-exec-history",
        target="example.com",
        payload=payload,
        updated_at="2026-03-06T12:00:00Z",
    )

    analysis = build_report_analysis(manager, job_id="job-exec-history")

    explanation = analysis["execution_history"][0]["ranking_explanation"]
    assert "Enumerate likely subdomains through passive certificate transparency sources." in explanation["reasons"]
    assert "Scheduled in phase: passive_recon" in explanation["reasons"]
    assert "Preconditions satisfied: target_in_scope, not_already_done, domain_scope_declared" in explanation["reasons"]


def test_render_generated_report_html_supports_cjk_fonts_and_wraps_long_urls() -> None:
    long_url = "https://example.com/reports/very/long/path/that/should/not/be/truncated?alpha=1&beta=2&gamma=3"

    html = render_generated_report_html(
        item={
            "job_id": "job-zh",
            "target": "中文站点.example.com",
            "status": "completed",
            "updated_at": "2026-03-18T12:00:00Z",
            "finding_total": 1,
            "severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        },
        analysis={
            "findings": [
                {
                    "title": "中文说明",
                    "severity": "medium",
                    "plugin_name": "agent",
                    "evidence_text": "{}",
                }
            ],
            "attack_surface": {
                "entry_points": [{"type": "origin", "method": "GET", "url": long_url}],
                "sensitive_paths": [{"type": "path", "path": "/admin/portal", "url": long_url}],
            },
        },
    )

    assert 'lang="zh-CN"' in html
    assert "Microsoft YaHei" in html
    assert "Noto Sans SC" in html
    assert "overflow-wrap: anywhere" in html
    assert "table-layout: auto" in html
    assert "class='url-text'" in html
    assert "<wbr>" in html
    assert html_escape(long_url) in html
    assert "Jump to Sections" in html
    assert "class=\"report-layout\"" in html
    assert "class='table-wrap'" in html
    assert "class='severity-badge'" in html
