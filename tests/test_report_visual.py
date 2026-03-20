from __future__ import annotations

import json
from pathlib import Path

from autosecaudit.core.report_visual import build_visual_analysis_payload


def _write_payload(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_build_visual_analysis_payload_preserves_ranking_and_batch_diff(tmp_path: Path) -> None:
    output_root = tmp_path / "web-jobs"
    previous_json = output_root / "job-previous-redis-example" / "agent" / "audit_report.json"
    current_json = output_root / "job-current-redis-example" / "agent" / "audit_report.json"

    _write_payload(
        previous_json,
        {
            "meta": {
                "target": "redis.example.com",
                "generated_at": "2026-03-01T10:00:00Z",
            },
            "scope": {
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
                "surface": {},
            },
            "findings": [],
            "history": [],
            "execution": {"current_phase": "verification", "phase_history": []},
        },
    )

    current_payload = {
        "meta": {
            "target": "redis.example.com",
            "generated_at": "2026-03-02T10:00:00Z",
        },
        "scope": {
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
                            "rag_recommended_tools": ["cve_verify"],
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
        },
        "findings": [
            {
                "type": "vuln",
                "name": "Redis unauthenticated access",
                "severity": "high",
                "related_asset_ids": ["service:tcp:redis.example.com:6379:redis"],
                "evidence": {"host": "redis.example.com", "port": 6379},
            }
        ],
        "history": [
            {
                "tool": "cve_verify",
                "target": "redis.example.com",
                "status": "completed",
                "phase": "verification",
                "metadata_summary": {
                    "component": "redis",
                    "service": "redis",
                    "version": "7.2.1",
                    "verification_order": ["CVE-2025-0001"],
                    "selected_templates": ["network/redis/cve-2025-0001.yaml"],
                },
            }
        ],
        "execution": {
            "current_phase": "verification",
            "phase_history": [{"phase": "verification", "reason": "advance:deep_testing"}],
        },
    }
    _write_payload(current_json, current_payload)

    analysis = build_visual_analysis_payload(
        audit_payload=current_payload,
        state_payload={"target": "redis.example.com"},
        audit_report_json_path=current_json,
    )

    ranking_blocks = analysis["verification_ranking"]
    verify_block = next(item for item in ranking_blocks if item["tool"] == "cve_verify")
    current_batch = next(item for item in analysis["asset_batch_trends"] if item["is_current"])

    assert verify_block["selected_candidate"] == "CVE-2025-0001"
    assert verify_block["items"][0]["template_count"] == 2
    assert current_batch["delta_assets"] == 1
    assert analysis["batch_diff"]["new_assets_count"] == 1
    assert analysis["batch_diff"]["persistent_services_count"] == 1
