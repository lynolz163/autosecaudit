"""Helpers for building visual report analysis payloads."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse


def build_visual_analysis_payload(
    *,
    audit_payload: dict[str, Any],
    state_payload: dict[str, Any],
    audit_report_json_path: Path,
) -> dict[str, Any]:
    findings = _extract_visual_findings(audit_payload)
    assets = _extract_visual_assets(audit_payload, findings=findings)
    return {
        "verification_ranking": _build_visual_verification_ranking(audit_payload),
        "asset_phase_trends": _build_visual_asset_phase_trends(
            audit_payload,
            assets=assets,
            findings=findings,
        ),
        "asset_batch_trends": _build_visual_asset_batch_trends(
            audit_payload=audit_payload,
            state_payload=state_payload,
            audit_report_json_path=audit_report_json_path,
        ),
        "batch_diff": _build_visual_batch_diff(
            audit_payload=audit_payload,
            state_payload=state_payload,
            audit_report_json_path=audit_report_json_path,
        ),
    }


def _extract_visual_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_findings = payload.get("findings", []) if isinstance(payload, dict) else []
    output: list[dict[str, Any]] = []
    if not isinstance(raw_findings, list):
        return output
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "severity": _normalize_severity(str(item.get("severity", "")).strip().lower(), str(item.get("name", ""))),
                "related_asset_ids": [
                    str(asset_id).strip()
                    for asset_id in item.get("related_asset_ids", [])
                    if str(asset_id).strip()
                ] if isinstance(item.get("related_asset_ids", []), list) else [],
            }
        )
    return output


def _extract_visual_assets(
    payload: dict[str, Any],
    *,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    scope = payload.get("scope", {}) if isinstance(payload, dict) else {}
    raw_assets = scope.get("assets", []) if isinstance(scope, dict) else []
    if not isinstance(raw_assets, list):
        return []

    finding_count_by_asset: dict[str, int] = {}
    highest_severity_by_asset: dict[str, str] = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = _normalize_severity(str(item.get("severity", "")).strip().lower(), "")
        for asset_id in item.get("related_asset_ids", []):
            key = str(asset_id).strip()
            if not key:
                continue
            finding_count_by_asset[key] = finding_count_by_asset.get(key, 0) + 1
            current = highest_severity_by_asset.get(key, "info")
            if severity_rank.get(severity, 9) < severity_rank.get(current, 9):
                highest_severity_by_asset[key] = severity

    output: list[dict[str, Any]] = []
    for asset in raw_assets:
        if not isinstance(asset, dict):
            continue
        asset_id = str(asset.get("id", "")).strip()
        output.append(
            {
                "id": asset_id,
                "kind": str(asset.get("kind", "")).strip().lower() or "asset",
                "source_tool": str(asset.get("source_tool", "")).strip() or None,
                "attributes": asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {},
                "finding_count": int(finding_count_by_asset.get(asset_id, 0)),
                "highest_severity": highest_severity_by_asset.get(asset_id, "info"),
            }
        )
    return output


def _summarize_visual_assets(assets: list[dict[str, Any]]) -> dict[str, int]:
    total_assets = len(assets)
    service_assets = 0
    linked_findings = 0
    for asset in assets:
        if str(asset.get("kind", "")).strip().lower() == "service":
            service_assets += 1
        linked_findings += int(asset.get("finding_count", 0) or 0)
    return {
        "total_assets": total_assets,
        "service_assets": service_assets,
        "asset_linked_findings": linked_findings,
    }


def _normalize_visual_phase_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    return re.sub(r"[^a-z0-9_]+", "_", text)


def _visual_phase_sort_key(value: str) -> tuple[int, str]:
    order = {
        "passive_recon": 0,
        "active_discovery": 1,
        "deep_testing": 2,
        "verification": 3,
        "reporting": 4,
        "unknown": 98,
    }
    normalized = _normalize_visual_phase_name(value)
    return order.get(normalized, 97), normalized


def _build_visual_asset_phase_trends(
    payload: dict[str, Any],
    *,
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    execution = payload.get("execution", {}) if isinstance(payload, dict) else {}
    history = payload.get("history", []) if isinstance(payload, dict) else []
    phase_history = execution.get("phase_history", []) if isinstance(execution, dict) else []
    current_phase = _normalize_visual_phase_name(
        (execution.get("current_phase") if isinstance(execution, dict) else None)
        or (payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}).get("current_phase")
    )
    rows: dict[str, dict[str, Any]] = {}
    first_phase_by_tool: dict[str, str] = {}
    asset_phase_by_id: dict[str, str] = {}

    def ensure_row(phase_name: str) -> dict[str, Any]:
        normalized = _normalize_visual_phase_name(phase_name)
        if normalized not in rows:
            rows[normalized] = {
                "phase": normalized,
                "executed_actions": 0,
                "unique_tools": 0,
                "tool_names": [],
                "asset_count": 0,
                "service_assets": 0,
                "linked_findings": 0,
                "finding_count": 0,
                "delta_assets": 0,
                "reason": None,
                "is_current": normalized == current_phase,
            }
        return rows[normalized]

    if isinstance(history, list):
        for entry in history:
            if not isinstance(entry, dict):
                continue
            phase_name = _normalize_visual_phase_name(entry.get("phase"))
            row = ensure_row(phase_name)
            row["executed_actions"] += 1
            tool_name = str(entry.get("tool", "")).strip()
            if tool_name:
                if tool_name not in row["tool_names"]:
                    row["tool_names"].append(tool_name)
                first_phase_by_tool.setdefault(tool_name, phase_name)

    if isinstance(phase_history, list):
        for entry in phase_history:
            if not isinstance(entry, dict):
                continue
            phase_name = _normalize_visual_phase_name(entry.get("phase"))
            row = ensure_row(phase_name)
            reason = str(entry.get("reason", "")).strip() or None
            if reason and not row.get("reason"):
                row["reason"] = reason

    for asset in assets:
        source_tool = str(asset.get("source_tool", "")).strip()
        phase_name = first_phase_by_tool.get(source_tool) or current_phase
        row = ensure_row(phase_name)
        row["asset_count"] += 1
        if str(asset.get("kind", "")).strip().lower() == "service":
            row["service_assets"] += 1
        asset_id = str(asset.get("id", "")).strip()
        if asset_id:
            asset_phase_by_id[asset_id] = phase_name

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        related_asset_ids = [
            str(asset_id).strip()
            for asset_id in finding.get("related_asset_ids", [])
            if str(asset_id).strip()
        ]
        matched_phases = {
            asset_phase_by_id[asset_id]
            for asset_id in related_asset_ids
            if asset_id in asset_phase_by_id
        }
        if not matched_phases:
            matched_phases = {current_phase}
        for phase_name in matched_phases:
            row = ensure_row(phase_name)
            row["finding_count"] += 1
            row["linked_findings"] += 1

    ordered_rows = sorted(rows.values(), key=lambda item: _visual_phase_sort_key(item.get("phase", "")))
    previous_assets = 0
    for row in ordered_rows:
        row["unique_tools"] = len(row["tool_names"])
        row["delta_assets"] = int(row["asset_count"] or 0) - previous_assets
        previous_assets = int(row["asset_count"] or 0)
    return ordered_rows


def _build_visual_asset_batch_trends(
    *,
    audit_payload: dict[str, Any],
    state_payload: dict[str, Any],
    audit_report_json_path: Path,
) -> list[dict[str, Any]]:
    current_target = str(
        (audit_payload.get("meta", {}) if isinstance(audit_payload.get("meta", {}), dict) else {}).get("target")
        or state_payload.get("target", "")
    ).strip()
    target_slug = _slugify_report_target(current_target)
    if not target_slug:
        return []

    current_job_dir = audit_report_json_path.parent.parent if audit_report_json_path.parent.name == "agent" else audit_report_json_path.parent
    current_job_id = current_job_dir.name
    root_dir = current_job_dir.parent
    if not root_dir.exists() or not root_dir.is_dir():
        return []

    collected: list[dict[str, Any]] = []
    for candidate_dir in root_dir.iterdir():
        if not candidate_dir.is_dir():
            continue
        payload_path = None
        for candidate in (candidate_dir / "agent" / "audit_report.json", candidate_dir / "audit_report.json"):
            if candidate.is_file():
                payload_path = candidate
                break
        if payload_path is None:
            continue
        payload = audit_payload if candidate_dir == current_job_dir else _read_json_object(payload_path)
        meta = payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}
        candidate_target = str(meta.get("target", "")).strip()
        if _slugify_report_target(candidate_target) != target_slug:
            continue
        findings = _extract_visual_findings(payload)
        assets = _extract_visual_assets(payload, findings=findings)
        summary = _summarize_visual_assets(assets)
        collected.append(
            {
                "job_id": candidate_dir.name,
                "ended_at": str(meta.get("generated_at", "")).strip() or None,
                "updated_at": str(meta.get("generated_at", "")).strip() or None,
                "status": "completed",
                "finding_total": len(findings),
                "total_assets": summary["total_assets"],
                "service_assets": summary["service_assets"],
                "linked_findings": summary["asset_linked_findings"],
                "is_current": candidate_dir.name == current_job_id,
            }
        )

    ordered = sorted(
        collected,
        key=lambda item: (
            str(item.get("ended_at") or item.get("updated_at") or ""),
            str(item.get("job_id") or ""),
        ),
    )
    previous_assets = 0
    previous_findings = 0
    for row in ordered:
        row["delta_assets"] = int(row.get("total_assets", 0) or 0) - previous_assets
        row["delta_findings"] = int(row.get("finding_total", 0) or 0) - previous_findings
        previous_assets = int(row.get("total_assets", 0) or 0)
        previous_findings = int(row.get("finding_total", 0) or 0)
    return ordered


def _visual_finding_fingerprint(item: dict[str, Any]) -> str:
    payload = {
        "name": str(item.get("name") or item.get("title") or "").strip(),
        "severity": str(item.get("severity") or "").strip().lower(),
        "cve_id": str(item.get("cve_id") or "").strip().upper(),
        "evidence": item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {},
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _visual_asset_fingerprint(item: dict[str, Any]) -> str:
    asset_id = str(item.get("id", "")).strip()
    if asset_id:
        return asset_id
    payload = {
        "kind": str(item.get("kind", "")).strip().lower(),
        "attributes": item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {},
        "source_tool": str(item.get("source_tool", "")).strip(),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _visual_service_fingerprint(item: dict[str, Any]) -> str:
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    host = str(attributes.get("host", "")).strip().lower()
    port = str(attributes.get("port", "")).strip()
    service = str(attributes.get("service", "")).strip().lower()
    proto = str(attributes.get("proto", "")).strip().lower()
    if host or port or service:
        return "::".join((host, port, service, proto))
    return _visual_asset_fingerprint(item)


def _display_visual_asset_name(item: dict[str, Any]) -> str:
    kind = str(item.get("kind", "")).strip().lower() or "asset"
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    if kind == "service":
        host = str(attributes.get("host", "")).strip()
        port = str(attributes.get("port", "")).strip()
        service = str(attributes.get("service", "")).strip() or "service"
        if host and port:
            return f"{host}:{port} ({service})"
    if kind == "host":
        host = str(attributes.get("host", "")).strip()
        if host:
            return host
    if kind == "domain":
        domain = str(attributes.get("domain", "")).strip()
        if domain:
            return domain
    if kind == "ip":
        address = str(attributes.get("address", "")).strip()
        if address:
            return address
    if kind == "origin":
        origin = str(attributes.get("origin", "")).strip()
        if origin:
            return origin
    return str(item.get("id", "")).strip() or kind


def _compact_visual_asset_entries(items: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    ordered = sorted(
        (item for item in items if isinstance(item, dict)),
        key=lambda item: (
            0 if str(item.get("kind", "")).strip().lower() == "service" else 1,
            -int(item.get("finding_count", 0) or 0),
            _display_visual_asset_name(item),
        ),
    )
    output: list[dict[str, Any]] = []
    for item in ordered[:limit]:
        attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
        output.append(
            {
                "id": str(item.get("id", "")).strip() or None,
                "kind": str(item.get("kind", "")).strip().lower() or "asset",
                "display_name": _display_visual_asset_name(item),
                "source_tool": str(item.get("source_tool", "")).strip() or None,
                "host": str(attributes.get("host", "")).strip() or None,
                "port": str(attributes.get("port", "")).strip() or None,
                "service": str(attributes.get("service", "")).strip() or None,
                "proto": str(attributes.get("proto", "")).strip() or None,
                "finding_count": int(item.get("finding_count", 0) or 0),
            }
        )
    return output


def _visual_asset_highest_severity(item: dict[str, Any]) -> str:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    value = str(item.get("highest_severity", "")).strip().lower()
    if value in rank:
        return value
    return "info"


def _build_visual_asset_severity_breakdown(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for item in items:
        if not isinstance(item, dict):
            continue
        counts[_visual_asset_highest_severity(item)] += 1
    return counts


def _visual_service_protocol_label(item: dict[str, Any]) -> str:
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    service = str(attributes.get("service", "")).strip().lower()
    proto = str(attributes.get("proto", "")).strip().lower()
    if service and proto:
        return f"{service}/{proto}"
    if service:
        return service
    if proto:
        return proto
    return str(item.get("kind", "")).strip().lower() or "asset"


def _build_visual_protocol_breakdown(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        label = _visual_service_protocol_label(item)
        counts[label] = counts.get(label, 0) + 1
    return [
        {"label": key, "count": value}
        for key, value in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    ]


def _build_visual_batch_diff(
    *,
    audit_payload: dict[str, Any],
    state_payload: dict[str, Any],
    audit_report_json_path: Path,
) -> dict[str, Any]:
    batch_rows = _build_visual_asset_batch_trends(
        audit_payload=audit_payload,
        state_payload=state_payload,
        audit_report_json_path=audit_report_json_path,
    )
    current_row = next((item for item in batch_rows if item.get("is_current")), None)
    if current_row is None:
        return {}
    baseline_row = None
    for item in reversed(batch_rows):
        if item.get("job_id") == current_row.get("job_id"):
            continue
        baseline_row = item
        break
    if baseline_row is None:
        return {
            "baseline_job_id": None,
            "new_count": 0,
            "resolved_count": 0,
            "persistent_count": 0,
            "new_findings": [],
            "resolved_findings": [],
            "new_assets_count": 0,
            "resolved_assets_count": 0,
            "persistent_assets_count": 0,
            "new_assets": [],
            "resolved_assets": [],
            "new_services_count": 0,
            "resolved_services_count": 0,
            "persistent_services_count": 0,
            "new_services": [],
            "resolved_services": [],
            "new_asset_severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
            "resolved_asset_severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
            "persistent_asset_severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
            "new_service_protocol_counts": [],
            "resolved_service_protocol_counts": [],
            "persistent_service_protocol_counts": [],
        }

    current_job_dir = audit_report_json_path.parent.parent if audit_report_json_path.parent.name == "agent" else audit_report_json_path.parent
    root_dir = current_job_dir.parent
    baseline_job_dir = root_dir / str(baseline_row.get("job_id") or "")
    baseline_payload_path = baseline_job_dir / "agent" / "audit_report.json"
    if not baseline_payload_path.is_file():
        baseline_payload_path = baseline_job_dir / "audit_report.json"
    baseline_payload = _read_json_object(baseline_payload_path)

    current_findings_raw = [item for item in audit_payload.get("findings", []) if isinstance(item, dict)]
    baseline_findings_raw = [item for item in baseline_payload.get("findings", []) if isinstance(item, dict)]
    current_map = {_visual_finding_fingerprint(item): item for item in current_findings_raw}
    baseline_map = {_visual_finding_fingerprint(item): item for item in baseline_findings_raw}
    current_assets = _extract_visual_assets(audit_payload, findings=_extract_visual_findings(audit_payload))
    baseline_assets = _extract_visual_assets(baseline_payload, findings=_extract_visual_findings(baseline_payload))
    current_asset_map = {_visual_asset_fingerprint(item): item for item in current_assets}
    baseline_asset_map = {_visual_asset_fingerprint(item): item for item in baseline_assets}
    current_service_map = {
        _visual_service_fingerprint(item): item
        for item in current_assets
        if str(item.get("kind", "")).strip().lower() == "service"
    }
    baseline_service_map = {
        _visual_service_fingerprint(item): item
        for item in baseline_assets
        if str(item.get("kind", "")).strip().lower() == "service"
    }

    def _compact_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for item in items[:8]:
            output.append(
                {
                    "name": str(item.get("name") or item.get("title") or "").strip() or "Unnamed finding",
                    "severity": str(item.get("severity") or "info").strip().lower() or "info",
                    "cve_id": str(item.get("cve_id") or "").strip() or None,
                }
            )
        return output

    new_items = [current_map[key] for key in current_map.keys() - baseline_map.keys()]
    resolved_items = [baseline_map[key] for key in baseline_map.keys() - current_map.keys()]
    persistent_items = [current_map[key] for key in current_map.keys() & baseline_map.keys()]
    new_asset_items = [current_asset_map[key] for key in current_asset_map.keys() - baseline_asset_map.keys()]
    resolved_asset_items = [baseline_asset_map[key] for key in baseline_asset_map.keys() - current_asset_map.keys()]
    persistent_asset_items = [current_asset_map[key] for key in current_asset_map.keys() & baseline_asset_map.keys()]
    new_service_items = [current_service_map[key] for key in current_service_map.keys() - baseline_service_map.keys()]
    resolved_service_items = [baseline_service_map[key] for key in baseline_service_map.keys() - current_service_map.keys()]
    persistent_service_items = [current_service_map[key] for key in current_service_map.keys() & baseline_service_map.keys()]
    baseline_meta = baseline_payload.get("meta", {}) if isinstance(baseline_payload.get("meta"), dict) else {}
    return {
        "baseline_job_id": baseline_row.get("job_id"),
        "baseline_generated_at": baseline_meta.get("generated_at"),
        "new_count": len(new_items),
        "resolved_count": len(resolved_items),
        "persistent_count": len(persistent_items),
        "new_findings": _compact_findings(new_items),
        "resolved_findings": _compact_findings(resolved_items),
        "new_assets_count": len(new_asset_items),
        "resolved_assets_count": len(resolved_asset_items),
        "persistent_assets_count": len(persistent_asset_items),
        "new_assets": _compact_visual_asset_entries(new_asset_items),
        "resolved_assets": _compact_visual_asset_entries(resolved_asset_items),
        "new_services_count": len(new_service_items),
        "resolved_services_count": len(resolved_service_items),
        "persistent_services_count": len(persistent_service_items),
        "new_services": _compact_visual_asset_entries(new_service_items),
        "resolved_services": _compact_visual_asset_entries(resolved_service_items),
        "new_asset_severity_counts": _build_visual_asset_severity_breakdown(new_asset_items),
        "resolved_asset_severity_counts": _build_visual_asset_severity_breakdown(resolved_asset_items),
        "persistent_asset_severity_counts": _build_visual_asset_severity_breakdown(persistent_asset_items),
        "new_service_protocol_counts": _build_visual_protocol_breakdown(new_service_items),
        "resolved_service_protocol_counts": _build_visual_protocol_breakdown(resolved_service_items),
        "persistent_service_protocol_counts": _build_visual_protocol_breakdown(persistent_service_items),
    }


def _normalize_visual_target_value(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        if "://" in text:
            parsed = urlparse(text)
            host = (parsed.hostname or "").lower()
            port = str(parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else "")).strip()
            path = (parsed.path or "/").rstrip("/") or "/"
            return f"{parsed.scheme.lower()}://{host}:{port}{path}"
    except ValueError:
        return text.rstrip("/").lower()
    return text.rstrip("/").lower()


def _match_visual_ranked_candidate(
    *,
    cve_id: str,
    rows: list[dict[str, Any]],
    target: str | None,
    component: str | None,
    service: str | None,
    version: str | None,
) -> dict[str, Any]:
    best_row: dict[str, Any] = {}
    best_score = -1
    normalized_target = _normalize_visual_target_value(target)
    for row in rows:
        if str(row.get("cve_id", "")).strip().upper() != cve_id:
            continue
        score = 0
        if normalized_target and _normalize_visual_target_value(row.get("target")) == normalized_target:
            score += 4
        if component and str(row.get("component", "")).strip().lower() == component:
            score += 3
        if service and str(row.get("service", "")).strip().lower() == service:
            score += 2
        if version and str(row.get("version", "")).strip() == version:
            score += 1
        if int(row.get("rank", 0) or 0) > 0:
            score += 1
        if score > best_score:
            best_row = row
            best_score = score
    return best_row


def _build_visual_ranked_candidate_entry(
    *,
    cve_id: str,
    row: dict[str, Any],
    block_tool: str,
    verification_map: dict[str, bool],
    template_index: dict[str, dict[str, Any]],
    selected_candidate: str | None,
) -> dict[str, Any]:
    ranking_context = row.get("ranking_context", {}) if isinstance(row.get("ranking_context"), dict) else {}
    capability = row.get("template_capability", {}) if isinstance(row.get("template_capability"), dict) else {}
    if not capability:
        capability = template_index.get(cve_id, {}) if isinstance(template_index.get(cve_id, {}), dict) else {}

    template_count = int(capability.get("template_count", 0) or 0)
    protocol_tags = capability.get("protocol_tags", [])
    if not isinstance(protocol_tags, list):
        protocol_tags = []
    recommended_tools = ranking_context.get("rag_recommended_tools", [])
    if not isinstance(recommended_tools, list):
        recommended_tools = []
    rag_tags = ranking_context.get("rag_tags", [])
    if not isinstance(rag_tags, list):
        rag_tags = []
    aliases = ranking_context.get("protocol_aliases", [])
    if not isinstance(aliases, list):
        aliases = []

    normalized_tool = str(block_tool or "").strip().lower()
    component = str(ranking_context.get("component", "")).strip()
    service = str(ranking_context.get("service", "")).strip()
    version = str(ranking_context.get("version", "")).strip()
    reasons: list[str] = []
    if component:
        reasons.append(f"Component match: {component}")
    if service:
        reasons.append(f"Service match: {service}")
    if version:
        reasons.append(f"Version hint: {version}")
    if normalized_tool and normalized_tool in {str(item).strip().lower() for item in recommended_tools}:
        reasons.append(f"RAG recommended {normalized_tool}")
    if template_count > 0:
        reasons.append(f"Matched {template_count} template(s)")
    elif bool(row.get("has_nuclei_template", False)):
        reasons.append("Has nuclei template coverage")
    if protocol_tags:
        reasons.append(f"Protocol tags: {', '.join(str(item) for item in protocol_tags[:4])}")
    if aliases:
        reasons.append(f"Protocol aliases: {', '.join(str(item) for item in aliases[:4])}")
    if rag_tags:
        reasons.append(f"RAG tags: {', '.join(str(item) for item in rag_tags[:4])}")

    verified = verification_map.get(cve_id)
    if verified is True:
        reasons.append("Verified during nuclei validation")
    elif verified is False:
        reasons.append("Checked but not positively verified")

    return {
        "cve_id": cve_id,
        "rank": int(row.get("rank", 0) or 0) or None,
        "severity": _normalize_severity(str(row.get("severity", "")).strip().lower(), cve_id),
        "cvss_score": _safe_float(row.get("cvss_score")),
        "has_nuclei_template": bool(row.get("has_nuclei_template", template_count > 0)),
        "template_count": template_count,
        "template_capability": capability,
        "verified": verified,
        "selected": bool(selected_candidate and cve_id == selected_candidate),
        "ranking_context": ranking_context,
        "reasons": reasons,
    }


def _build_visual_verification_ranking(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scope = payload.get("scope", {}) if isinstance(payload, dict) else {}
    surface = scope.get("surface", {}) if isinstance(scope, dict) else {}
    history = payload.get("history", []) if isinstance(payload, dict) else []
    if not isinstance(surface, dict):
        surface = {}
    lookup_results = [item for item in surface.get("cve_lookup_results", []) if isinstance(item, dict)]
    verification_rows = [item for item in surface.get("cve_verification", []) if isinstance(item, dict)]
    template_index = surface.get("template_capability_index", {})
    if not isinstance(template_index, dict):
        template_index = {}

    verification_map = {
        str(item.get("cve_id", "")).strip().upper(): bool(item.get("verified"))
        for item in verification_rows
        if str(item.get("cve_id", "")).strip()
    }

    blocks: list[dict[str, Any]] = []
    grouped_lookup: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for row in lookup_results:
        key = (
            str(row.get("target", "")).strip(),
            str(row.get("component", "")).strip().lower(),
            str(row.get("service", "")).strip().lower(),
            str(row.get("version", "")).strip(),
        )
        grouped_lookup.setdefault(key, []).append(row)

    for key, rows in grouped_lookup.items():
        ordered_rows = sorted(
            rows,
            key=lambda item: (
                int(item.get("rank", 999) or 999),
                -(float(item.get("cvss_score", 0.0) or 0.0)),
                str(item.get("cve_id", "")),
            ),
        )
        items = [
            _build_visual_ranked_candidate_entry(
                cve_id=str(row.get("cve_id", "")).strip().upper(),
                row=row,
                block_tool="cve_lookup",
                verification_map=verification_map,
                template_index=template_index,
                selected_candidate=None,
            )
            for row in ordered_rows
            if str(row.get("cve_id", "")).strip()
        ]
        if items:
            blocks.append(
                {
                    "tool": "cve_lookup",
                    "target": key[0] or None,
                    "component": key[1] or None,
                    "service": key[2] or None,
                    "version": key[3] or None,
                    "selected_candidate": items[0]["cve_id"],
                    "selected_templates": [],
                    "items": items,
                }
            )

    if not isinstance(history, list):
        return blocks

    for entry in history:
        if not isinstance(entry, dict):
            continue
        tool_name = str(entry.get("tool", "")).strip()
        if tool_name not in {"cve_verify", "poc_sandbox_exec", "nuclei_exploit_check"}:
            continue
        metadata = entry.get("metadata_summary", {}) if isinstance(entry.get("metadata_summary"), dict) else {}
        if tool_name == "cve_verify":
            candidate_order = metadata.get("verification_order", [])
        elif tool_name == "nuclei_exploit_check":
            candidate_order = metadata.get("requested_cve_ids", [])
        else:
            candidate_order = metadata.get("candidate_order", [])
        if not isinstance(candidate_order, list):
            candidate_order = []
        normalized_order: list[str] = []
        seen_ids: set[str] = set()
        for item in candidate_order:
            cve_id = str(item).strip().upper()
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            normalized_order.append(cve_id)
        selected_candidate = normalized_order[0] if normalized_order else None
        selected_templates = metadata.get("selected_templates", [])
        if not isinstance(selected_templates, list):
            selected_templates = []
        template_name = str(metadata.get("template", "")).strip()
        if template_name and template_name not in selected_templates:
            selected_templates = [template_name, *selected_templates]
        component = str(metadata.get("component") or "").strip().lower() or None
        service = str(metadata.get("service") or "").strip().lower() or None
        version = str(metadata.get("version") or "").strip() or None
        target = str(entry.get("target") or "").strip() or None
        items = []
        for cve_id in normalized_order:
            row = _match_visual_ranked_candidate(
                cve_id=cve_id,
                rows=lookup_results,
                target=target,
                component=component,
                service=service,
                version=version,
            )
            items.append(
                _build_visual_ranked_candidate_entry(
                    cve_id=cve_id,
                    row=row,
                    block_tool=tool_name,
                    verification_map=verification_map,
                    template_index=template_index,
                    selected_candidate=selected_candidate,
                )
            )
        if items:
            blocks.append(
                {
                    "tool": tool_name,
                    "target": target,
                    "component": component,
                    "service": service,
                    "version": version,
                    "selected_candidate": selected_candidate,
                    "selected_templates": selected_templates[:12],
                    "items": items,
                }
            )
    return blocks


def _slugify_report_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return "target"

    host_candidate = raw
    if "://" in raw:
        parsed = urlparse(raw)
        host_candidate = parsed.netloc or parsed.path or raw
    host_candidate = host_candidate.split("/", 1)[0]
    host_candidate = host_candidate.split("@")[-1]
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", host_candidate).strip("-").lower()
    if not slug:
        return "target"
    return slug[:64]


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _normalize_severity(value: str, name: str) -> str:
    allowed = {"critical", "high", "medium", "low", "info"}
    if value in allowed:
        return value

    lowered_name = name.lower()
    if any(token in lowered_name for token in ("rce", "remote code execution", "critical")):
        return "critical"
    if any(token in lowered_name for token in ("sql injection", "sqli", "command injection", "xss")):
        return "high"
    if any(token in lowered_name for token in ("csrf", "ssrf", "path traversal", "idor")):
        return "medium"
    if any(token in lowered_name for token in ("information disclosure", "info leak", "misconfig")):
        return "low"
    return "medium"


def _safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


__all__ = ["build_visual_analysis_payload"]
