"""Dashboard and report aggregation helpers for the web console."""

from __future__ import annotations

import hashlib
from html import escape as html_escape
import json
from typing import Any

from fastapi import HTTPException

from .runtime import _utc_now
from .services.job_manager import JobManager


def build_dashboard_summary(manager: JobManager) -> dict[str, Any]:
    """Aggregate dashboard metrics from current jobs, assets, schedules, and reports."""
    jobs = manager.list_jobs()
    reports = build_report_items(manager)
    total_jobs = len(jobs)
    completed_jobs = sum(1 for item in jobs if item.get("status") == "completed")
    failed_jobs = sum(1 for item in jobs if item.get("status") in {"failed", "error"})
    running_jobs = sum(1 for item in jobs if item.get("status") in {"queued", "running"})
    success_rate = round((completed_jobs / total_jobs) * 100.0, 2) if total_jobs else 0.0
    total_findings = sum(int(report.get("finding_total", 0) or 0) for report in reports)
    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    targets: dict[str, int] = {}
    for report in reports:
        targets[str(report.get("target") or "")] = targets.get(str(report.get("target") or ""), 0) + 1
        report_counts = report.get("severity_counts", {})
        if isinstance(report_counts, dict):
            for level in severity_counts:
                severity_counts[level] += int(report_counts.get(level, 0) or 0)

    recent_jobs = [
        {
            "job_id": item.get("job_id"),
            "target": item.get("target"),
            "mode": item.get("mode"),
            "status": item.get("status"),
            "updated_at": item.get("last_updated_at"),
        }
        for item in jobs[:6]
    ]
    return {
        "generated_at": _utc_now(),
        "metrics": {
            "total_jobs": total_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "running_jobs": running_jobs,
            "success_rate": success_rate,
            "total_findings": total_findings,
            "distinct_targets": len([key for key in targets if key]),
            "total_assets": len(manager.store.list_assets()),
            "active_schedules": sum(1 for item in manager.store.list_schedules() if item.get("enabled")),
            "total_users": manager.store.count_users(),
        },
        "severity_counts": severity_counts,
        "recent_jobs": recent_jobs,
    }


def build_report_items(manager: JobManager, only_job_id: str | None = None) -> list[dict[str, Any]]:
    """Build report summaries from job artifacts."""
    jobs = manager.list_jobs()
    output: list[dict[str, Any]] = []
    for job in jobs:
        job_id = str(job.get("job_id", ""))
        if only_job_id and job_id != only_job_id:
            continue
        try:
            artifacts = manager.list_artifacts(job_id)
        except KeyError:
            continue
        item = build_report_item(manager, job=job, artifacts=artifacts)
        if item is not None:
            output.append(item)
    return output


def build_report_item(manager: JobManager, *, job: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
    artifact_paths = {str(item.get("path", "")) for item in artifacts}
    summary_payload = read_report_json(
        manager,
        job_id=str(job.get("job_id", "")),
        candidates=["agent/audit_report.json", "audit_report.json"],
    )
    markdown_path = first_existing(
        artifact_paths,
        [
            "agent/agent_report.md",
            "audit_report.md",
        ],
    )
    html_path = first_existing(
        artifact_paths,
        [
            "agent/agent_report_fixed.html",
            "agent/agent_report.html",
        ],
    )
    json_path = first_existing(
        artifact_paths,
        [
            "agent/audit_report.json",
            "audit_report.json",
        ],
    )

    if not any((summary_payload, markdown_path, html_path, json_path)):
        return None

    finding_total, severity_counts, decision_summary = extract_report_metrics(summary_payload)
    available_formats = [name for name, value in {"markdown": markdown_path, "html": html_path, "json": json_path}.items() if value]
    preview_path = markdown_path or html_path or json_path
    target = summary_payload.get("target") if isinstance(summary_payload, dict) else None
    target = str(target or job.get("target") or "").strip() or None
    return {
        "job_id": job.get("job_id"),
        "target": target,
        "target_key": normalize_target_key(target),
        "mode": job.get("mode"),
        "status": job.get("status"),
        "started_at": summary_payload.get("started_at") if isinstance(summary_payload, dict) else None,
        "ended_at": summary_payload.get("ended_at") if isinstance(summary_payload, dict) else None,
        "updated_at": job.get("last_updated_at"),
        "report_paths": {
            "markdown": markdown_path,
            "html": html_path,
            "json": json_path,
        },
        "available_formats": available_formats,
        "preview_path": preview_path,
        "finding_total": finding_total,
        "severity_counts": severity_counts,
        "decision_summary": decision_summary,
    }


def get_report_item_or_404(manager: JobManager, job_id: str) -> dict[str, Any]:
    items = build_report_items(manager, only_job_id=job_id)
    if not items:
        raise HTTPException(status_code=404, detail="report_not_found")
    return items[0]


def build_report_analysis(manager: JobManager, *, job_id: str, baseline_job_id: str | None = None) -> dict[str, Any]:
    item = get_report_item_or_404(manager, job_id)
    current_payload = read_report_json(
        manager,
        job_id=job_id,
        candidates=["agent/audit_report.json", "audit_report.json"],
    )
    current_findings = extract_report_findings(current_payload)
    current_assets = enrich_report_assets(
        extract_report_assets(current_payload),
        current_findings,
    )
    action_artifacts = _read_action_artifacts(manager, job_id=job_id)
    all_reports = build_report_items(manager)
    target_key = str(item.get("target_key") or "")
    target_reports = [report for report in all_reports if str(report.get("target_key") or "") == target_key]
    target_reports.sort(key=lambda report: str(report.get("ended_at") or report.get("updated_at") or report.get("job_id") or ""))

    baseline_item = None
    if baseline_job_id:
        for report in target_reports:
            if str(report.get("job_id")) == str(baseline_job_id):
                baseline_item = report
                break
    else:
        current_index = next((idx for idx, report in enumerate(target_reports) if str(report.get("job_id")) == job_id), -1)
        if current_index > 0:
            baseline_item = target_reports[current_index - 1]

    baseline_findings: list[dict[str, Any]] = []
    baseline_assets: list[dict[str, Any]] = []
    if baseline_item is not None:
        baseline_payload = read_report_json(
            manager,
            job_id=str(baseline_item["job_id"]),
            candidates=["agent/audit_report.json", "audit_report.json"],
        )
        baseline_findings = extract_report_findings(baseline_payload)
        baseline_assets = enrich_report_assets(
            extract_report_assets(baseline_payload),
            baseline_findings,
        )

    diff = build_report_diff(
        current_findings=current_findings,
        baseline_findings=baseline_findings,
        baseline_item=baseline_item,
        current_assets=current_assets,
        baseline_assets=baseline_assets,
    )
    execution_history = [
        entry
        for entry in current_payload.get("history", [])
        if isinstance(entry, dict)
    ] if isinstance(current_payload.get("history", []), list) else []
    execution_history = _hydrate_execution_history_with_artifacts(
        execution_history,
        action_artifacts=action_artifacts,
    )
    history = [
        {
            "job_id": report.get("job_id"),
            "target": report.get("target"),
            "status": report.get("status"),
            "mode": report.get("mode"),
            "updated_at": report.get("updated_at"),
            "ended_at": report.get("ended_at"),
            "finding_total": int(report.get("finding_total", 0) or 0),
            "severity_counts": dict(report.get("severity_counts", {})),
            "is_current": str(report.get("job_id")) == job_id,
        }
        for report in target_reports
    ]
    return {
        "job_id": job_id,
        "target": item.get("target"),
        "baseline_job_id": baseline_item.get("job_id") if baseline_item else None,
        "history": history,
        "history_count": len(history),
        "execution_history": execution_history,
        "execution_history_count": len(execution_history),
        "findings": current_findings,
        "finding_count": len(current_findings),
        "assets": current_assets,
        "asset_summary": summarize_report_assets(current_assets),
        "verification_ranking": _build_verification_ranking(
            current_payload,
            action_artifacts=action_artifacts,
        ),
        "asset_phase_trends": _build_asset_phase_trends(
            current_payload,
            assets=current_assets,
            findings=current_findings,
        ),
        "asset_batch_trends": _build_asset_batch_trends(
            manager,
            target_reports=target_reports,
            current_job_id=job_id,
        ),
        "diff": diff,
        "available_exports": available_report_exports(item),
    }


def _read_action_artifacts(manager: JobManager, *, job_id: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    try:
        artifacts = manager.list_artifacts(job_id)
    except KeyError:
        return output
    for artifact in artifacts:
        relative_path = str(artifact.get("path", "")).strip()
        normalized_path = relative_path.replace("\\", "/")
        if "/agent/artifacts/" not in f"/{normalized_path}" or not normalized_path.endswith(".json"):
            continue
        try:
            resolved = manager.resolve_file(job_id, relative_path)
            payload = json.loads(resolved.read_text(encoding="utf-8-sig"))
        except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            payload["_artifact_path"] = normalized_path
            output.append(payload)
    output.sort(key=lambda item: str(item.get("_artifact_path", "")))
    return output


def _normalize_artifact_lookup_key(path: Any) -> str:
    normalized = str(path or "").strip().replace("\\", "/")
    if not normalized:
        return ""
    marker = "/agent/artifacts/"
    prefixed = normalized if normalized.startswith("/") else f"/{normalized}"
    if marker in prefixed:
        suffix = prefixed.split(marker, maxsplit=1)[-1].strip("/")
        return f"agent/artifacts/{suffix}" if suffix else ""
    return normalized.split("/")[-1]


def _normalize_candidate_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _synthesize_history_ranking_explanation(*, row: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    options = action.get("options", {}) if isinstance(action.get("options"), dict) else {}
    component = str(options.get("component") or "").strip() or None
    service = str(options.get("service") or "").strip() or None
    version = str(options.get("version") or "").strip() or None
    candidate_order = (
        _normalize_candidate_list(options.get("cve_ids"))
        or _normalize_candidate_list(options.get("template_id"))
    )
    selected_candidate = str(options.get("cve_id") or "").strip() or (candidate_order[0] if candidate_order else None)
    selected_templates = _normalize_candidate_list(options.get("templates"))
    template_name = str(options.get("template") or "").strip()
    if template_name and template_name not in selected_templates:
        selected_templates = [template_name, *selected_templates]

    reasons: list[str] = []
    reason_text = str(action.get("reason") or row.get("reason") or "").strip()
    if reason_text:
        reasons.append(reason_text)
    phase_text = str(row.get("phase") or "").strip()
    if phase_text:
        reasons.append(f"Scheduled in phase: {phase_text}")
    preconditions = [str(item).strip() for item in (action.get("preconditions") or row.get("preconditions") or []) if str(item).strip()]
    if preconditions:
        reasons.append(f"Preconditions satisfied: {', '.join(preconditions[:4])}")
    if component:
        reasons.append(f"Component match: {component}")
    if service:
        reasons.append(f"Service match: {service}")
    if version:
        reasons.append(f"Version hint: {version}")
    if selected_templates:
        reasons.append(f"Matched {len(selected_templates)} template(s)")
    elif candidate_order:
        reasons.append(f"Candidate set narrowed to {len(candidate_order)} item(s)")

    if not reasons and not any([component, service, version, selected_candidate, selected_templates, candidate_order]):
        return {}
    deduped_reasons: list[str] = []
    for item in reasons:
        if item and item not in deduped_reasons:
            deduped_reasons.append(item)
    return {
        "tool": str(row.get("tool") or action.get("tool_name") or "").strip() or None,
        "target": str(row.get("target") or action.get("target") or "").strip() or None,
        "component": component,
        "service": service,
        "version": version,
        "selected_candidate": selected_candidate,
        "candidate_order": candidate_order[:12],
        "selected_templates": selected_templates[:12],
        "protocol_tags": [],
        "rag_recommended_tools": [],
        "reasons": deduped_reasons[:8],
    }


def _hydrate_execution_history_with_artifacts(
    rows: list[dict[str, Any]],
    *,
    action_artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or not rows:
        return []
    artifact_map: dict[str, dict[str, Any]] = {}
    for item in action_artifacts:
        if not isinstance(item, dict):
            continue
        key = _normalize_artifact_lookup_key(item.get("_artifact_path"))
        if key:
            artifact_map[key] = item
    hydrated: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        updated = dict(row)
        existing = updated.get("ranking_explanation", {})
        if isinstance(existing, dict) and existing:
            hydrated.append(updated)
            continue
        artifact_payload: dict[str, Any] = {}
        artifact_paths = updated.get("artifacts", []) if isinstance(updated.get("artifacts"), list) else []
        for path in artifact_paths:
            lookup_key = _normalize_artifact_lookup_key(path)
            if lookup_key and lookup_key in artifact_map:
                artifact_payload = artifact_map[lookup_key]
                break
        explanation = {}
        if artifact_payload:
            for candidate in (
                artifact_payload.get("ranking_explanation"),
                artifact_payload.get("action", {}).get("ranking_explanation") if isinstance(artifact_payload.get("action"), dict) else {},
            ):
                if isinstance(candidate, dict) and candidate:
                    explanation = dict(candidate)
                    break
            if not explanation and isinstance(artifact_payload.get("action"), dict):
                explanation = _synthesize_history_ranking_explanation(
                    row=updated,
                    action=artifact_payload.get("action", {}),
                )
        if explanation:
            updated["ranking_explanation"] = explanation
        hydrated.append(updated)
    return hydrated


def _normalize_phase_name(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized or "unassigned"


def _phase_sort_key(value: Any) -> tuple[int, str]:
    normalized = _normalize_phase_name(value)
    order = {
        "passive_recon": 0,
        "active_discovery": 1,
        "deep_testing": 2,
        "verification": 3,
        "reporting": 4,
        "unassigned": 99,
    }
    return order.get(normalized, 98), normalized


def _build_verification_ranking(
    payload: dict[str, Any],
    *,
    action_artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    scope = payload.get("scope", {}) if isinstance(payload, dict) else {}
    surface = scope.get("surface", {}) if isinstance(scope, dict) else {}
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
                -float(item.get("cvss_score", 0.0) or 0.0),
                str(item.get("cve_id", "")),
            ),
        )
        component = key[1] or None
        service = key[2] or None
        version = key[3] or None
        target = key[0] or None
        items = [
            _build_ranked_candidate_entry(
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
                    "target": target,
                    "component": component,
                    "service": service,
                    "version": version,
                    "selected_candidate": items[0]["cve_id"],
                    "selected_templates": [],
                    "items": items,
                }
            )

    for artifact in action_artifacts:
        action = artifact.get("action", {}) if isinstance(artifact.get("action"), dict) else {}
        metadata = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}
        tool_name = str(action.get("tool_name", "")).strip()
        if tool_name not in {"cve_verify", "poc_sandbox_exec", "nuclei_exploit_check"}:
            continue
        options = action.get("options", {}) if isinstance(action.get("options"), dict) else {}
        if tool_name == "cve_verify":
            candidate_order = metadata.get("verification_order")
        elif tool_name == "nuclei_exploit_check":
            candidate_order = metadata.get("requested_cve_ids")
        else:
            candidate_order = metadata.get("candidate_order")
        if not isinstance(candidate_order, list):
            candidate_order = options.get("cve_ids", []) if isinstance(options.get("cve_ids"), list) else []
        normalized_order = []
        seen_ids: set[str] = set()
        for item in candidate_order:
            cve_id = str(item).strip().upper()
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            normalized_order.append(cve_id)
        if not normalized_order:
            selected_from_option = str(options.get("cve_id", "")).strip().upper()
            if selected_from_option:
                normalized_order = [selected_from_option]
        selected_candidate = str(options.get("cve_id", "")).strip().upper() or (normalized_order[0] if normalized_order else None)
        selected_templates = metadata.get("selected_templates", [])
        if not isinstance(selected_templates, list):
            selected_templates = []
        if not selected_templates and isinstance(options.get("templates"), list):
            selected_templates = [
                str(item).strip()
                for item in options.get("templates", [])
                if str(item).strip()
            ]
        template_name = str(metadata.get("template", "")).strip()
        if template_name and template_name not in selected_templates:
            selected_templates = [template_name, *selected_templates]
        component = str(metadata.get("component") or options.get("component") or "").strip().lower() or None
        service = str(metadata.get("service") or options.get("service") or "").strip().lower() or None
        version = str(metadata.get("version") or options.get("version") or "").strip() or None
        target = str(action.get("target") or "").strip() or None
        items = []
        for cve_id in normalized_order:
            row = _match_ranked_candidate(
                cve_id=cve_id,
                rows=lookup_results,
                target=target,
                component=component,
                service=service,
                version=version,
            )
            items.append(
                _build_ranked_candidate_entry(
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


def _match_ranked_candidate(
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
    for row in rows:
        if str(row.get("cve_id", "")).strip().upper() != cve_id:
            continue
        score = 0
        if target and str(row.get("target", "")).strip() == target:
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


def _build_ranked_candidate_entry(
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
        candidate_capability = template_index.get(cve_id, {})
        capability = candidate_capability if isinstance(candidate_capability, dict) else {}
    template_count = int(capability.get("template_count", 0) or 0)
    protocol_tags = capability.get("protocol_tags", [])
    if not isinstance(protocol_tags, list):
        protocol_tags = []
    normalized_tool = str(block_tool or "").strip().lower()
    reasons: list[str] = []
    component = str(ranking_context.get("component", "")).strip()
    service = str(ranking_context.get("service", "")).strip()
    version = str(ranking_context.get("version", "")).strip()
    recommended_tools = ranking_context.get("rag_recommended_tools", [])
    if not isinstance(recommended_tools, list):
        recommended_tools = []
    rag_tags = ranking_context.get("rag_tags", [])
    if not isinstance(rag_tags, list):
        rag_tags = []
    aliases = ranking_context.get("protocol_aliases", [])
    if not isinstance(aliases, list):
        aliases = []
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
        "severity": normalize_severity(row.get("severity")),
        "cvss_score": _coerce_float(row.get("cvss_score")),
        "has_nuclei_template": bool(row.get("has_nuclei_template", template_count > 0)),
        "template_count": template_count,
        "template_capability": capability,
        "verified": verified,
        "selected": bool(selected_candidate and cve_id == selected_candidate),
        "ranking_context": ranking_context,
        "reasons": reasons,
    }


def _build_asset_phase_trends(
    payload: dict[str, Any],
    *,
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    execution = payload.get("execution", {}) if isinstance(payload, dict) else {}
    current_phase = _normalize_phase_name(
        (execution.get("current_phase") if isinstance(execution, dict) else None)
        or (payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}).get("current_phase")
    )
    history = payload.get("history", []) if isinstance(payload, dict) else []
    phase_history = execution.get("phase_history", []) if isinstance(execution, dict) else []
    rows: dict[str, dict[str, Any]] = {}
    first_phase_by_tool: dict[str, str] = {}

    def ensure_row(phase_name: str) -> dict[str, Any]:
        normalized = _normalize_phase_name(phase_name)
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
                "reason": None,
                "is_current": normalized == current_phase,
            }
        return rows[normalized]

    for entry in history:
        if not isinstance(entry, dict):
            continue
        phase_name = _normalize_phase_name(entry.get("phase"))
        row = ensure_row(phase_name)
        row["executed_actions"] += 1
        tool_name = str(entry.get("tool", "")).strip()
        if tool_name:
            if tool_name not in row["tool_names"]:
                row["tool_names"].append(tool_name)
            first_phase_by_tool.setdefault(tool_name, phase_name)

    for item in phase_history:
        if not isinstance(item, dict):
            continue
        phase_name = _normalize_phase_name(item.get("phase"))
        row = ensure_row(phase_name)
        reason = str(item.get("reason", "")).strip() or None
        if reason and not row.get("reason"):
            row["reason"] = reason

    ensure_row(current_phase)

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        source_tool = str(asset.get("source_tool", "")).strip()
        phase_name = first_phase_by_tool.get(source_tool, current_phase)
        row = ensure_row(phase_name)
        row["asset_count"] += 1
        if str(asset.get("kind", "")).strip().lower() == "service":
            row["service_assets"] += 1
        row["linked_findings"] += int(asset.get("finding_count", 0) or 0)

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        tool_name = str(finding.get("plugin_name") or finding.get("plugin_id") or "").strip()
        phase_name = first_phase_by_tool.get(tool_name, current_phase)
        row = ensure_row(phase_name)
        row["finding_count"] += 1

    ordered_rows = [
        {
            **row,
            "unique_tools": len(row["tool_names"]),
            "tool_names": row["tool_names"][:8],
        }
        for _phase, row in sorted(rows.items(), key=lambda item: _phase_sort_key(item[0]))
    ]
    previous_assets = 0
    previous_findings = 0
    for row in ordered_rows:
        row["delta_assets"] = row["asset_count"] - previous_assets
        row["delta_findings"] = row["finding_count"] - previous_findings
        previous_assets = row["asset_count"]
        previous_findings = row["finding_count"]
    return ordered_rows


def _build_asset_batch_trends(
    manager: JobManager,
    *,
    target_reports: list[dict[str, Any]],
    current_job_id: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    previous_assets = 0
    previous_findings = 0
    for report in target_reports:
        report_job_id = str(report.get("job_id", "")).strip()
        if not report_job_id:
            continue
        payload = read_report_json(
            manager,
            job_id=report_job_id,
            candidates=["agent/audit_report.json", "audit_report.json"],
        )
        findings = extract_report_findings(payload)
        assets = enrich_report_assets(extract_report_assets(payload), findings)
        summary = summarize_report_assets(assets)
        row = {
            "job_id": report_job_id,
            "ended_at": report.get("ended_at"),
            "updated_at": report.get("updated_at"),
            "status": report.get("status"),
            "finding_total": len(findings),
            "total_assets": summary.get("total_assets", len(assets)),
            "service_assets": summary.get("service_assets", 0),
            "linked_findings": summary.get("asset_linked_findings", 0),
            "is_current": report_job_id == current_job_id,
        }
        row["delta_assets"] = int(row["total_assets"] or 0) - previous_assets
        row["delta_findings"] = int(row["finding_total"] or 0) - previous_findings
        previous_assets = int(row["total_assets"] or 0)
        previous_findings = int(row["finding_total"] or 0)
        rows.append(row)
    return rows


def available_report_exports(item: dict[str, Any]) -> list[str]:
    formats = ["html"]
    report_paths = item.get("report_paths", {})
    if isinstance(report_paths, dict):
        if report_paths.get("markdown"):
            formats.append("markdown")
        if report_paths.get("json"):
            formats.append("json")
    return formats


def build_report_diff(
    *,
    current_findings: list[dict[str, Any]],
    baseline_findings: list[dict[str, Any]],
    baseline_item: dict[str, Any] | None,
    current_assets: list[dict[str, Any]] | None = None,
    baseline_assets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    current_map = {str(item["fingerprint"]): item for item in current_findings}
    baseline_map = {str(item["fingerprint"]): item for item in baseline_findings}
    new_items = [current_map[key] for key in current_map.keys() - baseline_map.keys()]
    resolved_items = [baseline_map[key] for key in baseline_map.keys() - current_map.keys()]
    persistent_items = [current_map[key] for key in current_map.keys() & baseline_map.keys()]
    current_asset_rows = current_assets if isinstance(current_assets, list) else []
    baseline_asset_rows = baseline_assets if isinstance(baseline_assets, list) else []
    current_asset_map = {_asset_fingerprint(item): item for item in current_asset_rows if isinstance(item, dict)}
    baseline_asset_map = {_asset_fingerprint(item): item for item in baseline_asset_rows if isinstance(item, dict)}
    new_asset_items = [current_asset_map[key] for key in current_asset_map.keys() - baseline_asset_map.keys()]
    resolved_asset_items = [baseline_asset_map[key] for key in baseline_asset_map.keys() - current_asset_map.keys()]
    persistent_asset_items = [current_asset_map[key] for key in current_asset_map.keys() & baseline_asset_map.keys()]

    current_service_map = {
        _service_asset_fingerprint(item): item
        for item in current_asset_rows
        if isinstance(item, dict) and str(item.get("kind", "")).strip().lower() == "service"
    }
    baseline_service_map = {
        _service_asset_fingerprint(item): item
        for item in baseline_asset_rows
        if isinstance(item, dict) and str(item.get("kind", "")).strip().lower() == "service"
    }
    new_service_items = [current_service_map[key] for key in current_service_map.keys() - baseline_service_map.keys()]
    resolved_service_items = [baseline_service_map[key] for key in baseline_service_map.keys() - current_service_map.keys()]
    persistent_service_items = [current_service_map[key] for key in current_service_map.keys() & baseline_service_map.keys()]
    return {
        "baseline_job_id": baseline_item.get("job_id") if baseline_item else None,
        "baseline_updated_at": baseline_item.get("updated_at") if baseline_item else None,
        "new_count": len(new_items),
        "resolved_count": len(resolved_items),
        "persistent_count": len(persistent_items),
        "new_findings": sort_findings(new_items),
        "resolved_findings": sort_findings(resolved_items),
        "persistent_findings": sort_findings(persistent_items),
        "new_assets_count": len(new_asset_items),
        "resolved_assets_count": len(resolved_asset_items),
        "persistent_assets_count": len(persistent_asset_items),
        "new_assets": _compact_diff_assets(new_asset_items),
        "resolved_assets": _compact_diff_assets(resolved_asset_items),
        "new_services_count": len(new_service_items),
        "resolved_services_count": len(resolved_service_items),
        "persistent_services_count": len(persistent_service_items),
        "new_services": _compact_diff_assets(new_service_items),
        "resolved_services": _compact_diff_assets(resolved_service_items),
        "new_asset_severity_counts": _build_asset_severity_breakdown(new_asset_items),
        "resolved_asset_severity_counts": _build_asset_severity_breakdown(resolved_asset_items),
        "persistent_asset_severity_counts": _build_asset_severity_breakdown(persistent_asset_items),
        "new_service_protocol_counts": _build_protocol_breakdown(new_service_items),
        "resolved_service_protocol_counts": _build_protocol_breakdown(resolved_service_items),
        "persistent_service_protocol_counts": _build_protocol_breakdown(persistent_service_items),
    }


def _asset_fingerprint(asset: dict[str, Any]) -> str:
    asset_id = str(asset.get("id", "")).strip()
    if asset_id:
        return asset_id
    payload = {
        "kind": str(asset.get("kind", "")).strip().lower(),
        "display_name": str(asset.get("display_name", "")).strip(),
        "attributes": asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {},
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _service_asset_fingerprint(asset: dict[str, Any]) -> str:
    attributes = asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {}
    host = str(attributes.get("host", "")).strip().lower()
    port = str(attributes.get("port", "")).strip()
    service = str(attributes.get("service", "")).strip().lower()
    proto = str(attributes.get("proto", "")).strip().lower()
    if host or port or service:
        return "::".join((host, port, service, proto))
    return _asset_fingerprint(asset)


def _compact_diff_assets(items: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    ordered = sorted(
        (item for item in items if isinstance(item, dict)),
        key=lambda item: (
            0 if str(item.get("kind", "")).strip().lower() == "service" else 1,
            -int(item.get("finding_count", 0) or 0),
            str(item.get("display_name", "") or item.get("id", "")),
        ),
    )
    for asset in ordered[:limit]:
        attributes = asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {}
        output.append(
            {
                "id": str(asset.get("id", "")).strip() or None,
                "kind": str(asset.get("kind", "")).strip().lower() or "asset",
                "display_name": str(asset.get("display_name", "")).strip() or str(asset.get("id", "")).strip() or "asset",
                "source_tool": str(asset.get("source_tool", "")).strip() or None,
                "host": str(attributes.get("host", "")).strip() or None,
                "port": str(attributes.get("port", "")).strip() or None,
                "service": str(attributes.get("service", "")).strip() or None,
                "proto": str(attributes.get("proto", "")).strip() or None,
                "finding_count": int(asset.get("finding_count", 0) or 0),
            }
        )
    return output


def _asset_highest_severity(asset: dict[str, Any]) -> str:
    related = asset.get("related_findings", []) if isinstance(asset, dict) else []
    highest = "info"
    if not isinstance(related, list):
        return highest
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for item in related:
        if not isinstance(item, dict):
            continue
        severity = normalize_severity(item.get("severity"))
        if rank.get(severity, 9) < rank.get(highest, 9):
            highest = severity
    return highest


def _build_asset_severity_breakdown(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for asset in items:
        if not isinstance(asset, dict):
            continue
        counts[_asset_highest_severity(asset)] += 1
    return counts


def _service_protocol_label(asset: dict[str, Any]) -> str:
    attributes = asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {}
    service = str(attributes.get("service", "")).strip().lower()
    proto = str(attributes.get("proto", "")).strip().lower()
    if service and proto:
        return f"{service}/{proto}"
    if service:
        return service
    if proto:
        return proto
    return str(asset.get("kind", "")).strip().lower() or "asset"


def _build_protocol_breakdown(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for asset in items:
        if not isinstance(asset, dict):
            continue
        label = _service_protocol_label(asset)
        counts[label] = counts.get(label, 0) + 1
    return [
        {"label": key, "count": value}
        for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def extract_report_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    plugin_results = payload.get("plugin_results", []) if isinstance(payload, dict) else []
    output: list[dict[str, Any]] = []
    if isinstance(plugin_results, list):
        for plugin in plugin_results:
            if not isinstance(plugin, dict):
                continue
            plugin_id = str(plugin.get("plugin_id", "")).strip()
            plugin_name = str(plugin.get("plugin_name", "")).strip()
            category = str(plugin.get("category", "")).strip() or None
            findings = plugin.get("findings", [])
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                evidence = finding.get("evidence", {})
                if not isinstance(evidence, dict):
                    evidence = {}
                severity = normalize_severity(finding.get("severity"))
                title = str(finding.get("title") or finding.get("name") or "").strip() or "Untitled finding"
                cve_id = str(finding.get("cve_id", "")).strip() or None
                cvss_score = _coerce_float(finding.get("cvss_score"))
                cve_verified = bool(finding.get("cve_verified", False))
                fingerprint = finding_fingerprint(
                    plugin_id=plugin_id,
                    finding_id=str(finding.get("finding_id") or finding.get("id") or "").strip(),
                    title=title,
                    severity=severity,
                    evidence=evidence,
                    cve_id=cve_id,
                )
                output.append(
                    {
                        "fingerprint": fingerprint,
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name or plugin_id,
                        "category": category,
                        "finding_id": str(finding.get("finding_id") or finding.get("id") or "").strip() or None,
                        "title": title,
                        "description": str(finding.get("description", "")).strip() or None,
                        "severity": severity,
                        "recommendation": str(finding.get("recommendation") or finding.get("remediation") or "").strip() or None,
                        "evidence": evidence,
                        "evidence_text": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "cve_verified": cve_verified,
                        "related_asset_ids": [
                            str(item).strip()
                            for item in finding.get("related_asset_ids", [])
                            if str(item).strip()
                        ] if isinstance(finding.get("related_asset_ids", []), list) else [],
                    }
                )

    agent_findings = payload.get("findings", []) if isinstance(payload, dict) else []
    if isinstance(agent_findings, list):
        for finding in agent_findings:
            if not isinstance(finding, dict):
                continue
            plugin_id = str(finding.get("tool", "")).strip() or "agent"
            plugin_name = plugin_id
            evidence = finding.get("evidence", {})
            if not isinstance(evidence, dict):
                evidence = {"raw": str(evidence)}
            severity = normalize_severity(finding.get("severity"))
            title = str(finding.get("title") or finding.get("name") or "").strip() or "Untitled finding"
            cve_id = str(finding.get("cve_id", "")).strip() or None
            cvss_score = _coerce_float(finding.get("cvss_score"))
            cve_verified = bool(finding.get("cve_verified", False))
            fingerprint = finding_fingerprint(
                plugin_id=plugin_id,
                finding_id=str(finding.get("finding_id") or finding.get("id") or "").strip(),
                title=title,
                severity=severity,
                evidence=evidence,
                cve_id=cve_id,
            )
            output.append(
                {
                    "fingerprint": fingerprint,
                    "plugin_id": plugin_id,
                    "plugin_name": plugin_name,
                    "category": str(finding.get("category", "")).strip() or None,
                    "finding_id": str(finding.get("finding_id") or finding.get("id") or "").strip() or None,
                    "title": title,
                    "description": str(finding.get("description", "")).strip() or None,
                    "severity": severity,
                    "recommendation": str(finding.get("recommendation") or finding.get("remediation") or "").strip() or None,
                    "evidence": evidence,
                    "evidence_text": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "cve_verified": cve_verified,
                    "related_asset_ids": [
                        str(item).strip()
                        for item in finding.get("related_asset_ids", [])
                        if str(item).strip()
                    ] if isinstance(finding.get("related_asset_ids", []), list) else [],
                }
            )
    return sort_findings(output)


def extract_report_assets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scope = payload.get("scope", {}) if isinstance(payload, dict) else {}
    raw_assets = scope.get("assets", []) if isinstance(scope, dict) else []
    output: list[dict[str, Any]] = []
    if not isinstance(raw_assets, list):
        return output
    for asset in raw_assets:
        if not isinstance(asset, dict):
            continue
        attributes = asset.get("attributes", {})
        evidence = asset.get("evidence", {})
        if not isinstance(attributes, dict):
            attributes = {}
        if not isinstance(evidence, dict):
            evidence = {}
        asset_id = str(asset.get("id", "")).strip()
        kind = str(asset.get("kind", "")).strip().lower() or "asset"
        output.append(
            {
                "id": asset_id,
                "kind": kind,
                "parent_id": str(asset.get("parent_id", "")).strip() or None,
                "source_tool": str(asset.get("source_tool", "")).strip() or None,
                "attributes": attributes,
                "evidence": evidence,
                "display_name": build_report_asset_display_name(kind, asset_id, attributes),
            }
        )
    return output


def enrich_report_assets(
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    finding_map: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for asset_id in finding.get("related_asset_ids", []):
            normalized = str(asset_id).strip()
            if not normalized:
                continue
            finding_map.setdefault(normalized, []).append(
                {
                    "fingerprint": finding.get("fingerprint"),
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "plugin_name": finding.get("plugin_name"),
                }
            )
    output: list[dict[str, Any]] = []
    for asset in assets:
        asset_id = str(asset.get("id", "")).strip()
        related = finding_map.get(asset_id, [])
        enriched = dict(asset)
        enriched["finding_count"] = len(related)
        enriched["related_findings"] = related
        output.append(enriched)
    output.sort(
        key=lambda item: (
            0 if str(item.get("kind", "")) == "service" else 1,
            -int(item.get("finding_count", 0) or 0),
            str(item.get("display_name", "")),
        )
    )
    return output


def summarize_report_assets(assets: list[dict[str, Any]]) -> dict[str, Any]:
    kind_counts: dict[str, int] = {}
    service_count = 0
    related_finding_count = 0
    for asset in assets:
        kind = str(asset.get("kind", "")).strip().lower() or "asset"
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        if kind == "service":
            service_count += 1
        related_finding_count += int(asset.get("finding_count", 0) or 0)
    return {
        "total_assets": len(assets),
        "service_assets": service_count,
        "assets_by_kind": kind_counts,
        "asset_linked_findings": related_finding_count,
    }


def build_report_asset_display_name(kind: str, asset_id: str, attributes: dict[str, Any]) -> str:
    if kind == "service":
        host = str(attributes.get("host", "")).strip()
        port = str(attributes.get("port", "")).strip()
        service = str(attributes.get("service", "")).strip()
        if host and port:
            return f"{host}:{port} ({service or 'service'})"
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
    return asset_id or kind


def sort_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        items,
        key=lambda item: (
            severity_rank.get(str(item.get("severity", "info")), 9),
            str(item.get("plugin_name", "")),
            str(item.get("title", "")),
            str(item.get("fingerprint", "")),
        ),
    )


def normalize_severity(value: Any) -> str:
    normalized = str(value or "info").strip().lower()
    if normalized not in {"critical", "high", "medium", "low", "info"}:
        return "info"
    return normalized


def finding_fingerprint(
    *,
    plugin_id: str,
    finding_id: str,
    title: str,
    severity: str,
    evidence: dict[str, Any],
    cve_id: str | None = None,
) -> str:
    base = json.dumps(
        {
            "plugin_id": plugin_id,
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "cve_id": cve_id,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def _coerce_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_target_key(value: Any) -> str:
    return str(value or "").strip().lower()


def read_report_json(manager: JobManager, *, job_id: str, candidates: list[str]) -> dict[str, Any]:
    for candidate in candidates:
        try:
            path = manager.resolve_file(job_id, candidate)
        except (KeyError, FileNotFoundError, PermissionError):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def extract_report_metrics(payload: dict[str, Any]) -> tuple[int, dict[str, int], str | None]:
    summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    if isinstance(summary, dict):
        raw_counts = summary.get("severity_counts", {})
        if isinstance(raw_counts, dict):
            for level in severity_counts:
                severity_counts[level] = int(raw_counts.get(level, 0) or 0)

    total_findings = 0
    if isinstance(summary, dict):
        total_findings = int(
            summary.get("total_findings")
            or summary.get("vulnerability_findings")
            or 0
        )

    decision_summary = None
    meta = payload.get("meta", {}) if isinstance(payload, dict) else {}
    if isinstance(meta, dict):
        raw_summary = str(meta.get("decision_summary") or "").strip()
        decision_summary = raw_summary or None
    return total_findings, severity_counts, decision_summary


def _render_verification_ranking_html(blocks: list[dict[str, Any]]) -> str:
    if not blocks:
        return "<p>No verification ranking context captured for this run.</p>"
    output: list[str] = []
    for block in blocks:
        target = html_escape(str(block.get("target") or "-"))
        tool = html_escape(str(block.get("tool") or "-"))
        component = html_escape(str(block.get("component") or "-"))
        service = html_escape(str(block.get("service") or "-"))
        version = html_escape(str(block.get("version") or "-"))
        selected_candidate = html_escape(str(block.get("selected_candidate") or "-"))
        selected_templates = block.get("selected_templates", [])
        if not isinstance(selected_templates, list):
            selected_templates = []
        template_text = ", ".join(html_escape(str(item)) for item in selected_templates[:6]) or "-"
        rows = []
        for item in block.get("items", []):
            if not isinstance(item, dict):
                continue
            reasons = item.get("reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            rows.append(
                "<tr>"
                f"<td>{html_escape(str(item.get('cve_id') or '-'))}</td>"
                f"<td>{html_escape(str(item.get('severity') or '-'))}</td>"
                f"<td>{html_escape(str(item.get('cvss_score') if item.get('cvss_score') is not None else '-'))}</td>"
                f"<td>{'yes' if item.get('has_nuclei_template') else 'no'}</td>"
                f"<td>{html_escape(str(item.get('template_count') or 0))}</td>"
                f"<td>{'selected' if item.get('selected') else ('verified' if item.get('verified') else '-')}</td>"
                f"<td>{html_escape('; '.join(str(reason) for reason in reasons[:4]) or '-')}</td>"
                "</tr>"
            )
        table_rows = "".join(rows) or "<tr><td colspan='7'>No ranked candidates</td></tr>"
        output.append(
            "<article class='card' style='margin-bottom:14px'>"
            f"<h3>{tool}</h3>"
            f"<p><strong>Target:</strong> {target} | <strong>Component:</strong> {component} | "
            f"<strong>Service:</strong> {service} | <strong>Version:</strong> {version}</p>"
            f"<p><strong>Selected:</strong> {selected_candidate} | <strong>Templates:</strong> {template_text}</p>"
            "<table>"
            "<thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Template</th><th>Count</th><th>Status</th><th>Why ranked first</th></tr></thead>"
            f"<tbody>{table_rows}</tbody>"
            "</table>"
            "</article>"
        )
    return "".join(output)


def _render_asset_trend_rows(rows: list[dict[str, Any]], *, kind: str) -> str:
    if not rows:
        col_span = 8 if kind == "phase" else 7
        return f"<tr><td colspan='{col_span}'>No trend data</td></tr>"
    output: list[str] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        if kind == "phase":
            output.append(
                "<tr>"
                f"<td>{html_escape(str(item.get('phase') or '-'))}</td>"
                f"<td>{int(item.get('executed_actions', 0) or 0)}</td>"
                f"<td>{int(item.get('unique_tools', 0) or 0)}</td>"
                f"<td>{int(item.get('asset_count', 0) or 0)}</td>"
                f"<td>{int(item.get('service_assets', 0) or 0)}</td>"
                f"<td>{int(item.get('finding_count', 0) or 0)}</td>"
                f"<td>{int(item.get('delta_assets', 0) or 0):+d}</td>"
                f"<td>{html_escape(str(item.get('reason') or '-'))}</td>"
                "</tr>"
            )
        else:
            output.append(
                "<tr>"
                f"<td>{html_escape(str(item.get('job_id') or '-'))}</td>"
                f"<td>{html_escape(str(item.get('ended_at') or item.get('updated_at') or '-'))}</td>"
                f"<td>{int(item.get('total_assets', 0) or 0)}</td>"
                f"<td>{int(item.get('service_assets', 0) or 0)}</td>"
                f"<td>{int(item.get('finding_total', 0) or 0)}</td>"
                f"<td>{int(item.get('delta_assets', 0) or 0):+d}</td>"
                f"<td>{int(item.get('delta_findings', 0) or 0):+d}</td>"
                "</tr>"
            )
    return "".join(output)


def _render_asset_diff_cards(title: str, entries: list[dict[str, Any]], empty_text: str) -> str:
    if not isinstance(entries, list) or not entries:
        return (
            "<div class='card'>"
            f"<h3>{html_escape(title)}</h3>"
            f"<p>{html_escape(empty_text)}</p>"
            "</div>"
        )
    rows: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        meta_parts = [
            str(entry.get("kind") or "").strip().upper(),
            str(entry.get("service") or "").strip(),
            f"port {entry.get('port')}" if entry.get("port") else "",
            f"source {entry.get('source_tool')}" if entry.get("source_tool") else "",
        ]
        meta = " | ".join(part for part in meta_parts if part)
        rows.append(
            "<div style='border: 1px solid rgba(29,43,39,0.08); border-radius: 12px; padding: 10px 12px; margin-top: 10px;'>"
            f"<div><strong>{html_escape(str(entry.get('display_name') or entry.get('id') or '-'))}</strong></div>"
            f"<div style='margin-top: 4px; font-size: 12px; color: #546477;'>{html_escape(meta or '-')}</div>"
            "</div>"
        )
    body = "".join(rows) or f"<p>{html_escape(empty_text)}</p>"
    return (
        "<div class='card'>"
        f"<h3>{html_escape(title)}</h3>"
        f"{body}"
        "</div>"
    )


def _render_count_chip_rows(title: str, counts: dict[str, Any], empty_text: str) -> str:
    order = ("critical", "high", "medium", "low", "info")
    if not isinstance(counts, dict):
        counts = {}
    chips = "".join(
        f"<span class='chip chip-{html_escape(level)}'>{html_escape(level.upper())} {int(counts.get(level, 0) or 0)}</span>"
        for level in order
        if int(counts.get(level, 0) or 0) > 0
    )
    if not chips:
        chips = f"<p>{html_escape(empty_text)}</p>"
    return (
        "<div class='card'>"
        f"<h3>{html_escape(title)}</h3>"
        f"{chips}"
        "</div>"
    )


def _render_protocol_breakdown_cards(title: str, rows: list[dict[str, Any]], empty_text: str) -> str:
    if not isinstance(rows, list) or not rows:
        return (
            "<div class='card'>"
            f"<h3>{html_escape(title)}</h3>"
            f"<p>{html_escape(empty_text)}</p>"
            "</div>"
        )
    body = "".join(
        f"<span class='chip chip-info'>{html_escape(str(item.get('label') or '-'))} {int(item.get('count', 0) or 0)}</span>"
        for item in rows[:10]
        if isinstance(item, dict)
    ) or f"<p>{html_escape(empty_text)}</p>"
    return (
        "<div class='card'>"
        f"<h3>{html_escape(title)}</h3>"
        f"{body}"
        "</div>"
    )


def _render_execution_history_html(rows: list[dict[str, Any]]) -> str:
    if not isinstance(rows, list) or not rows:
        return "<p>No execution history recorded for this run.</p>"
    output: list[str] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        explanation = row.get("ranking_explanation", {}) if isinstance(row.get("ranking_explanation"), dict) else {}
        reasons = explanation.get("reasons", []) if isinstance(explanation.get("reasons"), list) else []
        selected_templates = explanation.get("selected_templates", []) if isinstance(explanation.get("selected_templates"), list) else []
        candidate_order = explanation.get("candidate_order", []) if isinstance(explanation.get("candidate_order"), list) else []
        template_text = ", ".join(html_escape(str(item)) for item in selected_templates[:6]) or "-"
        reason_text = "".join(f"<li>{html_escape(str(reason))}</li>" for reason in reasons[:8]) or "<li>No detailed selection rationale recorded.</li>"
        candidate_text = ", ".join(html_escape(str(item)) for item in candidate_order[:8]) or "-"
        error_text = str(row.get("error") or "").strip()
        error_html = f"<p><strong>Error:</strong> {html_escape(error_text)}</p>" if error_text else ""
        output.append(
            "<article class='card' style='margin-bottom:14px'>"
            f"<h3>{index}. {html_escape(str(row.get('tool') or '-'))}</h3>"
            f"<p><strong>Target:</strong> {html_escape(str(row.get('target') or '-'))} | "
            f"<strong>Phase:</strong> {html_escape(str(row.get('phase') or '-'))} | "
            f"<strong>Status:</strong> {html_escape(str(row.get('status') or '-'))}</p>"
            f"<p><strong>Selected Candidate:</strong> {html_escape(str(explanation.get('selected_candidate') or '-'))}</p>"
            f"<p><strong>Candidate Order:</strong> {candidate_text}</p>"
            f"<p><strong>Selected Templates:</strong> {template_text}</p>"
            "<div><strong>Why Executed:</strong><ul>"
            f"{reason_text}"
            "</ul></div>"
            f"{error_html}"
            "</article>"
        )
    return "".join(output) or "<p>No execution history recorded for this run.</p>"


def render_generated_report_html(*, item: dict[str, Any], analysis: dict[str, Any]) -> str:
    diff = analysis.get("diff", {}) if isinstance(analysis, dict) else {}
    history = analysis.get("history", []) if isinstance(analysis, dict) else []
    execution_history = analysis.get("execution_history", []) if isinstance(analysis, dict) else []
    findings = analysis.get("findings", []) if isinstance(analysis, dict) else []
    verification_ranking = analysis.get("verification_ranking", []) if isinstance(analysis, dict) else []
    asset_phase_trends = analysis.get("asset_phase_trends", []) if isinstance(analysis, dict) else []
    asset_batch_trends = analysis.get("asset_batch_trends", []) if isinstance(analysis, dict) else []
    severity_counts = item.get("severity_counts", {}) if isinstance(item, dict) else {}
    chips = "".join(
        f"<span class='chip chip-{html_escape(level)}'>{html_escape(level)} {int(severity_counts.get(level, 0) or 0)}</span>"
        for level in ("critical", "high", "medium", "low", "info")
    )
    history_rows = "".join(
        (
            "<tr>"
            f"<td>{html_escape(str(entry.get('job_id') or ''))}</td>"
            f"<td>{html_escape(str(entry.get('ended_at') or entry.get('updated_at') or '-'))}</td>"
            f"<td>{html_escape(str(entry.get('status') or '-'))}</td>"
            f"<td>{int(entry.get('finding_total', 0) or 0)}</td>"
            "</tr>"
        )
        for entry in history
    ) or "<tr><td colspan='4'>No history</td></tr>"
    finding_cards = "".join(render_finding_html(entry) for entry in findings) or "<p>No findings recorded in this report.</p>"
    verification_html = _render_verification_ranking_html(verification_ranking if isinstance(verification_ranking, list) else [])
    phase_rows = _render_asset_trend_rows(asset_phase_trends if isinstance(asset_phase_trends, list) else [], kind="phase")
    batch_rows = _render_asset_trend_rows(asset_batch_trends if isinstance(asset_batch_trends, list) else [], kind="batch")
    new_asset_cards = _render_asset_diff_cards(
        "New Assets",
        diff.get("new_assets", []) if isinstance(diff, dict) else [],
        "No new assets relative to the baseline.",
    )
    resolved_asset_cards = _render_asset_diff_cards(
        "Resolved Assets",
        diff.get("resolved_assets", []) if isinstance(diff, dict) else [],
        "No resolved assets relative to the baseline.",
    )
    new_service_cards = _render_asset_diff_cards(
        "New Services",
        diff.get("new_services", []) if isinstance(diff, dict) else [],
        "No new services relative to the baseline.",
    )
    resolved_service_cards = _render_asset_diff_cards(
        "Resolved Services",
        diff.get("resolved_services", []) if isinstance(diff, dict) else [],
        "No resolved services relative to the baseline.",
    )
    new_asset_severity_cards = _render_count_chip_rows(
        "New Asset Severity",
        diff.get("new_asset_severity_counts", {}) if isinstance(diff, dict) else {},
        "No new asset severity signal.",
    )
    resolved_asset_severity_cards = _render_count_chip_rows(
        "Resolved Asset Severity",
        diff.get("resolved_asset_severity_counts", {}) if isinstance(diff, dict) else {},
        "No resolved asset severity signal.",
    )
    persistent_asset_severity_cards = _render_count_chip_rows(
        "Persistent Asset Severity",
        diff.get("persistent_asset_severity_counts", {}) if isinstance(diff, dict) else {},
        "No persistent asset severity signal.",
    )
    new_service_protocol_cards = _render_protocol_breakdown_cards(
        "New Service Protocols",
        diff.get("new_service_protocol_counts", []) if isinstance(diff, dict) else [],
        "No new protocol changes.",
    )
    resolved_service_protocol_cards = _render_protocol_breakdown_cards(
        "Resolved Service Protocols",
        diff.get("resolved_service_protocol_counts", []) if isinstance(diff, dict) else [],
        "No resolved protocol changes.",
    )
    persistent_service_protocol_cards = _render_protocol_breakdown_cards(
        "Persistent Service Protocols",
        diff.get("persistent_service_protocol_counts", []) if isinstance(diff, dict) else [],
        "No persistent protocol changes.",
    )
    execution_history_html = _render_execution_history_html(execution_history if isinstance(execution_history, list) else [])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html_escape(str(item.get("target") or item.get("job_id") or "AutoSecAudit Report"))}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; margin: 0; color: #1d2b27; background: #f4efe6; }}
    .page {{ max-width: 1080px; margin: 0 auto; padding: 32px; }}
    .hero {{ background: #fffaf4; border: 1px solid rgba(29,43,39,0.12); border-radius: 24px; padding: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-top: 18px; }}
    .card {{ background: white; border-radius: 18px; padding: 16px; border: 1px solid rgba(29,43,39,0.1); }}
    .section {{ margin-top: 18px; background: white; border-radius: 24px; padding: 20px; border: 1px solid rgba(29,43,39,0.1); }}
    .chip {{ display: inline-block; padding: 7px 11px; border-radius: 999px; margin-right: 8px; margin-top: 8px; font-size: 12px; font-weight: 700; }}
    .chip-critical {{ background: rgba(185,28,28,0.12); color: #b91c1c; }}
    .chip-high {{ background: rgba(217,119,6,0.14); color: #b45309; }}
    .chip-medium {{ background: rgba(202,138,4,0.14); color: #a16207; }}
    .chip-low {{ background: rgba(14,116,144,0.13); color: #0e7490; }}
    .chip-info {{ background: rgba(15,118,110,0.13); color: #0f766e; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ border-bottom: 1px solid rgba(29,43,39,0.08); padding: 10px 6px; text-align: left; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #15211f; color: #e7fff4; padding: 12px; border-radius: 14px; }}
    h1, h2, h3, p {{ margin-top: 0; }}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <p>AutoSecAudit Report Export</p>
      <h1>{html_escape(str(item.get("target") or item.get("job_id") or "Report"))}</h1>
      <p>Job {html_escape(str(item.get("job_id") or '-'))} | Status {html_escape(str(item.get("status") or '-'))} | Updated {html_escape(str(item.get("updated_at") or '-'))}</p>
      <div>{chips}</div>
      <div class="grid">
        <div class="card"><strong>Total Findings</strong><p>{int(item.get("finding_total", 0) or 0)}</p></div>
        <div class="card"><strong>New vs Baseline</strong><p>{int(diff.get("new_count", 0) or 0)}</p></div>
        <div class="card"><strong>Resolved vs Baseline</strong><p>{int(diff.get("resolved_count", 0) or 0)}</p></div>
        <div class="card"><strong>Persistent vs Baseline</strong><p>{int(diff.get("persistent_count", 0) or 0)}</p></div>
      </div>
    </section>
    <section class="section">
      <h2>Baseline Asset / Service Diff</h2>
      <div class="grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
        <div class="card"><strong>New Assets</strong><p>{int(diff.get("new_assets_count", 0) or 0)}</p></div>
        <div class="card"><strong>Resolved Assets</strong><p>{int(diff.get("resolved_assets_count", 0) or 0)}</p></div>
        <div class="card"><strong>New Services</strong><p>{int(diff.get("new_services_count", 0) or 0)}</p></div>
        <div class="card"><strong>Resolved Services</strong><p>{int(diff.get("resolved_services_count", 0) or 0)}</p></div>
      </div>
      <div class="grid" style="grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 18px;">
        {new_asset_cards}
        {resolved_asset_cards}
        {new_service_cards}
        {resolved_service_cards}
      </div>
      <div class="grid" style="grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 18px;">
        {new_asset_severity_cards}
        {resolved_asset_severity_cards}
        {persistent_asset_severity_cards}
        {new_service_protocol_cards}
        {resolved_service_protocol_cards}
        {persistent_service_protocol_cards}
      </div>
    </section>
    <section class="section">
      <h2>History</h2>
      <table>
        <thead><tr><th>Job</th><th>Completed</th><th>Status</th><th>Findings</th></tr></thead>
        <tbody>{history_rows}</tbody>
      </table>
    </section>
    <section class="section">
      <h2>Execution History</h2>
      {execution_history_html}
    </section>
    <section class="section">
      <h2>Verification Ranking</h2>
      {verification_html}
    </section>
    <section class="section">
      <h2>Asset Trends by Phase</h2>
      <table>
        <thead><tr><th>Phase</th><th>Actions</th><th>Tools</th><th>Assets</th><th>Services</th><th>Findings</th><th>Delta Assets</th><th>Reason</th></tr></thead>
        <tbody>{phase_rows}</tbody>
      </table>
    </section>
    <section class="section">
      <h2>Asset Trends by Run Batch</h2>
      <table>
        <thead><tr><th>Job</th><th>Completed</th><th>Assets</th><th>Services</th><th>Findings</th><th>Delta Assets</th><th>Delta Findings</th></tr></thead>
        <tbody>{batch_rows}</tbody>
      </table>
    </section>
    <section class="section">
      <h2>Findings</h2>
      {finding_cards}
    </section>
  </div>
</body>
</html>"""


def render_finding_html(item: dict[str, Any]) -> str:
    description = html_escape(str(item.get("description") or ""))
    recommendation = html_escape(str(item.get("recommendation") or ""))
    return (
        "<article class='card' style='margin-bottom:14px'>"
        f"<h3>{html_escape(str(item.get('title') or 'Untitled finding'))}</h3>"
        f"<p><strong>{html_escape(str(item.get('severity') or 'info').upper())}</strong> | "
        f"{html_escape(str(item.get('plugin_name') or item.get('plugin_id') or '-'))}</p>"
        f"{f'<p>{description}</p>' if description else ''}"
        f"{f'<p><strong>Recommendation:</strong> {recommendation}</p>' if recommendation else ''}"
        f"<pre>{html_escape(str(item.get('evidence_text') or '{}'))}</pre>"
        "</article>"
    )


def first_existing(paths: set[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in paths:
            return candidate
    return None
