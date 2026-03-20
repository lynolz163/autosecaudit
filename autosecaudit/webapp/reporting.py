"""Dashboard and report aggregation helpers for the web console."""

from __future__ import annotations

import hashlib
from html import escape as html_escape
import json
from pathlib import Path
import re
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


def build_global_search_results(manager: JobManager, *, query: str, limit: int = 10) -> dict[str, Any]:
    """Search jobs, reports, findings, assets, and schedules from one entry point."""
    normalized_query = str(query or "").strip()
    if len(normalized_query) < 2:
        return {"query": normalized_query, "total": 0, "groups": {}, "items": []}

    tokens = _tokenize_search_query(normalized_query)
    if not tokens:
        return {"query": normalized_query, "total": 0, "groups": {}, "items": []}

    results: list[dict[str, Any]] = []

    jobs = _collect_search_jobs(manager)

    for job in jobs:
        job_id = str(job.get("job_id") or "").strip()
        target = str(job.get("target") or "").strip()
        score = _score_search_match(
            query=normalized_query,
            tokens=tokens,
            primary_fields=[job_id, target],
            secondary_fields=[job.get("mode"), job.get("status"), job.get("session_status")],
        )
        if score <= 0:
            continue
        results.append(
            {
                "kind": "job",
                "route": "jobs",
                "title": target or job_id or "Job",
                "subtitle": " / ".join(item for item in [job_id, job.get("status"), job.get("mode")] if item),
                "summary": str(job.get("last_updated_at") or "").strip() or None,
                "score": score,
                "target": target or None,
                "job_id": job_id or None,
                "metadata": {
                    "status": job.get("status"),
                    "session_status": job.get("session_status"),
                    "mode": job.get("mode"),
                },
            }
        )

    for asset in manager.store.list_assets():
        asset_id = int(asset.get("asset_id", 0) or 0)
        target = str(asset.get("target") or "").strip()
        score = _score_search_match(
            query=normalized_query,
            tokens=tokens,
            primary_fields=[asset.get("name"), target],
            secondary_fields=[asset.get("scope"), asset.get("notes"), ", ".join(asset.get("tags", []) or [])],
        )
        if score <= 0:
            continue
        results.append(
            {
                "kind": "asset",
                "route": "assets",
                "title": str(asset.get("name") or target or f"Asset #{asset_id}").strip(),
                "subtitle": " / ".join(item for item in [target, asset.get("default_mode")] if item),
                "summary": _search_summary(asset.get("notes")) or _search_summary(", ".join(asset.get("tags", []) or [])),
                "score": score,
                "target": target or None,
                "asset_id": asset_id or None,
                "metadata": {
                    "tags": list(asset.get("tags", []) or []),
                    "enabled": bool(asset.get("enabled", False)),
                },
            }
        )

    for schedule in manager.store.list_schedules():
        schedule_id = int(schedule.get("schedule_id", 0) or 0)
        target = str(schedule.get("target") or "").strip()
        score = _score_search_match(
            query=normalized_query,
            tokens=tokens,
            primary_fields=[schedule.get("name"), target],
            secondary_fields=[schedule.get("cron_expr"), schedule.get("last_job_id"), schedule.get("notes")],
        )
        if score <= 0:
            continue
        results.append(
            {
                "kind": "schedule",
                "route": "schedules",
                "title": str(schedule.get("name") or target or f"Schedule #{schedule_id}").strip(),
                "subtitle": " / ".join(item for item in [target, schedule.get("cron_expr")] if item),
                "summary": _search_summary(schedule.get("notes")) or _search_summary(schedule.get("last_job_id")),
                "score": score,
                "target": target or None,
                "schedule_id": schedule_id or None,
                "metadata": {
                    "enabled": bool(schedule.get("enabled", False)),
                    "asset_id": schedule.get("asset_id"),
                },
            }
        )

    for job in jobs:
        job_id = str(job.get("job_id") or "").strip()
        try:
            artifacts = manager.store.list_artifacts(job_id)
        except Exception:  # noqa: BLE001
            artifacts = []
        report = build_report_item(manager, job=job, artifacts=artifacts)
        if report is None:
            continue
        job_id = str(report.get("job_id") or "").strip()
        target = str(report.get("target") or "").strip()
        report_score = _score_search_match(
            query=normalized_query,
            tokens=tokens,
            primary_fields=[job_id, target],
            secondary_fields=[report.get("decision_summary"), report.get("status"), report.get("mode")],
        )
        if report_score > 0:
            results.append(
                {
                    "kind": "report",
                    "route": "reports",
                    "title": target or job_id or "Report",
                    "subtitle": " / ".join(item for item in [job_id, report.get("status"), report.get("mode")] if item),
                    "summary": _search_summary(report.get("decision_summary")),
                    "score": report_score,
                    "target": target or None,
                    "job_id": job_id or None,
                    "metadata": {
                        "finding_total": int(report.get("finding_total", 0) or 0),
                        "severity_counts": dict(report.get("severity_counts", {})),
                    },
                }
            )

        payload = read_report_json(manager, job_id=job_id, candidates=["agent/audit_report.json", "audit_report.json"])
        for finding in extract_report_findings(payload):
            fingerprint = str(finding.get("fingerprint") or "").strip()
            finding_score = _score_search_match(
                query=normalized_query,
                tokens=tokens,
                primary_fields=[finding.get("finding_id"), finding.get("cve_id"), finding.get("title")],
                secondary_fields=[
                    finding.get("description"),
                    finding.get("plugin_name"),
                    finding.get("evidence_text"),
                    target,
                ],
            )
            if finding_score <= 0:
                continue
            results.append(
                {
                    "kind": "finding",
                    "route": "reports",
                    "title": str(finding.get("title") or "Finding").strip(),
                    "subtitle": " / ".join(
                        item
                        for item in [
                            str(finding.get("severity") or "").upper(),
                            finding.get("cve_id"),
                            finding.get("plugin_name"),
                            target,
                        ]
                        if item
                    ),
                    "summary": _search_summary(
                        finding.get("description")
                        or finding.get("recommendation")
                        or finding.get("evidence_text")
                    ),
                    "score": finding_score + 1.5,
                    "target": target or None,
                    "job_id": job_id or None,
                    "metadata": {
                        "fingerprint": fingerprint or None,
                        "finding_id": finding.get("finding_id"),
                        "severity": finding.get("severity"),
                        "cve_id": finding.get("cve_id"),
                    },
                }
            )

    deduped: dict[str, dict[str, Any]] = {}
    for item in results:
        key = _search_result_key(item)
        current = deduped.get(key)
        if current is None or float(item.get("score", 0.0) or 0.0) > float(current.get("score", 0.0) or 0.0):
            deduped[key] = item

    items = sorted(
        deduped.values(),
        key=lambda item: (
            -float(item.get("score", 0.0) or 0.0),
            _search_kind_rank(str(item.get("kind") or "")),
            str(item.get("title") or ""),
        ),
    )[: max(1, int(limit or 10))]
    groups: dict[str, int] = {}
    for item in items:
        kind = str(item.get("kind") or "other")
        groups[kind] = groups.get(kind, 0) + 1
    return {
        "query": normalized_query,
        "total": len(items),
        "groups": groups,
        "items": items,
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
    runtime = current_payload.get("execution", {}).get("runtime", {}) if isinstance(current_payload.get("execution", {}), dict) else {}
    scope = current_payload.get("scope", {}) if isinstance(current_payload.get("scope", {}), dict) else {}
    scope_surface = scope.get("surface", {}) if isinstance(scope.get("surface", {}), dict) else {}
    return {
        "job_id": job_id,
        "target": item.get("target"),
        "baseline_job_id": baseline_item.get("job_id") if baseline_item else None,
        "session_status": str(runtime.get("session_status") or current_payload.get("meta", {}).get("session_status") or item.get("status") or "").strip() or None,
        "pending_approval": runtime.get("pending_approval", {}) if isinstance(runtime.get("pending_approval", {}), dict) else {},
        "loop_guard": runtime.get("loop_guard", {}) if isinstance(runtime.get("loop_guard", {}), dict) else {},
        "thought_stream": current_payload.get("thought_stream", []) if isinstance(current_payload.get("thought_stream", []), list) else [],
        "evidence_graph": current_payload.get("evidence_graph", {}) if isinstance(current_payload.get("evidence_graph", {}), dict) else {},
        "cve_validation": current_payload.get("cve_validation", {}) if isinstance(current_payload.get("cve_validation", {}), dict) else {},
        "infrastructure": current_payload.get("infrastructure", {}) if isinstance(current_payload.get("infrastructure", {}), dict) else {},
        "risk_matrix": current_payload.get("risk_matrix", {}) if isinstance(current_payload.get("risk_matrix", {}), dict) else {},
        "attack_surface": current_payload.get("attack_surface", {}) if isinstance(current_payload.get("attack_surface", {}), dict) else {},
        "remediation_priority": current_payload.get("remediation_priority", []) if isinstance(current_payload.get("remediation_priority", []), list) else [],
        "path_graph": current_payload.get("path_graph", {}) if isinstance(current_payload.get("path_graph", {}), dict) else {},
        "knowledge_context": current_payload.get("knowledge_context", {}) if isinstance(current_payload.get("knowledge_context", {}), dict) else (
            scope_surface.get("knowledge_context", {}) if isinstance(scope_surface.get("knowledge_context", {}), dict) else {}
        ),
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


def _collect_search_jobs(manager: JobManager) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    store = getattr(manager, "store", None)
    if store is not None and hasattr(store, "list_jobs"):
        for item in store.list_jobs():
            job_id = str(item.get("job_id") or "").strip()
            if not job_id:
                continue
            merged[job_id] = dict(item)
    for item in manager.list_jobs():
        job_id = str(item.get("job_id") or "").strip()
        if not job_id:
            continue
        current = dict(merged.get(job_id, {}))
        current.update(dict(item))
        merged[job_id] = current
    items = list(merged.values())
    items.sort(key=lambda item: str(item.get("created_at") or item.get("last_updated_at") or ""), reverse=True)
    return items


def _tokenize_search_query(query: str) -> list[str]:
    tokens = [item.strip().lower() for item in str(query or "").split() if item.strip()]
    output: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        output.append(token)
    return output


def _normalize_search_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, list):
        return " ".join(_normalize_search_text(item) for item in value if _normalize_search_text(item)).strip().lower()
    if isinstance(value, dict):
        return " ".join(
            f"{_normalize_search_text(key)} {_normalize_search_text(item)}".strip()
            for key, item in value.items()
            if _normalize_search_text(key) or _normalize_search_text(item)
        ).strip().lower()
    return " ".join(str(value).strip().lower().split())


def _score_search_match(*, query: str, tokens: list[str], primary_fields: list[Any], secondary_fields: list[Any]) -> float:
    primary_text = _normalize_search_text(primary_fields)
    secondary_text = _normalize_search_text(secondary_fields)
    combined_text = " ".join(item for item in [primary_text, secondary_text] if item).strip()
    if not combined_text or not all(token in combined_text for token in tokens):
        return 0.0

    score = 0.0
    normalized_query = " ".join(str(query or "").strip().lower().split())
    if normalized_query and normalized_query in primary_text:
        score += 12.0
    elif normalized_query and normalized_query in secondary_text:
        score += 6.0

    for token in tokens:
        if token in primary_text:
            score += 4.0
        elif token in secondary_text:
            score += 2.0
    return score + min(3.0, float(len(tokens)))


def _search_result_key(item: dict[str, Any]) -> str:
    kind = str(item.get("kind") or "other").strip().lower()
    if kind in {"job", "report"}:
        return f"{kind}:{item.get('job_id')}"
    if kind == "finding":
        fingerprint = item.get("metadata", {}).get("fingerprint") if isinstance(item.get("metadata"), dict) else None
        return f"{kind}:{item.get('job_id')}:{fingerprint or item.get('title')}"
    if kind == "asset":
        return f"{kind}:{item.get('asset_id')}"
    if kind == "schedule":
        return f"{kind}:{item.get('schedule_id')}"
    return f"{kind}:{item.get('title')}"


def _search_kind_rank(kind: str) -> int:
    order = {"finding": 0, "report": 1, "job": 2, "asset": 3, "schedule": 4}
    return order.get(str(kind or "").strip().lower(), 9)


def _search_summary(value: Any, *, max_length: int = 180) -> str | None:
    text = _normalize_search_text(value)
    if not text:
        return None
    if len(text) <= max_length:
        return text
    return text[: max_length - 1].rstrip() + "…"


def read_report_json(manager: JobManager, *, job_id: str, candidates: list[str]) -> dict[str, Any]:
    job_record: dict[str, Any] | None = None
    if hasattr(manager, "get_job"):
        try:
            job_record = manager.get_job(job_id)
        except KeyError:
            job_record = None
    if job_record is None:
        for item in _collect_search_jobs(manager):
            if str(item.get("job_id") or "").strip() == str(job_id).strip():
                job_record = item
                break
    for candidate in candidates:
        path: Path | None = None
        try:
            path = manager.resolve_file(job_id, candidate)
        except (KeyError, FileNotFoundError, PermissionError):
            output_dir = Path(str(job_record.get("output_dir") or "")).resolve() if isinstance(job_record, dict) and job_record.get("output_dir") else None
            if output_dir is None:
                continue
            fallback = (output_dir / candidate).resolve()
            if not fallback.is_relative_to(output_dir) or not fallback.is_file():
                continue
            path = fallback
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
            "<article class='card'>"
            f"<h3>{tool}</h3>"
            "<div class='detail-meta'>"
            f"<span class='meta-tag'>Target {target}</span>"
            f"<span class='meta-tag'>Component {component}</span>"
            f"<span class='meta-tag'>Service {service}</span>"
            f"<span class='meta-tag'>Version {version}</span>"
            "</div>"
            f"<p class='section-summary'><strong>Selected:</strong> {selected_candidate} | <strong>Templates:</strong> {template_text}</p>"
            "<div class='table-wrap'><table>"
            "<thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Template</th><th>Count</th><th>Status</th><th>Why ranked first</th></tr></thead>"
            f"<tbody>{table_rows}</tbody>"
            "</table></div>"
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
            "<div class='subcard'>"
            f"<div><strong>{html_escape(str(entry.get('display_name') or entry.get('id') or '-'))}</strong></div>"
            f"<div class='subcard-meta'>{html_escape(meta or '-')}</div>"
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
            "<article class='card timeline-card'>"
            f"<span class='timeline-index'>{index}</span>"
            f"<h3>{index}. {html_escape(str(row.get('tool') or '-'))}</h3>"
            "<div class='detail-meta'>"
            f"<span class='meta-tag'>Target {html_escape(str(row.get('target') or '-'))}</span>"
            f"<span class='meta-tag'>Phase {html_escape(str(row.get('phase') or '-'))}</span>"
            f"<span class='meta-tag'>Status {html_escape(str(row.get('status') or '-'))}</span>"
            f"<span class='meta-tag'>Selected {html_escape(str(explanation.get('selected_candidate') or '-'))}</span>"
            "</div>"
            f"<p class='section-summary'><strong>Candidate Order:</strong> {candidate_text}</p>"
            f"<p class='section-summary'><strong>Selected Templates:</strong> {template_text}</p>"
            "<div><strong>Why Executed:</strong><ul class='reason-list'>"
            f"{reason_text}"
            "</ul></div>"
            f"{error_html}"
            "</article>"
        )
    return "".join(output) or "<p>No execution history recorded for this run.</p>"


def _contains_cjk_text(value: Any) -> bool:
    if isinstance(value, str):
        return any(
            0x3400 <= ord(char) <= 0x9FFF or 0xF900 <= ord(char) <= 0xFAFF
            for char in value
        )
    if isinstance(value, dict):
        return any(_contains_cjk_text(key) or _contains_cjk_text(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_cjk_text(item) for item in value)
    return False


def _detect_generated_report_lang(*, item: dict[str, Any], analysis: dict[str, Any]) -> str:
    sample = {
        "target": item.get("target"),
        "decision_summary": item.get("decision_summary"),
        "findings": analysis.get("findings", [])[:10] if isinstance(analysis.get("findings", []), list) else [],
        "attack_surface": analysis.get("attack_surface", {}) if isinstance(analysis.get("attack_surface", {}), dict) else {},
    }
    return "zh-CN" if _contains_cjk_text(sample) else "en"


def _render_html_value(value: Any) -> str:
    text = str(value or "").strip() or "-"
    escaped = html_escape(text)
    display = _render_wrapped_html_text(text)
    if text.startswith(("http://", "https://")):
        return f"<a class='url-text' href='{escaped}' title='{escaped}' dir='ltr'>{display}</a>"
    return f"<span class='url-text' title='{escaped}' dir='auto'>{display}</span>"


def _render_wrapped_html_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return html_escape("-")
    parts = re.split(r"([/?#&=._:%-]+)", text)
    rendered: list[str] = []
    for part in parts:
        if not part:
            continue
        rendered.append(html_escape(part))
        if re.fullmatch(r"[/?#&=._:%-]+", part):
            rendered.append("<wbr>")
    return "".join(rendered)


def _render_report_metric_card(
    label: str,
    value: Any,
    *,
    detail: str | None = None,
    tone: str = "neutral",
) -> str:
    normalized_tone = str(tone or "neutral").strip().lower()
    if normalized_tone not in {"critical", "high", "medium", "low", "info", "neutral"}:
        normalized_tone = "neutral"
    detail_html = f"<p class='metric-detail'>{html_escape(str(detail))}</p>" if detail else ""
    return (
        f"<div class='metric-card metric-card-{html_escape(normalized_tone)}'>"
        f"<p class='metric-label'>{html_escape(label)}</p>"
        f"<p class='metric-value'>{html_escape(str(value if value not in (None, '') else '-'))}</p>"
        f"{detail_html}"
        "</div>"
    )


def _render_report_fact(label: str, value: Any) -> str:
    return (
        "<div class='fact-row'>"
        f"<span class='fact-label'>{html_escape(label)}</span>"
        f"<span class='fact-value'>{html_escape(str(value if value not in (None, '') else '-'))}</span>"
        "</div>"
    )


def _render_report_nav_link(anchor: str, title: str, meta: str) -> str:
    return (
        f"<a class='toc-link' href='#{html_escape(anchor)}'>"
        f"<strong>{html_escape(title)}</strong>"
        f"<small>{html_escape(meta)}</small>"
        "</a>"
    )


def render_generated_report_html(*, item: dict[str, Any], analysis: dict[str, Any]) -> str:
    diff = analysis.get("diff", {}) if isinstance(analysis, dict) else {}
    history = analysis.get("history", []) if isinstance(analysis, dict) else []
    execution_history = analysis.get("execution_history", []) if isinstance(analysis, dict) else []
    findings = analysis.get("findings", []) if isinstance(analysis, dict) else []
    verification_ranking = analysis.get("verification_ranking", []) if isinstance(analysis, dict) else []
    asset_phase_trends = analysis.get("asset_phase_trends", []) if isinstance(analysis, dict) else []
    asset_batch_trends = analysis.get("asset_batch_trends", []) if isinstance(analysis, dict) else []
    infrastructure = analysis.get("infrastructure", {}) if isinstance(analysis, dict) else {}
    risk_matrix = analysis.get("risk_matrix", {}) if isinstance(analysis, dict) else {}
    attack_surface = analysis.get("attack_surface", {}) if isinstance(analysis, dict) else {}
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
    infrastructure_html = _render_infrastructure_html(infrastructure if isinstance(infrastructure, dict) else {})
    risk_matrix_html = _render_risk_matrix_html(risk_matrix if isinstance(risk_matrix, dict) else {})
    attack_surface_html = _render_attack_surface_html(attack_surface if isinstance(attack_surface, dict) else {})
    html_lang = _detect_generated_report_lang(item=item, analysis=analysis)
    asset_summary = analysis.get("asset_summary", {}) if isinstance(analysis.get("asset_summary", {}), dict) else {}
    total_assets = int(asset_summary.get("total_assets", 0) or 0)
    service_assets = int(asset_summary.get("service_assets", 0) or 0)
    baseline_job_id = str(analysis.get("baseline_job_id") or "None").strip() or "None"
    session_status = str(analysis.get("session_status") or item.get("status") or "-").strip() or "-"
    decision_summary = str(item.get("decision_summary") or "").strip()
    ports = infrastructure.get("ports", []) if isinstance(infrastructure.get("ports", []), list) else []
    tech_stack = infrastructure.get("tech_stack", []) if isinstance(infrastructure.get("tech_stack", []), list) else []
    risk_categories = risk_matrix.get("categories", []) if isinstance(risk_matrix.get("categories", []), list) else []
    risk_score = int(risk_matrix.get("total_score", 0) or 0)
    entry_points = attack_surface.get("entry_points", []) if isinstance(attack_surface.get("entry_points", []), list) else []
    sensitive_paths = attack_surface.get("sensitive_paths", []) if isinstance(attack_surface.get("sensitive_paths", []), list) else []
    report_nav = "".join(
        (
            _render_report_nav_link(
                "baseline-diff",
                "Baseline Diff",
                f"{int(diff.get('new_count', 0) or 0)} new · {int(diff.get('resolved_count', 0) or 0)} resolved",
            ),
            _render_report_nav_link("infrastructure", "Infrastructure", f"{len(ports)} ports · {len(tech_stack)} tech hints"),
            _render_report_nav_link("risk-matrix", "Risk Matrix", f"score {risk_score} · {len(risk_categories)} categories"),
            _render_report_nav_link("attack-surface", "Attack Surface", f"{len(entry_points)} entry points · {len(sensitive_paths)} paths"),
            _render_report_nav_link("history", "History", f"{len(history)} related runs"),
            _render_report_nav_link("execution-history", "Execution", f"{len(execution_history)} action records"),
            _render_report_nav_link("verification-ranking", "Verification", f"{len(verification_ranking)} ranking blocks"),
            _render_report_nav_link("asset-trends-phase", "Phase Trends", f"{len(asset_phase_trends)} phases"),
            _render_report_nav_link("asset-trends-batch", "Batch Trends", f"{len(asset_batch_trends)} batches"),
            _render_report_nav_link("findings", "Findings", f"{len(findings)} total findings"),
        )
    )
    overview_facts = "".join(
        (
            _render_report_fact("Session Status", session_status),
            _render_report_fact("Baseline Job", baseline_job_id),
            _render_report_fact("History Count", len(history)),
            _render_report_fact("Execution Steps", len(execution_history)),
            _render_report_fact("Total Assets", total_assets),
            _render_report_fact("Service Assets", service_assets),
        )
    )
    hero_metrics = "".join(
        (
            _render_report_metric_card(
                "Total Findings",
                int(item.get("finding_total", 0) or 0),
                detail="All findings in this exported run",
                tone="critical" if int(item.get("finding_total", 0) or 0) else "neutral",
            ),
            _render_report_metric_card(
                "New vs Baseline",
                int(diff.get("new_count", 0) or 0),
                detail=f"Compared with {baseline_job_id}",
                tone="high" if int(diff.get("new_count", 0) or 0) else "neutral",
            ),
            _render_report_metric_card(
                "Resolved vs Baseline",
                int(diff.get("resolved_count", 0) or 0),
                detail="Items no longer present in the latest run",
                tone="low" if int(diff.get("resolved_count", 0) or 0) else "neutral",
            ),
            _render_report_metric_card(
                "Persistent vs Baseline",
                int(diff.get("persistent_count", 0) or 0),
                detail="Findings that remain across runs",
                tone="medium" if int(diff.get("persistent_count", 0) or 0) else "neutral",
            ),
            _render_report_metric_card(
                "Total Assets",
                total_assets,
                detail=f"{service_assets} service assets",
                tone="info" if total_assets else "neutral",
            ),
            _render_report_metric_card(
                "Execution Steps",
                len(execution_history),
                detail=f"{len(verification_ranking)} verification ranking blocks",
                tone="neutral",
            ),
        )
    )
    diff_metrics = "".join(
        (
            _render_report_metric_card("New Assets", int(diff.get("new_assets_count", 0) or 0), tone="high"),
            _render_report_metric_card("Resolved Assets", int(diff.get("resolved_assets_count", 0) or 0), tone="low"),
            _render_report_metric_card("New Services", int(diff.get("new_services_count", 0) or 0), tone="high"),
            _render_report_metric_card("Resolved Services", int(diff.get("resolved_services_count", 0) or 0), tone="low"),
        )
    )
    lede = decision_summary or "Grouped export with readable sections, sticky navigation, and full-width URL wrapping."
    return f"""<!doctype html>
<html lang="{html_lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html_escape(str(item.get("target") or item.get("job_id") or "AutoSecAudit Report"))}</title>
  <style>
    * {{ box-sizing: border-box; }}
    html {{ -webkit-text-size-adjust: 100%; }}
    body {{
      font-family: "Noto Sans SC", "Noto Sans CJK SC", "Source Han Sans SC", "Microsoft YaHei UI",
        "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", "Heiti SC", "SimHei", "Segoe UI",
        system-ui, sans-serif;
      margin: 0;
      color: #1d2b27;
      background: #f4efe6;
      line-height: 1.6;
      text-rendering: optimizeLegibility;
      font-synthesis-weight: none;
      overflow-wrap: anywhere;
    }}
    html[lang="zh-CN"] body {{
      font-family: "Noto Sans SC", "Noto Sans CJK SC", "Source Han Sans SC", "Microsoft YaHei UI",
        "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", "Heiti SC", "SimHei", system-ui, sans-serif;
    }}
    .page {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
    .hero {{ background: #fffaf4; border: 1px solid rgba(29,43,39,0.12); border-radius: 24px; padding: 24px; overflow-wrap: anywhere; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-top: 18px; }}
    .card {{ background: white; border-radius: 18px; padding: 16px; border: 1px solid rgba(29,43,39,0.1); overflow-wrap: anywhere; }}
    .section {{ margin-top: 18px; background: white; border-radius: 24px; padding: 20px; border: 1px solid rgba(29,43,39,0.1); overflow-wrap: anywhere; }}
    .chip {{ display: inline-block; padding: 7px 11px; border-radius: 999px; margin-right: 8px; margin-top: 8px; font-size: 12px; font-weight: 700; }}
    .chip-critical {{ background: rgba(185,28,28,0.12); color: #b91c1c; }}
    .chip-high {{ background: rgba(217,119,6,0.14); color: #b45309; }}
    .chip-medium {{ background: rgba(202,138,4,0.14); color: #a16207; }}
    .chip-low {{ background: rgba(14,116,144,0.13); color: #0e7490; }}
    .chip-info {{ background: rgba(15,118,110,0.13); color: #0f766e; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: auto; }}
    td, th {{ border-bottom: 1px solid rgba(29,43,39,0.08); padding: 10px 6px; text-align: left; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      overflow-wrap: anywhere;
      background: #15211f;
      color: #e7fff4;
      padding: 12px;
      border-radius: 14px;
      font-family: "Cascadia Mono", "Noto Sans Mono CJK SC", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    }}
    p, li, td, th, strong, span, a {{ overflow-wrap: anywhere; }}
    .url-text {{
      display: block;
      width: 100%;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
      color: inherit;
      text-decoration: none;
      line-height: 1.7;
      unicode-bidi: plaintext;
    }}
    .url-text:hover {{ text-decoration: underline; }}
    :root {{
      color-scheme: light;
      --bg: #efe7dc;
      --panel-strong: #fffdfa;
      --line: rgba(55, 74, 69, 0.12);
      --text: #20332e;
      --muted: #5a6d67;
      --shadow: 0 18px 38px rgba(38, 54, 48, 0.08);
      --accent: #2f6f62;
      --accent-soft: rgba(47, 111, 98, 0.12);
      --critical: #b91c1c;
      --high: #b45309;
      --medium: #a16207;
      --low: #0e7490;
      --info: #0f766e;
    }}
    body {{
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(255,255,255,0.9), transparent 28%),
        linear-gradient(180deg, #f8f2e8 0%, var(--bg) 100%);
    }}
    a {{ color: var(--accent); text-decoration-thickness: 1px; text-underline-offset: 2px; }}
    .page {{ max-width: 1480px; padding: 28px; }}
    .hero {{
      background: linear-gradient(180deg, rgba(255, 251, 245, 0.96), rgba(255, 255, 255, 0.9));
      border-color: var(--line);
      border-radius: 28px;
      padding: 28px;
      box-shadow: var(--shadow);
    }}
    .hero-shell {{
      display: grid;
      grid-template-columns: minmax(0, 1.7fr) minmax(280px, 0.95fr);
      gap: 24px;
      align-items: start;
    }}
    .eyebrow, .panel-title, .section-kicker, .metric-label, .fact-label, thead th {{
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 700;
    }}
    .hero h1 {{ margin-bottom: 0; font-size: clamp(28px, 4vw, 42px); line-height: 1.15; }}
    .lede {{ margin: 12px 0 0; max-width: 72ch; color: var(--muted); font-size: 15px; }}
    .meta-row, .chip-row, .detail-meta, .finding-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}
    .meta-row, .chip-row {{ margin-top: 18px; }}
    .meta-pill, .meta-tag, .section-badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.88);
      color: var(--muted);
      font-size: 13px;
    }}
    .hero-panel, .toc-panel, .section, .card, .metric-card {{
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 22px;
      box-shadow: 0 10px 28px rgba(30, 45, 40, 0.04);
    }}
    .hero-panel, .toc-panel, .section, .card, .metric-card {{ overflow-wrap: anywhere; }}
    .hero-panel {{ padding: 18px; background: rgba(255, 255, 255, 0.72); }}
    .panel-title {{ margin: 0; }}
    .fact-grid {{ display: grid; gap: 10px; margin-top: 14px; }}
    .fact-row {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 16px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--line);
    }}
    .fact-row:last-child {{ border-bottom: 0; padding-bottom: 0; }}
    .fact-value {{ font-size: 14px; font-weight: 600; text-align: right; color: var(--text); }}
    .metric-grid, .card-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }}
    .metric-grid {{ margin-top: 20px; }}
    .card-grid.two-up {{ grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }}
    .card-grid.three-up {{ grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }}
    .space-top {{ margin-top: 18px; }}
    .metric-card {{ padding: 18px; position: relative; }}
    .metric-card::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 4px;
      background: rgba(55, 74, 69, 0.16);
    }}
    .metric-card-critical::before {{ background: rgba(185, 28, 28, 0.72); }}
    .metric-card-high::before {{ background: rgba(180, 83, 9, 0.72); }}
    .metric-card-medium::before {{ background: rgba(161, 98, 7, 0.72); }}
    .metric-card-low::before {{ background: rgba(14, 116, 144, 0.72); }}
    .metric-card-info::before {{ background: rgba(15, 118, 110, 0.72); }}
    .metric-label {{ margin: 0; }}
    .metric-value {{ margin: 10px 0 0; font-size: clamp(28px, 3.2vw, 38px); line-height: 1.1; font-weight: 800; }}
    .metric-detail, .section-summary, .muted {{ color: var(--muted); }}
    .metric-detail, .section-summary {{ margin: 8px 0 0; font-size: 14px; }}
    .report-layout {{
      display: grid;
      grid-template-columns: minmax(250px, 290px) minmax(0, 1fr);
      gap: 20px;
      margin-top: 22px;
      align-items: start;
    }}
    .toc-panel {{ position: sticky; top: 20px; padding: 18px; background: rgba(255, 251, 245, 0.9); }}
    .toc-links {{ display: grid; gap: 10px; margin-top: 14px; }}
    .toc-link {{
      display: block;
      padding: 12px 14px;
      border-radius: 16px;
      border: 1px solid rgba(55, 74, 69, 0.08);
      background: rgba(255, 255, 255, 0.82);
      text-decoration: none;
      color: inherit;
    }}
    .toc-link strong {{ display: block; font-size: 14px; color: var(--text); }}
    .toc-link small {{ display: block; margin-top: 4px; font-size: 12px; color: var(--muted); }}
    .toc-note {{
      margin-top: 16px;
      padding: 12px 14px;
      border-radius: 16px;
      background: var(--accent-soft);
      color: var(--muted);
      font-size: 13px;
    }}
    .report-main {{ display: grid; gap: 18px; }}
    .section {{ padding: 24px; }}
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .section h2, .card h3 {{ margin: 0; line-height: 1.25; }}
    .section h2 {{ font-size: clamp(22px, 3vw, 28px); }}
    .card {{ padding: 18px; }}
    .subcard {{
      margin-top: 10px;
      padding: 12px 14px;
      border-radius: 16px;
      border: 1px solid rgba(55, 74, 69, 0.08);
      background: rgba(250, 250, 248, 0.92);
    }}
    .subcard-meta {{ margin-top: 6px; font-size: 12px; color: var(--muted); }}
    .table-wrap {{
      width: 100%;
      overflow-x: auto;
      border: 1px solid rgba(55, 74, 69, 0.08);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.76);
    }}
    table {{ min-width: 100%; }}
    thead th {{
      position: sticky;
      top: 0;
      background: rgba(250, 248, 244, 0.96);
      z-index: 1;
    }}
    tbody tr:nth-child(even) {{ background: rgba(245, 241, 235, 0.5); }}
    td, th {{ padding: 12px; }}
    .finding-card {{ border-left: 4px solid rgba(55, 74, 69, 0.14); }}
    .finding-card.severity-critical {{ border-left-color: rgba(185, 28, 28, 0.72); }}
    .finding-card.severity-high {{ border-left-color: rgba(180, 83, 9, 0.72); }}
    .finding-card.severity-medium {{ border-left-color: rgba(161, 98, 7, 0.72); }}
    .finding-card.severity-low {{ border-left-color: rgba(14, 116, 144, 0.72); }}
    .finding-card.severity-info {{ border-left-color: rgba(15, 118, 110, 0.72); }}
    .severity-badge {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 90px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .severity-critical .severity-badge {{ background: rgba(185, 28, 28, 0.12); color: var(--critical); }}
    .severity-high .severity-badge {{ background: rgba(180, 83, 9, 0.12); color: var(--high); }}
    .severity-medium .severity-badge {{ background: rgba(161, 98, 7, 0.12); color: var(--medium); }}
    .severity-low .severity-badge {{ background: rgba(14, 116, 144, 0.12); color: var(--low); }}
    .severity-info .severity-badge {{ background: rgba(15, 118, 110, 0.12); color: var(--info); }}
    .timeline-card {{ position: relative; padding-left: 64px; }}
    .timeline-index {{
      position: absolute;
      left: 18px;
      top: 18px;
      width: 32px;
      height: 32px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 800;
    }}
    .reason-list {{ margin: 8px 0 0; padding-left: 18px; color: var(--muted); }}
    .stack-sm > * + * {{ margin-top: 12px; }}
    h1, h2, h3, p {{ margin-top: 0; }}
    @media (max-width: 900px) {{
      .page {{ padding: 16px; }}
      .grid,
      .hero-shell,
      .report-layout {{ grid-template-columns: 1fr; }}
      .hero,
      .section {{ padding: 20px; }}
      .toc-panel {{ position: static; order: -1; }}
      .timeline-card {{ padding-left: 18px; }}
      .timeline-index {{ position: static; margin-bottom: 10px; }}
    }}
  </style>
</head>
<body>
  <div class="page" id="top">
    <section class="hero">
      <div class="hero-shell">
        <div>
          <p class="eyebrow">AutoSecAudit Report Export</p>
          <h1>{html_escape(str(item.get("target") or item.get("job_id") or "Report"))}</h1>
          <p class="lede">{html_escape(lede)}</p>
          <div class="meta-row">
            <span class="meta-pill">Job {html_escape(str(item.get("job_id") or '-'))}</span>
            <span class="meta-pill">Status {html_escape(str(item.get("status") or '-'))}</span>
            <span class="meta-pill">Updated {html_escape(str(item.get("updated_at") or '-'))}</span>
            <span class="meta-pill">Baseline {html_escape(baseline_job_id)}</span>
          </div>
          <div class="chip-row">{chips}</div>
        </div>
        <aside class="hero-panel">
          <p class="panel-title">Report Overview</p>
          <div class="fact-grid">{overview_facts}</div>
        </aside>
      </div>
      <div class="metric-grid">{hero_metrics}</div>
    </section>
    <div class="report-layout">
      <aside class="toc-panel report-nav">
        <p class="panel-title">Jump to Sections</p>
        <nav class="toc-links">{report_nav}</nav>
        <div class="toc-note">This export keeps long URLs fully visible, wraps wide text, and groups dense data into smaller reading blocks.</div>
      </aside>
      <main class="report-main">
        <section class="section" id="baseline-diff">
          <div class="section-header">
            <div>
              <p class="section-kicker">Compare Runs</p>
              <h2>Baseline Asset / Service Diff</h2>
              <p class="section-summary">Asset and service deltas compared with baseline job {html_escape(baseline_job_id)}.</p>
            </div>
            <span class="section-badge">Baseline {html_escape(baseline_job_id)}</span>
          </div>
          <div class="metric-grid">{diff_metrics}</div>
          <div class="card-grid two-up space-top">{new_asset_cards}{resolved_asset_cards}{new_service_cards}{resolved_service_cards}</div>
          <div class="card-grid two-up space-top">{new_asset_severity_cards}{resolved_asset_severity_cards}{persistent_asset_severity_cards}{new_service_protocol_cards}{resolved_service_protocol_cards}{persistent_service_protocol_cards}</div>
        </section>
        <section class="section" id="infrastructure">
          <div class="section-header">
            <div>
              <p class="section-kicker">Surface Snapshot</p>
              <h2>Infrastructure Summary</h2>
              <p class="section-summary">Ports, middleware, technology hints, certificates, and DNS records detected for this run.</p>
            </div>
            <span class="section-badge">{len(ports)} ports</span>
          </div>
          {infrastructure_html}
        </section>
        <section class="section" id="risk-matrix">
          <div class="section-header">
            <div>
              <p class="section-kicker">Scoring</p>
              <h2>Risk Matrix</h2>
              <p class="section-summary">High-level risk breakdown by category with severity distribution.</p>
            </div>
            <span class="section-badge">Score {risk_score}</span>
          </div>
          {risk_matrix_html}
        </section>
        <section class="section" id="attack-surface">
          <div class="section-header">
            <div>
              <p class="section-kicker">Exposure View</p>
              <h2>Attack Surface</h2>
              <p class="section-summary">Entry points, exposed services, and sensitive URLs or paths observed in the scan output.</p>
            </div>
            <span class="section-badge">{len(entry_points)} entry points</span>
          </div>
          {attack_surface_html}
        </section>
        <section class="section" id="history">
          <div class="section-header">
            <div>
              <p class="section-kicker">Timeline</p>
              <h2>History</h2>
              <p class="section-summary">Related report runs for the same target, ordered by completion time.</p>
            </div>
            <span class="section-badge">{len(history)} runs</span>
          </div>
          <div class="table-wrap"><table><thead><tr><th>Job</th><th>Completed</th><th>Status</th><th>Findings</th></tr></thead><tbody>{history_rows}</tbody></table></div>
        </section>
        <section class="section" id="execution-history">
          <div class="section-header">
            <div>
              <p class="section-kicker">Agent Flow</p>
              <h2>Execution History</h2>
              <p class="section-summary">Why each tool or candidate was selected, with ranked candidates and templates when available.</p>
            </div>
            <span class="section-badge">{len(execution_history)} actions</span>
          </div>
          <div class="stack-sm">{execution_history_html}</div>
        </section>
        <section class="section" id="verification-ranking">
          <div class="section-header">
            <div>
              <p class="section-kicker">Validation Context</p>
              <h2>Verification Ranking</h2>
              <p class="section-summary">Ranked CVE candidates, template coverage, and verification outcomes associated with the run.</p>
            </div>
            <span class="section-badge">{len(verification_ranking)} blocks</span>
          </div>
          <div class="stack-sm">{verification_html}</div>
        </section>
        <section class="section" id="asset-trends-phase">
          <div class="section-header">
            <div>
              <p class="section-kicker">Trend Analysis</p>
              <h2>Asset Trends by Phase</h2>
              <p class="section-summary">How the asset graph and finding count changed as the scan progressed through phases.</p>
            </div>
            <span class="section-badge">{len(asset_phase_trends)} phases</span>
          </div>
          <div class="table-wrap"><table><thead><tr><th>Phase</th><th>Actions</th><th>Tools</th><th>Assets</th><th>Services</th><th>Findings</th><th>Delta Assets</th><th>Reason</th></tr></thead><tbody>{phase_rows}</tbody></table></div>
        </section>
        <section class="section" id="asset-trends-batch">
          <div class="section-header">
            <div>
              <p class="section-kicker">Run Comparison</p>
              <h2>Asset Trends by Run Batch</h2>
              <p class="section-summary">Cross-run asset and finding changes for the same target across historical batches.</p>
            </div>
            <span class="section-badge">{len(asset_batch_trends)} batches</span>
          </div>
          <div class="table-wrap"><table><thead><tr><th>Job</th><th>Completed</th><th>Assets</th><th>Services</th><th>Findings</th><th>Delta Assets</th><th>Delta Findings</th></tr></thead><tbody>{batch_rows}</tbody></table></div>
        </section>
        <section class="section" id="findings">
          <div class="section-header">
            <div>
              <p class="section-kicker">Detailed Output</p>
              <h2>Findings</h2>
              <p class="section-summary">Each finding now uses clearer severity markers, grouped metadata, and isolated evidence blocks.</p>
            </div>
            <span class="section-badge">{len(findings)} findings</span>
          </div>
          <div class="stack-sm">{finding_cards}</div>
        </section>
      </main>
    </div>
  </div>
</body>
</html>"""


def render_finding_html(item: dict[str, Any]) -> str:
    description = html_escape(str(item.get("description") or ""))
    recommendation = html_escape(str(item.get("recommendation") or ""))
    severity = normalize_severity(item.get("severity"))
    plugin_label = str(item.get("plugin_name") or item.get("plugin_id") or "-").strip() or "-"
    return (
        f"<article class='card finding-card severity-{html_escape(severity)}'>"
        f"<h3>{html_escape(str(item.get('title') or 'Untitled finding'))}</h3>"
        "<div class='finding-meta'>"
        f"<span class='severity-badge'>{html_escape(severity.upper())}</span>"
        f"<span class='meta-tag'>Source {html_escape(plugin_label)}</span>"
        "</div>"
        "<div class='finding-body'>"
        f"{f'<p>{description}</p>' if description else ''}"
        f"{f'<p><strong>Recommendation:</strong> {recommendation}</p>' if recommendation else ''}"
        "</div>"
        f"<pre>{html_escape(str(item.get('evidence_text') or '{}'))}</pre>"
        "</article>"
    )


def _render_infrastructure_html(infrastructure: dict[str, Any]) -> str:
    ports = infrastructure.get("ports", []) if isinstance(infrastructure.get("ports", []), list) else []
    middleware = infrastructure.get("middleware", []) if isinstance(infrastructure.get("middleware", []), list) else []
    tech_stack = infrastructure.get("tech_stack", []) if isinstance(infrastructure.get("tech_stack", []), list) else []
    waf = infrastructure.get("waf", {}) if isinstance(infrastructure.get("waf", {}), dict) else {}
    certificates = infrastructure.get("certificates", []) if isinstance(infrastructure.get("certificates", []), list) else []
    dns = infrastructure.get("dns", {}) if isinstance(infrastructure.get("dns", {}), dict) else {}
    dns_records = dns.get("records", {}) if isinstance(dns.get("records", {}), dict) else {}

    port_rows = "".join(
        "<tr>"
        f"<td>{html_escape(str(item.get('host') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('port') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('protocol') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('service') or '-'))}</td>"
        f"<td>{'yes' if item.get('tls') else 'no'}</td>"
        "</tr>"
        for item in ports[:20]
        if isinstance(item, dict)
    ) or "<tr><td colspan='5'>No exposed ports summarized.</td></tr>"
    middleware_chips = "".join(
        f"<span class='chip chip-info'>{html_escape(str(item.get('name') or '-'))} · {html_escape(str(item.get('source') or '-'))}</span>"
        for item in middleware[:12]
        if isinstance(item, dict)
    ) or "<p>No middleware fingerprint available.</p>"
    tech_chips = "".join(
        f"<span class='chip chip-low'>{html_escape(str(item))}</span>"
        for item in tech_stack[:16]
        if str(item).strip()
    ) or "<p>No technology hints recorded.</p>"
    cert_cards = "".join(
        "<div class='card'>"
        f"<strong>{html_escape(str(item.get('host') or '-'))}:{html_escape(str(item.get('port') or 443))}</strong>"
        f"<p>TLS {html_escape(str(item.get('tls_version') or '-'))} · expires {html_escape(str(item.get('expires_at') or '-'))}</p>"
        "</div>"
        for item in certificates[:4]
        if isinstance(item, dict)
    ) or "<p>No certificate metadata recorded.</p>"
    dns_rows = "".join(
        "<tr>"
        f"<td>{html_escape(str(rtype))}</td>"
        f"<td>{html_escape(', '.join(str(value) for value in records[:8]))}</td>"
        "</tr>"
        for rtype, records in dns_records.items()
        if isinstance(records, list)
    ) or "<tr><td colspan='2'>No DNS records recorded.</td></tr>"
    waf_vendors = waf.get("vendors", []) if isinstance(waf.get("vendors", []), list) else []
    waf_html = "".join(f"<span class='chip chip-medium'>{html_escape(str(item))}</span>" for item in waf_vendors[:8]) or "<span>None</span>"
    return (
        "<div class='card-grid two-up'>"
        "<div class='card'><h3>Open Ports</h3>"
        "<div class='table-wrap'><table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>TLS</th></tr></thead>"
        f"<tbody>{port_rows}</tbody></table></div></div>"
        f"<div class='card'><h3>Middleware</h3><div>{middleware_chips}</div><div class='detail-meta'><span class='meta-tag'>WAF {waf_html}</span><span class='meta-tag'>Detected {'yes' if waf.get('detected') else 'no'}</span></div></div>"
        f"<div class='card'><h3>Technology Stack</h3><div class='chip-row'>{tech_chips}</div></div>"
        f"<div class='card'><h3>Certificates</h3><div class='stack-sm'>{cert_cards}</div></div>"
        "<div class='card'><h3>DNS</h3>"
        "<div class='table-wrap'><table><thead><tr><th>Type</th><th>Values</th></tr></thead>"
        f"<tbody>{dns_rows}</tbody></table></div></div>"
        "</div>"
    )


def _render_risk_matrix_html(risk_matrix: dict[str, Any]) -> str:
    categories = risk_matrix.get("categories", []) if isinstance(risk_matrix.get("categories", []), list) else []
    total_score = int(risk_matrix.get("total_score", 0) or 0)
    rows = "".join(
        "<tr>"
        f"<td>{html_escape(str(item.get('name') or '-'))}</td>"
        f"<td>{int(item.get('score', 0) or 0)}</td>"
        f"<td>{int(item.get('finding_count', 0) or 0)}</td>"
        f"<td>{html_escape(json.dumps(item.get('severity_counts', {}), ensure_ascii=False))}</td>"
        "</tr>"
        for item in categories
        if isinstance(item, dict)
    ) or "<tr><td colspan='4'>No categorized risk findings.</td></tr>"
    return (
        "<div class='card-grid two-up'>"
        f"{_render_report_metric_card('Total Risk Score', total_score, detail='Aggregate score across categories', tone='medium' if total_score else 'neutral')}"
        f"<div class='card'><h3>Category Breakdown</h3><div class='table-wrap'><table><thead><tr><th>Category</th><th>Score</th><th>Findings</th><th>Severity Mix</th></tr></thead><tbody>{rows}</tbody></table></div></div>"
        "</div>"
    )


def _render_attack_surface_html(attack_surface: dict[str, Any]) -> str:
    entry_points = attack_surface.get("entry_points", []) if isinstance(attack_surface.get("entry_points", []), list) else []
    exposed_services = attack_surface.get("exposed_services", []) if isinstance(attack_surface.get("exposed_services", []), list) else []
    sensitive_paths = attack_surface.get("sensitive_paths", []) if isinstance(attack_surface.get("sensitive_paths", []), list) else []
    entry_rows = "".join(
        "<tr>"
        f"<td>{html_escape(str(item.get('type') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('method') or '-'))}</td>"
        f"<td>{_render_html_value(item.get('url'))}</td>"
        "</tr>"
        for item in entry_points[:20]
        if isinstance(item, dict)
    ) or "<tr><td colspan='3'>No entry points summarized.</td></tr>"
    service_rows = "".join(
        "<tr>"
        f"<td>{html_escape(str(item.get('host') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('port') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('service') or '-'))}</td>"
        f"<td>{html_escape(str(item.get('protocol') or '-'))}</td>"
        "</tr>"
        for item in exposed_services[:20]
        if isinstance(item, dict)
    ) or "<tr><td colspan='4'>No exposed services summarized.</td></tr>"
    path_rows = "".join(
        "<tr>"
        f"<td>{html_escape(str(item.get('type') or '-'))}</td>"
        f"<td>{_render_html_value(item.get('path'))}</td>"
        f"<td>{_render_html_value(item.get('url'))}</td>"
        "</tr>"
        for item in sensitive_paths[:20]
        if isinstance(item, dict)
    ) or "<tr><td colspan='3'>No sensitive paths summarized.</td></tr>"
    return (
        "<div class='card-grid three-up'>"
        "<div class='card'><h3>Entry Points</h3>"
        "<div class='table-wrap'><table><thead><tr><th>Type</th><th>Method</th><th>URL</th></tr></thead>"
        f"<tbody>{entry_rows}</tbody></table></div></div>"
        "<div class='card'><h3>Exposed Services</h3>"
        "<div class='table-wrap'><table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Proto</th></tr></thead>"
        f"<tbody>{service_rows}</tbody></table></div></div>"
        "<div class='card'><h3>Sensitive Paths</h3>"
        "<div class='table-wrap'><table><thead><tr><th>Type</th><th>Path</th><th>URL</th></tr></thead>"
        f"<tbody>{path_rows}</tbody></table></div></div>"
        "</div>"
    )


def first_existing(paths: set[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in paths:
            return candidate
    return None
