"""CVE query and verification routes for the web console API."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from autosecaudit.agent_core.cve_service import CveServiceError, NvdCveService

from ..api_support import require_role
from ..auth import AuthPrincipal
from ..reporting import extract_report_findings, read_report_json
from ..schemas import (
    CveJobResultResponse,
    CveSearchResponse,
    CveVerifyRequest,
    CveVerifyResponse,
    CveSearchRequest,
)


router = APIRouter(tags=["cve"])
require_viewer = require_role("viewer")
require_operator = require_role("operator")


@router.post("/cve/search", response_model=CveSearchResponse)
async def cve_search(
    payload: CveSearchRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> CveSearchResponse:
    del request
    del principal
    service = NvdCveService()
    try:
        if payload.components:
            items = service.lookup_components(
                components=[str(item).strip() for item in payload.components if str(item).strip()],
                severity=payload.severity,
                max_results_per_component=int(payload.max_results),
            )
        else:
            items = service.search(
                keyword=payload.keyword,
                cpe_name=payload.cpe_name,
                severity=payload.severity,
                max_results=int(payload.max_results),
            )
    except CveServiceError as exc:
        raise HTTPException(status_code=502, detail=f"cve_search_failed:{exc}") from exc
    return CveSearchResponse(items=[item for item in items if isinstance(item, dict)])


@router.get("/cve/job/{job_id}", response_model=CveJobResultResponse)
async def cve_job(
    job_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> CveJobResultResponse:
    del principal
    manager = request.app.state.manager
    report_payload = read_report_json(
        manager,
        job_id=job_id,
        candidates=["agent/audit_report.json", "audit_report.json"],
    )
    findings = [
        item
        for item in extract_report_findings(report_payload)
        if str(item.get("cve_id", "")).strip()
    ]

    state_payload = _read_job_json(
        manager,
        job_id=job_id,
        candidates=["agent/agent_state.json"],
    )
    surface = state_payload.get("surface", {}) if isinstance(state_payload, dict) else {}
    if not isinstance(surface, dict):
        surface = {}

    candidates = surface.get("cve_lookup_results", [])
    if not isinstance(candidates, list):
        candidates = []
    verification = surface.get("cve_verification", [])
    if not isinstance(verification, list):
        verification = []

    return CveJobResultResponse(
        job_id=job_id,
        findings=findings,
        candidates=[item for item in candidates if isinstance(item, dict)],
        verification=[item for item in verification if isinstance(item, dict)],
    )


@router.post("/cve/verify", response_model=CveVerifyResponse, status_code=201)
async def cve_verify(
    payload: CveVerifyRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> CveVerifyResponse:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="authorization_confirmed_required")
    if payload.allow_high_risk and payload.safety_grade != "aggressive":
        raise HTTPException(status_code=400, detail="allow_high_risk_requires_aggressive_grade")

    cve_ids = [str(item).strip().upper() for item in payload.cve_ids if str(item).strip()]
    if not cve_ids and not payload.cve_candidates:
        raise HTTPException(status_code=400, detail="cve_ids_or_candidates_required")

    candidates: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in payload.cve_candidates:
        cve_id = str(item.cve_id).strip().upper()
        target = str(item.target or payload.target).strip()
        if not cve_id or not target:
            continue
        key = (cve_id, target)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        candidates.append(
            {
                "cve_id": cve_id,
                "target": target,
                "component": item.component,
                "version": item.version,
                "safe_only": bool(item.safe_only),
                "allow_high_risk": bool(item.allow_high_risk),
                "authorization_confirmed": bool(item.authorization_confirmed),
            }
        )

    for cve_id in cve_ids:
        key = (cve_id, str(payload.target).strip())
        if key in seen_keys:
            continue
        seen_keys.add(key)
        candidates.append(
            {
                "cve_id": cve_id,
                "target": str(payload.target).strip(),
                "safe_only": bool(payload.safe_only),
                "allow_high_risk": bool(payload.allow_high_risk),
                "authorization_confirmed": bool(payload.authorization_confirmed),
            }
        )

    if not candidates:
        raise HTTPException(status_code=400, detail="no_valid_cve_candidates")

    surface_payload = {
        "authorization_confirmed": bool(payload.authorization_confirmed),
        "cve_candidates": candidates,
    }
    submit_payload = {
        "target": str(payload.target).strip(),
        "mode": "agent",
        "safety_grade": payload.safety_grade,
        "budget": 60,
        "max_iterations": 1,
        "global_timeout": 900,
        "tools": ["cve_verify"],
        "skills": ["cve_verify"],
        "no_llm_hints": True,
        "surface": surface_payload,
    }
    try:
        job = request.app.state.manager.submit(submit_payload, actor=principal.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"cve_verify_submit_failed:{exc}") from exc
    return CveVerifyResponse(job=job)


def _read_job_json(manager: Any, *, job_id: str, candidates: list[str]) -> dict[str, Any]:
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
