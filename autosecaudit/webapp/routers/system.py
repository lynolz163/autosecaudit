"""System-readiness and environment status routes."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, Query, Request

from autosecaudit.commands.doctor import run_doctor

from ..api_support import require_role
from ..auth import AuthPrincipal
from ..reporting import build_global_search_results
from ..schemas import DoctorReportResponse, GlobalSearchResponse


router = APIRouter(tags=["system"])
require_viewer = require_role("viewer")


@router.get("/system/doctor", response_model=DoctorReportResponse)
async def get_system_doctor(
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> DoctorReportResponse:
    """Return environment readiness checks for the current deployment."""
    del principal
    report = request.app.state.cache.get_or_compute(
        "system:doctor:v1",
        ttl_seconds=60.0,
        builder=lambda: run_doctor(
            workspace=request.app.state.workspace,
            llm_config=None,
        ),
    )
    return DoctorReportResponse.model_validate(report)


@router.get("/search/global", response_model=GlobalSearchResponse)
async def get_global_search(
    request: Request,
    q: str = Query("", min_length=0, max_length=120),
    limit: int = Query(10, ge=1, le=50),
    principal: AuthPrincipal = Depends(require_viewer),
) -> GlobalSearchResponse:
    del principal
    query = str(q or "").strip()
    if len(query) < 2:
        return GlobalSearchResponse(query=query, total=0, groups={}, items=[])
    digest = hashlib.sha1(f"{query}|{limit}".encode("utf-8")).hexdigest()[:16]
    payload = request.app.state.cache.get_or_compute(
        f"system:search:{digest}:v1",
        ttl_seconds=10.0,
        builder=lambda: build_global_search_results(request.app.state.manager, query=query, limit=limit),
    )
    return GlobalSearchResponse.model_validate(payload)
