"""System-readiness and environment status routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from autosecaudit.commands.doctor import run_doctor

from ..api_support import require_role
from ..auth import AuthPrincipal
from ..schemas import DoctorReportResponse


router = APIRouter(tags=["system"])
require_viewer = require_role("viewer")


@router.get("/system/doctor", response_model=DoctorReportResponse)
async def get_system_doctor(
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> DoctorReportResponse:
    """Return environment readiness checks for the current deployment."""
    del principal
    report = run_doctor(
        workspace=request.app.state.workspace,
        llm_config=None,
    )
    return DoctorReportResponse.model_validate(report)
