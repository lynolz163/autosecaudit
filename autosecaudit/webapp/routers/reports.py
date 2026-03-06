"""Report routers for the web console API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from ..api_support import require_role
from ..auth import AuthPrincipal
from ..reporting import build_report_analysis, build_report_items, get_report_item_or_404, render_generated_report_html
from ..schemas import ReportAnalysisResponse, ReportItemResponse, ReportListResponse


router = APIRouter(tags=["reports"])
require_viewer = require_role("viewer")


@router.get("/reports", response_model=ReportListResponse)
async def list_reports(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> ReportListResponse:
    del principal
    return ReportListResponse(items=build_report_items(request.app.state.manager))


@router.get("/reports/{job_id}", response_model=ReportItemResponse)
async def get_report(job_id: str, request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> ReportItemResponse:
    del principal
    items = build_report_items(request.app.state.manager, only_job_id=job_id)
    if not items:
        raise HTTPException(status_code=404, detail="report_not_found")
    return ReportItemResponse(item=items[0])


@router.get("/reports/{job_id}/analysis", response_model=ReportAnalysisResponse)
async def get_report_analysis(
    job_id: str,
    request: Request,
    baseline_job_id: str | None = None,
    principal: AuthPrincipal = Depends(require_viewer),
) -> ReportAnalysisResponse:
    del principal
    item = get_report_item_or_404(request.app.state.manager, job_id)
    analysis = build_report_analysis(request.app.state.manager, job_id=job_id, baseline_job_id=baseline_job_id)
    return ReportAnalysisResponse(item=item, analysis=analysis)


@router.get("/reports/{job_id}/export")
async def export_report(
    job_id: str,
    request: Request,
    format: str = "html",
    principal: AuthPrincipal = Depends(require_viewer),
) -> Any:
    del principal
    item = get_report_item_or_404(request.app.state.manager, job_id)
    safe_format = str(format or "html").strip().lower()
    if safe_format in {"json", "markdown", "md"}:
        key = "json" if safe_format == "json" else "markdown"
        relative_path = item.get("report_paths", {}).get(key)
        if not relative_path:
            raise HTTPException(status_code=404, detail="report_format_not_available")
        try:
            resolved = request.app.state.manager.resolve_file(job_id, str(relative_path))
        except (KeyError, FileNotFoundError, PermissionError) as exc:
            raise HTTPException(status_code=404, detail="report_format_not_available") from exc
        return FileResponse(resolved, filename=resolved.name)
    if safe_format != "html":
        raise HTTPException(status_code=400, detail="unsupported_export_format")
    analysis = build_report_analysis(request.app.state.manager, job_id=job_id, baseline_job_id=None)
    html_body = render_generated_report_html(item=item, analysis=analysis)
    headers = {"Content-Disposition": f'attachment; filename="{job_id}-report.html"'}
    return HTMLResponse(content=html_body, headers=headers)
