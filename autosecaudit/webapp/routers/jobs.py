"""Job and dashboard routers for the web console API."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from ..api_support import require_role
from ..auth import AuthPrincipal
from ..reporting import build_dashboard_summary
from ..schemas import DashboardSummaryResponse, JobArtifactsResponse, JobCreateRequest, JobItemResponse, JobListResponse, JobLogsResponse
from ..services.job_manager import _to_float, _to_int


router = APIRouter(tags=["jobs"])
require_viewer = require_role("viewer")
require_operator = require_role("operator")


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> JobListResponse:
    del principal
    return JobListResponse(items=request.app.state.manager.list_jobs())


@router.get("/jobs/catalog")
async def get_job_catalog(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> dict[str, Any]:
    del principal
    return request.app.state.manager.get_planner_catalog()


@router.post("/jobs", response_model=JobItemResponse, status_code=201)
async def create_job(payload: JobCreateRequest, request: Request, principal: AuthPrincipal = Depends(require_operator)) -> JobItemResponse:
    try:
        job = request.app.state.manager.submit(payload.model_dump(exclude_none=True), actor=principal.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"submit_failed: {exc}") from exc
    return JobItemResponse(job=job)


@router.get("/jobs/{job_id}", response_model=JobItemResponse)
async def get_job(job_id: str, request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> JobItemResponse:
    del principal
    try:
        return JobItemResponse(job=request.app.state.manager.get_job(job_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc


@router.post("/jobs/{job_id}/cancel", response_model=JobItemResponse)
async def cancel_job(job_id: str, request: Request, principal: AuthPrincipal = Depends(require_operator)) -> JobItemResponse:
    try:
        job = request.app.state.manager.cancel(job_id, actor=principal.actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc
    return JobItemResponse(job=job)


@router.get("/jobs/{job_id}/logs", response_model=JobLogsResponse)
async def get_job_logs(
    job_id: str,
    request: Request,
    offset: int = 0,
    limit: int = 500,
    principal: AuthPrincipal = Depends(require_viewer),
) -> JobLogsResponse:
    del principal
    try:
        payload = request.app.state.manager.get_logs(
            job_id,
            offset=_to_int(offset, 0, minimum=0),
            limit=_to_int(limit, 500, minimum=1, maximum=5000),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc
    return JobLogsResponse.model_validate(payload)


@router.get("/jobs/{job_id}/stream")
async def stream_job_logs(
    job_id: str,
    request: Request,
    offset: int = 0,
    limit: int = 200,
    heartbeat: float = 15.0,
    principal: AuthPrincipal = Depends(require_viewer),
) -> StreamingResponse:
    del principal
    safe_offset = _to_int(offset, 0, minimum=0)
    safe_limit = _to_int(limit, 200, minimum=1, maximum=1000)
    safe_heartbeat = _to_float(heartbeat, 15.0, minimum=2.0, maximum=60.0)

    try:
        request.app.state.manager.get_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc

    async def event_stream() -> Any:
        current_offset = safe_offset
        current_status = ""
        yield "retry: 1500\n\n"
        while True:
            snapshot = request.app.state.manager.get_stream_snapshot(job_id, offset=current_offset, limit=safe_limit)
            next_status = str(snapshot["job"].get("status", ""))
            if next_status != current_status:
                current_status = next_status
                yield _format_sse_event(
                    "status",
                    {
                        "job": snapshot["job"],
                        "total": snapshot["total"],
                        "offset": current_offset,
                    },
                )

            for item in snapshot["items"]:
                yield _format_sse_event(
                    "log",
                    {
                        "job_id": job_id,
                        "offset": current_offset,
                        "total": snapshot["total"],
                        "item": item,
                    },
                )
                current_offset += 1

            if snapshot["terminal"] and current_offset >= int(snapshot["total"]):
                break

            changed = await asyncio.to_thread(
                request.app.state.manager.wait_for_job_update,
                job_id,
                offset=current_offset,
                status=current_status,
                timeout=safe_heartbeat,
            )
            if not changed:
                yield _format_sse_event(
                    "heartbeat",
                    {
                        "job_id": job_id,
                        "offset": current_offset,
                        "status": current_status,
                    },
                )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/jobs/{job_id}/artifacts", response_model=JobArtifactsResponse)
async def list_artifacts(job_id: str, request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> JobArtifactsResponse:
    del principal
    try:
        return JobArtifactsResponse(job_id=job_id, items=request.app.state.manager.list_artifacts(job_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc


@router.get("/jobs/{job_id}/files/{file_path:path}")
async def read_artifact(
    job_id: str,
    file_path: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> FileResponse:
    del principal
    try:
        resolved = request.app.state.manager.resolve_file(job_id, file_path)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="artifact_not_found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="forbidden") from exc
    return FileResponse(resolved)


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def dashboard_summary(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> DashboardSummaryResponse:
    del principal
    return DashboardSummaryResponse.model_validate(build_dashboard_summary(request.app.state.manager))


def _format_sse_event(event_name: str, payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False)
    lines = [f"event: {event_name}"]
    lines.extend(f"data: {line}" for line in body.splitlines())
    return "\n".join(lines) + "\n\n"
