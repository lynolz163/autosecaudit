"""Job and dashboard routers for the web console API."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from ..api_support import public_error_code, require_role
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
    return request.app.state.cache.get_or_compute(
        "jobs:catalog:v1",
        ttl_seconds=300.0,
        builder=request.app.state.manager.get_planner_catalog,
    )


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


@router.post("/jobs/{job_id}/approve-resume", response_model=JobItemResponse)
async def approve_and_resume_job(job_id: str, request: Request, principal: AuthPrincipal = Depends(require_operator)) -> JobItemResponse:
    try:
        job = request.app.state.manager.approve_and_resume(job_id, actor=principal.actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job_not_found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
    payload = request.app.state.cache.get_or_compute(
        "dashboard:summary:v1",
        ttl_seconds=8.0,
        builder=lambda: build_dashboard_summary(request.app.state.manager),
    )
    return DashboardSummaryResponse.model_validate(payload)


@router.websocket("/jobs/ws")
async def stream_jobs_realtime(
    websocket: WebSocket,
    heartbeat: float = 20.0,
) -> None:
    principal = await _authenticate_websocket(websocket, required_role="viewer")
    if principal is None:
        return
    del principal

    manager = websocket.app.state.manager
    safe_heartbeat = _to_float(heartbeat, 20.0, minimum=2.0, maximum=60.0)
    current_signature = manager.get_jobs_summary_signature()

    try:
        await _send_ws_event(websocket, "snapshot", _build_jobs_realtime_payload(manager))
        while True:
            changed = await asyncio.to_thread(
                manager.wait_for_jobs_summary_change,
                current_signature,
                timeout=safe_heartbeat,
            )
            next_signature = manager.get_jobs_summary_signature()
            if changed and next_signature != current_signature:
                current_signature = next_signature
                await _send_ws_event(websocket, "jobs", _build_jobs_realtime_payload(manager))
                continue
            await _send_ws_event(websocket, "heartbeat", {"scope": "jobs"})
    except WebSocketDisconnect:
        return


@router.websocket("/jobs/{job_id}/ws")
async def stream_job_realtime(
    websocket: WebSocket,
    job_id: str,
    offset: int = 0,
    limit: int = 500,
    heartbeat: float = 15.0,
) -> None:
    principal = await _authenticate_websocket(websocket, required_role="viewer")
    if principal is None:
        return
    del principal

    manager = websocket.app.state.manager
    safe_offset = _to_int(offset, 0, minimum=0)
    safe_limit = _to_int(limit, 500, minimum=1, maximum=5000)
    safe_heartbeat = _to_float(heartbeat, 15.0, minimum=2.0, maximum=60.0)

    try:
        manager.get_job(job_id)
    except KeyError:
        await websocket.close(code=4404, reason="job_not_found")
        return

    current_offset = safe_offset
    last_status = ""
    last_job_signature = ""
    last_analysis_signature = ""

    try:
        initial_snapshot = manager.get_stream_snapshot(job_id, offset=current_offset, limit=safe_limit)
        current_offset = int(initial_snapshot.get("next_offset", current_offset))
        last_status = str(initial_snapshot["job"].get("status", ""))
        last_job_signature = _job_realtime_signature(initial_snapshot["job"])
        last_analysis_signature = _analysis_stream_signature(initial_snapshot["job"])
        await _send_ws_event(
            websocket,
            "snapshot",
            {
                **initial_snapshot,
                "artifacts": manager.list_artifacts(job_id),
                "analysis_available": bool(last_analysis_signature),
                "analysis_signature": last_analysis_signature or None,
            },
        )

        while True:
            if initial_snapshot["terminal"] and current_offset >= int(initial_snapshot["total"]):
                await _send_ws_event(
                    websocket,
                    "terminal",
                    {
                        "job": initial_snapshot["job"],
                        "total": initial_snapshot["total"],
                        "offset": current_offset,
                        "artifacts": manager.list_artifacts(job_id),
                        "analysis_available": bool(last_analysis_signature),
                        "analysis_signature": last_analysis_signature or None,
                    },
                )
                break

            changed = await asyncio.to_thread(
                manager.wait_for_job_update,
                job_id,
                offset=current_offset,
                status=last_status,
                timeout=safe_heartbeat,
            )
            if not changed:
                await _send_ws_event(
                    websocket,
                    "heartbeat",
                    {
                        "job_id": job_id,
                        "offset": current_offset,
                        "status": last_status,
                    },
                )
                continue

            next_snapshot = manager.get_stream_snapshot(job_id, offset=current_offset, limit=safe_limit)
            next_job = next_snapshot["job"]
            next_status = str(next_job.get("status", ""))
            next_job_signature = _job_realtime_signature(next_job)
            next_analysis_signature = _analysis_stream_signature(next_job)

            if next_job_signature != last_job_signature:
                await _send_ws_event(
                    websocket,
                    "status",
                    {
                        "job": next_job,
                        "total": next_snapshot["total"],
                        "offset": current_offset,
                        "artifacts": manager.list_artifacts(job_id),
                        "analysis_available": bool(next_analysis_signature),
                        "analysis_signature": next_analysis_signature or None,
                    },
                )
                last_job_signature = next_job_signature
                last_status = next_status

            for item in next_snapshot["items"]:
                await _send_ws_event(
                    websocket,
                    "log",
                    {
                        "job_id": job_id,
                        "offset": current_offset,
                        "total": next_snapshot["total"],
                        "item": item,
                    },
                )
                current_offset += 1

            if next_analysis_signature != last_analysis_signature:
                await _send_ws_event(
                    websocket,
                    "analysis",
                    {
                        "job_id": job_id,
                        "analysis_available": bool(next_analysis_signature),
                        "analysis_signature": next_analysis_signature or None,
                    },
                )
                last_analysis_signature = next_analysis_signature

            if next_snapshot["terminal"] and current_offset >= int(next_snapshot["total"]):
                await _send_ws_event(
                    websocket,
                    "terminal",
                    {
                        "job": next_job,
                        "total": next_snapshot["total"],
                        "offset": current_offset,
                        "artifacts": manager.list_artifacts(job_id),
                        "analysis_available": bool(next_analysis_signature),
                        "analysis_signature": next_analysis_signature or None,
                    },
                )
                break

            initial_snapshot = next_snapshot
            last_status = next_status
    except WebSocketDisconnect:
        return


def _format_sse_event(event_name: str, payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False)
    lines = [f"event: {event_name}"]
    lines.extend(f"data: {line}" for line in body.splitlines())
    return "\n".join(lines) + "\n\n"


async def _authenticate_websocket(websocket: WebSocket, *, required_role: str) -> AuthPrincipal | None:
    token = ""
    auth_header = str(websocket.headers.get("authorization", "")).strip()
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = str(websocket.headers.get("x-api-token", "")).strip()
    if not token:
        token = str(websocket.query_params.get("api_token") or websocket.query_params.get("token") or "").strip()

    try:
        principal = websocket.app.state.auth_service.get_principal_from_bearer(token)
    except ValueError as exc:
        await websocket.close(code=4401, reason=public_error_code(str(exc)))
        return None

    if not principal.allows(required_role):
        await websocket.close(code=4403, reason="forbidden")
        return None

    await websocket.accept()
    return principal


async def _send_ws_event(websocket: WebSocket, event_name: str, payload: dict[str, Any]) -> None:
    await websocket.send_json({"event": event_name, "payload": payload})


def _build_jobs_realtime_payload(manager: Any) -> dict[str, Any]:
    items = manager.list_jobs()
    approval_queue = [
        item["job_id"]
        for item in items
        if str(item.get("session_status") or item.get("status") or "").strip().lower() == "waiting_approval"
    ]
    return {
        "items": items,
        "approval_total": len(approval_queue),
        "approval_job_ids": approval_queue,
    }


def _job_realtime_signature(job: dict[str, Any]) -> str:
    return json.dumps(
        {
            "job_id": job.get("job_id"),
            "status": job.get("status"),
            "session_status": job.get("session_status"),
            "return_code": job.get("return_code"),
            "pid": job.get("pid"),
            "error": job.get("error"),
            "cancel_requested": job.get("cancel_requested"),
            "artifact_count": job.get("artifact_count"),
            "pending_approval": job.get("pending_approval", {}),
            "loop_guard": job.get("loop_guard", {}),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _analysis_stream_signature(job: dict[str, Any]) -> str:
    output_dir_text = str(job.get("output_dir") or "").strip()
    if not output_dir_text:
        return ""
    output_dir = Path(output_dir_text)

    parts: list[tuple[str, int, int]] = []
    for relative_path in ("agent/agent_state.json", "agent/audit_report.json", "audit_report.json"):
        candidate = output_dir / relative_path
        try:
            stat = candidate.stat()
        except OSError:
            continue
        if not candidate.is_file():
            continue
        parts.append((relative_path, int(stat.st_mtime_ns), int(stat.st_size)))

    if not parts:
        return ""
    digest = hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8")).hexdigest()
    return digest
