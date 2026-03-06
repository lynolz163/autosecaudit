"""Schedule-management routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..runtime import _utc_now
from ..schedule_service import utc_now_dt
from ..schemas import ScheduleCreateRequest, ScheduleDeleteResponse, ScheduleItemResponse, ScheduleListResponse, ScheduleUpdateRequest


router = APIRouter(tags=["schedules"])
require_viewer = require_role("viewer")
require_operator = require_role("operator")


@router.get("/schedules", response_model=ScheduleListResponse)
async def list_schedules(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> ScheduleListResponse:
    del principal
    items = [_enrich_schedule(request, item) for item in request.app.state.manager.store.list_schedules()]
    return ScheduleListResponse(items=items)


@router.post("/schedules", response_model=ScheduleItemResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScheduleCreateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> ScheduleItemResponse:
    try:
        request.app.state.schedule_service.preview_next_run(str(payload.cron_expr).strip(), after=utc_now_dt())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        item = request.app.state.manager.store.create_schedule(
            {
                **payload.model_dump(exclude_none=True),
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
            }
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="schedule_created",
        resource_type="schedule",
        resource_id=str(item["schedule_id"]),
        detail={"cron_expr": item["cron_expr"]},
    )
    return ScheduleItemResponse(item=_enrich_schedule(request, item))


@router.get("/schedules/{schedule_id}", response_model=ScheduleItemResponse)
async def get_schedule(
    schedule_id: int,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> ScheduleItemResponse:
    del principal
    try:
        item = request.app.state.manager.store.get_schedule(schedule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="schedule_not_found") from exc
    return ScheduleItemResponse(item=_enrich_schedule(request, item))


@router.put("/schedules/{schedule_id}", response_model=ScheduleItemResponse)
async def update_schedule(
    schedule_id: int,
    payload: ScheduleUpdateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> ScheduleItemResponse:
    update_payload = payload.model_dump(exclude_none=True)
    if "name" in update_payload and not str(update_payload.get("name", "")).strip():
        raise HTTPException(status_code=400, detail="schedule name is required")
    if str(update_payload.get("cron_expr", "")).strip():
        try:
            request.app.state.schedule_service.preview_next_run(str(update_payload["cron_expr"]).strip(), after=utc_now_dt())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        item = request.app.state.manager.store.update_schedule(schedule_id, {**update_payload, "updated_at": _utc_now()})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="schedule_not_found") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="schedule_updated",
        resource_type="schedule",
        resource_id=str(schedule_id),
        detail={"cron_expr": item["cron_expr"]},
    )
    return ScheduleItemResponse(item=_enrich_schedule(request, item))


@router.delete("/schedules/{schedule_id}", response_model=ScheduleDeleteResponse)
async def delete_schedule(
    schedule_id: int,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> ScheduleDeleteResponse:
    try:
        request.app.state.manager.store.delete_schedule(schedule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="schedule_not_found") from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="schedule_deleted",
        resource_type="schedule",
        resource_id=str(schedule_id),
        detail={},
    )
    return ScheduleDeleteResponse(ok=True)


def _enrich_schedule(request: Request, item: dict[str, object]) -> dict[str, object]:
    enriched = dict(item)
    cron_expr = str(item.get("cron_expr", "")).strip()
    if cron_expr:
        try:
            enriched["next_run_at"] = request.app.state.schedule_service.preview_next_run(cron_expr, after=utc_now_dt())
        except ValueError:
            enriched["next_run_at"] = None
    else:
        enriched["next_run_at"] = None
    return enriched
