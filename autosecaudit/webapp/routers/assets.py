"""Asset-management routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..api_support import audit_event, public_error_code, require_role
from ..auth import AuthPrincipal
from ..runtime import _utc_now
from ..schemas import AssetCreateRequest, AssetDeleteResponse, AssetItemResponse, AssetListResponse, AssetUpdateRequest, JobItemResponse, JsonObjectRequest


router = APIRouter(tags=["assets"])
require_viewer = require_role("viewer")
require_operator = require_role("operator")


@router.get("/assets", response_model=AssetListResponse)
async def list_assets(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> AssetListResponse:
    del principal
    return AssetListResponse(items=request.app.state.manager.store.list_assets())


@router.post("/assets", response_model=AssetItemResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> AssetItemResponse:
    try:
        item = request.app.state.manager.store.create_asset(
            {
                **payload.model_dump(exclude_none=True),
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
            }
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=public_error_code(str(exc), default="asset_request_invalid")) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="asset_created",
        resource_type="asset",
        resource_id=str(item["asset_id"]),
        detail={"target": item["target"]},
    )
    return AssetItemResponse(item=item)


@router.get("/assets/{asset_id}", response_model=AssetItemResponse)
async def get_asset(asset_id: int, request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> AssetItemResponse:
    del principal
    try:
        item = request.app.state.manager.store.get_asset(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="asset_not_found") from exc
    return AssetItemResponse(item=item)


@router.put("/assets/{asset_id}", response_model=AssetItemResponse)
async def update_asset(
    asset_id: int,
    payload: AssetUpdateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> AssetItemResponse:
    update_payload = payload.model_dump(exclude_none=True)
    if "name" in update_payload and not str(update_payload.get("name", "")).strip():
        raise HTTPException(status_code=400, detail="asset name is required")
    if "target" in update_payload and not str(update_payload.get("target", "")).strip():
        raise HTTPException(status_code=400, detail="asset target is required")
    try:
        item = request.app.state.manager.store.update_asset(asset_id, {**update_payload, "updated_at": _utc_now()})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="asset_not_found") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=public_error_code(str(exc), default="asset_request_invalid")) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="asset_updated",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={"target": item["target"]},
    )
    return AssetItemResponse(item=item)


@router.delete("/assets/{asset_id}", response_model=AssetDeleteResponse)
async def delete_asset(
    asset_id: int,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> AssetDeleteResponse:
    try:
        request.app.state.manager.store.delete_asset(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="asset_not_found") from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="asset_deleted",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={},
    )
    return AssetDeleteResponse(ok=True)


@router.post("/assets/{asset_id}/scan", response_model=JobItemResponse, status_code=status.HTTP_201_CREATED)
async def scan_asset(
    asset_id: int,
    payload: JsonObjectRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> JobItemResponse:
    try:
        asset = request.app.state.manager.store.get_asset(asset_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="asset_not_found") from exc

    merged_payload = dict(asset.get("default_payload", {}))
    merged_payload.update(payload.root)
    merged_payload.setdefault("target", asset.get("target"))
    merged_payload.setdefault("scope", asset.get("scope"))
    merged_payload.setdefault("mode", asset.get("default_mode") or "agent")
    try:
        job = request.app.state.manager.submit(merged_payload, actor=principal.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=public_error_code(str(exc), default="asset_request_invalid")) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="asset_scan_started",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={"job_id": job["job_id"], "target": asset["target"]},
    )
    return JobItemResponse(job=job)
