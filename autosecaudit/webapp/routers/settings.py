"""Settings and audit routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..schemas import (
    AuditEventListResponse,
    JsonObjectRequest,
    LlmSettingsResponse,
    LlmSettingsSaveRequest,
    LlmTestRequest,
    LlmTestResponse,
    NotificationSettingsResponse,
)


router = APIRouter(tags=["settings"])
require_admin = require_role("admin")


@router.get("/settings/notifications", response_model=NotificationSettingsResponse)
async def get_notification_settings(
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> NotificationSettingsResponse:
    del principal
    return NotificationSettingsResponse(item=request.app.state.manager.get_notification_settings())


@router.put("/settings/notifications", response_model=NotificationSettingsResponse)
async def update_notification_settings(
    payload: JsonObjectRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> NotificationSettingsResponse:
    item = request.app.state.manager.update_notification_settings(payload.root)
    audit_event(
        request,
        actor=principal.actor,
        event_type="notification_settings_updated",
        resource_type="settings",
        resource_id="notification_config",
        detail={"enabled_events": item.get("events", [])},
    )
    return NotificationSettingsResponse(item=item)


# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------


@router.get("/settings/llm", response_model=LlmSettingsResponse)
async def get_llm_settings(
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> LlmSettingsResponse:
    del principal
    data = request.app.state.manager.get_llm_settings()
    return LlmSettingsResponse(**data)


@router.put("/settings/llm", response_model=LlmSettingsResponse)
async def save_llm_settings(
    payload: LlmSettingsSaveRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> LlmSettingsResponse:
    config = payload.model_dump()
    data = request.app.state.manager.save_llm_settings(config)
    audit_event(
        request,
        actor=principal.actor,
        event_type="llm_settings_updated",
        resource_type="settings",
        resource_id="llm_config",
        detail={"model": config.get("model"), "preset_id": config.get("preset_id")},
    )
    return LlmSettingsResponse(**data)


@router.post("/settings/llm/test", response_model=LlmTestResponse)
async def test_llm_connection(
    payload: LlmTestRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> LlmTestResponse:
    del principal
    result = request.app.state.manager.test_llm_connection(payload.model_dump())
    return LlmTestResponse(**result)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


@router.get("/audit/events", response_model=AuditEventListResponse)
async def list_audit_events(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    principal: AuthPrincipal = Depends(require_admin),
) -> AuditEventListResponse:
    del principal
    return AuditEventListResponse(items=request.app.state.manager.store.list_audit_events(limit=limit))
