"""Plugin-management routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..schemas import PluginCatalogResponse, PluginSettingsRequest, PluginSettingsResponse


router = APIRouter(tags=["plugins"])
require_admin = require_role("admin")


@router.get("/plugins", response_model=PluginCatalogResponse)
async def list_plugins(request: Request, principal: AuthPrincipal = Depends(require_admin)) -> PluginCatalogResponse:
    payload = request.app.state.manager.list_plugins()
    payload["actor"] = principal.username
    return PluginCatalogResponse.model_validate(payload)


@router.put("/plugins/settings", response_model=PluginSettingsResponse)
async def update_plugin_settings(
    payload: PluginSettingsRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> PluginSettingsResponse:
    item = request.app.state.manager.update_plugin_settings(payload.model_dump())
    audit_event(
        request,
        actor=principal.actor,
        event_type="plugin_settings_updated",
        resource_type="settings",
        resource_id="plugin_runtime_config",
        detail={"plugin_dirs": item.get("plugin_dirs", [])},
    )
    return PluginSettingsResponse.model_validate({"item": item})


@router.post("/plugins/reload", response_model=PluginCatalogResponse)
async def reload_plugins(request: Request, principal: AuthPrincipal = Depends(require_admin)) -> PluginCatalogResponse:
    payload = request.app.state.manager.reload_plugins()
    audit_event(
        request,
        actor=principal.actor,
        event_type="plugins_reloaded",
        resource_type="plugin_runtime",
        resource_id=None,
        detail={
            "loaded_plugin_ids": payload.get("settings", {}).get("runtime", {}).get("loaded_plugin_ids", []),
            "errors": payload.get("settings", {}).get("runtime", {}).get("errors", []),
        },
    )
    payload["actor"] = principal.username
    return PluginCatalogResponse.model_validate(payload)


@router.post("/plugins/{plugin_id}/reload", response_model=PluginCatalogResponse)
async def reload_one_plugin(
    plugin_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> PluginCatalogResponse:
    try:
        payload = request.app.state.manager.reload_plugins(plugin_id=plugin_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="plugin_not_found") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="plugin_reloaded",
        resource_type="plugin",
        resource_id=plugin_id,
        detail={"plugin_id": plugin_id},
    )
    payload["actor"] = principal.username
    return PluginCatalogResponse.model_validate(payload)
