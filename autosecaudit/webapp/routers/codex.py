"""Codex OAuth routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..schemas import CodexConfigResponse, CodexLoginStartResponse, CodexLoginStatusResponse, CodexModelsResponse


router = APIRouter(tags=["codex"])
oauth_router = APIRouter(tags=["codex"])
require_admin = require_role("admin")


@oauth_router.get("/oauth/codex/callback", response_class=HTMLResponse, include_in_schema=False)
async def codex_callback(request: Request) -> HTMLResponse:
    query = _normalize_query_mapping(request)
    status_code, html = request.app.state.codex_auth.handle_callback(query)
    return HTMLResponse(content=html, status_code=status_code)


@router.get("/llm/codex/config", response_model=CodexConfigResponse)
async def codex_config(request: Request, principal: AuthPrincipal = Depends(require_admin)) -> CodexConfigResponse:
    return CodexConfigResponse.model_validate(
        {
            **request.app.state.codex_auth.config_summary(),
            "actor": principal.username,
        }
    )


@router.post("/llm/codex/login/start", response_model=CodexLoginStartResponse)
async def codex_login_start(request: Request, principal: AuthPrincipal = Depends(require_admin)) -> CodexLoginStartResponse:
    try:
        data = request.app.state.codex_auth.start_login(
            request_headers=request.headers,
            host_fallback=str(request.headers.get("host") or "127.0.0.1"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"codex_login_start_failed: {exc}") from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="codex_login_started",
        resource_type="llm",
        resource_id=str(data.get("session_id") or ""),
        detail={"provider_alias": data.get("provider_alias")},
    )
    return CodexLoginStartResponse.model_validate(data)


@router.get("/llm/codex/login/status", response_model=CodexLoginStatusResponse)
async def codex_login_status(
    request: Request,
    session_id: str,
    principal: AuthPrincipal = Depends(require_admin),
) -> CodexLoginStatusResponse:
    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id:
        raise HTTPException(status_code=400, detail="missing_session_id")
    try:
        payload = request.app.state.codex_auth.get_status(normalized_session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="session_not_found") from exc
    payload["actor"] = principal.username
    return CodexLoginStatusResponse.model_validate(payload)


@router.get("/llm/codex/models", response_model=CodexModelsResponse)
async def codex_models(request: Request, principal: AuthPrincipal = Depends(require_admin)) -> CodexModelsResponse:
    try:
        payload = request.app.state.codex_auth.list_models()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"models_fetch_failed: {exc}") from exc
    payload["actor"] = principal.username
    return CodexModelsResponse.model_validate(payload)


def _normalize_query_mapping(request: Request) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        normalized.setdefault(str(key), []).append(str(value))
    return normalized
