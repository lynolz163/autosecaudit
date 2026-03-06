"""Authentication routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..api_support import audit_event, authenticate_request, permission_summary, require_role
from ..auth import AuthPrincipal
from ..schemas import AuthMeResponse, AuthStatusResponse, BootstrapRequest, LoginRequest, RefreshRequest, TokenBundleResponse, UserView


router = APIRouter(tags=["auth"])
require_viewer = require_role("viewer")


@router.get("/auth/status", response_model=AuthStatusResponse)
async def auth_status(request: Request) -> AuthStatusResponse:
    return AuthStatusResponse.model_validate(request.app.state.auth_service.status())


@router.post("/auth/login", response_model=TokenBundleResponse)
async def auth_login(payload: LoginRequest, request: Request) -> TokenBundleResponse:
    username = str(payload.username or "").strip()
    password = str(payload.password or "")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")
    try:
        item = request.app.state.auth_service.login(username=username, password=password)
    except ValueError as exc:
        audit_event(
            request,
            actor=f"auth:{username or 'unknown'}",
            event_type="auth_login_failed",
            resource_type="user",
            resource_id=None,
            detail={"username": username, "error": str(exc)},
        )
        detail = str(exc)
        status_code = 403 if detail == "user_disabled" else 401
        raise HTTPException(status_code=status_code, detail=detail) from exc

    audit_event(
        request,
        actor=f"auth:{username}",
        event_type="auth_login_succeeded",
        resource_type="user",
        resource_id=str(item["user"]["user_id"]),
        detail={"username": username, "role": item["user"]["role"]},
    )
    return TokenBundleResponse.model_validate(item)


@router.post("/auth/refresh", response_model=TokenBundleResponse)
async def auth_refresh(payload: RefreshRequest, request: Request) -> TokenBundleResponse:
    refresh_token = str(payload.refresh_token or "").strip()
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token is required")
    try:
        item = request.app.state.auth_service.refresh_token(refresh_token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    audit_event(
        request,
        actor=f"auth:{item['user']['username']}",
        event_type="auth_token_refreshed",
        resource_type="user",
        resource_id=str(item["user"]["user_id"]),
        detail={"username": item["user"]["username"], "role": item["user"]["role"]},
    )
    return TokenBundleResponse.model_validate(item)


@router.post("/auth/bootstrap", response_model=TokenBundleResponse, status_code=status.HTTP_201_CREATED)
async def auth_bootstrap(payload: BootstrapRequest, request: Request) -> TokenBundleResponse:
    principal = authenticate_request(request)
    if principal.auth_type != "bootstrap":
        raise HTTPException(status_code=403, detail="bootstrap_token_required")
    if request.app.state.auth_service.status().get("has_users"):
        raise HTTPException(status_code=409, detail="bootstrap_locked")

    username = str(payload.username or "").strip()
    password = str(payload.password or "")
    display_name = str(payload.display_name or "").strip() or None
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    try:
        item = request.app.state.auth_service.bootstrap_admin(
            username=username,
            password=password,
            display_name=display_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="bootstrap_admin_created",
        resource_type="user",
        resource_id=str(item["user"]["user_id"]),
        detail={"username": username},
    )
    return TokenBundleResponse.model_validate(item)


@router.get("/auth/me", response_model=AuthMeResponse)
async def auth_me(request: Request, principal: AuthPrincipal = Depends(require_viewer)) -> AuthMeResponse:
    if principal.user_id is None:
        user = UserView(
            user_id=None,
            username=principal.username,
            role=principal.role,
            display_name=principal.display_name,
            enabled=True,
            auth_type=principal.auth_type,
        )
    else:
        user = UserView.model_validate(
            {
                **request.app.state.auth_service.get_user(principal.user_id),
                "auth_type": principal.auth_type,
            }
        )
    return AuthMeResponse(user=user, permissions=permission_summary(principal))
