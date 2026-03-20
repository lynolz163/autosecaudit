"""User-management routers for the web console API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..api_support import audit_event, public_error_code, require_role
from ..auth import AuthPrincipal
from ..schemas import UserCreateRequest, UserDeleteResponse, UserItemResponse, UserListResponse, UserUpdateRequest


router = APIRouter(tags=["users"])
require_admin = require_role("admin")


@router.get("/users", response_model=UserListResponse)
async def list_users(request: Request, principal: AuthPrincipal = Depends(require_admin)) -> UserListResponse:
    return UserListResponse(items=request.app.state.auth_service.list_users(), actor=principal.username)


@router.post("/users", response_model=UserItemResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> UserItemResponse:
    username = str(payload.username or "").strip()
    password = str(payload.password or "")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")
    try:
        item = request.app.state.auth_service.create_user(
            username=username,
            password=password,
            role=str(payload.role).strip().lower(),
            display_name=(str(payload.display_name).strip() or None) if payload.display_name is not None else None,
            enabled=bool(payload.enabled),
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=public_error_code(str(exc), default="user_request_invalid")) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="user_created",
        resource_type="user",
        resource_id=str(item["user_id"]),
        detail={"username": item["username"], "role": item["role"]},
    )
    return UserItemResponse(item=item)


@router.put("/users/{user_id}", response_model=UserItemResponse)
async def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> UserItemResponse:
    try:
        item = request.app.state.auth_service.update_user(
            user_id,
            username=(str(payload.username).strip() if payload.username is not None else None),
            password=(str(payload.password) if str(payload.password or "").strip() else None),
            role=(str(payload.role).strip().lower() if payload.role is not None else None),
            display_name=(str(payload.display_name).strip() if payload.display_name is not None else None),
            enabled=payload.enabled,
            actor_user_id=principal.user_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="user_not_found") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=public_error_code(str(exc), default="user_update_rejected")) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="user_updated",
        resource_type="user",
        resource_id=str(item["user_id"]),
        detail={"username": item["username"], "role": item["role"], "enabled": item["enabled"]},
    )
    return UserItemResponse(item=item)


@router.delete("/users/{user_id}", response_model=UserDeleteResponse)
async def delete_user(
    user_id: int,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> UserDeleteResponse:
    try:
        target = request.app.state.auth_service.get_user(user_id)
        request.app.state.auth_service.delete_user(user_id, actor_user_id=principal.user_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="user_not_found") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=public_error_code(str(exc), default="user_update_rejected")) from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="user_deleted",
        resource_type="user",
        resource_id=str(user_id),
        detail={"username": target.get("username"), "role": target.get("role")},
    )
    return UserDeleteResponse(ok=True, user_id=int(user_id))
