"""Shared FastAPI helpers for auth, RBAC, and audit events."""

from __future__ import annotations

import time
from typing import Any, Callable

from fastapi import HTTPException, Request

from .auth import AuthPrincipal


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def extract_bearer_token(request: Request) -> str:
    """Read bearer or fallback API token from one request."""
    auth_header = str(request.headers.get("authorization", "")).strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    fallback = str(request.headers.get("x-api-token", "")).strip()
    if fallback:
        return fallback
    return str(request.query_params.get("api_token") or request.query_params.get("token") or "").strip()


def authenticate_request(request: Request) -> AuthPrincipal:
    """Resolve the authenticated principal or raise 401."""
    token = extract_bearer_token(request)
    try:
        return request.app.state.auth_service.get_principal_from_bearer(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def require_role(required_role: str) -> Callable[[Request], AuthPrincipal]:
    """Return one dependency that enforces the required RBAC role."""

    async def dependency(request: Request) -> AuthPrincipal:
        principal = authenticate_request(request)
        if not principal.allows(required_role):
            raise HTTPException(status_code=403, detail="forbidden")
        return principal

    return dependency


def permission_summary(principal: AuthPrincipal) -> dict[str, Any]:
    """Summarize frontend-visible permissions for one principal."""
    return {
        "role": principal.role,
        "can_view": principal.allows("viewer"),
        "can_operate": principal.allows("operator"),
        "can_admin": principal.allows("admin"),
    }


def audit_event(
    request: Request,
    *,
    actor: str,
    event_type: str,
    resource_type: str,
    resource_id: str | None,
    detail: dict[str, Any] | None,
) -> None:
    """Write one audit event through the current app manager."""
    request.app.state.manager.store.add_audit_event(
        created_at=_utc_now(),
        actor=actor,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail or {},
    )
