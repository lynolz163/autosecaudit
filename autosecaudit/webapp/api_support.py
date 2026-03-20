"""Shared FastAPI helpers for auth, RBAC, and audit events."""

from __future__ import annotations

import time
from typing import Any, Callable

from fastapi import HTTPException, Request

from .auth import AuthPrincipal

PUBLIC_ERROR_CODE_MAP = {
    "bootstrap_locked": "bootstrap_unavailable",
    "last_enabled_admin": "user_update_rejected",
    "cannot_delete_self": "user_update_rejected",
    "cannot_freeze_self": "user_update_rejected",
    "cannot_change_own_role": "user_update_rejected",
}
PUBLIC_ERROR_PREFIX_MAP = {
    "submit_failed": "job_submit_failed",
    "mission_submit_failed": "job_submit_failed",
    "cve_verify_submit_failed": "job_submit_failed",
    "codex_login_start_failed": "codex_login_failed",
    "models_fetch_failed": "codex_models_failed",
    "cve_search_failed": "cve_backend_unavailable",
    "rag_corpus_invalid": "rag_request_invalid",
    "rag_corpus_write_failed": "rag_write_failed",
    "mission_missing_required_fields": "mission_request_incomplete",
    "mission_session_not_found": "session_not_found",
}


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
        raise HTTPException(status_code=401, detail=public_error_code(str(exc))) from exc


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


def public_error_code(detail: str, *, default: str | None = None) -> str:
    """Map internal service codes to stable public API error codes."""
    normalized = str(detail or "").strip()
    if not normalized:
        return default or "request_failed"
    if normalized.startswith(("'", '"')) and normalized.endswith(("'", '"')) and len(normalized) >= 2:
        normalized = normalized[1:-1].strip()
        if not normalized:
            return default or "request_failed"
    prefix = normalized.split(":", 1)[0].strip().lower()
    if prefix in PUBLIC_ERROR_PREFIX_MAP:
        return PUBLIC_ERROR_PREFIX_MAP[prefix]
    return PUBLIC_ERROR_CODE_MAP.get(normalized, normalized)


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
