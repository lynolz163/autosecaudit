"""FastAPI web console for AutoSecAudit."""

from __future__ import annotations

from contextlib import asynccontextmanager
import hashlib
import os
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

from autosecaudit.agent_core.mission_intake import MissionSessionManager

from .api_support import extract_bearer_token
from .auth import AuthService
from .metrics import instrument_app, render_metrics_response
from .rate_limit import InMemoryRateLimiter, RateLimitResult
from .routers.assets import router as assets_router
from .routers.auth import router as auth_router
from .routers.codex import oauth_router as codex_oauth_router
from .routers.codex import router as codex_router
from .routers.cve import router as cve_router
from .routers.jobs import router as jobs_router
from .routers.mission import router as mission_router
from .routers.plugins import router as plugins_router
from .routers.rag import router as rag_router
from .routers.reports import router as reports_router
from .routers.schedules import router as schedules_router
from .routers.settings import router as settings_router
from .routers.system import router as system_router
from .routers.users import router as users_router
from .runtime import _resolve_static_dir, _utc_now
from .schedule_service import ScheduleService
from .services.codex_auth import CodexWebAuthManager
from .services.job_manager import JobManager


def create_app(
    *,
    workspace: Path,
    static_dir: Path,
    manager: JobManager,
    codex_auth: CodexWebAuthManager,
    api_token: str | None,
) -> FastAPI:
    """Create the FastAPI web service."""
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.schedule_service.start()
        try:
            yield
        finally:
            app.state.schedule_service.stop()
            app.state.manager.close()

    app = FastAPI(
        title="AutoSecAudit Web Console",
        version="0.2.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    app.state.workspace = workspace.resolve()
    app.state.static_dir = static_dir.resolve()
    app.state.frontend_dir = _resolve_frontend_dir(workspace=workspace, static_dir=static_dir)
    app.state.manager = manager
    app.state.mission_sessions = MissionSessionManager()
    app.state.auth_service = AuthService(manager.store, bootstrap_token=api_token)
    app.state.codex_auth = codex_auth
    app.state.api_token = api_token.strip() if isinstance(api_token, str) and api_token.strip() else None
    app.state.schedule_service = ScheduleService(manager)
    app.state.rate_limiter = InMemoryRateLimiter.from_env()
    app.state.cors_allow_origins = _resolve_cors_allow_origins()

    if app.state.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=app.state.cors_allow_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-API-Token"],
            expose_headers=["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
        )

    if os.getenv("AUTOSECAUDIT_WEB_ENABLE_METRICS", "1").strip().lower() not in {"0", "false", "no", "off"}:
        instrument_app(app)

    @app.middleware("http")
    async def apply_rate_limits(request: Request, call_next: Any) -> Any:
        bucket = _rate_limit_bucket_for_request(request)
        rate_limit_result: RateLimitResult | None = None
        if bucket:
            rate_limit_result = app.state.rate_limiter.hit(bucket, _rate_limit_subject(request))
            if rate_limit_result is not None and not rate_limit_result.allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "rate_limited",
                        "bucket": rate_limit_result.bucket,
                        "retry_after": rate_limit_result.retry_after_seconds,
                    },
                    headers=_rate_limit_headers(rate_limit_result),
                )

        response = await call_next(request)
        if rate_limit_result is not None:
            for key, value in _rate_limit_headers(rate_limit_result).items():
                response.headers[key] = value
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "ts": _utc_now()}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        body, content_type = render_metrics_response(app.state.manager)
        return Response(content=body, media_type=content_type)

    app.include_router(codex_oauth_router, include_in_schema=False)
    app.include_router(auth_router, prefix="/api", include_in_schema=False)
    app.include_router(users_router, prefix="/api", include_in_schema=False)
    app.include_router(codex_router, prefix="/api", include_in_schema=False)
    app.include_router(cve_router, prefix="/api", include_in_schema=False)
    app.include_router(mission_router, prefix="/api", include_in_schema=False)
    app.include_router(rag_router, prefix="/api", include_in_schema=False)
    app.include_router(jobs_router, prefix="/api", include_in_schema=False)
    app.include_router(reports_router, prefix="/api", include_in_schema=False)
    app.include_router(assets_router, prefix="/api", include_in_schema=False)
    app.include_router(schedules_router, prefix="/api", include_in_schema=False)
    app.include_router(settings_router, prefix="/api", include_in_schema=False)
    app.include_router(plugins_router, prefix="/api", include_in_schema=False)
    app.include_router(system_router, prefix="/api", include_in_schema=False)
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")
    app.include_router(codex_router, prefix="/api/v1")
    app.include_router(cve_router, prefix="/api/v1")
    app.include_router(mission_router, prefix="/api/v1")
    app.include_router(rag_router, prefix="/api/v1")
    app.include_router(jobs_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(assets_router, prefix="/api/v1")
    app.include_router(schedules_router, prefix="/api/v1")
    app.include_router(settings_router, prefix="/api/v1")
    app.include_router(plugins_router, prefix="/api/v1")
    app.include_router(system_router, prefix="/api/v1")

    @app.get("/static/{file_path:path}")
    async def static_file(file_path: str) -> FileResponse:
        resolved = _resolve_frontend_asset(
            root_dir=app.state.static_dir,
            relative_path=file_path,
        )
        if resolved is None:
            raise HTTPException(status_code=404, detail="static_not_found")
        return FileResponse(resolved)

    @app.get("/{full_path:path}")
    async def spa_entry(full_path: str) -> Any:
        if full_path.startswith(("api/", "oauth/", "healthz", "docs", "redoc", "openapi.json")):
            raise HTTPException(status_code=404, detail="not_found")
        frontend_dir: Path = app.state.frontend_dir
        relative_path = full_path.strip("/") or "index.html"
        resolved = _resolve_frontend_asset(root_dir=frontend_dir, relative_path=relative_path)
        if resolved is not None:
            return FileResponse(resolved)
        index_file = _resolve_frontend_asset(root_dir=frontend_dir, relative_path="index.html")
        if index_file is None:
            raise HTTPException(status_code=404, detail="frontend_not_found")
        return FileResponse(index_file)

    return app


def _resolve_cors_allow_origins() -> list[str]:
    origins: list[str] = []
    raw_origins = os.getenv("AUTOSECAUDIT_WEB_CORS_ALLOW_ORIGINS", "").strip()
    if raw_origins:
        for item in raw_origins.split(","):
            normalized = str(item).strip()
            if normalized and normalized not in origins:
                origins.append(normalized)

    public_origin = _origin_from_url(os.getenv("AUTOSECAUDIT_WEB_PUBLIC_BASE_URL", "").strip())
    if public_origin and public_origin not in origins:
        origins.append(public_origin)
    return origins


def _origin_from_url(value: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urlsplit(text)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _rate_limit_bucket_for_request(request: Request) -> str | None:
    path = str(request.url.path or "")
    method = str(request.method or "GET").upper()
    if method == "OPTIONS" or not path.startswith("/api/"):
        return None
    normalized = path
    if path.startswith("/api/v1/"):
        normalized = "/api" + path[len("/api/v1"):]
    if normalized in {"/api/auth/login", "/api/auth/bootstrap"}:
        return "auth_login"
    if normalized == "/api/auth/refresh":
        return "auth_refresh"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "api_write"
    return None


def _rate_limit_subject(request: Request) -> str:
    bearer = extract_bearer_token(request)
    if bearer:
        token_hash = hashlib.sha256(bearer.encode("utf-8")).hexdigest()[:24]
        return f"token:{token_hash}"

    forwarded_for = str(request.headers.get("x-forwarded-for", "")).strip()
    if forwarded_for:
        client_ip = forwarded_for.split(",", 1)[0].strip()
        if client_ip:
            return f"ip:{client_ip}"

    if request.client and request.client.host:
        return f"ip:{request.client.host}"
    return "ip:unknown"


def _rate_limit_headers(result: RateLimitResult) -> dict[str, str]:
    headers = {
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset": str(result.reset_after_seconds),
    }
    if not result.allowed:
        headers["Retry-After"] = str(result.retry_after_seconds)
    return headers


def _resolve_frontend_dir(*, workspace: Path, static_dir: Path) -> Path:
    """Prefer the built React console, with env override for the legacy static console."""
    preferred = os.getenv("AUTOSECAUDIT_WEB_FRONTEND", "").strip().lower()
    if preferred in {"static", "legacy"}:
        if static_dir.exists() and (static_dir / "index.html").is_file():
            return static_dir.resolve()
    candidates = [
        (Path(__file__).resolve().parent / "frontend_dist").resolve(),
        (workspace / "autosecaudit" / "webapp" / "frontend_dist").resolve(),
    ]
    for candidate in candidates:
        if candidate.exists() and (candidate / "index.html").is_file():
            return candidate
    if preferred in {"dist", "react", "frontend_dist"}:
        return static_dir.resolve()
    if static_dir.exists() and (static_dir / "index.html").is_file():
        return static_dir.resolve()
    return static_dir.resolve()


def _resolve_frontend_asset(*, root_dir: Path, relative_path: str) -> Path | None:
    """Resolve a static asset path safely under the given root."""
    relative = relative_path.strip().lstrip("/")
    target = (root_dir / relative).resolve()
    if not target.is_relative_to(root_dir.resolve()):
        return None
    if target.is_file():
        return target
    return None


def resolve_runtime_paths(*, workspace: Path) -> tuple[Path, Path]:
    """Resolve workspace-relative static directories for the web service."""
    static_dir = _resolve_static_dir(workspace)
    if static_dir is None:
        expected = (Path(__file__).resolve().parent / "static").resolve()
        raise FileNotFoundError(
            f"static dir not found: {expected}. Rebuild package assets or verify source checkout."
        )
    frontend_dir = _resolve_frontend_dir(workspace=workspace, static_dir=static_dir)
    return static_dir, frontend_dir
