"""Interactive web UI launcher for AutoSecAudit."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any

from .auth import AuthConfigurationError
from .fastapi_app import create_app, resolve_runtime_paths
from .runtime import _resolve_static_dir, _utc_now
from .services.codex_auth import CodexWebAuthManager
from .services.job_manager import JobManager


def _to_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    """Parse bounded integer."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for web UI service."""
    parser = argparse.ArgumentParser(
        prog="autosecaudit-web",
        description="Interactive web console for AutoSecAudit CLI/Agent runs.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host. Default: 0.0.0.0")
    parser.add_argument("--port", type=int, default=8080, help="Bind port. Default: 8080")
    parser.add_argument(
        "--workspace",
        default=str(Path.cwd()),
        help="Workspace directory used to run autosecaudit.cli subprocesses.",
    )
    parser.add_argument(
        "--output-root",
        default="output/web-jobs",
        help="Output directory root for web-launched jobs (relative to workspace if not absolute).",
    )
    parser.add_argument(
        "--python-executable",
        default=sys.executable,
        help="Python interpreter used to launch child CLI processes. Default: current interpreter.",
    )
    parser.add_argument(
        "--max-jobs",
        type=int,
        default=_to_int(os.getenv("AUTOSECAUDIT_WEB_MAX_JOBS"), 200, minimum=1, maximum=100000),
        help="Max retained jobs in memory. Default: 200",
    )
    parser.add_argument(
        "--max-running-jobs",
        type=int,
        default=_to_int(os.getenv("AUTOSECAUDIT_WEB_MAX_RUNNING_JOBS"), 4, minimum=1, maximum=1000),
        help="Max concurrently active (queued/running) jobs. Default: 4",
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("AUTOSECAUDIT_WEB_API_TOKEN", ""),
        help="Optional bearer token required for /api endpoints. Default from AUTOSECAUDIT_WEB_API_TOKEN.",
    )
    return parser


def _build_manager(
    *,
    workspace: Path,
    output_root: Path,
    python_executable: str,
    max_jobs: int,
    max_running_jobs: int,
) -> JobManager:
    """Create JobManager with writable output fallback."""
    try:
        return JobManager(
            workspace_dir=workspace,
            output_root=output_root,
            python_executable=python_executable,
            max_jobs=max_jobs,
            max_running_jobs=max_running_jobs,
        )
    except PermissionError as exc:
        fallback_output_root = (Path.home() / ".autosecaudit" / "web-jobs").resolve()
        print(
            f"[autosecaudit-web] output root not writable: {output_root} ({exc})",
            file=sys.stderr,
        )
        print(
            f"[autosecaudit-web] falling back to writable output root: {fallback_output_root}",
            file=sys.stderr,
        )
        return JobManager(
            workspace_dir=workspace,
            output_root=fallback_output_root,
            python_executable=python_executable,
            max_jobs=max_jobs,
            max_running_jobs=max_running_jobs,
        )


def main(argv: list[str] | None = None) -> int:
    """Run FastAPI web UI server."""
    args = build_parser().parse_args(argv)
    workspace = Path(args.workspace).resolve()
    if not workspace.exists() or not workspace.is_dir():
        print(f"[autosecaudit-web] invalid workspace: {workspace}", file=sys.stderr)
        return 2

    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = (workspace / output_root).resolve()

    try:
        import uvicorn
    except Exception as exc:  # noqa: BLE001
        print(
            "[autosecaudit-web] FastAPI runtime dependencies missing. "
            "Install project dependencies (`pip install -e .`) before starting web mode.",
            file=sys.stderr,
        )
        print(f"[autosecaudit-web] import error: {exc}", file=sys.stderr)
        return 2

    try:
        static_dir, frontend_dir = resolve_runtime_paths(workspace=workspace)
    except FileNotFoundError as exc:
        print(f"[autosecaudit-web] {exc}", file=sys.stderr)
        return 2

    manager = _build_manager(
        workspace=workspace,
        output_root=output_root,
        python_executable=str(args.python_executable),
        max_jobs=int(args.max_jobs),
        max_running_jobs=int(args.max_running_jobs),
    )
    try:
        app = create_app(
            workspace=workspace,
            static_dir=static_dir,
            manager=manager,
            codex_auth=CodexWebAuthManager(),
            api_token=str(args.api_token),
        )
    except AuthConfigurationError as exc:
        print(f"[autosecaudit-web] invalid auth configuration: {exc}", file=sys.stderr)
        manager.close()
        return 2

    print(f"[autosecaudit-web] serving http://{args.host}:{args.port}", flush=True)
    print(f"[autosecaudit-web] workspace={workspace}", flush=True)
    print(f"[autosecaudit-web] output_root={manager._output_root}", flush=True)
    print(f"[autosecaudit-web] frontend_dir={frontend_dir}", flush=True)
    if app.state.api_token and app.state.auth_service.status().get("has_users"):
        auth_mode = "bootstrap+jwt"
    elif app.state.api_token:
        auth_mode = "bootstrap_only"
    elif app.state.auth_service.status().get("has_users"):
        auth_mode = "jwt_only"
    else:
        auth_mode = "open"
    print(
        f"[autosecaudit-web] auth_mode={auth_mode} "
        f"max_jobs={manager._max_jobs} max_running_jobs={manager._max_running_jobs}",
        flush=True,
    )

    try:
        uvicorn.run(app, host=str(args.host), port=int(args.port), log_level="info")
    except KeyboardInterrupt:
        pass
    finally:
        manager.close()
    return 0


__all__ = [
    "CodexWebAuthManager",
    "JobManager",
    "_resolve_static_dir",
    "_utc_now",
    "build_parser",
    "main",
]
