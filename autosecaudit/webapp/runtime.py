"""Shared runtime helpers for AutoSecAudit web services."""

from __future__ import annotations

import time
from pathlib import Path


def _utc_now() -> str:
    """Return UTC timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _resolve_static_dir(workspace: Path) -> Path | None:
    """
    Resolve web static directory from multiple locations.

    Order:
    1) Installed package path (site-packages)
    2) Source tree adjacent to current module (works in local dev / copied source)
    3) Docker build source path `/app/autosecaudit/webapp/static`
    4) Workspace checkout path `<workspace>/autosecaudit/webapp/static`
    """
    candidates = [
        (Path(__file__).resolve().parent / "static"),
        (Path(__file__).resolve().parents[2] / "autosecaudit" / "webapp" / "static"),
        Path("/app/autosecaudit/webapp/static"),
        (workspace / "autosecaudit" / "webapp" / "static"),
    ]
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.exists() and resolved.is_dir() and (resolved / "index.html").is_file():
            return resolved
    return None
