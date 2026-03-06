"""Shared SQLite store primitives."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SQLiteStoreContext:
    """Shared SQLite resources reused by sub-stores."""

    db_path: Path
    lock: threading.RLock
    conn: sqlite3.Connection | None

    def require_conn(self) -> sqlite3.Connection:
        """Return the active connection or fail if the store is closed."""
        if self.conn is None:
            raise RuntimeError("sqlite store is closed")
        return self.conn


class BaseStore:
    """Base helper class for concrete SQLite-backed stores."""

    def __init__(self, context: SQLiteStoreContext) -> None:
        self._context = context

    @property
    def _lock(self) -> threading.RLock:
        return self._context.lock

    @property
    def _conn(self) -> sqlite3.Connection:
        return self._context.require_conn()

    def _parse_json_field(self, raw: Any, *, default: Any) -> Any:
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return default
        return default
