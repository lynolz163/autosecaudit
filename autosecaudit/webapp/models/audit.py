"""Audit event persistence store."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .base import BaseStore


class AuditEventStore(BaseStore):
    """Persist platform audit events."""

    def add_audit_event(
        self,
        *,
        created_at: str,
        actor: str,
        event_type: str,
        resource_type: str,
        resource_id: str | None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = detail if isinstance(detail, dict) else {}
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO audit_events (created_at, actor, event_type, resource_type, resource_id, detail_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    actor,
                    event_type,
                    resource_type,
                    resource_id,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            event_id = int(cursor.lastrowid)
            row = self._conn.execute("SELECT * FROM audit_events WHERE event_id = ?", (event_id,)).fetchone()
        return self._deserialize_audit_event_row(row)

    def list_audit_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_events ORDER BY created_at DESC, event_id DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [self._deserialize_audit_event_row(row) for row in rows]

    def _deserialize_audit_event_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": int(row["event_id"]),
            "created_at": row["created_at"],
            "actor": str(row["actor"]),
            "event_type": str(row["event_type"]),
            "resource_type": str(row["resource_type"]),
            "resource_id": row["resource_id"],
            "detail": self._parse_json_field(row["detail_json"], default={}),
        }
