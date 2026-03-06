"""Schedule persistence store."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .base import BaseStore


class ScheduleStore(BaseStore):
    """Persist cron schedules and last-run metadata."""

    def create_schedule(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._serialize_schedule_payload(payload, existing=None)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO schedules (
                    asset_id,
                    name,
                    cron_expr,
                    payload_json,
                    notify_on_json,
                    enabled,
                    created_at,
                    updated_at,
                    last_run_at,
                    last_job_id,
                    last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized["asset_id"],
                    normalized["name"],
                    normalized["cron_expr"],
                    normalized["payload_json"],
                    normalized["notify_on_json"],
                    normalized["enabled"],
                    normalized["created_at"],
                    normalized["updated_at"],
                    normalized["last_run_at"],
                    normalized["last_job_id"],
                    normalized["last_error"],
                ),
            )
            schedule_id = int(cursor.lastrowid)
            row = self._conn.execute("SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        return self._deserialize_schedule_row(row)

    def list_schedules(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM schedules ORDER BY updated_at DESC, schedule_id DESC"
            ).fetchall()
        return [self._deserialize_schedule_row(row) for row in rows]

    def get_schedule(self, schedule_id: int) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?",
                (int(schedule_id),),
            ).fetchone()
        if row is None:
            raise KeyError(schedule_id)
        return self._deserialize_schedule_row(row)

    def update_schedule(self, schedule_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_schedule(schedule_id)
        normalized = self._serialize_schedule_payload(payload, existing=existing)
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE schedules
                SET asset_id = ?, name = ?, cron_expr = ?, payload_json = ?, notify_on_json = ?,
                    enabled = ?, updated_at = ?, last_run_at = ?, last_job_id = ?, last_error = ?
                WHERE schedule_id = ?
                """,
                (
                    normalized["asset_id"],
                    normalized["name"],
                    normalized["cron_expr"],
                    normalized["payload_json"],
                    normalized["notify_on_json"],
                    normalized["enabled"],
                    normalized["updated_at"],
                    normalized["last_run_at"],
                    normalized["last_job_id"],
                    normalized["last_error"],
                    int(schedule_id),
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?",
                (int(schedule_id),),
            ).fetchone()
        return self._deserialize_schedule_row(row)

    def delete_schedule(self, schedule_id: int) -> None:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM schedules WHERE schedule_id = ?", (int(schedule_id),))
        if int(cursor.rowcount or 0) == 0:
            raise KeyError(schedule_id)

    def update_schedule_run(
        self,
        schedule_id: int,
        *,
        updated_at: str,
        last_run_at: str | None,
        last_job_id: str | None,
        last_error: str | None,
    ) -> dict[str, Any]:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE schedules
                SET updated_at = ?, last_run_at = ?, last_job_id = ?, last_error = ?
                WHERE schedule_id = ?
                """,
                (updated_at, last_run_at, last_job_id, last_error, int(schedule_id)),
            )
            row = self._conn.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?",
                (int(schedule_id),),
            ).fetchone()
        return self._deserialize_schedule_row(row)

    def _serialize_schedule_payload(self, payload: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
        current = existing or {}
        notify_on = payload.get("notify_on", current.get("notify_on", []))
        if not isinstance(notify_on, list):
            notify_on = [item.strip() for item in str(notify_on).split(",") if item.strip()]
        schedule_payload = payload.get("payload", current.get("payload", {}))
        if not isinstance(schedule_payload, dict):
            schedule_payload = {}
        asset_id_value = payload.get("asset_id", current.get("asset_id"))
        asset_id = int(asset_id_value) if asset_id_value not in (None, "") else None
        return {
            "asset_id": asset_id,
            "name": str(payload.get("name", current.get("name", ""))).strip() or str(current.get("name", "")).strip(),
            "cron_expr": str(payload.get("cron_expr", current.get("cron_expr", ""))).strip() or str(current.get("cron_expr", "")).strip(),
            "payload_json": json.dumps(schedule_payload, ensure_ascii=False),
            "notify_on_json": json.dumps(notify_on, ensure_ascii=False),
            "enabled": 1 if bool(payload.get("enabled", current.get("enabled", True))) else 0,
            "created_at": str(current.get("created_at") or payload.get("created_at")),
            "updated_at": str(payload.get("updated_at") or current.get("updated_at")),
            "last_run_at": payload.get("last_run_at", current.get("last_run_at")),
            "last_job_id": payload.get("last_job_id", current.get("last_job_id")),
            "last_error": payload.get("last_error", current.get("last_error")),
        }

    def _deserialize_schedule_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schedule_id": int(row["schedule_id"]),
            "asset_id": int(row["asset_id"]) if row["asset_id"] is not None else None,
            "name": str(row["name"]),
            "cron_expr": str(row["cron_expr"]),
            "payload": self._parse_json_field(row["payload_json"], default={}),
            "notify_on": self._parse_json_field(row["notify_on_json"], default=[]),
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_run_at": row["last_run_at"],
            "last_job_id": row["last_job_id"],
            "last_error": row["last_error"],
        }
