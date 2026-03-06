"""Asset persistence store."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .base import BaseStore


class AssetStore(BaseStore):
    """Persist managed assets."""

    def create_asset(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._serialize_asset_payload(payload, existing=None)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO assets (
                    name,
                    target,
                    scope,
                    default_mode,
                    tags_json,
                    default_payload_json,
                    enabled,
                    created_at,
                    updated_at,
                    notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized["name"],
                    normalized["target"],
                    normalized["scope"],
                    normalized["default_mode"],
                    normalized["tags_json"],
                    normalized["default_payload_json"],
                    normalized["enabled"],
                    normalized["created_at"],
                    normalized["updated_at"],
                    normalized["notes"],
                ),
            )
            asset_id = int(cursor.lastrowid)
            row = self._conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return self._deserialize_asset_row(row)

    def list_assets(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM assets ORDER BY updated_at DESC, asset_id DESC"
            ).fetchall()
        return [self._deserialize_asset_row(row) for row in rows]

    def get_asset(self, asset_id: int) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM assets WHERE asset_id = ?", (int(asset_id),)).fetchone()
        if row is None:
            raise KeyError(asset_id)
        return self._deserialize_asset_row(row)

    def update_asset(self, asset_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_asset(asset_id)
        normalized = self._serialize_asset_payload(payload, existing=existing)
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE assets
                SET name = ?, target = ?, scope = ?, default_mode = ?, tags_json = ?,
                    default_payload_json = ?, enabled = ?, updated_at = ?, notes = ?
                WHERE asset_id = ?
                """,
                (
                    normalized["name"],
                    normalized["target"],
                    normalized["scope"],
                    normalized["default_mode"],
                    normalized["tags_json"],
                    normalized["default_payload_json"],
                    normalized["enabled"],
                    normalized["updated_at"],
                    normalized["notes"],
                    int(asset_id),
                ),
            )
            row = self._conn.execute("SELECT * FROM assets WHERE asset_id = ?", (int(asset_id),)).fetchone()
        return self._deserialize_asset_row(row)

    def delete_asset(self, asset_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM schedules WHERE asset_id = ?", (int(asset_id),))
            cursor = self._conn.execute("DELETE FROM assets WHERE asset_id = ?", (int(asset_id),))
        if int(cursor.rowcount or 0) == 0:
            raise KeyError(asset_id)

    def _serialize_asset_payload(self, payload: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
        current = existing or {}
        tags = payload.get("tags", current.get("tags", []))
        if not isinstance(tags, list):
            tags = [item.strip() for item in str(tags).split(",") if item.strip()]
        default_payload = payload.get("default_payload", current.get("default_payload", {}))
        if not isinstance(default_payload, dict):
            default_payload = {}
        return {
            "name": str(payload.get("name", current.get("name", ""))).strip() or str(current.get("name", "")).strip(),
            "target": str(payload.get("target", current.get("target", ""))).strip() or str(current.get("target", "")).strip(),
            "scope": str(payload.get("scope", current.get("scope", ""))).strip() or None,
            "default_mode": str(payload.get("default_mode", current.get("default_mode", "agent"))).strip() or "agent",
            "tags_json": json.dumps(tags, ensure_ascii=False),
            "default_payload_json": json.dumps(default_payload, ensure_ascii=False),
            "enabled": 1 if bool(payload.get("enabled", current.get("enabled", True))) else 0,
            "created_at": str(current.get("created_at") or payload.get("created_at")),
            "updated_at": str(payload.get("updated_at") or current.get("updated_at")),
            "notes": str(payload.get("notes", current.get("notes", ""))).strip() or None,
        }

    def _deserialize_asset_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "asset_id": int(row["asset_id"]),
            "name": str(row["name"]),
            "target": str(row["target"]),
            "scope": row["scope"],
            "default_mode": str(row["default_mode"]),
            "tags": self._parse_json_field(row["tags_json"], default=[]),
            "default_payload": self._parse_json_field(row["default_payload_json"], default={}),
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "notes": row["notes"],
        }
