"""Application settings store."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseStore


class SettingsStore(BaseStore):
    """Persist JSON runtime settings."""

    def set_setting(self, key: str, value: Any, *, updated_at: str) -> dict[str, Any]:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO app_settings (setting_key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (str(key), json.dumps(value, ensure_ascii=False), updated_at),
            )
        return {"setting_key": str(key), "value": value, "updated_at": updated_at}

    def get_setting(self, key: str, default: Any = None) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT setting_key, value_json, updated_at FROM app_settings WHERE setting_key = ?",
                (str(key),),
            ).fetchone()
        if row is None:
            return {"setting_key": str(key), "value": default, "updated_at": None}
        try:
            value = json.loads(str(row["value_json"]))
        except json.JSONDecodeError:
            value = default
        return {"setting_key": str(row["setting_key"]), "value": value, "updated_at": row["updated_at"]}
