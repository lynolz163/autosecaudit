"""User persistence store."""

from __future__ import annotations

import sqlite3
from typing import Any

from .base import BaseStore


class UserStore(BaseStore):
    """Persist users and authentication metadata."""

    def count_users(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS value FROM users").fetchone()
        return int((row["value"] if row is not None else 0) or 0)

    def count_enabled_admins(self) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS value
                FROM users
                WHERE enabled = 1 AND lower(role) = 'admin'
                """
            ).fetchone()
        return int((row["value"] if row is not None else 0) or 0)

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._serialize_user_payload(payload, existing=None)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role,
                    display_name,
                    enabled,
                    created_at,
                    updated_at,
                    last_login_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized["username"],
                    normalized["password_hash"],
                    normalized["role"],
                    normalized["display_name"],
                    normalized["enabled"],
                    normalized["created_at"],
                    normalized["updated_at"],
                    normalized["last_login_at"],
                ),
            )
            user_id = int(cursor.lastrowid)
            row = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return self._deserialize_user_row(row)

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users ORDER BY username ASC, user_id ASC"
            ).fetchall()
        return [self._deserialize_user_row(row) for row in rows]

    def get_user(self, user_id: int) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (int(user_id),)).fetchone()
        if row is None:
            raise KeyError(user_id)
        return self._deserialize_user_row(row)

    def get_user_by_username(self, username: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE lower(username) = lower(?)",
                (str(username).strip(),),
            ).fetchone()
        if row is None:
            raise KeyError(username)
        return self._deserialize_user_row(row)

    def get_user_auth_record(self, username: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE lower(username) = lower(?)",
                (str(username).strip(),),
            ).fetchone()
        if row is None:
            raise KeyError(username)
        return self._deserialize_user_row(row, include_secret=True)

    def get_user_auth_record_by_id(self, user_id: int) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (int(user_id),)).fetchone()
        if row is None:
            raise KeyError(user_id)
        return self._deserialize_user_row(row, include_secret=True)

    def update_user(self, user_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_user_auth_record_by_id(user_id)
        normalized = self._serialize_user_payload(payload, existing=existing)
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE users
                SET username = ?, password_hash = ?, role = ?, display_name = ?,
                    enabled = ?, updated_at = ?, last_login_at = ?
                WHERE user_id = ?
                """,
                (
                    normalized["username"],
                    normalized["password_hash"],
                    normalized["role"],
                    normalized["display_name"],
                    normalized["enabled"],
                    normalized["updated_at"],
                    normalized["last_login_at"],
                    int(user_id),
                ),
            )
            row = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (int(user_id),)).fetchone()
        return self._deserialize_user_row(row)

    def delete_user(self, user_id: int) -> None:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM users WHERE user_id = ?", (int(user_id),))
        if int(cursor.rowcount or 0) == 0:
            raise KeyError(user_id)

    def touch_user_login(self, user_id: int, *, last_login_at: str, updated_at: str | None = None) -> dict[str, Any]:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE users
                SET last_login_at = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (last_login_at, updated_at or last_login_at, int(user_id)),
            )
            row = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (int(user_id),)).fetchone()
        if row is None:
            raise KeyError(user_id)
        return self._deserialize_user_row(row)

    def _serialize_user_payload(self, payload: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
        current = existing or {}
        username = str(payload.get("username", current.get("username", ""))).strip()
        password_hash = str(payload.get("password_hash", current.get("password_hash", ""))).strip()
        role = str(payload.get("role", current.get("role", "viewer"))).strip().lower() or "viewer"
        if role not in {"admin", "operator", "viewer"}:
            raise ValueError(f"invalid_role: {role}")
        if not username:
            raise ValueError("username is required")
        if not password_hash:
            raise ValueError("password_hash is required")
        return {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "display_name": str(payload.get("display_name", current.get("display_name", ""))).strip() or None,
            "enabled": 1 if bool(payload.get("enabled", current.get("enabled", True))) else 0,
            "created_at": str(current.get("created_at") or payload.get("created_at")),
            "updated_at": str(payload.get("updated_at") or current.get("updated_at")),
            "last_login_at": payload.get("last_login_at", current.get("last_login_at")),
        }

    def _deserialize_user_row(self, row: sqlite3.Row, *, include_secret: bool = False) -> dict[str, Any]:
        item = {
            "user_id": int(row["user_id"]),
            "username": str(row["username"]),
            "role": str(row["role"]),
            "display_name": row["display_name"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_login_at": row["last_login_at"],
        }
        if include_secret:
            item["password_hash"] = str(row["password_hash"])
        return item
