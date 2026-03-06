"""SQLite-backed persistence facade for web-launched jobs."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import threading
from typing import Any

from .models import AssetStore, AuditEventStore, JobStore, ScheduleStore, SettingsStore, UserStore
from .models.base import SQLiteStoreContext
from .models.schema import init_schema


class JobIndexStore:
    """Facade that keeps the historical store API stable while delegating by domain."""

    def __init__(self, db_path: Path) -> None:
        resolved = db_path.resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        lock = threading.RLock()
        conn = sqlite3.connect(str(resolved), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        init_schema(conn, lock)
        self._context = SQLiteStoreContext(db_path=resolved, lock=lock, conn=conn)
        self.jobs = JobStore(self._context)
        self.assets = AssetStore(self._context)
        self.schedules = ScheduleStore(self._context)
        self.settings = SettingsStore(self._context)
        self.users = UserStore(self._context)
        self.audit = AuditEventStore(self._context)

    @property
    def path(self) -> Path:
        """Return SQLite file path."""
        return self._context.db_path

    def close(self) -> None:
        """Close SQLite connection."""
        with self._context.lock:
            if self._context.conn is None:
                return
            self._context.conn.close()
            self._context.conn = None

    def upsert_job(self, record: dict[str, Any]) -> None:
        self.jobs.upsert_job(record)

    def append_log(self, job_id: str, *, line_no: int, entry: dict[str, Any]) -> None:
        self.jobs.append_log(job_id, line_no=line_no, entry=entry)

    def replace_artifacts(self, job_id: str, artifacts: list[dict[str, Any]]) -> None:
        self.jobs.replace_artifacts(job_id, artifacts)

    def get_logs(self, job_id: str, *, offset: int, limit: int) -> dict[str, Any]:
        return self.jobs.get_logs(job_id, offset=offset, limit=limit)

    def list_artifacts(self, job_id: str) -> list[dict[str, Any]]:
        return self.jobs.list_artifacts(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return self.jobs.list_jobs()

    def create_asset(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.assets.create_asset(payload)

    def list_assets(self) -> list[dict[str, Any]]:
        return self.assets.list_assets()

    def get_asset(self, asset_id: int) -> dict[str, Any]:
        return self.assets.get_asset(asset_id)

    def update_asset(self, asset_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.assets.update_asset(asset_id, payload)

    def delete_asset(self, asset_id: int) -> None:
        self.assets.delete_asset(asset_id)

    def create_schedule(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.schedules.create_schedule(payload)

    def list_schedules(self) -> list[dict[str, Any]]:
        return self.schedules.list_schedules()

    def get_schedule(self, schedule_id: int) -> dict[str, Any]:
        return self.schedules.get_schedule(schedule_id)

    def update_schedule(self, schedule_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.schedules.update_schedule(schedule_id, payload)

    def delete_schedule(self, schedule_id: int) -> None:
        self.schedules.delete_schedule(schedule_id)

    def update_schedule_run(
        self,
        schedule_id: int,
        *,
        updated_at: str,
        last_run_at: str | None,
        last_job_id: str | None,
        last_error: str | None,
    ) -> dict[str, Any]:
        return self.schedules.update_schedule_run(
            schedule_id,
            updated_at=updated_at,
            last_run_at=last_run_at,
            last_job_id=last_job_id,
            last_error=last_error,
        )

    def set_setting(self, key: str, value: Any, *, updated_at: str) -> dict[str, Any]:
        return self.settings.set_setting(key, value, updated_at=updated_at)

    def get_setting(self, key: str, default: Any = None) -> dict[str, Any]:
        return self.settings.get_setting(key, default=default)

    def count_users(self) -> int:
        return self.users.count_users()

    def count_enabled_admins(self) -> int:
        return self.users.count_enabled_admins()

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.users.create_user(payload)

    def list_users(self) -> list[dict[str, Any]]:
        return self.users.list_users()

    def get_user(self, user_id: int) -> dict[str, Any]:
        return self.users.get_user(user_id)

    def get_user_by_username(self, username: str) -> dict[str, Any]:
        return self.users.get_user_by_username(username)

    def get_user_auth_record(self, username: str) -> dict[str, Any]:
        return self.users.get_user_auth_record(username)

    def get_user_auth_record_by_id(self, user_id: int) -> dict[str, Any]:
        return self.users.get_user_auth_record_by_id(user_id)

    def update_user(self, user_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.users.update_user(user_id, payload)

    def delete_user(self, user_id: int) -> None:
        self.users.delete_user(user_id)

    def touch_user_login(self, user_id: int, *, last_login_at: str, updated_at: str | None = None) -> dict[str, Any]:
        return self.users.touch_user_login(user_id, last_login_at=last_login_at, updated_at=updated_at)

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
        return self.audit.add_audit_event(
            created_at=created_at,
            actor=actor,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
        )

    def list_audit_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.audit.list_audit_events(limit=limit)
