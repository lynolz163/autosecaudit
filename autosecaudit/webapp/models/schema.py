"""SQLite schema bootstrap and lightweight migration runner."""

from __future__ import annotations

from dataclasses import dataclass
import sqlite3
import threading
import time
from typing import Callable


def _ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, ddl: str) -> None:
    """Add one column if it does not exist yet."""
    existing = {
        str(row[1]).lower()
        for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        if len(row) > 1
    }
    if column_name.lower() in existing:
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")


@dataclass(frozen=True)
class _SchemaMigration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def _migration_0001_initial_schema(conn: sqlite3.Connection) -> None:
    """Create/align baseline schema expected by current web console."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT,
            started_at TEXT,
            ended_at TEXT,
            last_updated_at TEXT,
            target TEXT,
            mode TEXT,
            safety_grade TEXT NOT NULL DEFAULT 'balanced',
            command_json TEXT NOT NULL,
            output_dir TEXT,
            resume TEXT,
            llm_config TEXT,
            return_code INTEGER,
            pid INTEGER,
            error TEXT,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            log_line_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS job_logs (
            job_id TEXT NOT NULL,
            line_no INTEGER NOT NULL,
            ts TEXT NOT NULL,
            line TEXT NOT NULL,
            PRIMARY KEY (job_id, line_no)
        );

        CREATE TABLE IF NOT EXISTS job_artifacts (
            job_id TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL,
            PRIMARY KEY (job_id, path)
        );

        CREATE TABLE IF NOT EXISTS assets (
            asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            scope TEXT,
            default_mode TEXT NOT NULL DEFAULT 'agent',
            tags_json TEXT NOT NULL DEFAULT '[]',
            default_payload_json TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS schedules (
            schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            name TEXT NOT NULL,
            cron_expr TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            notify_on_json TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_run_at TEXT,
            last_job_id TEXT,
            last_error TEXT
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_type TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            detail_json TEXT NOT NULL DEFAULT '{}'
        );

        """
    )
    _ensure_column(conn, "jobs", "created_at", "created_at TEXT")
    _ensure_column(conn, "jobs", "started_at", "started_at TEXT")
    _ensure_column(conn, "jobs", "ended_at", "ended_at TEXT")
    _ensure_column(conn, "jobs", "last_updated_at", "last_updated_at TEXT")
    _ensure_column(conn, "jobs", "target", "target TEXT")
    _ensure_column(conn, "jobs", "mode", "mode TEXT")
    _ensure_column(conn, "jobs", "safety_grade", "safety_grade TEXT NOT NULL DEFAULT 'balanced'")
    _ensure_column(conn, "jobs", "output_dir", "output_dir TEXT")
    _ensure_column(conn, "jobs", "resume", "resume TEXT")
    _ensure_column(conn, "jobs", "llm_config", "llm_config TEXT")
    _ensure_column(conn, "jobs", "return_code", "return_code INTEGER")
    _ensure_column(conn, "jobs", "pid", "pid INTEGER")
    _ensure_column(conn, "jobs", "error", "error TEXT")
    _ensure_column(conn, "jobs", "cancel_requested", "cancel_requested INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "jobs", "log_line_count", "log_line_count INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "assets", "updated_at", "updated_at TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "schedules", "enabled", "enabled INTEGER NOT NULL DEFAULT 1")
    _ensure_column(conn, "schedules", "updated_at", "updated_at TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "username", "username TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "audit_events", "created_at", "created_at TEXT NOT NULL DEFAULT ''")

    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_jobs_created_at
            ON jobs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_job_logs_job_line
            ON job_logs(job_id, line_no);
        CREATE INDEX IF NOT EXISTS idx_job_artifacts_job
            ON job_artifacts(job_id);
        CREATE INDEX IF NOT EXISTS idx_assets_updated_at
            ON assets(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_schedules_enabled
            ON schedules(enabled, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_users_username
            ON users(username);
        CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
            ON audit_events(created_at DESC);
        """
    )


_MIGRATIONS: tuple[_SchemaMigration, ...] = (
    _SchemaMigration(version=1, name="initial_schema", apply=_migration_0001_initial_schema),
)


def _ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Return max applied migration version (0 when none)."""
    _ensure_migration_table(conn)
    row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
    if not row:
        return 0
    return int(row[0] or 0)


def init_schema(conn: sqlite3.Connection, lock: threading.RLock) -> None:
    """Apply schema migrations (idempotent)."""
    with lock, conn:
        _ensure_migration_table(conn)
        applied_versions = {
            int(row[0])
            for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
            if row and row[0] is not None
        }
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for migration in _MIGRATIONS:
            if int(migration.version) in applied_versions:
                continue
            migration.apply(conn)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES(?,?,?)",
                (int(migration.version), migration.name, now),
            )
