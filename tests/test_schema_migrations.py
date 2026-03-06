from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from autosecaudit.webapp.models.schema import get_schema_version, init_schema


def _open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def test_init_schema_bootstraps_migration_table(tmp_path: Path) -> None:
    db_path = tmp_path / "schema.db"
    conn = _open_db(db_path)
    try:
        init_schema(conn, threading.RLock())
        assert get_schema_version(conn) == 1
        jobs_row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='jobs'"
        ).fetchone()
        assert jobs_row is not None
    finally:
        conn.close()


def test_init_schema_upgrades_legacy_jobs_table(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    conn = _open_db(db_path)
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    command_json TEXT NOT NULL
                )
                """
            )
        init_schema(conn, threading.RLock())
        columns = {
            str(row[1]).lower()
            for row in conn.execute("PRAGMA table_info(jobs)").fetchall()
            if len(row) > 1
        }
        assert "safety_grade" in columns
        assert get_schema_version(conn) == 1
    finally:
        conn.close()

