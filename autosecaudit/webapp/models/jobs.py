"""Job persistence store."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .base import BaseStore


class JobStore(BaseStore):
    """Persist job metadata, logs, and artifact indexes."""

    def upsert_job(self, record: dict[str, Any]) -> None:
        payload = self._serialize_job_record(record)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO jobs (
                    job_id,
                    status,
                    created_at,
                    started_at,
                    ended_at,
                    last_updated_at,
                    target,
                    mode,
                    safety_grade,
                    command_json,
                    output_dir,
                    resume,
                    llm_config,
                    return_code,
                    pid,
                    error,
                    cancel_requested,
                    log_line_count
                ) VALUES (
                    :job_id,
                    :status,
                    :created_at,
                    :started_at,
                    :ended_at,
                    :last_updated_at,
                    :target,
                    :mode,
                    :safety_grade,
                    :command_json,
                    :output_dir,
                    :resume,
                    :llm_config,
                    :return_code,
                    :pid,
                    :error,
                    :cancel_requested,
                    :log_line_count
                )
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    created_at = excluded.created_at,
                    started_at = excluded.started_at,
                    ended_at = excluded.ended_at,
                    last_updated_at = excluded.last_updated_at,
                    target = excluded.target,
                    mode = excluded.mode,
                    safety_grade = excluded.safety_grade,
                    command_json = excluded.command_json,
                    output_dir = excluded.output_dir,
                    resume = excluded.resume,
                    llm_config = excluded.llm_config,
                    return_code = excluded.return_code,
                    pid = excluded.pid,
                    error = excluded.error,
                    cancel_requested = excluded.cancel_requested,
                    log_line_count = excluded.log_line_count
                """,
                payload,
            )

    def append_log(self, job_id: str, *, line_no: int, entry: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO job_logs (job_id, line_no, ts, line)
                VALUES (?, ?, ?, ?)
                """,
                (job_id, int(line_no), str(entry.get("ts", "")), str(entry.get("line", ""))),
            )

    def replace_artifacts(self, job_id: str, artifacts: list[dict[str, Any]]) -> None:
        normalized = [
            (
                job_id,
                str(item.get("path", "")),
                int(item.get("size", 0) or 0),
                int(item.get("mtime", 0) or 0),
            )
            for item in artifacts
            if str(item.get("path", ""))
        ]
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM job_artifacts WHERE job_id = ?", (job_id,))
            if normalized:
                self._conn.executemany(
                    """
                    INSERT INTO job_artifacts (job_id, path, size, mtime)
                    VALUES (?, ?, ?, ?)
                    """,
                    normalized,
                )

    def get_logs(self, job_id: str, *, offset: int, limit: int) -> dict[str, Any]:
        safe_offset = max(0, int(offset))
        safe_limit = max(1, int(limit))
        with self._lock:
            row = self._conn.execute(
                "SELECT log_line_count FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise KeyError(job_id)
            total = int(row["log_line_count"] or 0)
            rows = self._conn.execute(
                """
                SELECT ts, line
                FROM job_logs
                WHERE job_id = ? AND line_no >= ?
                ORDER BY line_no ASC
                LIMIT ?
                """,
                (job_id, safe_offset, safe_limit),
            ).fetchall()
        items = [{"ts": str(item["ts"]), "line": str(item["line"])} for item in rows]
        return {
            "job_id": job_id,
            "offset": safe_offset,
            "next_offset": safe_offset + len(items),
            "total": total,
            "items": items,
        }

    def list_artifacts(self, job_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT path, size, mtime
                FROM job_artifacts
                WHERE job_id = ?
                ORDER BY path ASC
                """,
                (job_id,),
            ).fetchall()
        return [
            {"path": str(item["path"]), "size": int(item["size"] or 0), "mtime": int(item["mtime"] or 0)}
            for item in rows
        ]

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    job_id,
                    status,
                    created_at,
                    started_at,
                    ended_at,
                    last_updated_at,
                    target,
                    mode,
                    safety_grade,
                    command_json,
                    output_dir,
                    resume,
                    llm_config,
                    return_code,
                    pid,
                    error,
                    cancel_requested,
                    log_line_count
                FROM jobs
                ORDER BY created_at DESC, job_id DESC
                """
            ).fetchall()
        return [self._deserialize_job_row(row) for row in rows]

    def _serialize_job_record(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "job_id": str(record.get("job_id", "")),
            "status": str(record.get("status", "")),
            "created_at": record.get("created_at"),
            "started_at": record.get("started_at"),
            "ended_at": record.get("ended_at"),
            "last_updated_at": record.get("last_updated_at"),
            "target": record.get("target"),
            "mode": record.get("mode"),
            "safety_grade": record.get("safety_grade") or "balanced",
            "command_json": json.dumps(list(record.get("command", [])), ensure_ascii=False),
            "output_dir": record.get("output_dir"),
            "resume": record.get("resume"),
            "llm_config": record.get("llm_config"),
            "return_code": record.get("return_code"),
            "pid": record.get("pid"),
            "error": record.get("error"),
            "cancel_requested": 1 if bool(record.get("cancel_requested", False)) else 0,
            "log_line_count": int(record.get("log_line_count", 0) or 0),
        }

    def _deserialize_job_row(self, row: sqlite3.Row) -> dict[str, Any]:
        command_payload = row["command_json"]
        command: list[str] = []
        if isinstance(command_payload, str) and command_payload.strip():
            try:
                parsed = json.loads(command_payload)
            except json.JSONDecodeError:
                parsed = []
            if isinstance(parsed, list):
                command = [str(item) for item in parsed]
        return {
            "job_id": str(row["job_id"]),
            "status": str(row["status"]),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "ended_at": row["ended_at"],
            "last_updated_at": row["last_updated_at"],
            "target": row["target"],
            "mode": row["mode"],
            "safety_grade": row["safety_grade"] or "balanced",
            "command": command,
            "output_dir": row["output_dir"],
            "resume": row["resume"],
            "llm_config": row["llm_config"],
            "return_code": row["return_code"],
            "pid": row["pid"],
            "error": row["error"],
            "cancel_requested": bool(row["cancel_requested"]),
            "log_line_count": int(row["log_line_count"] or 0),
        }
