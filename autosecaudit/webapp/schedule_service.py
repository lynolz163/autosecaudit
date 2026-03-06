"""In-process cron scheduler for AutoSecAudit web jobs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import Any

from .runtime import _utc_now
from .services.job_manager import JobManager


def utc_now_dt() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class CronField:
    """One parsed cron field."""

    allowed: set[int]

    def matches(self, value: int) -> bool:
        return value in self.allowed


class CronExpression:
    """Minimal 5-field cron matcher."""

    def __init__(self, expr: str) -> None:
        parts = [item.strip() for item in str(expr).split() if item.strip()]
        if len(parts) != 5:
            raise ValueError("cron expression must contain exactly 5 fields")

        self._minute = self._parse_field(parts[0], minimum=0, maximum=59)
        self._hour = self._parse_field(parts[1], minimum=0, maximum=23)
        self._day = self._parse_field(parts[2], minimum=1, maximum=31)
        self._month = self._parse_field(parts[3], minimum=1, maximum=12)
        self._weekday = self._parse_field(parts[4], minimum=0, maximum=7)

    def matches(self, dt: datetime) -> bool:
        weekday = (dt.weekday() + 1) % 7
        return (
            self._minute.matches(dt.minute)
            and self._hour.matches(dt.hour)
            and self._day.matches(dt.day)
            and self._month.matches(dt.month)
            and (weekday in self._weekday.allowed or (weekday == 0 and 7 in self._weekday.allowed))
        )

    def next_after(self, dt: datetime, *, max_minutes: int = 60 * 24 * 366) -> datetime | None:
        current = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(max_minutes):
            if self.matches(current):
                return current
            current += timedelta(minutes=1)
        return None

    def _parse_field(self, raw: str, *, minimum: int, maximum: int) -> CronField:
        values: set[int] = set()
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            step = 1
            base = token
            if "/" in token:
                base, step_raw = token.split("/", maxsplit=1)
                try:
                    step = int(step_raw)
                except ValueError as exc:
                    raise ValueError(f"invalid cron step: {token}") from exc
                if step <= 0:
                    raise ValueError(f"invalid cron step: {token}")

            if base == "*":
                start = minimum
                end = maximum
            elif "-" in base:
                start_raw, end_raw = base.split("-", maxsplit=1)
                start = int(start_raw)
                end = int(end_raw)
            else:
                start = int(base)
                end = start

            if start < minimum or end > maximum or start > end:
                raise ValueError(f"cron field out of range: {raw}")
            for value in range(start, end + 1, step):
                values.add(value)

        if not values:
            raise ValueError(f"empty cron field: {raw}")
        return CronField(allowed=values)


class ScheduleService:
    """Background service that triggers jobs from persisted schedules."""

    def __init__(self, manager: JobManager, *, poll_interval_seconds: float = 15.0) -> None:
        self._manager = manager
        self._poll_interval_seconds = max(5.0, float(poll_interval_seconds))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start background scheduler thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="autosecaudit-scheduler")
        self._thread.start()

    def stop(self) -> None:
        """Stop background scheduler thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def preview_next_run(self, cron_expr: str, *, after: datetime | None = None) -> str | None:
        """Compute next run timestamp for one cron expression."""
        expr = CronExpression(cron_expr)
        next_dt = expr.next_after(after or utc_now_dt())
        return next_dt.isoformat() if next_dt is not None else None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                pass
            self._stop_event.wait(self._poll_interval_seconds)

    def _tick(self) -> None:
        store = self._manager.store
        now = utc_now_dt().replace(second=0, microsecond=0)
        schedules = store.list_schedules()
        for schedule in schedules:
            if not bool(schedule.get("enabled", False)):
                continue
            cron_expr = str(schedule.get("cron_expr", "")).strip()
            if not cron_expr:
                continue
            try:
                expression = CronExpression(cron_expr)
            except ValueError as exc:
                store.update_schedule_run(
                    int(schedule["schedule_id"]),
                    updated_at=_utc_now(),
                    last_run_at=schedule.get("last_run_at"),
                    last_job_id=schedule.get("last_job_id"),
                    last_error=str(exc),
                )
                continue

            if not expression.matches(now):
                continue
            last_run_at = str(schedule.get("last_run_at") or "").strip()
            if last_run_at:
                try:
                    last_run_dt = datetime.fromisoformat(last_run_at.replace("Z", "+00:00"))
                except ValueError:
                    last_run_dt = None
                if last_run_dt is not None and last_run_dt.replace(second=0, microsecond=0) >= now:
                    continue

            self._run_schedule(schedule)

    def _run_schedule(self, schedule: dict[str, Any]) -> None:
        store = self._manager.store
        now_iso = _utc_now()
        schedule_id = int(schedule["schedule_id"])
        try:
            payload = self._build_payload(schedule)
            job = self._manager.submit(payload, actor=f"scheduler:schedule-{schedule_id}")
            store.update_schedule_run(
                schedule_id,
                updated_at=now_iso,
                last_run_at=now_iso,
                last_job_id=str(job["job_id"]),
                last_error=None,
            )
            store.add_audit_event(
                created_at=now_iso,
                actor="scheduler",
                event_type="schedule_triggered",
                resource_type="schedule",
                resource_id=str(schedule_id),
                detail={"job_id": job["job_id"], "payload_target": payload.get("target")},
            )
        except Exception as exc:  # noqa: BLE001
            store.update_schedule_run(
                schedule_id,
                updated_at=now_iso,
                last_run_at=now_iso,
                last_job_id=None,
                last_error=str(exc),
            )
            store.add_audit_event(
                created_at=now_iso,
                actor="scheduler",
                event_type="schedule_failed",
                resource_type="schedule",
                resource_id=str(schedule_id),
                detail={"error": str(exc)},
            )

    def _build_payload(self, schedule: dict[str, Any]) -> dict[str, Any]:
        store = self._manager.store
        payload = dict(schedule.get("payload", {}))
        asset_id = schedule.get("asset_id")
        if asset_id is not None:
            asset = store.get_asset(int(asset_id))
            if not bool(asset.get("enabled", False)):
                raise ValueError(f"asset_disabled: {asset_id}")
            base_payload = dict(asset.get("default_payload", {}))
            base_payload.update(payload)
            payload = base_payload
            payload.setdefault("target", asset.get("target"))
            payload.setdefault("scope", asset.get("scope"))
            payload.setdefault("mode", asset.get("default_mode") or "agent")
        if not str(payload.get("target", "")).strip():
            raise ValueError("schedule target is required")
        return payload
