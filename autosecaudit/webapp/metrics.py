"""Prometheus metrics for the AutoSecAudit web console."""

from __future__ import annotations

from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest
from prometheus_fastapi_instrumentator import Instrumentator


JOB_STATUS_GAUGE = Gauge(
    "autosecaudit_jobs_total",
    "Indexed AutoSecAudit jobs by status.",
    labelnames=("status",),
)
QUEUE_DEPTH_GAUGE = Gauge(
    "autosecaudit_job_queue_depth",
    "Queued and running AutoSecAudit jobs.",
)
ASSET_TOTAL_GAUGE = Gauge(
    "autosecaudit_assets_total",
    "Managed asset records.",
)
SCHEDULE_TOTAL_GAUGE = Gauge(
    "autosecaudit_schedules_total",
    "Persisted schedule records.",
)
ACTIVE_SCHEDULE_TOTAL_GAUGE = Gauge(
    "autosecaudit_schedules_active_total",
    "Enabled schedule records.",
)
USER_TOTAL_GAUGE = Gauge(
    "autosecaudit_users_total",
    "Persisted user records.",
)
AUDIT_EVENT_TOTAL_GAUGE = Gauge(
    "autosecaudit_audit_events_recent_total",
    "Recent audit event rows returned by the store window.",
)


def instrument_app(app: Any) -> None:
    """Attach Prometheus HTTP instrumentation to one FastAPI app."""
    Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=False,
        excluded_handlers=["/healthz"],
        inprogress_name="autosecaudit_http_requests_inprogress",
        inprogress_labels=True,
    ).instrument(app)


def update_runtime_metrics(manager: Any) -> None:
    """Refresh gauges derived from current persisted web runtime state."""
    jobs = manager.list_jobs()
    counts = {status: 0 for status in ("queued", "running", "completed", "failed", "error", "canceled")}
    for item in jobs:
        status = str(item.get("status", "") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    for status, value in counts.items():
        JOB_STATUS_GAUGE.labels(status=status).set(value)

    active_count = counts.get("queued", 0) + counts.get("running", 0)
    QUEUE_DEPTH_GAUGE.set(active_count)

    assets = manager.store.list_assets()
    schedules = manager.store.list_schedules()
    users_total = manager.store.count_users()
    audit_events = manager.store.list_audit_events(limit=100)

    ASSET_TOTAL_GAUGE.set(len(assets))
    SCHEDULE_TOTAL_GAUGE.set(len(schedules))
    ACTIVE_SCHEDULE_TOTAL_GAUGE.set(sum(1 for item in schedules if bool(item.get("enabled"))))
    USER_TOTAL_GAUGE.set(users_total)
    AUDIT_EVENT_TOTAL_GAUGE.set(len(audit_events))


def render_metrics_response(manager: Any) -> tuple[bytes, str]:
    """Render the Prometheus text exposition payload."""
    update_runtime_metrics(manager)
    return generate_latest(), CONTENT_TYPE_LATEST
