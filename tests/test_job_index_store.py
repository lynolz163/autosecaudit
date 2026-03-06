from __future__ import annotations

from pathlib import Path

from autosecaudit.webapp.job_index import JobIndexStore


def test_job_index_store_handles_assets_schedules_settings_and_audit(tmp_path: Path) -> None:
    store = JobIndexStore(tmp_path / "web.sqlite3")
    try:
        asset = store.create_asset(
            {
                "name": "Primary Asset",
                "target": "https://example.com",
                "scope": "example.com",
                "default_mode": "agent",
                "tags": ["external", "prod"],
                "default_payload": {"budget": 25},
                "enabled": True,
                "created_at": "2026-03-03T00:00:00Z",
                "updated_at": "2026-03-03T00:00:00Z",
                "notes": "seed",
            }
        )
        schedule = store.create_schedule(
            {
                "asset_id": asset["asset_id"],
                "name": "Weekly Scan",
                "cron_expr": "0 2 * * 1",
                "payload": {"mode": "agent", "budget": 50},
                "notify_on": ["completed", "finding_high"],
                "enabled": True,
                "created_at": "2026-03-03T00:10:00Z",
                "updated_at": "2026-03-03T00:10:00Z",
            }
        )
        setting = store.set_setting("notification_config", {"events": ["completed"]}, updated_at="2026-03-03T00:20:00Z")
        store.add_audit_event(
            created_at="2026-03-03T00:30:00Z",
            actor="tester",
            event_type="asset_created",
            resource_type="asset",
            resource_id=str(asset["asset_id"]),
            detail={"target": asset["target"]},
        )

        assert store.get_asset(asset["asset_id"])["target"] == "https://example.com"
        assert store.list_assets()[0]["tags"] == ["external", "prod"]
        assert store.get_schedule(schedule["schedule_id"])["notify_on"] == ["completed", "finding_high"]
        assert store.list_schedules()[0]["payload"]["budget"] == 50
        assert setting["value"] == {"events": ["completed"]}
        assert store.get_setting("notification_config")["value"] == {"events": ["completed"]}

        events = store.list_audit_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_type"] == "asset_created"
    finally:
        store.close()


def test_job_index_store_counts_enabled_admins(tmp_path: Path) -> None:
    store = JobIndexStore(tmp_path / "users.sqlite3")
    try:
        admin = store.create_user(
            {
                "username": "admin",
                "password_hash": "pbkdf2$demo",
                "role": "admin",
                "display_name": "Admin",
                "enabled": True,
                "created_at": "2026-03-03T01:00:00Z",
                "updated_at": "2026-03-03T01:00:00Z",
                "last_login_at": None,
            }
        )
        store.create_user(
            {
                "username": "viewer",
                "password_hash": "pbkdf2$viewer",
                "role": "viewer",
                "display_name": "Viewer",
                "enabled": True,
                "created_at": "2026-03-03T01:05:00Z",
                "updated_at": "2026-03-03T01:05:00Z",
                "last_login_at": None,
            }
        )

        assert store.count_users() == 2
        assert store.count_enabled_admins() == 1

        store.update_user(
            admin["user_id"],
            {
                "username": "admin",
                "password_hash": "pbkdf2$demo",
                "role": "admin",
                "display_name": "Admin",
                "enabled": False,
                "updated_at": "2026-03-03T01:10:00Z",
            },
        )
        assert store.count_enabled_admins() == 0
    finally:
        store.close()


def test_job_index_store_persists_job_safety_grade(tmp_path: Path) -> None:
    store = JobIndexStore(tmp_path / "jobs.sqlite3")
    try:
        store.upsert_job(
            {
                "job_id": "job-1",
                "status": "queued",
                "created_at": "2026-03-03T02:00:00Z",
                "started_at": None,
                "ended_at": None,
                "last_updated_at": "2026-03-03T02:00:00Z",
                "target": "https://example.com",
                "mode": "agent",
                "safety_grade": "conservative",
                "command": ["python", "-m", "autosecaudit.cli", "--agent-safety-grade", "conservative"],
                "output_dir": str(tmp_path / "out"),
                "resume": None,
                "llm_config": None,
                "return_code": None,
                "pid": None,
                "error": None,
                "cancel_requested": False,
                "log_line_count": 0,
            }
        )

        listed = store.list_jobs()

        assert len(listed) == 1
        assert listed[0]["safety_grade"] == "conservative"
    finally:
        store.close()
