from __future__ import annotations

from datetime import datetime, timezone

from autosecaudit.webapp.schedule_service import CronExpression, ScheduleService


class _FakeStore:
    def get_asset(self, asset_id: int) -> dict[str, object]:
        assert asset_id == 7
        return {
            "asset_id": 7,
            "target": "https://example.com",
            "scope": "example.com",
            "default_mode": "agent",
            "default_payload": {"budget": 25},
            "enabled": True,
        }


class _FakeManager:
    def __init__(self) -> None:
        self.store = _FakeStore()


def test_cron_expression_matches_and_computes_next_run() -> None:
    expr = CronExpression("0 2 * * 1")
    monday_0200 = datetime(2026, 3, 2, 2, 0, tzinfo=timezone.utc)
    monday_0100 = datetime(2026, 3, 2, 1, 0, tzinfo=timezone.utc)

    assert expr.matches(monday_0200)
    assert not expr.matches(monday_0100)
    assert expr.next_after(monday_0100) == monday_0200


def test_schedule_service_build_payload_merges_asset_defaults() -> None:
    service = ScheduleService(_FakeManager())
    payload = service._build_payload(  # noqa: SLF001
        {
            "asset_id": 7,
            "payload": {"budget": 50, "mode": "plan"},
        }
    )

    assert payload["target"] == "https://example.com"
    assert payload["scope"] == "example.com"
    assert payload["budget"] == 50
    assert payload["mode"] == "plan"
