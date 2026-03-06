"""Tests for notifier integrations (integrations/notifier.py)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from autosecaudit.integrations.notifier import (
    DingTalkNotifier,
    NotificationEvent,
    NotifierFanout,
    TelegramNotifier,
    WeComNotifier,
    WebhookNotifier,
    build_notifier_from_config,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def high_event() -> NotificationEvent:
    return NotificationEvent(
        event_type="audit_finding",
        severity="high",
        title="SQL Injection Detected",
        message="Parameterized endpoint /api/user is vulnerable.",
        context={"target": "http://example.com", "param": "id"},
    )


@pytest.fixture()
def info_event() -> NotificationEvent:
    return NotificationEvent(
        event_type="audit_completed",
        severity="info",
        title="Scan Completed",
        message="All checks passed.",
        context={},
    )


FAKE_URL = "https://oapi.dingtalk.com/robot/send?access_token=TEST"


# ---------------------------------------------------------------------------
# DingTalkNotifier
# ---------------------------------------------------------------------------

class TestDingTalkNotifier:
    def test_high_severity_at_all(self, high_event: NotificationEvent):
        """High severity events should trigger @all notification."""
        n = DingTalkNotifier(webhook_url=FAKE_URL)
        payload = n._build_webhook_payload(high_event)
        assert payload.get("msgtype") == "markdown"
        assert payload["at"]["isAtAll"] is True
        n.close()

    def test_info_severity_no_at_all(self, info_event: NotificationEvent):
        """Info severity should not trigger @all."""
        n = DingTalkNotifier(webhook_url=FAKE_URL)
        payload = n._build_webhook_payload(info_event)
        assert payload["at"]["isAtAll"] is False
        n.close()

    def test_payload_has_title(self, high_event: NotificationEvent):
        n = DingTalkNotifier(webhook_url=FAKE_URL)
        payload = n._build_webhook_payload(high_event)
        assert payload["markdown"]["title"] == high_event.title
        n.close()

    def test_payload_contains_message(self, high_event: NotificationEvent):
        n = DingTalkNotifier(webhook_url=FAKE_URL)
        payload = n._build_webhook_payload(high_event)
        markdown_text = payload["markdown"]["text"]
        assert "SQL Injection" in markdown_text
        n.close()

    def test_gateway_path(self, high_event: NotificationEvent):
        """With gateway_base_url, payload should be wrapped for routing."""
        n = DingTalkNotifier(webhook_url=FAKE_URL, gateway_base_url="https://gw.example.com")
        payload = n._build_webhook_payload(high_event)
        assert payload.get("route") == "dingtalk"
        assert "json" in payload
        assert "event" in payload
        n.close()


# ---------------------------------------------------------------------------
# WeComNotifier
# ---------------------------------------------------------------------------

class TestWeComNotifier:
    def test_msgtype_is_markdown(self, high_event: NotificationEvent):
        n = WeComNotifier(webhook_url=FAKE_URL)
        payload = n._build_webhook_payload(high_event)
        assert payload.get("msgtype") == "markdown"
        assert "content" in payload["markdown"]
        n.close()

    def test_payload_contains_title(self, high_event: NotificationEvent):
        n = WeComNotifier(webhook_url=FAKE_URL)
        payload = n._build_webhook_payload(high_event)
        assert "SQL Injection" in payload["markdown"]["content"]
        n.close()

    def test_gateway_path(self, info_event: NotificationEvent):
        n = WeComNotifier(webhook_url=FAKE_URL, gateway_base_url="https://gw.example.com")
        payload = n._build_webhook_payload(info_event)
        assert payload.get("route") == "wecom"
        n.close()


# ---------------------------------------------------------------------------
# TelegramNotifier
# ---------------------------------------------------------------------------

class TestTelegramNotifier:
    def test_telegram_payload_has_chat_id(self, high_event: NotificationEvent):
        n = TelegramNotifier(bot_token="FAKE_TOKEN", chat_id="12345678")
        payload = n._build_webhook_payload(high_event)
        assert payload.get("chat_id") == "12345678"
        assert payload.get("parse_mode") == "Markdown"
        n.close()

    def test_telegram_message_contains_severity(self, high_event: NotificationEvent):
        n = TelegramNotifier(bot_token="FAKE_TOKEN", chat_id="12345678")
        payload = n._build_webhook_payload(high_event)
        text = payload.get("text", "")
        # High severity should have [HIGH] prefix
        assert "[HIGH]" in text
        n.close()


# ---------------------------------------------------------------------------
# WebhookNotifier – dispatch
# ---------------------------------------------------------------------------

class TestWebhookNotifier:
    def test_dispatch_sends_post_request(self, high_event: NotificationEvent):
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        n = WebhookNotifier(webhook_url="https://example.com/webhook")
        with patch("autosecaudit.integrations.notifier.urllib_request.urlopen", fake_urlopen):
            n.notify(high_event)
            n.flush(timeout_seconds=1.0)

        assert len(captured) == 1
        sent = captured[0]
        assert sent.get_method() == "POST"
        body = json.loads(sent.data.decode("utf-8"))
        assert body["title"] == high_event.title
        n.close()


# ---------------------------------------------------------------------------
# NotifierFanout
# ---------------------------------------------------------------------------

class TestNotifierFanout:
    def test_fanout_delivers_to_all(self, high_event: NotificationEvent):
        n1 = MagicMock()
        n2 = MagicMock()
        fanout = NotifierFanout([n1, n2])
        fanout.notify(high_event)
        n1.notify.assert_called_once_with(high_event)
        n2.notify.assert_called_once_with(high_event)

    def test_fanout_flush_calls_all(self):
        n1, n2 = MagicMock(), MagicMock()
        fanout = NotifierFanout([n1, n2])
        fanout.flush(timeout_seconds=0.5)
        n1.flush.assert_called_once()
        n2.flush.assert_called_once()


# ---------------------------------------------------------------------------
# build_notifier_from_config
# ---------------------------------------------------------------------------

class TestBuildNotifierFromConfig:
    def test_telegram_notifier_built(self):
        config = {
            "notifiers": {
                "tg": {
                    "enabled": True,
                    "type": "telegram",
                    "bot_token": "FAKE_TOKEN",
                    "chat_id": "99",
                }
            }
        }
        n = build_notifier_from_config(config)
        assert isinstance(n, TelegramNotifier)
        n.close()

    def test_dingtalk_notifier_built(self):
        config = {
            "notifiers": {
                "dk": {
                    "enabled": True,
                    "type": "dingtalk",
                    "webhook_url": FAKE_URL,
                }
            }
        }
        n = build_notifier_from_config(config)
        assert isinstance(n, DingTalkNotifier)
        n.close()

    def test_wecom_notifier_built(self):
        config = {
            "notifiers": {
                "wc": {
                    "enabled": True,
                    "type": "wecom",
                    "webhook_url": FAKE_URL,
                }
            }
        }
        n = build_notifier_from_config(config)
        assert isinstance(n, WeComNotifier)
        n.close()

    def test_disabled_notifier_skipped(self):
        config = {
            "notifiers": {
                "dk": {
                    "enabled": False,
                    "type": "dingtalk",
                    "webhook_url": FAKE_URL,
                }
            }
        }
        n = build_notifier_from_config(config)
        assert n is None

    def test_multiple_notifiers_fanout(self):
        config = {
            "notifiers": {
                "dk": {"enabled": True, "type": "dingtalk", "webhook_url": FAKE_URL},
                "wc": {"enabled": True, "type": "wecom", "webhook_url": FAKE_URL},
            }
        }
        n = build_notifier_from_config(config)
        assert isinstance(n, NotifierFanout)
        n.close()

    def test_empty_config_returns_none(self):
        assert build_notifier_from_config({}) is None
        assert build_notifier_from_config({"notifiers": {}}) is None

    def test_unknown_notifier_type_ignored(self):
        """Unknown types should be silently skipped, not raise."""
        config = {
            "notifiers": {
                "slack": {"enabled": True, "type": "slack", "webhook_url": FAKE_URL}
            }
        }
        # Result will be None since no known types are matched
        result = build_notifier_from_config(config)
        assert result is None
