"""Asynchronous notifier integrations for agent runtime alerts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
import queue
import threading
import time
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request


@dataclass(frozen=True)
class NotificationEvent:
    """Structured runtime notification event."""

    event_type: str
    severity: str
    title: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize event to dict."""
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp,
        }


class BaseNotifier(ABC):
    """Abstract notifier contract."""

    @abstractmethod
    def notify(self, event: NotificationEvent) -> None:
        """Enqueue or send one event."""
        raise NotImplementedError

    def flush(self, timeout_seconds: float = 2.0) -> None:
        """Flush pending events if supported."""
        return

    def close(self) -> None:
        """Close notifier resources if supported."""
        return


class NoopNotifier(BaseNotifier):
    """No-op notifier implementation."""

    def notify(self, event: NotificationEvent) -> None:
        return


class WebhookNotifier(BaseNotifier):
    """
    Async JSON webhook notifier.

    Features:
    - Background worker thread
    - Configurable headers and timeout
    - Optional `gateway_base_url` to support gateway/proxy dispatch routing
    """

    def __init__(
        self,
        *,
        webhook_url: str,
        timeout_seconds: float = 5.0,
        headers: dict[str, str] | None = None,
        gateway_base_url: str | None = None,
        logger: Any | None = None,
        queue_size: int = 200,
    ) -> None:
        self._webhook_url = webhook_url.strip()
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self._headers = dict(headers or {})
        self._gateway_base_url = (gateway_base_url or "").strip()
        self._logger = logger
        self._queue: queue.Queue[NotificationEvent | None] = queue.Queue(maxsize=max(10, queue_size))
        self._closed = False
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="autosecaudit-notifier")
        self._worker.start()

    def notify(self, event: NotificationEvent) -> None:
        """Queue one event for async delivery."""
        if self._closed:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._log_warning("Notifier queue full; dropping event: %s", event.title)

    def flush(self, timeout_seconds: float = 2.0) -> None:
        """Best-effort wait until queue drains."""
        deadline = time.time() + max(0.1, timeout_seconds)
        while not self._queue.empty() and time.time() < deadline:
            time.sleep(0.05)

    def close(self) -> None:
        """Stop worker thread after flushing queue."""
        if self._closed:
            return
        self._closed = True
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._worker.join(timeout=1.5)

    def _worker_loop(self) -> None:
        """Background worker dispatch loop."""
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                if self._closed:
                    break
                continue

            if item is None:
                self._queue.task_done()
                break

            try:
                self._dispatch_event(item)
            except Exception as exc:  # noqa: BLE001
                self._log_warning("Notifier dispatch failed: %s", exc)
            finally:
                self._queue.task_done()

    def _dispatch_event(self, event: NotificationEvent) -> None:
        """Send one event to webhook endpoint."""
        endpoint = self._resolve_endpoint_url()
        payload = self._build_webhook_payload(event)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self._headers)
        request = urllib_request.Request(
            url=endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=self._timeout_seconds) as _response:
                return
        except urllib_error.HTTPError as exc:
            response_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {response_body[:300]}") from exc
        except urllib_error.URLError as exc:
            raise RuntimeError(f"network error: {exc}") from exc
        except OSError as exc:
            raise RuntimeError(f"request error: {exc}") from exc

    def _resolve_endpoint_url(self) -> str:
        """
        Resolve endpoint URL.

        If `gateway_base_url` is set, use `<gateway_base_url>/notify` and include the
        original webhook URL in the payload for gateway-side routing.
        """
        if self._gateway_base_url:
            return f"{self._gateway_base_url.rstrip('/')}/notify"
        return self._webhook_url

    def _build_webhook_payload(self, event: NotificationEvent) -> dict[str, Any]:
        """Build payload sent to webhook/gateway."""
        if self._gateway_base_url:
            return {
                "route": "webhook",
                "target_url": self._webhook_url,
                "event": event.to_dict(),
            }
        return event.to_dict()

    def _log_warning(self, message: str, *args: object) -> None:
        if self._logger is None:
            return
        try:
            self._logger.warning(message, *args)
        except Exception:  # noqa: BLE001
            return


class TelegramNotifier(WebhookNotifier):
    """
    Telegram notifier (async) built on WebhookNotifier.

    Supports direct Telegram Bot API or gateway-routed delivery by setting `gateway_base_url`.
    """

    def __init__(
        self,
        *,
        bot_token: str,
        chat_id: str,
        timeout_seconds: float = 5.0,
        api_base_url: str = "https://api.telegram.org",
        gateway_base_url: str | None = None,
        headers: dict[str, str] | None = None,
        logger: Any | None = None,
    ) -> None:
        self._bot_token = bot_token.strip()
        self._chat_id = str(chat_id).strip()
        self._api_base_url = api_base_url.strip() or "https://api.telegram.org"
        telegram_url = f"{self._api_base_url.rstrip('/')}/bot{self._bot_token}/sendMessage"
        super().__init__(
            webhook_url=telegram_url,
            timeout_seconds=timeout_seconds,
            headers=headers,
            gateway_base_url=gateway_base_url,
            logger=logger,
        )

    def _build_webhook_payload(self, event: NotificationEvent) -> dict[str, Any]:
        """Build Telegram sendMessage payload (or gateway-wrapped payload)."""
        telegram_payload = {
            "chat_id": self._chat_id,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
            "text": self._format_telegram_message(event),
        }
        if self._gateway_base_url:
            return {
                "route": "telegram",
                "target_url": self._webhook_url,
                "headers": self._headers,
                "json": telegram_payload,
                "event": event.to_dict(),
            }
        return telegram_payload

    def _format_telegram_message(self, event: NotificationEvent) -> str:
        """Render structured event into compact Telegram Markdown."""
        severity_icon = {
            "critical": "[CRIT]",
            "high": "[HIGH]",
            "medium": "[MED]",
            "low": "[LOW]",
            "info": "[INFO]",
            "warning": "[WARN]",
        }.get(event.severity.lower(), "[INFO]")
        lines = [
            f"{severity_icon} *{_escape_md(event.title)}*",
            "",
            _escape_md(event.message)[:1800],
        ]
        if event.context:
            compact = json.dumps(event.context, ensure_ascii=False, separators=(",", ":"))
            if len(compact) > 800:
                compact = compact[:797] + "..."
            lines.extend(["", "```json", compact, "```"])
        return "\n".join(lines)


class DingTalkNotifier(WebhookNotifier):
    """DingTalk robot webhook notifier."""

    def _build_webhook_payload(self, event: NotificationEvent) -> dict[str, Any]:
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": event.title,
                "text": _format_markdown_message(event, heading_prefix="##"),
            },
            "at": {
                "isAtAll": event.severity.lower() in {"critical", "high"},
            },
        }
        if self._gateway_base_url:
            return {
                "route": "dingtalk",
                "target_url": self._webhook_url,
                "headers": self._headers,
                "json": payload,
                "event": event.to_dict(),
            }
        return payload


class WeComNotifier(WebhookNotifier):
    """WeCom robot webhook notifier."""

    def _build_webhook_payload(self, event: NotificationEvent) -> dict[str, Any]:
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": _format_markdown_message(event, heading_prefix="##"),
            },
        }
        if self._gateway_base_url:
            return {
                "route": "wecom",
                "target_url": self._webhook_url,
                "headers": self._headers,
                "json": payload,
                "event": event.to_dict(),
            }
        return payload


class NotifierFanout(BaseNotifier):
    """Fan-out notifier for multiple sinks."""

    def __init__(self, notifiers: list[BaseNotifier]) -> None:
        self._notifiers = [item for item in notifiers if item is not None]

    def notify(self, event: NotificationEvent) -> None:
        for notifier in self._notifiers:
            notifier.notify(event)

    def flush(self, timeout_seconds: float = 2.0) -> None:
        for notifier in self._notifiers:
            notifier.flush(timeout_seconds=timeout_seconds)

    def close(self) -> None:
        for notifier in self._notifiers:
            notifier.close()


def build_notifier_from_config(config: dict[str, Any], logger: Any | None = None) -> BaseNotifier | None:
    """
    Build notifier(s) from top-level config template.

    Expected shape (optional):
    {
      "notifiers": {
        "telegram": {...},
        "dingtalk": {...},
        "wecom": {...}
      }
    }
    """
    notifiers_payload = config.get("notifiers", {})
    if not isinstance(notifiers_payload, dict):
        return None

    built: list[BaseNotifier] = []
    for name, item in notifiers_payload.items():
        if not isinstance(item, dict):
            continue
        if not bool(item.get("enabled", False)):
            continue

        notifier_type = str(item.get("type", "")).strip().lower()
        if notifier_type == "telegram":
            token = ""
            token_env = str(item.get("bot_token_env", "")).strip()
            if token_env:
                import os

                token = os.getenv(token_env, "").strip()
            token = token or str(item.get("bot_token", "")).strip()
            chat_id = str(item.get("chat_id", "")).strip()
            if not token or not chat_id:
                if logger is not None:
                    try:
                        logger.warning(
                            "Telegram notifier '%s' skipped: missing bot token or chat_id", name
                        )
                    except Exception:  # noqa: BLE001
                        pass
                continue

            headers = item.get("headers", {})
            built.append(
                TelegramNotifier(
                    bot_token=token,
                    chat_id=chat_id,
                    timeout_seconds=float(item.get("timeout_seconds", 8)),
                    api_base_url=str(item.get("api_base_url", "https://api.telegram.org")),
                    gateway_base_url=str(item.get("gateway_base_url", "")).strip() or None,
                    headers=dict(headers) if isinstance(headers, dict) else None,
                    logger=logger,
                )
            )
        elif notifier_type == "webhook":
            webhook_url = str(item.get("webhook_url", "")).strip()
            if not webhook_url:
                continue
            headers = item.get("headers", {})
            built.append(
                WebhookNotifier(
                    webhook_url=webhook_url,
                    timeout_seconds=float(item.get("timeout_seconds", 8)),
                    headers=dict(headers) if isinstance(headers, dict) else None,
                    gateway_base_url=str(item.get("gateway_base_url", "")).strip() or None,
                    logger=logger,
                )
            )
        elif notifier_type == "dingtalk":
            webhook_url = str(item.get("webhook_url", "")).strip()
            if not webhook_url:
                continue
            headers = item.get("headers", {})
            built.append(
                DingTalkNotifier(
                    webhook_url=webhook_url,
                    timeout_seconds=float(item.get("timeout_seconds", 8)),
                    headers=dict(headers) if isinstance(headers, dict) else None,
                    gateway_base_url=str(item.get("gateway_base_url", "")).strip() or None,
                    logger=logger,
                )
            )
        elif notifier_type == "wecom":
            webhook_url = str(item.get("webhook_url", "")).strip()
            if not webhook_url:
                continue
            headers = item.get("headers", {})
            built.append(
                WeComNotifier(
                    webhook_url=webhook_url,
                    timeout_seconds=float(item.get("timeout_seconds", 8)),
                    headers=dict(headers) if isinstance(headers, dict) else None,
                    gateway_base_url=str(item.get("gateway_base_url", "")).strip() or None,
                    logger=logger,
                )
            )

    if not built:
        return None
    if len(built) == 1:
        return built[0]
    return NotifierFanout(built)


def _escape_md(text: str) -> str:
    """Escape a minimal subset of Telegram MarkdownV2/Markdown specials."""
    # We use basic Markdown mode; keep escaping light to avoid breaking code snippets.
    escaped = str(text)
    for token in ("*", "_", "`"):
        escaped = escaped.replace(token, f"\\{token}")
    return escaped


def _format_markdown_message(event: NotificationEvent, *, heading_prefix: str = "##") -> str:
    """Render a generic markdown message for webhook-style chat clients."""
    lines = [
        f"{heading_prefix} {_escape_md(event.title)}",
        "",
        f"- Severity: `{_escape_md(event.severity)}`",
        f"- Event: `{_escape_md(event.event_type)}`",
        f"- Message: {_escape_md(event.message)}",
    ]
    if event.context:
        compact = json.dumps(event.context, ensure_ascii=False, sort_keys=True, indent=2)
        if len(compact) > 1500:
            compact = compact[:1497] + "..."
        lines.extend(["", "```json", compact, "```"])
    return "\n".join(lines)
