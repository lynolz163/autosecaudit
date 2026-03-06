"""In-memory API rate limiting for the web console."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
import threading
import time
from typing import Callable


DEFAULT_RULES = {
    "auth_login": "5/60",
    "auth_refresh": "20/300",
    "api_write": "120/60",
}


@dataclass(frozen=True)
class RateLimitRule:
    """One bucket rule."""

    bucket: str
    max_requests: int
    window_seconds: float


@dataclass(frozen=True)
class RateLimitResult:
    """Result metadata for one hit."""

    bucket: str
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    reset_after_seconds: int


class InMemoryRateLimiter:
    """Thread-safe sliding window limiter."""

    def __init__(self, rules: dict[str, RateLimitRule], *, now_fn: Callable[[], float] | None = None) -> None:
        self._rules = dict(rules)
        self._entries: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._now = now_fn or time.monotonic

    @classmethod
    def from_env(cls) -> InMemoryRateLimiter:
        rules: dict[str, RateLimitRule] = {}
        for bucket, default_value in DEFAULT_RULES.items():
            env_name = f"AUTOSECAUDIT_WEB_RATE_LIMIT_{bucket.upper()}"
            rule = _parse_rule(bucket, os.getenv(env_name, "").strip(), default_value)
            if rule is not None:
                rules[bucket] = rule
        return cls(rules)

    def enabled(self, bucket: str) -> bool:
        return str(bucket) in self._rules

    def hit(self, bucket: str, subject: str) -> RateLimitResult | None:
        rule = self._rules.get(str(bucket))
        if rule is None:
            return None

        subject_key = str(subject or "anonymous").strip() or "anonymous"
        entry_key = f"{rule.bucket}:{subject_key}"
        now = float(self._now())
        window_start = now - float(rule.window_seconds)

        with self._lock:
            samples = [value for value in self._entries.get(entry_key, []) if value > window_start]
            self._entries[entry_key] = samples

            if len(samples) >= int(rule.max_requests):
                retry_after = _seconds_until(samples[0] + float(rule.window_seconds), now)
                return RateLimitResult(
                    bucket=rule.bucket,
                    allowed=False,
                    limit=int(rule.max_requests),
                    remaining=0,
                    retry_after_seconds=retry_after,
                    reset_after_seconds=retry_after,
                )

            samples.append(now)
            self._entries[entry_key] = samples
            remaining = max(0, int(rule.max_requests) - len(samples))
            reset_after = _seconds_until(samples[0] + float(rule.window_seconds), now)
            return RateLimitResult(
                bucket=rule.bucket,
                allowed=True,
                limit=int(rule.max_requests),
                remaining=remaining,
                retry_after_seconds=0,
                reset_after_seconds=reset_after,
            )


def _parse_rule(bucket: str, raw_value: str, default_value: str) -> RateLimitRule | None:
    text = str(raw_value or "").strip().lower()
    if not text:
        text = str(default_value).strip().lower()
    if text in {"0", "off", "false", "disabled", "none"}:
        return None

    normalized = text.replace(":", "/")
    count_text, separator, window_text = normalized.partition("/")
    if not separator:
        raise ValueError(f"invalid rate limit for {bucket}: expected requests/window_seconds")

    try:
        max_requests = max(1, int(count_text))
        window_seconds = max(1.0, float(window_text))
    except ValueError as exc:
        raise ValueError(f"invalid rate limit for {bucket}: {raw_value or default_value}") from exc

    return RateLimitRule(bucket=str(bucket), max_requests=max_requests, window_seconds=window_seconds)


def _seconds_until(target: float, now: float) -> int:
    return max(1, int(math.ceil(max(0.0, target - now))))
