"""In-memory API rate limiting for the web console."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
import math
import os
import threading
import time
from typing import Callable
import uuid


DEFAULT_RULES = {
    "auth_login": "5/60",
    "auth_refresh": "20/300",
    "api_write": "120/60",
}
_LOGGER = logging.getLogger(__name__)


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
        return cls(_load_rules_from_env())

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


class RedisRateLimiter:
    """Redis-backed sliding-window limiter suitable for multi-instance deployments."""

    def __init__(
        self,
        rules: dict[str, RateLimitRule],
        *,
        redis_url: str,
        now_fn: Callable[[], float] | None = None,
        client: object | None = None,
    ) -> None:
        self._rules = dict(rules)
        self._now = now_fn or time.time
        self._redis_url = str(redis_url or "").strip()
        if client is not None:
            self._client = client
            return
        if not self._redis_url:
            raise RuntimeError("redis_url_missing")
        try:
            import redis
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("redis_package_missing") from exc
        self._client = redis.Redis.from_url(self._redis_url, decode_responses=True)
        self._client.ping()

    @classmethod
    def from_env(cls) -> RedisRateLimiter:
        redis_url = str(os.getenv("AUTOSECAUDIT_REDIS_URL", "") or "").strip()
        return cls(_load_rules_from_env(), redis_url=redis_url)

    def enabled(self, bucket: str) -> bool:
        return str(bucket) in self._rules

    def hit(self, bucket: str, subject: str) -> RateLimitResult | None:
        rule = self._rules.get(str(bucket))
        if rule is None:
            return None

        subject_key = str(subject or "anonymous").strip() or "anonymous"
        hashed_subject = hashlib.sha256(subject_key.encode("utf-8")).hexdigest()[:24]
        entry_key = f"autosecaudit:rate_limit:{rule.bucket}:{hashed_subject}"
        now = float(self._now())
        window_start = now - float(rule.window_seconds)

        self._client.zremrangebyscore(entry_key, "-inf", window_start)
        current_count = int(self._client.zcard(entry_key))
        earliest_entry = self._client.zrange(entry_key, 0, 0, withscores=True)
        earliest_score = float(earliest_entry[0][1]) if earliest_entry else now

        if current_count >= int(rule.max_requests):
            retry_after = _seconds_until(earliest_score + float(rule.window_seconds), now)
            return RateLimitResult(
                bucket=rule.bucket,
                allowed=False,
                limit=int(rule.max_requests),
                remaining=0,
                retry_after_seconds=retry_after,
                reset_after_seconds=retry_after,
            )

        member_id = f"{now:.6f}:{uuid.uuid4().hex}"
        self._client.zadd(entry_key, {member_id: now})
        self._client.expire(entry_key, max(1, int(math.ceil(rule.window_seconds)) + 1))
        current_count += 1
        earliest_score = min(earliest_score, now) if earliest_entry else now
        remaining = max(0, int(rule.max_requests) - current_count)
        reset_after = _seconds_until(earliest_score + float(rule.window_seconds), now)
        return RateLimitResult(
            bucket=rule.bucket,
            allowed=True,
            limit=int(rule.max_requests),
            remaining=remaining,
            retry_after_seconds=0,
            reset_after_seconds=reset_after,
        )


def create_rate_limiter() -> InMemoryRateLimiter | RedisRateLimiter:
    backend = str(os.getenv("AUTOSECAUDIT_WEB_RATE_LIMIT_BACKEND", "auto") or "auto").strip().lower()
    redis_url = str(os.getenv("AUTOSECAUDIT_REDIS_URL", "") or "").strip()

    if backend in {"redis", "auto"} and redis_url:
        try:
            limiter = RedisRateLimiter.from_env()
        except Exception as exc:  # noqa: BLE001
            if backend == "redis":
                raise RuntimeError(f"redis_rate_limiter_unavailable:{exc}") from exc
            _LOGGER.warning("Redis rate limiter unavailable, falling back to memory limiter: %s", exc)
        else:
            _LOGGER.info("Web rate limiter backend enabled: redis")
            return limiter

    limiter = InMemoryRateLimiter.from_env()
    _LOGGER.info("Web rate limiter backend enabled: memory")
    return limiter


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


def _load_rules_from_env() -> dict[str, RateLimitRule]:
    rules: dict[str, RateLimitRule] = {}
    for bucket, default_value in DEFAULT_RULES.items():
        env_name = f"AUTOSECAUDIT_WEB_RATE_LIMIT_{bucket.upper()}"
        rule = _parse_rule(bucket, os.getenv(env_name, "").strip(), default_value)
        if rule is not None:
            rules[bucket] = rule
    return rules


def _seconds_until(target: float, now: float) -> int:
    return max(1, int(math.ceil(max(0.0, target - now))))
