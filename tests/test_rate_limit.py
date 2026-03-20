"""Tests for webapp rate limiting and related helpers."""

from __future__ import annotations

from starlette.requests import Request

from autosecaudit.webapp.fastapi_app import (
    _origin_from_url,
    _rate_limit_bucket_for_request,
    _resolve_cors_allow_origins,
)
from autosecaudit.webapp.rate_limit import InMemoryRateLimiter, RateLimitRule, RedisRateLimiter, create_rate_limiter


def _request(method: str, path: str) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )


class TestInMemoryRateLimiter:
    def test_blocks_after_limit(self) -> None:
        clock = iter([0.0, 1.0, 2.0, 3.0])
        limiter = InMemoryRateLimiter(
            {"auth_login": RateLimitRule(bucket="auth_login", max_requests=2, window_seconds=60.0)},
            now_fn=lambda: next(clock),
        )

        first = limiter.hit("auth_login", "ip:127.0.0.1")
        second = limiter.hit("auth_login", "ip:127.0.0.1")
        third = limiter.hit("auth_login", "ip:127.0.0.1")

        assert first is not None and first.allowed
        assert second is not None and second.allowed
        assert third is not None and not third.allowed
        assert third.retry_after_seconds >= 1

    def test_disabled_bucket_returns_none(self) -> None:
        limiter = InMemoryRateLimiter({})
        assert limiter.hit("api_write", "ip:127.0.0.1") is None


class _FakeRedisClient:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, float]] = {}
        self._ttl: dict[str, int] = {}

    def ping(self) -> bool:
        return True

    def zremrangebyscore(self, key: str, minimum, maximum) -> int:  # noqa: ANN001
        key_store = self._store.get(key, {})
        if minimum == "-inf":
            lower_bound = float("-inf")
        else:
            lower_bound = float(minimum)
        upper_bound = float(maximum)
        removed = [member for member, score in key_store.items() if lower_bound <= score <= upper_bound]
        for member in removed:
            key_store.pop(member, None)
        if key_store:
            self._store[key] = key_store
        else:
            self._store.pop(key, None)
        return len(removed)

    def zcard(self, key: str) -> int:
        return len(self._store.get(key, {}))

    def zrange(self, key: str, start: int, stop: int, *, withscores: bool = False):  # noqa: ANN001
        items = sorted(self._store.get(key, {}).items(), key=lambda item: item[1])
        if not items:
            return []
        if stop == -1:
            sliced = items[start:]
        else:
            sliced = items[start : stop + 1]
        if withscores:
            return [(member, score) for member, score in sliced]
        return [member for member, _score in sliced]

    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        bucket = self._store.setdefault(key, {})
        for member, score in mapping.items():
            bucket[member] = float(score)
        return len(mapping)

    def expire(self, key: str, seconds: int) -> bool:
        self._ttl[key] = int(seconds)
        return True


class TestRedisRateLimiter:
    def test_blocks_after_limit(self) -> None:
        clock = iter([0.0, 1.0, 2.0, 3.0])
        limiter = RedisRateLimiter(
            {"auth_login": RateLimitRule(bucket="auth_login", max_requests=2, window_seconds=60.0)},
            redis_url="redis://example.test/0",
            now_fn=lambda: next(clock),
            client=_FakeRedisClient(),
        )

        first = limiter.hit("auth_login", "ip:127.0.0.1")
        second = limiter.hit("auth_login", "ip:127.0.0.1")
        third = limiter.hit("auth_login", "ip:127.0.0.1")

        assert first is not None and first.allowed
        assert second is not None and second.allowed
        assert third is not None and not third.allowed
        assert third.retry_after_seconds >= 1

    def test_create_rate_limiter_falls_back_to_memory_when_redis_unavailable(self, monkeypatch) -> None:
        monkeypatch.setenv("AUTOSECAUDIT_WEB_RATE_LIMIT_BACKEND", "auto")
        monkeypatch.setenv("AUTOSECAUDIT_REDIS_URL", "redis://example.test/0")

        class _UnavailableRedisRateLimiter:
            @classmethod
            def from_env(cls):  # noqa: ANN102
                raise RuntimeError("redis_down")

        monkeypatch.setattr("autosecaudit.webapp.rate_limit.RedisRateLimiter", _UnavailableRedisRateLimiter)

        limiter = create_rate_limiter()

        assert isinstance(limiter, InMemoryRateLimiter)


class TestCorsHelpers:
    def test_origin_from_url(self) -> None:
        assert _origin_from_url("https://audit.example.com/app") == "https://audit.example.com"
        assert _origin_from_url("not-a-url") is None

    def test_resolve_cors_allow_origins(self, monkeypatch) -> None:
        monkeypatch.setenv("AUTOSECAUDIT_WEB_CORS_ALLOW_ORIGINS", "https://console.example.com, https://ops.example.com")
        monkeypatch.setenv("AUTOSECAUDIT_WEB_PUBLIC_BASE_URL", "https://audit.example.com/ui")

        origins = _resolve_cors_allow_origins()

        assert origins == [
            "https://console.example.com",
            "https://ops.example.com",
            "https://audit.example.com",
        ]


class TestRateLimitBucketSelection:
    def test_login_bucket(self) -> None:
        assert _rate_limit_bucket_for_request(_request("POST", "/api/auth/login")) == "auth_login"

    def test_refresh_bucket(self) -> None:
        assert _rate_limit_bucket_for_request(_request("POST", "/api/auth/refresh")) == "auth_refresh"

    def test_versioned_login_bucket(self) -> None:
        assert _rate_limit_bucket_for_request(_request("POST", "/api/v1/auth/login")) == "auth_login"

    def test_write_bucket(self) -> None:
        assert _rate_limit_bucket_for_request(_request("POST", "/api/jobs")) == "api_write"

    def test_read_requests_are_not_limited(self) -> None:
        assert _rate_limit_bucket_for_request(_request("GET", "/api/jobs")) is None

    def test_options_requests_are_not_limited(self) -> None:
        assert _rate_limit_bucket_for_request(_request("OPTIONS", "/api/jobs")) is None
