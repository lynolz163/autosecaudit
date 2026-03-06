"""Tests for webapp rate limiting and related helpers."""

from __future__ import annotations

from starlette.requests import Request

from autosecaudit.webapp.fastapi_app import (
    _origin_from_url,
    _rate_limit_bucket_for_request,
    _resolve_cors_allow_origins,
)
from autosecaudit.webapp.rate_limit import InMemoryRateLimiter, RateLimitRule


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
