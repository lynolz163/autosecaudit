"""Lightweight cache backends for the web console."""

from __future__ import annotations

import json
import logging
import os
from threading import RLock
import time
from typing import Any, Callable


_LOGGER = logging.getLogger("autosecaudit")


class CacheBackend:
    """Minimal cache interface used by the web console."""

    backend_name = "none"

    def get_json(self, key: str) -> Any | None:
        """Return cached JSON value, or None when unavailable."""
        return None

    def set_json(self, key: str, value: Any, ttl_seconds: float) -> None:
        """Persist one JSON-serializable value."""
        del key, value, ttl_seconds

    def get_or_compute(self, key: str, ttl_seconds: float, builder: Callable[[], Any]) -> Any:
        """Load one cached value or compute and cache it."""
        cached = self.get_json(key)
        if cached is not None:
            return cached
        value = builder()
        self.set_json(key, value, ttl_seconds=ttl_seconds)
        return value


class InMemoryCacheBackend(CacheBackend):
    """Process-local TTL cache."""

    backend_name = "memory"

    def __init__(self) -> None:
        self._lock = RLock()
        self._items: dict[str, tuple[float, Any]] = {}

    def get_json(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            record = self._items.get(str(key))
            if record is None:
                return None
            expires_at, value = record
            if expires_at <= now:
                self._items.pop(str(key), None)
                return None
            return value

    def set_json(self, key: str, value: Any, ttl_seconds: float) -> None:
        expires_at = time.time() + max(0.1, float(ttl_seconds))
        with self._lock:
            self._items[str(key)] = (expires_at, value)


class RedisCacheBackend(CacheBackend):
    """Redis-backed TTL cache."""

    backend_name = "redis"

    def __init__(self, redis_url: str) -> None:
        try:
            import redis
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("redis_package_missing") from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._client.ping()

    def get_json(self, key: str) -> Any | None:
        raw = self._client.get(str(key))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            self._client.delete(str(key))
            return None

    def set_json(self, key: str, value: Any, ttl_seconds: float) -> None:
        self._client.setex(
            str(key),
            max(1, int(float(ttl_seconds))),
            json.dumps(value, ensure_ascii=False, separators=(",", ":")),
        )


def create_cache_backend() -> CacheBackend:
    """Create cache backend from environment variables."""
    backend = str(os.getenv("AUTOSECAUDIT_CACHE_BACKEND", "memory") or "memory").strip().lower()
    redis_url = str(os.getenv("AUTOSECAUDIT_REDIS_URL", "")).strip()

    if backend in {"redis", "auto"} and redis_url:
        try:
            cache = RedisCacheBackend(redis_url)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("Redis cache unavailable, falling back to memory cache: %s", exc)
        else:
            _LOGGER.info("Web cache backend enabled: redis")
            return cache

    cache = InMemoryCacheBackend()
    _LOGGER.info("Web cache backend enabled: memory")
    return cache


__all__ = [
    "CacheBackend",
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    "create_cache_backend",
]
