"""Shared synchronous HTTP helpers for agent tools."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import time
from typing import Any

import httpx


DEFAULT_HTTP_USER_AGENT = "Mozilla/5.0 (compatible; SecurityResearchBot)"
DEFAULT_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
DEFAULT_RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class HttpClientError(RuntimeError):
    """Raised when an HTTP request cannot be completed."""


@dataclass(frozen=True)
class HttpRetryPolicy:
    """Retry policy for bounded HTTP requests."""

    attempts: int = 2
    backoff_seconds: float = 0.35
    max_backoff_seconds: float = 2.5
    retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES
    retry_methods: frozenset[str] = DEFAULT_RETRY_METHODS
    retry_on_transport_error: bool = True


@dataclass(frozen=True)
class HttpResponse:
    """Normalized bounded HTTP response payload."""

    status_code: int
    headers: dict[str, str]
    header_lists: dict[str, list[str]]
    content: bytes
    text: str
    url: str


def default_user_agent() -> str:
    """Return the default outbound HTTP user-agent."""
    configured = str(os.getenv("AUTOSECAUDIT_HTTP_USER_AGENT", "")).strip()
    return configured or DEFAULT_HTTP_USER_AGENT


def request_text(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    content: bytes | str | None = None,
    accept: str | None = None,
    timeout: float = 8.0,
    max_bytes: int = 500_000,
    retry_policy: HttpRetryPolicy | dict[str, Any] | None = None,
    follow_redirects: bool = True,
) -> HttpResponse:
    """Fetch bounded text content while respecting proxy environment."""
    prepared_headers = _prepare_headers(headers, accept=accept)
    return _send_request(
        url,
        method=method,
        headers=prepared_headers,
        content=content,
        timeout=timeout,
        max_bytes=max_bytes,
        retry_policy=retry_policy,
        follow_redirects=follow_redirects,
    )


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    content: bytes | str | None = None,
    accept: str = "application/json",
    timeout: float = 8.0,
    max_bytes: int = 2_000_000,
    retry_policy: HttpRetryPolicy | dict[str, Any] | None = None,
    follow_redirects: bool = True,
) -> tuple[HttpResponse, Any]:
    """Fetch bounded JSON content and parse it."""
    response = request_text(
        url,
        method=method,
        headers=headers,
        content=content,
        accept=accept,
        timeout=timeout,
        max_bytes=max_bytes,
        retry_policy=retry_policy,
        follow_redirects=follow_redirects,
    )
    try:
        payload = json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise HttpClientError("invalid_json_payload") from exc
    return response, payload


def _prepare_headers(headers: dict[str, str] | None, *, accept: str | None) -> dict[str, str]:
    prepared = {str(key): str(value) for key, value in (headers or {}).items() if str(key).strip()}
    lower_map = {key.lower(): key for key in prepared}
    if "user-agent" not in lower_map:
        prepared["User-Agent"] = default_user_agent()
    if accept and "accept" not in lower_map:
        prepared["Accept"] = accept
    return prepared


def _send_request(
    url: str,
    *,
    method: str,
    headers: dict[str, str],
    content: bytes | str | None,
    timeout: float,
    max_bytes: int,
    retry_policy: HttpRetryPolicy | dict[str, Any] | None,
    follow_redirects: bool,
) -> HttpResponse:
    normalized_method = str(method or "GET").strip().upper() or "GET"
    policy = _coerce_retry_policy(retry_policy)
    attempts = policy.attempts if normalized_method in policy.retry_methods else 1
    last_transport_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        try:
            with httpx.Client(
                follow_redirects=follow_redirects,
                trust_env=True,
                timeout=max(0.1, float(timeout)),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            ) as client:
                with client.stream(normalized_method, url, headers=headers, content=content) as response:
                    body = _read_bounded_body(response, max_bytes=max_bytes)
                    built = _build_response(response, body)
            if built.status_code in policy.retry_statuses and attempt < attempts:
                _sleep_backoff(policy=policy, attempt=attempt)
                continue
            return built
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_transport_error = exc
            if not policy.retry_on_transport_error or attempt >= attempts:
                break
            _sleep_backoff(policy=policy, attempt=attempt)

    if last_transport_error is None:
        raise HttpClientError("request_failed")
    raise HttpClientError(f"{type(last_transport_error).__name__}: {last_transport_error}") from last_transport_error


def _read_bounded_body(response: httpx.Response, *, max_bytes: int) -> bytes:
    if max_bytes <= 0:
        return b""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        if not chunk:
            continue
        remaining = max_bytes - total
        if remaining <= 0:
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _build_response(response: httpx.Response, body: bytes) -> HttpResponse:
    header_lists: dict[str, list[str]] = {}
    for key, value in response.headers.multi_items():
        normalized_key = str(key).lower()
        header_lists.setdefault(normalized_key, []).append(str(value))
    headers = {key: values[-1] for key, values in header_lists.items() if values}
    encoding = response.encoding or "utf-8"
    try:
        text = body.decode(encoding, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    return HttpResponse(
        status_code=int(response.status_code),
        headers=headers,
        header_lists=header_lists,
        content=body,
        text=text,
        url=str(response.url),
    )


def _coerce_retry_policy(raw: HttpRetryPolicy | dict[str, Any] | None) -> HttpRetryPolicy:
    if isinstance(raw, HttpRetryPolicy):
        return raw
    payload = raw if isinstance(raw, dict) else {}
    attempts = _to_int(payload.get("attempts"), default=_to_int(os.getenv("AUTOSECAUDIT_HTTP_RETRY_ATTEMPTS"), default=2))
    backoff_seconds = _to_float(payload.get("backoff_seconds"), default=_to_float(os.getenv("AUTOSECAUDIT_HTTP_RETRY_BACKOFF_SECONDS"), default=0.35))
    max_backoff_seconds = _to_float(
        payload.get("max_backoff_seconds"),
        default=_to_float(os.getenv("AUTOSECAUDIT_HTTP_RETRY_MAX_BACKOFF_SECONDS"), default=2.5),
    )
    retry_statuses_raw = payload.get("retry_statuses")
    retry_methods_raw = payload.get("retry_methods")
    retry_on_transport_error = bool(
        payload.get(
            "retry_on_transport_error",
            str(os.getenv("AUTOSECAUDIT_HTTP_RETRY_ON_TRANSPORT_ERROR", "1")).strip().lower() not in {"0", "false", "no", "off"},
        )
    )
    retry_statuses = _to_int_set(retry_statuses_raw, default=DEFAULT_RETRY_STATUSES)
    retry_methods = _to_string_set(retry_methods_raw, default=DEFAULT_RETRY_METHODS)
    return HttpRetryPolicy(
        attempts=max(1, min(attempts, 5)),
        backoff_seconds=max(0.0, min(backoff_seconds, 10.0)),
        max_backoff_seconds=max(0.0, min(max_backoff_seconds, 30.0)),
        retry_statuses=frozenset(retry_statuses),
        retry_methods=frozenset(retry_methods),
        retry_on_transport_error=retry_on_transport_error,
    )


def _sleep_backoff(*, policy: HttpRetryPolicy, attempt: int) -> None:
    if policy.backoff_seconds <= 0:
        return
    delay = min(policy.max_backoff_seconds, policy.backoff_seconds * (2 ** max(0, attempt - 1)))
    if delay > 0:
        time.sleep(delay)


def _to_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int_set(value: Any, *, default: frozenset[int]) -> set[int]:
    if isinstance(value, (list, tuple, set, frozenset)):
        output: set[int] = set()
        for item in value:
            try:
                output.add(int(item))
            except (TypeError, ValueError):
                continue
        return output or set(default)
    return set(default)


def _to_string_set(value: Any, *, default: frozenset[str]) -> set[str]:
    if isinstance(value, (list, tuple, set, frozenset)):
        output = {str(item).strip().upper() for item in value if str(item).strip()}
        return output or set(default)
    return set(default)
