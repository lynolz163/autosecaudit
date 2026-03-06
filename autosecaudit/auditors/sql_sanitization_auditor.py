"""Non-destructive SQL sanitization auditor for web applications."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


SQLCheckType = Literal["error_based", "time_based"]


@dataclass(frozen=True)
class SQLAuditFinding:
    """One confirmed SQL sanitization weakness signal."""

    parameter: str
    check_type: SQLCheckType
    payload: str
    evidence: str
    baseline_time_ms: int
    probe_time_ms: int


@dataclass(frozen=True)
class SQLAuditResult:
    """Structured output for one SQL sanitization audit run."""

    target_url: str
    is_vulnerable: bool
    checked_parameters: list[str]
    tested_payloads: int
    finding: SQLAuditFinding | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _ProbeResponse:
    """Internal HTTP probe response object."""

    status_code: int | None
    body: str
    elapsed_ms: int
    error: str | None = None


class SQLSanitizationAuditor:
    """
    Perform non-destructive SQL injection defense auditing.

    Behavior:
    - Sends lightweight special-character and boolean probes.
    - Detects common DB error signatures in response bodies.
    - Runs time-based probes only when no direct reflection/evidence appears.
    - Stops immediately when one vulnerability signal is confirmed.
    """

    _ERROR_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"warning:\s*mysql", re.IGNORECASE),
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"quoted string not properly terminated", re.IGNORECASE),
        re.compile(r"sqlstate\[[0-9a-z]+\]", re.IGNORECASE),
        re.compile(r"syntax error at or near", re.IGNORECASE),
        re.compile(r"pg_query\(\)", re.IGNORECASE),
        re.compile(r"sqlite(3)?\s+error", re.IGNORECASE),
        re.compile(r"odbc sql server driver", re.IGNORECASE),
        re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
    )

    _HEURISTIC_PAYLOADS: tuple[str, ...] = (
        "'",
        '"',
        "\\",
        "1 AND 1=1",
        "1' AND '1'='1",
    )

    _TIME_PAYLOAD_TEMPLATES: tuple[str, ...] = (
        "1 AND SLEEP({delay})",
        "1' AND SLEEP({delay})-- ",
        "1 OR pg_sleep({delay})-- ",
        "1'; WAITFOR DELAY '0:0:{delay}'--",
    )

    def __init__(
        self,
        timeout_seconds: float = 8.0,
        user_agent: str = "AutoSecAudit-SQLAuditor/0.1",
        max_body_bytes: int = 200_000,
        time_delay_seconds: int = 5,
        time_delta_threshold_ms: int = 3500,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be > 0")
        if time_delay_seconds < 1:
            raise ValueError("time_delay_seconds must be >= 1")
        if time_delta_threshold_ms < 500:
            raise ValueError("time_delta_threshold_ms must be >= 500")

        self._timeout_seconds = timeout_seconds
        self._user_agent = user_agent
        self._max_body_bytes = max_body_bytes
        self._time_delay_seconds = time_delay_seconds
        self._time_delta_threshold_ms = time_delta_threshold_ms

    def audit_url(self, url: str, params: dict[str, Any]) -> SQLAuditResult:
        """
        Audit one URL for SQL sanitization quality using safe probes.

        Args:
            url: Target URL.
            params: Query parameters to test.
        """
        normalized_url = self._normalize_url(url)
        param_map = self._build_param_map(normalized_url, params)
        checked_parameters = sorted(param_map.keys())

        if not checked_parameters:
            return SQLAuditResult(
                target_url=normalized_url,
                is_vulnerable=False,
                checked_parameters=[],
                tested_payloads=0,
                notes=["No query parameters provided; nothing to audit."],
            )

        baseline = self._send_probe(normalized_url, param_map)
        baseline_time_ms = baseline.elapsed_ms
        errors: list[str] = []
        notes: list[str] = []
        tested_payloads = 0
        if baseline.error:
            errors.append(f"Baseline request failed: {baseline.error}")
            notes.append("Time-based confidence may be reduced due to baseline instability.")

        for parameter in checked_parameters:
            reflected_seen = False

            for payload in self._HEURISTIC_PAYLOADS:
                tested_payloads += 1
                candidate = dict(param_map)
                candidate[parameter] = payload

                response = self._send_probe(normalized_url, candidate)
                if response.error:
                    errors.append(
                        f"Heuristic probe failed ({parameter}, payload={payload!r}): {response.error}"
                    )
                    continue

                if payload and payload in response.body:
                    reflected_seen = True

                matched_error = self._find_sql_error_signature(response.body)
                if matched_error:
                    return SQLAuditResult(
                        target_url=normalized_url,
                        is_vulnerable=True,
                        checked_parameters=checked_parameters,
                        tested_payloads=tested_payloads,
                        finding=SQLAuditFinding(
                            parameter=parameter,
                            check_type="error_based",
                            payload=payload,
                            evidence=matched_error,
                            baseline_time_ms=baseline_time_ms,
                            probe_time_ms=response.elapsed_ms,
                        ),
                        notes=["Audit stopped after first confirmed signal (safety policy)."],
                        errors=errors,
                    )

            if reflected_seen:
                notes.append(
                    f"Parameter `{parameter}` appears reflected; skipped time-based check for this parameter."
                )
                continue

            for payload in self._build_time_payloads():
                tested_payloads += 1
                candidate = dict(param_map)
                candidate[parameter] = payload
                response = self._send_probe(normalized_url, candidate)

                if response.error:
                    errors.append(
                        f"Time-based probe failed ({parameter}, payload={payload!r}): {response.error}"
                    )
                    continue

                delay = response.elapsed_ms - baseline_time_ms
                if delay >= self._time_delta_threshold_ms:
                    evidence = (
                        f"Observed delay delta {delay}ms (baseline {baseline_time_ms}ms -> "
                        f"probe {response.elapsed_ms}ms)"
                    )
                    return SQLAuditResult(
                        target_url=normalized_url,
                        is_vulnerable=True,
                        checked_parameters=checked_parameters,
                        tested_payloads=tested_payloads,
                        finding=SQLAuditFinding(
                            parameter=parameter,
                            check_type="time_based",
                            payload=payload,
                            evidence=evidence,
                            baseline_time_ms=baseline_time_ms,
                            probe_time_ms=response.elapsed_ms,
                        ),
                        notes=["Audit stopped after first confirmed signal (safety policy)."],
                        errors=errors,
                    )

        return SQLAuditResult(
            target_url=normalized_url,
            is_vulnerable=False,
            checked_parameters=checked_parameters,
            tested_payloads=tested_payloads,
            notes=notes or ["No SQL error signatures or timing anomalies were observed."],
            errors=errors,
        )

    def _send_probe(self, base_url: str, params: dict[str, str]) -> _ProbeResponse:
        """Execute one GET probe request and capture response metadata."""
        request_url = self._build_get_url(base_url, params)
        request = Request(
            request_url,
            method="GET",
            headers={"User-Agent": self._user_agent, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
        )
        started = time.perf_counter()
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                body_bytes = response.read(self._max_body_bytes)
                body = body_bytes.decode("utf-8", errors="replace")
                return _ProbeResponse(
                    status_code=response.status,
                    body=body,
                    elapsed_ms=self._elapsed_ms(started),
                )
        except HTTPError as exc:
            try:
                body = (exc.read(self._max_body_bytes) or b"").decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return _ProbeResponse(
                status_code=exc.code,
                body=body,
                elapsed_ms=self._elapsed_ms(started),
                error=f"HTTP error {exc.code}",
            )
        except (URLError, TimeoutError, OSError) as exc:
            return _ProbeResponse(
                status_code=None,
                body="",
                elapsed_ms=self._elapsed_ms(started),
                error=str(exc),
            )

    def _normalize_url(self, url: str) -> str:
        """Validate and normalize HTTP(S) URL."""
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("url must start with http:// or https://")
        if not parsed.netloc:
            raise ValueError("url must contain a host")
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), parsed.netloc, path, "", parsed.query, ""))

    def _build_param_map(self, url: str, params: dict[str, Any]) -> dict[str, str]:
        """Build final parameter map from URL query + explicit params."""
        parsed = urlparse(url)
        merged: dict[str, str] = {}
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            merged[key] = value
        for key, value in params.items():
            merged[str(key)] = self._stringify_param(value)
        return merged

    def _build_get_url(self, base_url: str, params: dict[str, str]) -> str:
        """Compose GET URL with encoded parameters."""
        parsed = urlparse(base_url)
        query = urlencode(sorted(params.items(), key=lambda item: item[0]), doseq=False)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

    def _build_time_payloads(self) -> list[str]:
        """Construct DB-specific time-based payload probes."""
        payloads: list[str] = []
        for template in self._TIME_PAYLOAD_TEMPLATES:
            payloads.append(template.format(delay=self._time_delay_seconds))
        return payloads

    def _find_sql_error_signature(self, body: str) -> str | None:
        """Return matched SQL error signature snippet if present."""
        for pattern in self._ERROR_PATTERNS:
            matched = pattern.search(body)
            if matched:
                return matched.group(0)
        return None

    @staticmethod
    def _stringify_param(value: Any) -> str:
        """Convert any parameter value into request-safe text."""
        if value is None:
            return ""
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        return str(value)

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        """Return elapsed milliseconds."""
        return int((time.perf_counter() - started) * 1000)
