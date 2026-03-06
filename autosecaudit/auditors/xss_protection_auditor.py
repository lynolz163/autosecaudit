"""Non-destructive auditor for XSS output-encoding protections."""

from __future__ import annotations

from dataclasses import dataclass, field
import html
import secrets
import time
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


ReflectionContext = Literal["html_body", "html_attribute", "javascript", "unknown"]


@dataclass(frozen=True)
class ReflectionPoint:
    """One raw canary reflection point detected in response content."""

    parameter: str
    context: ReflectionContext
    position: int
    snippet: str
    request_url: str


@dataclass(frozen=True)
class BrowserVerificationResult:
    """Optional browser-level verification result."""

    attempted: bool
    js_executed: bool
    evidence: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class XSSAuditResult:
    """Structured result for one XSS protection audit run."""

    target_url: str
    canary: str
    tested_parameters: list[str]
    reflection_points: list[ReflectionPoint]
    is_reflected: bool
    browser_verification: BrowserVerificationResult | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _HTTPProbeResponse:
    """Internal HTTP probe response."""

    request_url: str
    status_code: int | None
    body: str
    elapsed_ms: int
    error: str | None = None


class XSSProtectionAuditor:
    """
    Audit web output encoding behavior using canary reflection analysis.

    Safety:
    - Read-only HTTP GET probes only.
    - Browser verification (optional) only checks JS execution by console marker.
    - No payloads for data extraction or destructive behavior.
    """

    def __init__(
        self,
        timeout_seconds: float = 8.0,
        user_agent: str = "AutoSecAudit-XSSAuditor/0.1",
        max_body_bytes: int = 250_000,
        snippet_radius: int = 80,
        browser_timeout_ms: int = 12_000,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be > 0")
        if snippet_radius < 20:
            raise ValueError("snippet_radius must be >= 20")
        if browser_timeout_ms < 1000:
            raise ValueError("browser_timeout_ms must be >= 1000")

        self._timeout_seconds = timeout_seconds
        self._user_agent = user_agent
        self._max_body_bytes = max_body_bytes
        self._snippet_radius = snippet_radius
        self._browser_timeout_ms = browser_timeout_ms

    def audit_url(
        self,
        url: str,
        params: dict[str, Any],
        *,
        verify_in_browser: bool = False,
    ) -> XSSAuditResult:
        """
        Audit one URL for output encoding quality and potential XSS reflection.

        Args:
            url: Target URL.
            params: Query parameters to probe.
            verify_in_browser: Whether to run optional Playwright verification.
        """
        target_url = self._normalize_url(url)
        baseline_params = self._build_param_map(target_url, params)
        tested_parameters = sorted(baseline_params.keys())
        canary = self._build_canary()
        notes: list[str] = []
        errors: list[str] = []

        if not tested_parameters:
            return XSSAuditResult(
                target_url=target_url,
                canary=canary,
                tested_parameters=[],
                reflection_points=[],
                is_reflected=False,
                notes=["No parameters provided; reflection analysis skipped."],
            )

        reflection_points: list[ReflectionPoint] = []
        for parameter in tested_parameters:
            probe_params = dict(baseline_params)
            probe_params[parameter] = canary
            response = self._send_get(target_url, probe_params)
            if response.error:
                errors.append(f"Probe failed for parameter `{parameter}`: {response.error}")
                continue

            points = self._find_reflection_points(
                body=response.body,
                canary=canary,
                parameter=parameter,
                request_url=response.request_url,
            )
            reflection_points.extend(points)

            if not points:
                encoded_matches = self._find_encoded_canary_forms(response.body, canary)
                if encoded_matches:
                    notes.append(
                        f"Parameter `{parameter}` appears encoded ({', '.join(encoded_matches)})."
                    )

        browser_verification: BrowserVerificationResult | None = None
        if verify_in_browser:
            if reflection_points:
                browser_verification = self._verify_with_playwright(
                    target_url=target_url,
                    baseline_params=baseline_params,
                    parameter=reflection_points[0].parameter,
                )
            else:
                browser_verification = BrowserVerificationResult(
                    attempted=False,
                    js_executed=False,
                    evidence="No reflection found; browser verification skipped.",
                )

        if reflection_points:
            notes.append(
                "Raw canary reflection detected. Output encoding should be reviewed per context."
            )
        else:
            notes.append("No raw canary reflection detected in tested responses.")

        return XSSAuditResult(
            target_url=target_url,
            canary=canary,
            tested_parameters=tested_parameters,
            reflection_points=reflection_points,
            is_reflected=bool(reflection_points),
            browser_verification=browser_verification,
            notes=notes,
            errors=errors,
        )

    def _send_get(self, base_url: str, params: dict[str, str]) -> _HTTPProbeResponse:
        """Send one read-only GET request for reflection probing."""
        request_url = self._build_get_url(base_url, params)
        request = Request(
            request_url,
            method="GET",
            headers={"User-Agent": self._user_agent, "Accept": "text/html,*/*;q=0.8"},
        )
        started = time.perf_counter()

        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                body = (response.read(self._max_body_bytes) or b"").decode(
                    "utf-8", errors="replace"
                )
                return _HTTPProbeResponse(
                    request_url=request_url,
                    status_code=response.status,
                    body=body,
                    elapsed_ms=self._elapsed_ms(started),
                )
        except HTTPError as exc:
            try:
                body = (exc.read(self._max_body_bytes) or b"").decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                body = ""
            return _HTTPProbeResponse(
                request_url=request_url,
                status_code=exc.code,
                body=body,
                elapsed_ms=self._elapsed_ms(started),
                error=f"HTTP error {exc.code}",
            )
        except (URLError, TimeoutError, OSError) as exc:
            return _HTTPProbeResponse(
                request_url=request_url,
                status_code=None,
                body="",
                elapsed_ms=self._elapsed_ms(started),
                error=str(exc),
            )

    def _find_reflection_points(
        self,
        body: str,
        canary: str,
        parameter: str,
        request_url: str,
    ) -> list[ReflectionPoint]:
        """Find raw canary reflections and classify their rendering contexts."""
        points: list[ReflectionPoint] = []
        search_start = 0
        while True:
            index = body.find(canary, search_start)
            if index < 0:
                break
            context = self._detect_context(body, index)
            snippet = self._extract_snippet(body, index, len(canary))
            points.append(
                ReflectionPoint(
                    parameter=parameter,
                    context=context,
                    position=index,
                    snippet=snippet,
                    request_url=request_url,
                )
            )
            search_start = index + len(canary)
        return points

    def _detect_context(self, body: str, index: int) -> ReflectionContext:
        """Classify reflection point context heuristically."""
        lowered = body.lower()

        script_open = lowered.rfind("<script", 0, index)
        script_close = lowered.rfind("</script", 0, index)
        if script_open != -1 and script_open > script_close:
            script_end_after = lowered.find("</script", index)
            if script_end_after != -1:
                return "javascript"

        tag_open = body.rfind("<", 0, index)
        tag_close_before = body.rfind(">", 0, index)
        if tag_open != -1 and tag_open > tag_close_before:
            tag_end = body.find(">", index)
            if tag_end != -1:
                return "html_attribute"
            return "unknown"

        return "html_body"

    def _extract_snippet(self, body: str, index: int, marker_length: int) -> str:
        """Extract a compact nearby snippet for analyst review."""
        start = max(0, index - self._snippet_radius)
        end = min(len(body), index + marker_length + self._snippet_radius)
        snippet = body[start:end].replace("\n", " ").replace("\r", " ")
        return " ".join(snippet.split())

    def _find_encoded_canary_forms(self, body: str, canary: str) -> list[str]:
        """Detect common encoded forms of the canary for informational notes."""
        candidates = {
            "html-escaped": html.escape(canary, quote=True),
            "double-quote-escaped": canary.replace('"', "&quot;"),
            "single-quote-escaped": canary.replace("'", "&#x27;"),
        }
        matched: list[str] = []
        for name, token in candidates.items():
            if token != canary and token in body:
                matched.append(name)
        return matched

    def _verify_with_playwright(
        self,
        target_url: str,
        baseline_params: dict[str, str],
        parameter: str,
    ) -> BrowserVerificationResult:
        """
        Optionally verify possible execution by observing a console marker.

        This check injects only a harmless console marker and does not attempt
        data extraction or state-changing actions.
        """
        marker = f"XSS_JS_MARKER_{secrets.token_hex(6)}"
        payload = f'\"><script>console.log("{marker}")</script>'
        candidate = dict(baseline_params)
        candidate[parameter] = payload
        verification_url = self._build_get_url(target_url, candidate)

        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import (
                TimeoutError as PlaywrightTimeoutError,
                sync_playwright,
            )
        except ImportError:
            return BrowserVerificationResult(
                attempted=False,
                js_executed=False,
                error="Playwright not installed. Run `pip install playwright` and `playwright install`.",
            )

        try:
            messages: list[str] = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.on("console", lambda msg: messages.append(msg.text))
                page.goto(
                    verification_url,
                    wait_until="networkidle",
                    timeout=self._browser_timeout_ms,
                )
                context.close()
                browser.close()

            for message in messages:
                if marker in message:
                    return BrowserVerificationResult(
                        attempted=True,
                        js_executed=True,
                        evidence=f"Console marker observed: {marker}",
                    )
            return BrowserVerificationResult(
                attempted=True,
                js_executed=False,
                evidence="No canary console marker observed.",
            )
        except PlaywrightTimeoutError:
            return BrowserVerificationResult(
                attempted=True,
                js_executed=False,
                error=f"Browser verification timed out at {self._browser_timeout_ms}ms",
            )
        except PlaywrightError as exc:
            return BrowserVerificationResult(
                attempted=True,
                js_executed=False,
                error=f"Browser verification failed: {exc}",
            )

    def _normalize_url(self, url: str) -> str:
        """Normalize and validate an HTTP(S) URL."""
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("url must start with http:// or https://")
        if not parsed.netloc:
            raise ValueError("url must contain a host")
        path = parsed.path or "/"
        return urlunparse((scheme, parsed.netloc, path, "", parsed.query, ""))

    def _build_param_map(self, url: str, params: dict[str, Any]) -> dict[str, str]:
        """Merge query parameters from URL and explicit input params."""
        parsed = urlparse(url)
        merged: dict[str, str] = {}
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            merged[key] = value
        for key, value in params.items():
            merged[str(key)] = self._stringify(value)
        return merged

    def _build_get_url(self, base_url: str, params: dict[str, str]) -> str:
        """Compose deterministic GET URL with sorted query arguments."""
        parsed = urlparse(base_url)
        query = urlencode(sorted(params.items(), key=lambda item: item[0]), doseq=False)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

    @staticmethod
    def _build_canary() -> str:
        """Build a unique reflection canary token."""
        return f"XSSA_CANARY_{secrets.token_hex(8)}"

    @staticmethod
    def _stringify(value: Any) -> str:
        """Convert any parameter value to text."""
        if value is None:
            return ""
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        return str(value)

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        """Compute elapsed milliseconds."""
        return int((time.perf_counter() - started) * 1000)
