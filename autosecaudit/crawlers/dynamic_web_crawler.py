"""Playwright-based dynamic crawler for in-scope URL discovery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
from typing import TYPE_CHECKING, Any
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

if TYPE_CHECKING:
    from playwright.sync_api import Page, Request, Route


@dataclass(frozen=True)
class APIEndpointRecord:
    """Represents one observed API endpoint."""

    url: str
    method: str
    source: str


@dataclass(frozen=True)
class CrawlResult:
    """Structured crawler output used for downstream auditing/fuzzing."""

    start_url: str
    max_depth: int
    visited_pages: int
    discovered_urls: list[str]
    api_endpoints: list[APIEndpointRecord]
    url_parameters: dict[str, list[str]]
    parameter_origins: dict[str, list[str]]
    tech_stack: list[str]
    errors: list[str] = field(default_factory=list)


class DynamicWebCrawler:
    """
    Crawl dynamic websites and extract URL/API structure within strict scope.

    Features:
    - Breadth-first crawling by depth.
    - Automatic event triggering (buttons/forms) for dynamic content.
    - Allowed-domain scope enforcement.
    - URL/API/parameter extraction for later validation and fuzzing.
    """

    _CLICK_KEYWORDS = (
        "load more",
        "show more",
        "see more",
        "next",
        "expand",
        "view more",
        "more",
        "submit",
        "search",
    )

    _NON_HTTP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:")

    def __init__(
        self,
        allowed_domains: list[str],
        *,
        headless: bool = True,
        max_pages: int = 200,
        request_timeout_ms: int = 15000,
        wait_after_action_ms: int = 1200,
        max_event_clicks_per_page: int = 12,
        max_forms_per_page: int = 6,
        allow_non_get_forms: bool = False,
    ) -> None:
        if not allowed_domains:
            raise ValueError("allowed_domains must contain at least one domain")
        self._allowed_domains = {item.lower().lstrip(".") for item in allowed_domains if item}
        if not self._allowed_domains:
            raise ValueError("allowed_domains contains no valid values")

        self._headless = headless
        self._max_pages = max_pages
        self._request_timeout_ms = request_timeout_ms
        self._wait_after_action_ms = wait_after_action_ms
        self._max_event_clicks_per_page = max_event_clicks_per_page
        self._max_forms_per_page = max_forms_per_page
        self._allow_non_get_forms = allow_non_get_forms

        self._visited: set[str] = set()
        self._queued: set[str] = set()
        self._discovered_urls: set[str] = set()
        self._param_values: dict[str, set[str]] = {}
        self._param_origins: dict[str, set[str]] = {}
        self._api_endpoints: dict[tuple[str, str], APIEndpointRecord] = {}
        self._tech_stack: set[str] = set()
        self._errors: list[str] = []

    def crawl(self, start_url: str, max_depth: int) -> CrawlResult:
        """
        Crawl the target from `start_url` up to `max_depth`.

        Args:
            start_url: In-scope start URL.
            max_depth: Maximum breadth-first traversal depth.
        """
        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")

        normalized_start_url = self._canonicalize_url(start_url)
        if not normalized_start_url:
            raise ValueError("start_url must be a valid HTTP(S) URL")
        if not self._is_allowed(normalized_start_url):
            raise ValueError(f"start_url is outside allowed_domains: {normalized_start_url}")

        self._reset_state()
        self._record_url(normalized_start_url)

        queue: deque[tuple[str, int]] = deque([(normalized_start_url, 0)])
        self._queued.add(normalized_start_url)

        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import (
                TimeoutError as PlaywrightTimeoutError,
                sync_playwright,
            )
        except ImportError as exc:
            raise RuntimeError(
                "playwright is required. Install with `pip install playwright` and run `playwright install`."
            ) from exc

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=self._headless)
            context = browser.new_context(ignore_https_errors=True)
            context.set_default_navigation_timeout(self._request_timeout_ms)
            context.route("**/*", self._route_handler)

            page = context.new_page()
            self._attach_page_handlers(page)
            context.on("page", self._on_popup_page)

            while queue and len(self._visited) < self._max_pages:
                current_url, depth = queue.popleft()
                self._queued.discard(current_url)
                if depth > max_depth or current_url in self._visited:
                    continue

                self._visited.add(current_url)
                if not self._visit_page(page, current_url, PlaywrightTimeoutError, PlaywrightError):
                    continue

                self._extract_from_dom(page)
                self._trigger_events(page, PlaywrightTimeoutError, PlaywrightError)
                self._extract_from_dom(page)

                if depth >= max_depth:
                    continue

                for link in self._collect_next_links(page):
                    if link in self._visited or link in self._queued:
                        continue
                    queue.append((link, depth + 1))
                    self._queued.add(link)

            context.close()
            browser.close()

        return self._build_result(normalized_start_url, max_depth)

    def _visit_page(
        self,
        page: Page,
        url: str,
        timeout_error: type[Exception],
        playwright_error: type[Exception],
    ) -> bool:
        """Navigate to one URL and enforce in-scope navigation."""
        try:
            page.goto(url, wait_until="networkidle", timeout=self._request_timeout_ms)
            self._record_url(page.url)
            if not self._is_allowed(page.url):
                self._errors.append(f"Blocked out-of-scope navigation: {page.url}")
                try:
                    page.go_back(wait_until="domcontentloaded", timeout=2000)
                except Exception:
                    pass
                return False
            return True
        except timeout_error:
            self._errors.append(f"Timeout visiting {url}")
            return False
        except playwright_error as exc:
            self._errors.append(f"Failed visiting {url}: {exc}")
            return False

    def _collect_next_links(self, page: Page) -> list[str]:
        """Collect in-scope next-hop links for BFS expansion."""
        candidates: list[str] = []
        try:
            hrefs: list[str] = page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(el => el.getAttribute('href') || '')",
            )
        except Exception:
            return candidates

        for href in hrefs:
            next_url = self._resolve_link(page.url, href)
            if not next_url or not self._is_allowed(next_url):
                continue
            self._record_url(next_url)
            candidates.append(next_url)
        return candidates

    def _extract_from_dom(self, page: Page) -> None:
        """Extract URLs and possible API patterns from DOM source."""
        try:
            raw_links: list[str] = page.evaluate(
                """() => {
                    const values = [];
                    const selectors = [
                        "a[href]",
                        "form[action]",
                        "link[href]",
                        "script[src]",
                        "iframe[src]"
                    ];
                    for (const selector of selectors) {
                        document.querySelectorAll(selector).forEach((el) => {
                            const candidate = el.getAttribute("href")
                                || el.getAttribute("action")
                                || el.getAttribute("src");
                            if (candidate) values.push(candidate);
                        });
                    }
                    return values;
                }"""
            )
        except Exception:
            raw_links = []

        for raw_link in raw_links:
            resolved = self._resolve_link(page.url, raw_link)
            if not resolved or not self._is_allowed(resolved):
                continue
            self._record_url(resolved)
            if self._looks_like_api_url(resolved):
                self._record_api_endpoint(resolved, "GET", "dom_pattern")

        try:
            html = page.content()
        except Exception:
            html = ""
        if html:
            self._record_tech_stack_from_text(html)
        if html:
            for match in re.findall(r"""["']((?:https?://|/)[^"'<>]*(?:api|graphql)[^"'<>]*)["']""", html, flags=re.IGNORECASE):
                resolved = self._resolve_link(page.url, match)
                if resolved and self._is_allowed(resolved):
                    self._record_api_endpoint(resolved, "GET", "content_pattern")
                    self._record_tech_stack_from_text(resolved)

    def _trigger_events(
        self,
        page: Page,
        timeout_error: type[Exception],
        playwright_error: type[Exception],
    ) -> None:
        """Trigger user-like events to expose dynamic links/endpoints."""
        self._trigger_buttons(page, timeout_error, playwright_error)
        self._trigger_forms(page, timeout_error, playwright_error)

    def _trigger_buttons(
        self,
        page: Page,
        timeout_error: type[Exception],
        playwright_error: type[Exception],
    ) -> None:
        """Click likely dynamic-content buttons/links (e.g., Load More)."""
        try:
            handles = page.query_selector_all(
                "button, [role='button'], input[type='button'], input[type='submit'], a[href]"
            )
        except Exception:
            return

        clicks_done = 0
        seen_signatures: set[str] = set()
        for handle in handles:
            if clicks_done >= self._max_event_clicks_per_page:
                break

            try:
                if not handle.is_visible():
                    continue
            except Exception:
                continue

            text = self._safe_lower_text(handle)
            if not self._matches_click_keyword(text):
                continue

            try:
                href = handle.get_attribute("href") or ""
            except Exception:
                href = ""
            if href:
                target_link = self._resolve_link(page.url, href)
                if not target_link or not self._is_allowed(target_link):
                    continue

            signature = f"{text}|{href}"
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)

            try:
                handle.click(timeout=2000)
                page.wait_for_timeout(self._wait_after_action_ms)
                try:
                    page.wait_for_load_state("networkidle", timeout=3500)
                except Exception:
                    pass
                if not self._is_allowed(page.url):
                    self._errors.append(f"Blocked out-of-scope button navigation: {page.url}")
                    try:
                        page.go_back(wait_until="domcontentloaded", timeout=2000)
                    except Exception:
                        pass
                    continue
                self._record_url(page.url)
                clicks_done += 1
            except timeout_error:
                self._errors.append("Button interaction timed out")
            except playwright_error as exc:
                self._errors.append(f"Button interaction failed: {exc}")

    def _trigger_forms(
        self,
        page: Page,
        timeout_error: type[Exception],
        playwright_error: type[Exception],
    ) -> None:
        """Submit a bounded number of forms to trigger dynamic requests."""
        try:
            forms = page.query_selector_all("form")
        except Exception:
            return

        submitted = 0
        for form in forms:
            if submitted >= self._max_forms_per_page:
                break

            try:
                method = (form.get_attribute("method") or "get").strip().lower()
                action = form.get_attribute("action") or page.url
            except Exception:
                continue

            action_url = self._resolve_link(page.url, action)
            if action_url and self._is_allowed(action_url):
                self._record_url(action_url)
            if method != "get" and not self._allow_non_get_forms:
                continue

            self._fill_form_inputs(form)
            try:
                form.evaluate(
                    """element => {
                        if (typeof element.requestSubmit === "function") {
                            element.requestSubmit();
                        } else {
                            element.submit();
                        }
                    }"""
                )
                page.wait_for_timeout(self._wait_after_action_ms)
                try:
                    page.wait_for_load_state("networkidle", timeout=3500)
                except Exception:
                    pass
                if not self._is_allowed(page.url):
                    self._errors.append(f"Blocked out-of-scope form navigation: {page.url}")
                    try:
                        page.go_back(wait_until="domcontentloaded", timeout=2000)
                    except Exception:
                        pass
                    continue
                self._record_url(page.url)
                submitted += 1
            except timeout_error:
                self._errors.append("Form interaction timed out")
            except playwright_error as exc:
                self._errors.append(f"Form interaction failed: {exc}")

    def _fill_form_inputs(self, form: Any) -> None:
        """Fill forms with benign placeholder values."""
        try:
            inputs = form.query_selector_all("input, textarea, select")
        except Exception:
            return

        for element in inputs[:20]:
            try:
                tag_name = (element.evaluate("el => el.tagName") or "").lower()
            except Exception:
                continue

            if tag_name == "select":
                try:
                    element.select_option(index=0)
                except Exception:
                    pass
                continue

            input_type = "text"
            if tag_name == "input":
                try:
                    input_type = (element.get_attribute("type") or "text").lower()
                except Exception:
                    input_type = "text"

            if input_type in {"hidden", "submit", "button", "reset", "file", "image", "password"}:
                continue

            try:
                if input_type in {"checkbox", "radio"}:
                    element.check(force=True)
                    continue
            except Exception:
                continue

            value = self._placeholder_for_type(input_type)
            try:
                element.fill(value, timeout=1000)
            except Exception:
                pass

    def _attach_page_handlers(self, page: Page) -> None:
        """Attach network event listeners."""
        try:
            page.on("request", self._on_request)
        except Exception:
            pass

    def _on_popup_page(self, popup_page: Page) -> None:
        """Handle popup pages by keeping only in-scope documents."""
        self._attach_page_handlers(popup_page)
        try:
            popup_page.wait_for_load_state("domcontentloaded", timeout=3000)
        except Exception:
            pass

        if not self._is_allowed(popup_page.url):
            self._errors.append(f"Closed out-of-scope popup: {popup_page.url}")
            try:
                popup_page.close()
            except Exception:
                pass
            return

        self._record_url(popup_page.url)
        self._extract_from_dom(popup_page)
        try:
            popup_page.close()
        except Exception:
            pass

    def _on_request(self, request: Request) -> None:
        """Capture in-scope network requests and classify API calls."""
        try:
            url = self._canonicalize_url(request.url)
        except Exception:
            return
        if not url or not self._is_allowed(url):
            return

        self._record_url(url)
        if self._looks_like_api_request(url=url, resource_type=request.resource_type):
            self._record_api_endpoint(
                url=url,
                method=(request.method or "GET").upper(),
                source=request.resource_type or "network",
            )

    def _route_handler(self, route: Route) -> None:
        """Abort out-of-scope document navigations."""
        try:
            request = route.request
            if (
                request.is_navigation_request()
                and request.resource_type == "document"
                and not self._is_allowed(request.url)
            ):
                self._errors.append(f"Blocked out-of-scope request: {request.url}")
                route.abort()
                return
            route.continue_()
        except Exception:
            try:
                route.abort()
            except Exception:
                pass

    def _record_url(self, url: str) -> None:
        """Store one in-scope URL and extract query parameters."""
        normalized = self._canonicalize_url(url)
        if not normalized or not self._is_allowed(normalized):
            return

        self._discovered_urls.add(normalized)
        self._record_tech_stack_from_text(normalized)
        parsed = urlparse(normalized)
        if not parsed.query:
            return

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            self._param_values.setdefault(key, set()).add(value)
            self._param_origins.setdefault(key, set()).add(normalized)

    def _record_api_endpoint(self, url: str, method: str, source: str) -> None:
        """Store API endpoint record with method+url deduplication."""
        normalized = self._canonicalize_url(url)
        if not normalized or not self._is_allowed(normalized):
            return
        key = (method.upper(), normalized)
        self._api_endpoints[key] = APIEndpointRecord(
            url=normalized,
            method=method.upper(),
            source=source,
        )

    def _build_result(self, start_url: str, max_depth: int) -> CrawlResult:
        """Build immutable crawl result."""
        url_parameters = {
            key: sorted(values)
            for key, values in sorted(self._param_values.items(), key=lambda item: item[0])
        }
        parameter_origins = {
            key: sorted(values)
            for key, values in sorted(self._param_origins.items(), key=lambda item: item[0])
        }
        endpoints = sorted(
            self._api_endpoints.values(),
            key=lambda item: (item.url, item.method, item.source),
        )
        return CrawlResult(
            start_url=start_url,
            max_depth=max_depth,
            visited_pages=len(self._visited),
            discovered_urls=sorted(self._discovered_urls),
            api_endpoints=endpoints,
            url_parameters=url_parameters,
            parameter_origins=parameter_origins,
            tech_stack=sorted(self._tech_stack),
            errors=list(self._errors),
        )

    def _reset_state(self) -> None:
        """Reset mutable crawl state before each run."""
        self._visited.clear()
        self._queued.clear()
        self._discovered_urls.clear()
        self._param_values.clear()
        self._param_origins.clear()
        self._api_endpoints.clear()
        self._tech_stack.clear()
        self._errors.clear()

    def _record_tech_stack_from_text(self, text: str) -> None:
        """Infer coarse technology stack hints from observed content and URLs."""
        lowered = str(text).lower()
        indicators = {
            "wordpress": ("wp-content", "wp-includes", "wordpress"),
            "spring": ("springframework", "/actuator", "whitelabel error page"),
            "jenkins": ("jenkins", "/crumbissuer/", "adjuncts"),
            "grafana": ("grafana", "public/build/grafana", "x-grafana"),
            "struts": ("struts", "struts2", "/struts/"),
            "drupal": ("drupal", "/sites/default/", "drupal-settings-json"),
            "joomla": ("joomla", "com_content", "/media/system/js/"),
        }
        for stack, tokens in indicators.items():
            if any(token in lowered for token in tokens):
                self._tech_stack.add(stack)

    def _resolve_link(self, base_url: str, raw_link: str) -> str:
        """Resolve relative links and normalize them."""
        candidate = raw_link.strip()
        if not candidate:
            return ""
        lowered = candidate.lower()
        if lowered.startswith(self._NON_HTTP_SCHEMES):
            return ""
        resolved = urljoin(base_url, candidate)
        return self._canonicalize_url(resolved)

    def _canonicalize_url(self, url: str) -> str:
        """Normalize URL for stable deduplication."""
        candidate = url.strip()
        if not candidate:
            return ""

        parsed = urlparse(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return ""
        if not parsed.netloc:
            return ""

        path = parsed.path or "/"
        normalized_query = urlencode(
            sorted(parse_qsl(parsed.query, keep_blank_values=True)),
            doseq=True,
        )
        return urlunparse(
            (
                scheme,
                parsed.netloc.lower(),
                path,
                "",
                normalized_query,
                "",
            )
        )

    def _is_allowed(self, url: str) -> bool:
        """Enforce domain scope (exact host or subdomain of allowed domain)."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        for allowed in self._allowed_domains:
            if host == allowed or host.endswith(f".{allowed}"):
                return True
        return False

    def _looks_like_api_request(self, url: str, resource_type: str) -> bool:
        """Classify likely API/network endpoints."""
        if resource_type in {"xhr", "fetch"}:
            return True
        return self._looks_like_api_url(url)

    @staticmethod
    def _looks_like_api_url(url: str) -> bool:
        """Detect common API URL patterns."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return (
            "/api/" in path
            or path.endswith(".json")
            or "/graphql" in path
            or path.endswith("/graphql")
            or "/rest/" in path
        )

    @staticmethod
    def _placeholder_for_type(input_type: str) -> str:
        """Return benign default values per input type."""
        mapping = {
            "email": "audit@example.com",
            "search": "security test",
            "url": "https://example.com",
            "tel": "1234567890",
            "number": "1",
            "date": "2026-01-01",
        }
        return mapping.get(input_type, "audit")

    @staticmethod
    def _safe_lower_text(handle: Any) -> str:
        """Read interactive element text safely."""
        chunks: list[str] = []
        try:
            inner_text = (handle.inner_text(timeout=500) or "").strip()
            if inner_text:
                chunks.append(inner_text)
        except Exception:
            pass
        try:
            value_text = (handle.get_attribute("value") or "").strip()
            if value_text:
                chunks.append(value_text)
        except Exception:
            pass
        try:
            aria_label = (handle.get_attribute("aria-label") or "").strip()
            if aria_label:
                chunks.append(aria_label)
        except Exception:
            pass
        return " ".join(chunks).lower()

    def _matches_click_keyword(self, text: str) -> bool:
        """Return whether control text should be auto-triggered."""
        if not text:
            return False
        return any(keyword in text for keyword in self._CLICK_KEYWORDS)

    def to_json(self, result: CrawlResult) -> str:
        """Serialize crawl result to JSON."""
        payload = {
            "start_url": result.start_url,
            "max_depth": result.max_depth,
            "visited_pages": result.visited_pages,
            "discovered_urls": result.discovered_urls,
            "api_endpoints": [
                {"url": item.url, "method": item.method, "source": item.source}
                for item in result.api_endpoints
            ],
            "url_parameters": result.url_parameters,
            "parameter_origins": result.parameter_origins,
            "tech_stack": result.tech_stack,
            "errors": result.errors,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)
