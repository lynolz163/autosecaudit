"""NVD CVE lookup service with lightweight local caching."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .template_capability_index import TemplateCapabilityIndex


DEFAULT_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_TTL_SECONDS = 21600
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_CACHE_PATH = "~/.autosecaudit/nvd_cache.sqlite3"


class CveServiceError(RuntimeError):
    """Raised when NVD query/parse operations fail."""


@dataclass(frozen=True)
class NormalizedCve:
    """One normalized CVE result entry."""

    cve_id: str
    severity: str
    description: str
    affected_versions: list[str]
    has_nuclei_template: bool
    cvss_score: float | None = None
    component: str | None = None
    version: str | None = None
    template_capability: dict[str, Any] | None = None
    source: str = "nvd"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "description": self.description,
            "affected_versions": list(self.affected_versions),
            "has_nuclei_template": self.has_nuclei_template,
            "cvss_score": self.cvss_score,
            "component": self.component,
            "version": self.version,
            "template_capability": dict(self.template_capability or {}),
            "source": self.source,
        }


class NvdCveService:
    """NVD API wrapper with bounded local cache."""

    _TEMPLATE_CACHE_IDS: set[str] | None = None
    _TEMPLATE_CACHE_LOADED_AT: float = 0.0

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
        cache_db_path: str | Path | None = None,
        cache_ttl_seconds: int | None = None,
    ) -> None:
        self._base_url = str(base_url or os.getenv("AUTOSECAUDIT_NVD_BASE_URL") or DEFAULT_NVD_BASE_URL).strip()
        if not self._base_url:
            self._base_url = DEFAULT_NVD_BASE_URL
        self._api_key = str(api_key or os.getenv("AUTOSECAUDIT_NVD_API_KEY") or "").strip() or None
        self._timeout_seconds = max(
            1.0,
            float(timeout_seconds or os.getenv("AUTOSECAUDIT_NVD_TIMEOUT_SECONDS") or DEFAULT_TIMEOUT_SECONDS),
        )

        ttl_raw = cache_ttl_seconds
        if ttl_raw is None:
            ttl_raw = int(os.getenv("AUTOSECAUDIT_NVD_CACHE_TTL_SECONDS", str(DEFAULT_CACHE_TTL_SECONDS)) or DEFAULT_CACHE_TTL_SECONDS)
        self._cache_ttl_seconds = max(0, int(ttl_raw))

        cache_path_raw = cache_db_path or os.getenv("AUTOSECAUDIT_NVD_CACHE_DB_PATH") or DEFAULT_CACHE_PATH
        self._cache_db_path = Path(str(cache_path_raw)).expanduser().resolve()
        self._cache_enabled = self._cache_ttl_seconds > 0
        if self._cache_enabled:
            self._init_cache_db()

    def search(
        self,
        *,
        keyword: str | None = None,
        cpe_name: str | None = None,
        severity: str | None = None,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """Query NVD and return normalized CVE list."""
        params: dict[str, str] = {
            "resultsPerPage": str(max(1, min(int(max_results or 20), 200))),
        }
        if keyword:
            params["keywordSearch"] = str(keyword).strip()
        if cpe_name:
            params["cpeName"] = str(cpe_name).strip()
        if severity:
            normalized = str(severity).strip().lower()
            mapped = {
                "critical": "CRITICAL",
                "high": "HIGH",
                "medium": "MEDIUM",
                "low": "LOW",
            }.get(normalized)
            if mapped:
                params["cvssV3Severity"] = mapped

        if not params.get("keywordSearch") and not params.get("cpeName"):
            raise CveServiceError("nvd_query_requires_keyword_or_cpe")

        cache_key = self._cache_key(params)
        if self._cache_enabled:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        payload = self._fetch_nvd_payload(params)
        normalized = self._normalize_nvd_payload(payload)

        if self._cache_enabled:
            self._cache_set(cache_key, normalized)
        return normalized

    def lookup_components(
        self,
        components: list[str],
        *,
        severity: str | None = None,
        max_results_per_component: int = 20,
        service: str | None = None,
        rag_hits: list[dict[str, Any]] | None = None,
        rag_recommended_tools: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Lookup CVEs for detected components (name/version)."""
        dedup_components: list[str] = []
        seen_components: set[str] = set()
        for raw in components:
            normalized = str(raw).strip()
            if not normalized:
                continue
            lowered = normalized.lower()
            if lowered in seen_components:
                continue
            seen_components.add(lowered)
            dedup_components.append(normalized)

        output: list[dict[str, Any]] = []
        seen_results: set[tuple[str, str]] = set()
        for raw_component in dedup_components:
            component, version = self._split_component(raw_component)
            cpe_name = self._component_to_cpe(component, version)
            component_results: list[dict[str, Any]] = []
            if cpe_name:
                component_results = self.search(
                    cpe_name=cpe_name,
                    severity=severity,
                    max_results=max_results_per_component,
                )
            if not component_results:
                keyword = f"{component} {version}".strip() if version else component
                component_results = self.search(
                    keyword=keyword,
                    severity=severity,
                    max_results=max_results_per_component,
                )

            ranked_component_results = self._rank_component_results(
                component_results,
                component=component,
                version=version,
                service=service,
                rag_hits=rag_hits or [],
                rag_recommended_tools=rag_recommended_tools or [],
            )
            for item in ranked_component_results:
                cve_id = str(item.get("cve_id", "")).strip().upper()
                if not cve_id:
                    continue
                key = (cve_id, component.lower())
                if key in seen_results:
                    continue
                seen_results.add(key)
                enriched = dict(item)
                enriched["component"] = component
                enriched["version"] = version
                enriched["service"] = str(service or "").strip().lower() or None
                output.append(enriched)
        return output

    def _fetch_nvd_payload(self, params: dict[str, str]) -> dict[str, Any]:
        query = urlencode(params, doseq=True)
        url = f"{self._base_url}?{query}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "AutoSecAudit/0.2 (NVD-CVE-Lookup)",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key
        request = Request(url=url, method="GET", headers=headers)
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                raw = (response.read(4_000_000) or b"").decode("utf-8", errors="replace")
        except HTTPError as exc:
            detail = ""
            try:
                detail = (exc.read(1000) or b"").decode("utf-8", errors="replace").strip()
            except Exception:  # noqa: BLE001
                detail = ""
            suffix = f": {detail}" if detail else ""
            raise CveServiceError(f"nvd_http_error:{exc.code}{suffix}") from exc
        except URLError as exc:
            raise CveServiceError(f"nvd_connection_error:{exc}") from exc
        except OSError as exc:
            raise CveServiceError(f"nvd_transport_error:{exc}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CveServiceError("nvd_invalid_json_payload") from exc
        if not isinstance(payload, dict):
            raise CveServiceError("nvd_payload_not_object")
        return payload

    def _normalize_nvd_payload(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return []

        output: list[dict[str, Any]] = []
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve", {})
            if not isinstance(cve, dict):
                continue

            cve_id = str(cve.get("id", "")).strip().upper()
            if not cve_id:
                continue
            description = self._extract_description(cve)
            cvss_score, severity = self._extract_cvss(cve.get("metrics", {}))
            affected_versions = self._extract_affected_versions(cve.get("configurations", []))
            template_capability = TemplateCapabilityIndex.get_capability(cve_id)
            normalized = NormalizedCve(
                cve_id=cve_id,
                severity=severity,
                description=description,
                affected_versions=affected_versions,
                has_nuclei_template=bool(template_capability.get("has_template", False)),
                cvss_score=cvss_score,
                template_capability=template_capability,
            )
            output.append(normalized.to_dict())

        output.sort(
            key=lambda item: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(item.get("severity", "info")), 9),
                -(float(item.get("cvss_score")) if isinstance(item.get("cvss_score"), (int, float)) else -1.0),
                str(item.get("cve_id", "")),
            )
        )
        return output

    def _rank_component_results(
        self,
        results: list[dict[str, Any]],
        *,
        component: str,
        version: str | None,
        service: str | None,
        rag_hits: list[dict[str, Any]],
        rag_recommended_tools: list[str],
    ) -> list[dict[str, Any]]:
        return self.rank_cve_candidates(
            results,
            component=component,
            version=version,
            service=service,
            rag_hits=rag_hits,
            rag_recommended_tools=rag_recommended_tools,
        )

    @classmethod
    def rank_cve_candidates(
        cls,
        candidates: list[dict[str, Any]],
        *,
        component: str | None,
        version: str | None,
        service: str | None,
        rag_hits: list[dict[str, Any]] | None = None,
        rag_recommended_tools: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        normalized_component = str(component).strip().lower()
        normalized_version = str(version or "").strip().lower()
        normalized_service = str(service or "").strip().lower()
        normalized_tools = {
            str(item).strip().lower()
            for item in (rag_recommended_tools or [])
            if str(item).strip()
        }
        rag_tags: set[str] = set()
        for item in (rag_hits or []):
            if not isinstance(item, dict):
                continue
            for raw_tag in item.get("tags", []):
                token = str(raw_tag).strip().lower()
                if token:
                    rag_tags.add(token)
            for text in (item.get("title"), item.get("summary"), item.get("snippet")):
                for token in re.findall(r"[a-z0-9][a-z0-9._:-]{1,48}", str(text or "").lower()):
                    rag_tags.add(token)

        component_aliases = cls._protocol_aliases(normalized_component)
        service_aliases = cls._protocol_aliases(normalized_service)

        def score(item: dict[str, Any]) -> tuple[float, int, float, str]:
            capability = item.get("template_capability", {})
            if not isinstance(capability, dict):
                capability = {}
            if not capability:
                capability = TemplateCapabilityIndex.get_capability(str(item.get("cve_id", "")).strip().upper())
            has_template = bool(item.get("has_nuclei_template", capability.get("has_template", False)))
            template_tags = {
                str(token).strip().lower()
                for token in capability.get("protocol_tags", [])
                if str(token).strip()
            }
            expanded_template_tags: set[str] = set()
            for token in template_tags:
                expanded_template_tags.update(cls._protocol_aliases(token))
            text_blob = " ".join(
                [
                    str(item.get("description", "")).lower(),
                    " ".join(str(entry).lower() for entry in item.get("affected_versions", []) if str(entry).strip()),
                ]
            )
            weighted = 0.0
            cvss_score = item.get("cvss_score")
            if isinstance(cvss_score, (int, float)):
                weighted += float(cvss_score)
            severity = str(item.get("severity", "info")).strip().lower()
            weighted += {
                "critical": 10.0,
                "high": 7.0,
                "medium": 4.0,
                "low": 1.0,
            }.get(severity, 0.0)
            if has_template:
                weighted += 6.0
            weighted += min(int(capability.get("template_count", 0) or 0), 5)
            if component_aliases and expanded_template_tags.intersection(component_aliases):
                weighted += 4.5
            if service_aliases and expanded_template_tags.intersection(service_aliases):
                weighted += 3.5
            if component_aliases and rag_tags.intersection(component_aliases):
                weighted += 3.0
            if service_aliases and rag_tags.intersection(service_aliases):
                weighted += 2.5
            if normalized_version and normalized_version in text_blob:
                weighted += 1.5
            if normalized_component and normalized_component in text_blob:
                weighted += 1.5
            if "cve_lookup" in normalized_tools:
                weighted += 1.0
            if "cve_verify" in normalized_tools and has_template:
                weighted += 3.0
            if "nuclei_exploit_check" in normalized_tools and has_template:
                weighted += 4.0
            if "poc_sandbox_exec" in normalized_tools and (
                expanded_template_tags.intersection(component_aliases)
                or expanded_template_tags.intersection(service_aliases)
                or rag_tags.intersection(component_aliases)
                or rag_tags.intersection(service_aliases)
            ):
                weighted += 3.0
            return (
                weighted,
                -{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 9),
                float(cvss_score) if isinstance(cvss_score, (int, float)) else -1.0,
                str(item.get("cve_id", "")),
            )

        ranked = [dict(item) for item in candidates if isinstance(item, dict)]
        ranked.sort(key=score, reverse=True)
        for index, item in enumerate(ranked, start=1):
            capability = item.get("template_capability", {})
            if not isinstance(capability, dict) or not capability:
                capability = TemplateCapabilityIndex.get_capability(str(item.get("cve_id", "")).strip().upper())
            item["template_capability"] = capability
            item["has_nuclei_template"] = bool(item.get("has_nuclei_template", capability.get("has_template", False)))
            item["rank"] = index
            item["ranking_context"] = {
                "component": normalized_component or None,
                "version": normalized_version or None,
                "service": normalized_service or None,
                "rag_recommended_tools": sorted(normalized_tools),
                "rag_tags": sorted(rag_tags)[:20],
                "protocol_aliases": sorted(component_aliases | service_aliases),
            }
        return ranked

    @staticmethod
    def _protocol_aliases(value: str) -> set[str]:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return set()
        alias_groups = (
            {"http", "https", "tls", "ssl"},
            {"ssh", "openssh", "dropbear"},
            {"postgres", "postgresql"},
            {"mysql", "mariadb"},
            {"redis"},
            {"memcached"},
            {"smtp", "mail"},
        )
        aliases = {normalized}
        for group in alias_groups:
            if normalized in group:
                aliases.update(group)
                break
        return aliases

    def _extract_description(self, cve: dict[str, Any]) -> str:
        descriptions = cve.get("descriptions", [])
        if isinstance(descriptions, list):
            for entry in descriptions:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("lang", "")).strip().lower() == "en":
                    text = str(entry.get("value", "")).strip()
                    if text:
                        return text
            for entry in descriptions:
                if isinstance(entry, dict):
                    text = str(entry.get("value", "")).strip()
                    if text:
                        return text
        return "No description provided by NVD."

    def _extract_cvss(self, metrics: Any) -> tuple[float | None, str]:
        if not isinstance(metrics, dict):
            return None, "info"
        metric_keys = (
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV40",
            "cvssMetricV2",
        )
        for key in metric_keys:
            entries = metrics.get(key, [])
            if not isinstance(entries, list) or not entries:
                continue
            first = entries[0] if isinstance(entries[0], dict) else {}
            cvss_data = first.get("cvssData", {}) if isinstance(first, dict) else {}
            score = None
            if isinstance(cvss_data, dict):
                try:
                    score = float(cvss_data.get("baseScore"))
                except (TypeError, ValueError):
                    score = None
                severity = str(cvss_data.get("baseSeverity", "")).strip().lower()
                if severity in {"critical", "high", "medium", "low"}:
                    return score, severity
            fallback_severity = str(first.get("baseSeverity", "")).strip().lower()
            if fallback_severity in {"critical", "high", "medium", "low"}:
                return score, fallback_severity
            if score is not None:
                return score, self._severity_from_score(score)
        return None, "info"

    def _extract_affected_versions(self, configurations: Any) -> list[str]:
        versions: list[str] = []
        seen: set[str] = set()
        if not isinstance(configurations, list):
            return versions
        for block in configurations:
            if not isinstance(block, dict):
                continue
            nodes = block.get("nodes", [])
            if not isinstance(nodes, list):
                continue
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                cpe_matches = node.get("cpeMatch", [])
                if not isinstance(cpe_matches, list):
                    continue
                for cpe_match in cpe_matches:
                    if not isinstance(cpe_match, dict):
                        continue
                    criteria = str(cpe_match.get("criteria", "")).strip()
                    if not criteria or criteria in seen:
                        continue
                    seen.add(criteria)
                    versions.append(criteria)
                    if len(versions) >= 20:
                        return versions
        return versions

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    @staticmethod
    def _split_component(raw_component: str) -> tuple[str, str | None]:
        normalized = str(raw_component).strip()
        if not normalized:
            return "", None
        for separator in ("/", " ", ":"):
            if separator in normalized:
                name, version = normalized.split(separator, maxsplit=1)
                return name.strip().lower(), version.strip() or None
        return normalized.lower(), None

    @staticmethod
    def _component_to_cpe(component: str, version: str | None) -> str | None:
        name = str(component).strip().lower()
        if not name:
            return None
        vendor_map = {
            "nginx": "nginx",
            "apache": "apache",
            "httpd": "apache",
            "wordpress": "wordpress",
            "drupal": "drupal",
            "joomla": "joomla",
            "jenkins": "jenkins",
            "grafana": "grafana",
            "spring": "vmware",
            "django": "djangoproject",
            "flask": "palletsprojects",
            "express": "expressjs",
            "react": "facebook",
            "angular": "google",
            "vue": "vuejs",
            "rails": "rubyonrails",
            "laravel": "laravel",
            "mysql": "oracle",
            "postgres": "postgresql",
            "postgresql": "postgresql",
            "redis": "redis",
            "memcached": "memcached",
            "openssh": "openbsd",
        }
        product_map = {
            "httpd": "http_server",
            "spring": "spring_framework",
            "express": "express",
            "react": "react",
            "angular": "angular",
            "vue": "vue.js",
            "rails": "ruby_on_rails",
            "postgres": "postgresql",
            "openssh": "openssh",
        }
        vendor = vendor_map.get(name, name)
        product = product_map.get(name, name)
        version_token = version or "*"
        return f"cpe:2.3:a:{vendor}:{product}:{version_token}:*:*:*:*:*:*:*"

    @classmethod
    def _has_nuclei_template(cls, cve_id: str) -> bool:
        normalized = str(cve_id).strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,8}", normalized):
            return False
        capability = TemplateCapabilityIndex.get_capability(normalized)
        return bool(capability.get("has_template", False))

    @classmethod
    def _load_nuclei_template_ids(cls) -> set[str]:
        ttl_seconds = max(
            1,
            int(os.getenv("AUTOSECAUDIT_NUCLEI_TEMPLATE_CACHE_TTL_SECONDS", "600") or 600),
        )
        now = time.time()
        if (
            cls._TEMPLATE_CACHE_IDS is not None
            and (now - cls._TEMPLATE_CACHE_LOADED_AT) <= ttl_seconds
        ):
            return cls._TEMPLATE_CACHE_IDS

        ids = TemplateCapabilityIndex.load_ids()
        cls._TEMPLATE_CACHE_IDS = ids
        cls._TEMPLATE_CACHE_LOADED_AT = now
        return ids

    def _cache_key(self, params: dict[str, str]) -> str:
        payload = json.dumps(params, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _init_cache_db(self) -> None:
        self._cache_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._cache_db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cache_key TEXT PRIMARY KEY,
                    fetched_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _cache_get(self, cache_key: str) -> list[dict[str, Any]] | None:
        now = int(time.time())
        with sqlite3.connect(str(self._cache_db_path)) as conn:
            row = conn.execute(
                "SELECT fetched_at, payload FROM cve_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if not row:
            return None
        fetched_at = int(row[0] or 0)
        if (now - fetched_at) > self._cache_ttl_seconds:
            return None
        try:
            payload = json.loads(str(row[1]))
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, list):
            return None
        return [item for item in payload if isinstance(item, dict)]

    def _cache_set(self, cache_key: str, payload: list[dict[str, Any]]) -> None:
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        now = int(time.time())
        with sqlite3.connect(str(self._cache_db_path)) as conn:
            conn.execute(
                """
                INSERT INTO cve_cache(cache_key, fetched_at, payload)
                VALUES(?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    fetched_at = excluded.fetched_at,
                    payload = excluded.payload
                """,
                (cache_key, now, serialized),
            )
            conn.commit()
