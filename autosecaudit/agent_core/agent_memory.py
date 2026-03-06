"""Local memory store with segmented memory, scoring, and RAG fusion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable
from urllib.parse import urlparse

from .rag_service import RagIntelService


DEFAULT_AGENT_MEMORY_DIR_ENV = "AUTOSECAUDIT_AGENT_MEMORY_DIR"
DEFAULT_AGENT_MEMORY_DIR = Path("config/agent_memory")
DEFAULT_RECON_TTL_ENV = "AUTOSECAUDIT_AGENT_MEMORY_RECON_TTL_SECONDS"
DEFAULT_EXPLOIT_TTL_ENV = "AUTOSECAUDIT_AGENT_MEMORY_EXPLOIT_TTL_SECONDS"
DEFAULT_REPORT_TTL_ENV = "AUTOSECAUDIT_AGENT_MEMORY_REPORT_TTL_SECONDS"
DEFAULT_RECON_TTL_SECONDS = 30 * 24 * 3600
DEFAULT_EXPLOIT_TTL_SECONDS = 14 * 24 * 3600
DEFAULT_REPORT_TTL_SECONDS = 21 * 24 * 3600
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


class AgentMemoryStore:
    """Persist target-scoped memory and provide compact planning context."""

    def __init__(
        self,
        *,
        base_dir: str | Path | None = None,
        rag_service: RagIntelService | None = None,
        rag_corpus_path: str | Path | None = None,
        recon_ttl_seconds: int | None = None,
        exploit_ttl_seconds: int | None = None,
        report_ttl_seconds: int | None = None,
    ) -> None:
        raw_base = str(
            base_dir
            or os.getenv(DEFAULT_AGENT_MEMORY_DIR_ENV, "").strip()
            or DEFAULT_AGENT_MEMORY_DIR
        ).strip()
        self._base_dir = Path(raw_base).expanduser()
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._recon_ttl_seconds = max(
            60,
            int(recon_ttl_seconds or os.getenv(DEFAULT_RECON_TTL_ENV, DEFAULT_RECON_TTL_SECONDS)),
        )
        self._exploit_ttl_seconds = max(
            60,
            int(exploit_ttl_seconds or os.getenv(DEFAULT_EXPLOIT_TTL_ENV, DEFAULT_EXPLOIT_TTL_SECONDS)),
        )
        self._report_ttl_seconds = max(
            60,
            int(report_ttl_seconds or os.getenv(DEFAULT_REPORT_TTL_ENV, DEFAULT_REPORT_TTL_SECONDS)),
        )
        self._rag_service = rag_service or RagIntelService(corpus_path=rag_corpus_path)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def load(self, *, target: str) -> dict[str, Any]:
        """Load one persisted target memory snapshot."""
        path = self.path_for_target(target)
        if not path.exists() or not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        return self._normalize_loaded_payload(payload, target=target)

    def persist(
        self,
        *,
        target: str,
        state: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Persist one target memory snapshot."""
        existing = self.load(target=target)
        payload = self._compose_memory_payload(
            target=target,
            state=state,
            persisted_memory=existing,
            findings=findings,
            increment_run_count=True,
        )
        path = self.path_for_target(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return payload

    def build_memory_context(
        self,
        *,
        state: dict[str, Any],
        persisted_memory: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build compact segmented context from runtime state and persisted memory."""
        target = str(state.get("target", "")).strip()
        normalized_memory = self._normalize_loaded_payload(persisted_memory or {}, target=target) if persisted_memory else {}
        payload = self._compose_memory_payload(
            target=target,
            state=state,
            persisted_memory=normalized_memory,
            findings=findings,
            increment_run_count=False,
        )
        return self._payload_to_context(payload=payload, state=state)

    def path_for_target(self, target: str) -> Path:
        """Return filesystem path for one target memory file."""
        key = self.target_key(target)
        slug = self._slugify(self._host_or_target(target))
        return self._base_dir / f"{slug}_{key[:12]}.json"

    def target_key(self, target: str) -> str:
        """Return stable hash key for one target."""
        token = self._host_or_target(target)
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _compose_memory_payload(
        self,
        *,
        target: str,
        state: dict[str, Any],
        persisted_memory: dict[str, Any],
        findings: list[dict[str, Any]] | None,
        increment_run_count: bool,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        persisted = persisted_memory or {}
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        local_findings = findings if isinstance(findings, list) else state.get("findings", [])
        local_findings = local_findings if isinstance(local_findings, list) else []

        rag_hits = self._collect_rag_hits(
            state=state,
            persisted_memory=persisted,
            findings=local_findings,
        )

        recon_items = {
            "origins": self._merge_observations(
                existing=self._get_items(persisted, "recon_memory", "origins"),
                observed=self._collect_known_origins(state),
                ttl_seconds=self._recon_ttl_seconds,
                now=now,
                source="runtime.recon",
                weight_getter=lambda _value: 1.2,
            ),
            "services": self._merge_observations(
                existing=self._get_items(persisted, "recon_memory", "services"),
                observed=self._collect_known_services(state),
                ttl_seconds=self._recon_ttl_seconds,
                now=now,
                source="runtime.recon",
                weight_getter=lambda _value: 1.6,
            ),
            "tech_stack": self._merge_observations(
                existing=self._get_items(persisted, "recon_memory", "tech_stack"),
                observed=self._dedupe_strings(surface.get("tech_stack", []))[:20],
                ttl_seconds=self._recon_ttl_seconds,
                now=now,
                source="runtime.recon",
                weight_getter=lambda _value: 1.4,
            ),
        }
        exploit_items = {
            "follow_up_tools": self._merge_observations(
                existing=self._get_items(persisted, "exploit_memory", "follow_up_tools"),
                observed=self._collect_current_follow_up_tools(state),
                ttl_seconds=self._exploit_ttl_seconds,
                now=now,
                source="runtime.feedback",
                weight_getter=lambda _value: 1.3,
            ),
            "findings": self._merge_observations(
                existing=self._get_items(persisted, "exploit_memory", "findings"),
                observed=self._collect_recent_findings(local_findings)[:10],
                ttl_seconds=self._exploit_ttl_seconds,
                now=now,
                source="runtime.findings",
                weight_getter=self._finding_weight,
            ),
            "cve_candidates": self._merge_observations(
                existing=self._get_items(persisted, "exploit_memory", "cve_candidates"),
                observed=self._collect_cve_candidates(state),
                ttl_seconds=self._exploit_ttl_seconds,
                now=now,
                source="runtime.cve",
                weight_getter=self._cve_candidate_weight,
            ),
            "rag_intel_hits": self._merge_observations(
                existing=self._get_items(persisted, "exploit_memory", "rag_intel_hits"),
                observed=rag_hits,
                ttl_seconds=self._exploit_ttl_seconds,
                now=now,
                source="rag",
                weight_getter=lambda value: 1.0 + min(float(value.get("score", 1.0)), 8.0) / 4.0,
            ),
        }
        report_items = {
            "run_summaries": self._merge_observations(
                existing=self._get_items(persisted, "report_memory", "run_summaries"),
                observed=[self._build_run_summary(state=state, findings=local_findings)],
                ttl_seconds=self._report_ttl_seconds,
                now=now,
                source="runtime.report",
                weight_getter=lambda _value: 1.0,
            ),
            "report_preferences": self._merge_observations(
                existing=self._get_items(persisted, "report_memory", "report_preferences"),
                observed=[self._build_report_preferences(state=state)],
                ttl_seconds=self._report_ttl_seconds,
                now=now,
                source="runtime.report",
                weight_getter=lambda _value: 0.9,
            ),
        }

        payload = {
            "version": 2,
            "target": str(target).strip(),
            "target_key": self.target_key(target),
            "updated_at": now_iso,
            "run_count": max(0, int(persisted.get("run_count", 0) or 0)) + (1 if increment_run_count else 0),
            "recon_memory": {
                "ttl_seconds": self._recon_ttl_seconds,
                "items": recon_items,
            },
            "exploit_memory": {
                "ttl_seconds": self._exploit_ttl_seconds,
                "items": exploit_items,
            },
            "report_memory": {
                "ttl_seconds": self._report_ttl_seconds,
                "items": report_items,
            },
        }
        payload["planning_hints"] = self._derive_planning_hints(payload)
        payload["summary"] = self._compose_summary(payload)
        payload["known_origins"] = [item["value"] for item in self._top_items(recon_items["origins"], limit=12)]
        payload["known_services"] = [item["value"] for item in self._top_items(recon_items["services"], limit=12)]
        payload["tech_stack"] = [item["value"] for item in self._top_items(recon_items["tech_stack"], limit=12)]
        payload["follow_up_tools"] = list(payload["planning_hints"].get("follow_up_tools", []))
        payload["recent_findings"] = [item["value"] for item in self._top_items(exploit_items["findings"], limit=10)]
        payload["recent_actions"] = self._collect_recent_actions(state)[:10]
        return payload

    def _normalize_loaded_payload(self, payload: dict[str, Any], *, target: str) -> dict[str, Any]:
        if not payload:
            return {}
        version = int(payload.get("version", 1) or 1)
        if version >= 2 and "recon_memory" in payload:
            normalized = dict(payload)
        else:
            normalized = self._migrate_legacy_payload(payload, target=target)
        return self._prune_expired_payload(normalized)

    def _migrate_legacy_payload(self, payload: dict[str, Any], *, target: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        updated_at = str(payload.get("updated_at", now_iso)).strip() or now_iso

        def legacy_items(values: list[Any], *, ttl_seconds: int, source: str, weight: float) -> list[dict[str, Any]]:
            output: list[dict[str, Any]] = []
            for value in values:
                output.append(
                    self._make_item(
                        value=value,
                        ttl_seconds=ttl_seconds,
                        now=now,
                        source=source,
                        weight=weight,
                        hit_count=1,
                        first_seen_at=updated_at,
                        last_seen_at=updated_at,
                    )
                )
            return output

        normalized = {
            "version": 2,
            "target": str(payload.get("target", target)).strip(),
            "target_key": str(payload.get("target_key", self.target_key(target))).strip() or self.target_key(target),
            "updated_at": updated_at,
            "run_count": max(0, int(payload.get("run_count", 0) or 0)),
            "recon_memory": {
                "ttl_seconds": self._recon_ttl_seconds,
                "items": {
                    "origins": legacy_items(payload.get("known_origins", []), ttl_seconds=self._recon_ttl_seconds, source="legacy.recon", weight=1.0),
                    "services": legacy_items(payload.get("known_services", []), ttl_seconds=self._recon_ttl_seconds, source="legacy.recon", weight=1.2),
                    "tech_stack": legacy_items(payload.get("tech_stack", []), ttl_seconds=self._recon_ttl_seconds, source="legacy.recon", weight=1.1),
                },
            },
            "exploit_memory": {
                "ttl_seconds": self._exploit_ttl_seconds,
                "items": {
                    "follow_up_tools": legacy_items(payload.get("follow_up_tools", []), ttl_seconds=self._exploit_ttl_seconds, source="legacy.exploit", weight=1.0),
                    "findings": legacy_items(payload.get("recent_findings", []), ttl_seconds=self._exploit_ttl_seconds, source="legacy.exploit", weight=1.1),
                    "cve_candidates": [],
                    "rag_intel_hits": [],
                },
            },
            "report_memory": {
                "ttl_seconds": self._report_ttl_seconds,
                "items": {
                    "run_summaries": legacy_items([{"summary": str(payload.get("summary", "")).strip()}], ttl_seconds=self._report_ttl_seconds, source="legacy.report", weight=0.8)
                    if str(payload.get("summary", "")).strip()
                    else [],
                    "report_preferences": [],
                },
            },
        }
        normalized["planning_hints"] = self._derive_planning_hints(normalized)
        normalized["summary"] = str(payload.get("summary", "")).strip() or self._compose_summary(normalized)
        normalized["known_origins"] = list(payload.get("known_origins", []))
        normalized["known_services"] = list(payload.get("known_services", []))
        normalized["tech_stack"] = list(payload.get("tech_stack", []))
        normalized["follow_up_tools"] = list(payload.get("follow_up_tools", []))
        normalized["recent_findings"] = list(payload.get("recent_findings", []))
        normalized["recent_actions"] = list(payload.get("recent_actions", []))
        return normalized

    def _prune_expired_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        for section_name in ("recon_memory", "exploit_memory", "report_memory"):
            section = payload.get(section_name, {})
            if not isinstance(section, dict):
                continue
            items = section.get("items", {})
            if not isinstance(items, dict):
                continue
            pruned: dict[str, list[dict[str, Any]]] = {}
            for category, values in items.items():
                pruned[str(category)] = [
                    self._refresh_item_scores(item, now=now)
                    for item in values
                    if isinstance(item, dict) and not self._is_expired(item, now=now)
                ]
            section["items"] = pruned
            payload[section_name] = section
        payload["planning_hints"] = self._derive_planning_hints(payload)
        payload["summary"] = str(payload.get("summary", "")).strip() or self._compose_summary(payload)
        payload["known_origins"] = [item["value"] for item in self._top_items(self._get_items(payload, "recon_memory", "origins"), limit=12)]
        payload["known_services"] = [item["value"] for item in self._top_items(self._get_items(payload, "recon_memory", "services"), limit=12)]
        payload["tech_stack"] = [item["value"] for item in self._top_items(self._get_items(payload, "recon_memory", "tech_stack"), limit=12)]
        payload["follow_up_tools"] = list(payload["planning_hints"].get("follow_up_tools", []))
        payload["recent_findings"] = [item["value"] for item in self._top_items(self._get_items(payload, "exploit_memory", "findings"), limit=10)]
        return payload

    def _payload_to_context(self, *, payload: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        recon_origins = self._top_items(self._get_items(payload, "recon_memory", "origins"), limit=8)
        recon_services = self._top_items(self._get_items(payload, "recon_memory", "services"), limit=8)
        recon_tech_stack = self._top_items(self._get_items(payload, "recon_memory", "tech_stack"), limit=8)
        exploit_follow_ups = self._top_items(self._get_items(payload, "exploit_memory", "follow_up_tools"), limit=8)
        exploit_findings = self._top_items(self._get_items(payload, "exploit_memory", "findings"), limit=8)
        exploit_cves = self._top_items(self._get_items(payload, "exploit_memory", "cve_candidates"), limit=6)
        exploit_rag = self._top_items(self._get_items(payload, "exploit_memory", "rag_intel_hits"), limit=5)
        report_runs = self._top_items(self._get_items(payload, "report_memory", "run_summaries"), limit=5)
        report_preferences = self._top_items(self._get_items(payload, "report_memory", "report_preferences"), limit=3)

        return {
            "compression_applied": True,
            "target": str(state.get("target", payload.get("target", ""))).strip(),
            "phase": str(state.get("current_phase", "")).strip(),
            "budget_remaining": max(0, int(state.get("budget_remaining", 0) or 0)),
            "iteration_count": max(0, int(state.get("iteration_count", 0) or 0)),
            "history_total": len(state.get("history", [])) if isinstance(state.get("history", []), list) else 0,
            "breadcrumbs_total": len(state.get("breadcrumbs", [])) if isinstance(state.get("breadcrumbs", []), list) else 0,
            "surface_keys": sorted(str(key) for key in surface.keys())[:40],
            "summary": str(payload.get("summary", "")).strip(),
            "persisted_summary": str(payload.get("summary", "")).strip(),
            "persisted_run_count": max(0, int(payload.get("run_count", 0) or 0)),
            "recon_memory": {
                "ttl_seconds": self._recon_ttl_seconds,
                "origins": [self._public_entry(item) for item in recon_origins],
                "services": [self._public_entry(item) for item in recon_services],
                "tech_stack": [self._public_entry(item) for item in recon_tech_stack],
            },
            "exploit_memory": {
                "ttl_seconds": self._exploit_ttl_seconds,
                "follow_up_tools": [self._public_entry(item) for item in exploit_follow_ups],
                "recent_findings": [self._public_entry(item) for item in exploit_findings],
                "cve_candidates": [self._public_entry(item) for item in exploit_cves],
                "rag_intel_hits": [self._public_entry(item) for item in exploit_rag],
            },
            "report_memory": {
                "ttl_seconds": self._report_ttl_seconds,
                "run_summaries": [self._public_entry(item) for item in report_runs],
                "report_preferences": [self._public_entry(item) for item in report_preferences],
            },
            "planning_hints": dict(payload.get("planning_hints", {})),
            "known_origins": [item["value"] for item in recon_origins],
            "known_services": [item["value"] for item in recon_services],
            "tech_stack": [item["value"] for item in recon_tech_stack],
            "recent_actions": self._collect_recent_actions(state)[:8],
            "recent_findings": [item["value"] for item in exploit_findings],
            "follow_up_tools": list(payload.get("planning_hints", {}).get("follow_up_tools", [])),
            "compression_notice": {
                "history_total": len(state.get("history", [])) if isinstance(state.get("history", []), list) else 0,
                "breadcrumbs_total": len(state.get("breadcrumbs", [])) if isinstance(state.get("breadcrumbs", []), list) else 0,
                "mode": "segmented_memory_context_v2",
            },
        }

    def _derive_planning_hints(self, payload: dict[str, Any]) -> dict[str, Any]:
        tech_stack_items = self._top_items(self._get_items(payload, "recon_memory", "tech_stack"), limit=8)
        follow_up_items = self._top_items(self._get_items(payload, "exploit_memory", "follow_up_tools"), limit=8)
        rag_hit_items = self._top_items(self._get_items(payload, "exploit_memory", "rag_intel_hits"), limit=5)
        tech_stack = [str(item.get("value", "")).strip() for item in tech_stack_items if str(item.get("value", "")).strip()]
        follow_up_tools = [str(item.get("value", "")).strip() for item in follow_up_items if str(item.get("value", "")).strip()]
        rag_recommended_tools: list[str] = []
        rag_hits_public: list[dict[str, Any]] = []
        for item in rag_hit_items:
            value = item.get("value", {})
            if not isinstance(value, dict):
                continue
            rag_hits_public.append(
                {
                    "doc_id": str(value.get("doc_id", "")).strip(),
                    "title": str(value.get("title", "")).strip(),
                    "severity_hint": str(value.get("severity_hint", "")).strip().lower(),
                    "score": round(float(value.get("score", 0.0) or 0.0), 4),
                    "recommended_tools": [
                        str(tool_name).strip()
                        for tool_name in value.get("recommended_tools", [])
                        if str(tool_name).strip()
                    ][:6],
                }
            )
            for tool_name in value.get("recommended_tools", []):
                normalized = str(tool_name).strip()
                if normalized and normalized not in rag_recommended_tools:
                    rag_recommended_tools.append(normalized)
        merged_follow_ups = self._dedupe_strings([*follow_up_tools, *rag_recommended_tools])[:12]
        return {
            "tech_stack": tech_stack[:8],
            "follow_up_tools": merged_follow_ups,
            "rag_recommended_tools": rag_recommended_tools[:12],
            "rag_intel_hits": rag_hits_public[:5],
        }

    def _get_items(self, payload: dict[str, Any], section_name: str, category: str) -> list[dict[str, Any]]:
        section = payload.get(section_name, {})
        if not isinstance(section, dict):
            return []
        items = section.get("items", {})
        if not isinstance(items, dict):
            return []
        values = items.get(category, [])
        return [dict(item) for item in values if isinstance(item, dict)]

    def _merge_observations(
        self,
        *,
        existing: list[dict[str, Any]],
        observed: list[Any],
        ttl_seconds: int,
        now: datetime,
        source: str,
        weight_getter: Callable[[Any], float],
    ) -> list[dict[str, Any]]:
        active_existing = {
            str(item.get("key", "")): self._refresh_item_scores(item, now=now)
            for item in existing
            if isinstance(item, dict) and not self._is_expired(item, now=now)
        }
        merged: dict[str, dict[str, Any]] = dict(active_existing)
        now_iso = now.isoformat()
        for raw_value in observed:
            key = self._item_key(raw_value)
            if not key:
                continue
            observed_weight = max(0.1, float(weight_getter(raw_value)))
            previous = active_existing.get(key)
            if previous is None:
                merged[key] = self._make_item(
                    value=raw_value,
                    ttl_seconds=ttl_seconds,
                    now=now,
                    source=source,
                    weight=observed_weight,
                    hit_count=1,
                    first_seen_at=now_iso,
                    last_seen_at=now_iso,
                )
                continue
            merged[key] = self._make_item(
                value=raw_value,
                ttl_seconds=ttl_seconds,
                now=now,
                source=source,
                weight=min(12.0, float(previous.get("weight", observed_weight) or observed_weight) + (observed_weight * 0.35)),
                hit_count=max(1, int(previous.get("hit_count", 1) or 1)) + 1,
                first_seen_at=str(previous.get("first_seen_at", now_iso)).strip() or now_iso,
                last_seen_at=now_iso,
            )
        return self._top_items(list(merged.values()), limit=24)

    def _make_item(
        self,
        *,
        value: Any,
        ttl_seconds: int,
        now: datetime,
        source: str,
        weight: float,
        hit_count: int,
        first_seen_at: str,
        last_seen_at: str,
    ) -> dict[str, Any]:
        expires_at = (now + timedelta(seconds=max(60, int(ttl_seconds)))).isoformat()
        item = {
            "key": self._item_key(value),
            "value": value,
            "source": str(source).strip(),
            "weight": round(float(weight), 4),
            "hit_count": max(1, int(hit_count)),
            "first_seen_at": first_seen_at,
            "last_seen_at": last_seen_at,
            "expires_at": expires_at,
            "ttl_seconds": max(60, int(ttl_seconds)),
        }
        return self._refresh_item_scores(item, now=now)

    def _refresh_item_scores(self, item: dict[str, Any], *, now: datetime) -> dict[str, Any]:
        refreshed = dict(item)
        ttl_seconds = max(60, int(refreshed.get("ttl_seconds", 60) or 60))
        expires_at = self._parse_datetime(refreshed.get("expires_at")) or (now + timedelta(seconds=ttl_seconds))
        remaining = max(0.0, (expires_at - now).total_seconds())
        freshness_score = max(0.0, min(1.0, remaining / float(ttl_seconds)))
        weight = max(0.1, float(refreshed.get("weight", 1.0) or 1.0))
        hit_count = max(1, int(refreshed.get("hit_count", 1) or 1))
        hit_score = round(weight * (0.5 + freshness_score) * (1.0 + min(hit_count, 10) / 10.0), 4)
        refreshed["freshness_score"] = round(freshness_score, 4)
        refreshed["hit_score"] = hit_score
        refreshed["expires_at"] = expires_at.isoformat()
        return refreshed

    def _is_expired(self, item: dict[str, Any], *, now: datetime) -> bool:
        expires_at = self._parse_datetime(item.get("expires_at"))
        if expires_at is None:
            return False
        return expires_at <= now

    def _collect_known_origins(self, state: dict[str, Any]) -> list[str]:
        items: list[str] = []
        for breadcrumb in state.get("breadcrumbs", []):
            if not isinstance(breadcrumb, dict):
                continue
            candidate = str(breadcrumb.get("data", "")).strip()
            parsed = urlparse(candidate)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                items.append(f"{parsed.scheme.lower()}://{parsed.netloc.lower()}")
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        for field in ("nmap_http_origins", "nmap_https_origins", "nmap_service_origins"):
            values = surface.get(field, [])
            if isinstance(values, list):
                items.extend(values)
        return self._dedupe_strings(items)[:30]

    def _collect_known_services(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        items: list[dict[str, Any]] = []
        for field in ("nmap_services", "service_banners"):
            values = surface.get(field, [])
            if not isinstance(values, list):
                continue
            for item in values:
                if not isinstance(item, dict):
                    continue
                row = {
                    "host": str(item.get("host", "")).strip(),
                    "port": int(item.get("port", 0) or 0),
                    "service": str(item.get("service", "")).strip().lower(),
                }
                if row["host"] and row["port"] > 0:
                    items.append(row)
        return self._dedupe_json_rows(items)[:30]

    def _collect_current_follow_up_tools(self, state: dict[str, Any]) -> list[str]:
        feedback = state.get("feedback", {}) if isinstance(state.get("feedback", {}), dict) else {}
        return self._dedupe_strings(feedback.get("follow_up_tools", []))[:20]

    def _collect_recent_actions(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        history = state.get("history", [])
        if not isinstance(history, list):
            return []
        output: list[dict[str, Any]] = []
        for item in history[-10:]:
            if not isinstance(item, dict):
                continue
            output.append(
                {
                    "tool": str(item.get("tool", "")).strip(),
                    "target": str(item.get("target", "")).strip(),
                    "status": str(item.get("status", "")).strip().lower(),
                }
            )
        return output

    def _collect_recent_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for item in findings[-10:]:
            if not isinstance(item, dict):
                continue
            output.append(
                {
                    "title": str(item.get("title", item.get("name", ""))).strip(),
                    "severity": str(item.get("severity", "")).strip().lower(),
                    "tool": str(item.get("tool", "")).strip(),
                    "cve_id": str(item.get("cve_id", "")).strip().upper(),
                }
            )
        return output

    def _collect_cve_candidates(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        values = surface.get("cve_candidates", state.get("cve_candidates", []))
        if not isinstance(values, list):
            return []
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in values:
            if not isinstance(item, dict):
                continue
            normalized = {
                "cve_id": str(item.get("cve_id", "")).strip().upper(),
                "target": str(item.get("target", state.get("target", ""))).strip(),
                "severity": str(item.get("severity", "info")).strip().lower(),
                "cvss_score": self._coerce_float(item.get("cvss_score")),
            }
            if not normalized["cve_id"]:
                continue
            marker = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(normalized)
        return output[:12]

    def _collect_rag_hits(
        self,
        *,
        state: dict[str, Any],
        persisted_memory: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        current_hits = [
            dict(item)
            for item in surface.get("rag_intel_hits", [])
            if isinstance(item, dict)
        ] if isinstance(surface.get("rag_intel_hits", []), list) else []

        query_terms: list[str] = []
        tech_stack = self._dedupe_strings(surface.get("tech_stack", [])) if isinstance(surface.get("tech_stack", []), list) else []
        if not tech_stack:
            tech_stack = [
                str(item.get("value", "")).strip()
                for item in self._top_items(self._get_items(persisted_memory, "recon_memory", "tech_stack"), limit=6)
            ]
        query_terms.extend(tech_stack[:4])

        services = [str(item.get("service", "")).strip().lower() for item in self._collect_known_services(state)]
        if not services:
            services = [
                str(item.get("value", {}).get("service", "")).strip().lower()
                for item in self._top_items(self._get_items(persisted_memory, "recon_memory", "services"), limit=6)
            ]
        query_terms.extend([service for service in services[:3] if service])

        for item in findings[-3:]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", item.get("name", ""))).strip()
            if title:
                query_terms.append(title)

        query = " ".join(term for term in query_terms if term).strip()
        searched_hits: list[dict[str, Any]] = []
        if query:
            primary_component, primary_version = self._split_component_token(tech_stack[0]) if tech_stack else ("", "")
            searched_hits = self._rag_service.search(
                query=query,
                component=primary_component or None,
                version=primary_version or None,
                tech_stack=tech_stack[:6],
                max_results=5,
                min_score=1.0,
            )

        merged: list[dict[str, Any]] = []
        seen_doc_ids: set[str] = set()
        for item in [*current_hits, *searched_hits]:
            if not isinstance(item, dict):
                continue
            normalized = {
                "doc_id": str(item.get("doc_id", item.get("id", ""))).strip(),
                "title": str(item.get("title", "")).strip(),
                "summary": str(item.get("summary", item.get("snippet", ""))).strip(),
                "snippet": str(item.get("snippet", item.get("summary", ""))).strip(),
                "source": str(item.get("source", "rag")).strip() or "rag",
                "recommended_tools": self._dedupe_strings(item.get("recommended_tools", []))[:8],
                "severity_hint": str(item.get("severity_hint", "info")).strip().lower() or "info",
                "score": round(float(item.get("score", 0.0) or 0.0), 4),
            }
            if not normalized["doc_id"] or normalized["doc_id"] in seen_doc_ids:
                continue
            seen_doc_ids.add(normalized["doc_id"])
            merged.append(normalized)
        return merged[:8]

    @staticmethod
    def _split_component_token(token: str) -> tuple[str, str]:
        value = str(token).strip().lower()
        if not value:
            return "", ""
        if "/" in value:
            component, version = value.split("/", maxsplit=1)
            return component.strip(), version.strip()
        return value, ""

    def _build_run_summary(self, *, state: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "phase": str(state.get("current_phase", "")).strip(),
            "budget_remaining": max(0, int(state.get("budget_remaining", 0) or 0)),
            "iteration_count": max(0, int(state.get("iteration_count", 0) or 0)),
            "findings_count": len(findings),
            "summary": (
                f"phase={str(state.get('current_phase', '')).strip() or 'unknown'} "
                f"budget={max(0, int(state.get('budget_remaining', 0) or 0))} "
                f"findings={len(findings)}"
            ),
        }

    def _build_report_preferences(self, *, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "report_lang": str(state.get("report_lang", "en")).strip().lower() or "en",
            "safety_grade": str(state.get("safety_grade", "balanced")).strip().lower() or "balanced",
        }

    def _finding_weight(self, value: Any) -> float:
        if not isinstance(value, dict):
            return 1.1
        severity = str(value.get("severity", "info")).strip().lower()
        return {
            "critical": 3.0,
            "high": 2.4,
            "medium": 1.8,
            "low": 1.3,
            "info": 1.1,
        }.get(severity, 1.1)

    def _cve_candidate_weight(self, value: Any) -> float:
        if not isinstance(value, dict):
            return 1.2
        cvss = self._coerce_float(value.get("cvss_score"))
        if cvss is None:
            severity = str(value.get("severity", "info")).strip().lower()
            return {
                "critical": 3.0,
                "high": 2.4,
                "medium": 1.8,
                "low": 1.3,
                "info": 1.1,
            }.get(severity, 1.2)
        return max(1.2, min(3.2, 1.0 + (cvss / 4.0)))

    def _public_entry(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "value": item.get("value"),
            "weight": round(float(item.get("weight", 0.0) or 0.0), 4),
            "hit_count": max(1, int(item.get("hit_count", 1) or 1)),
            "hit_score": round(float(item.get("hit_score", 0.0) or 0.0), 4),
            "freshness_score": round(float(item.get("freshness_score", 0.0) or 0.0), 4),
            "expires_at": str(item.get("expires_at", "")).strip(),
        }

    def _top_items(self, items: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
        ranked = sorted(
            (self._refresh_item_scores(item, now=datetime.now(timezone.utc)) for item in items if isinstance(item, dict)),
            key=lambda item: (
                -float(item.get("hit_score", 0.0) or 0.0),
                -float(item.get("weight", 0.0) or 0.0),
                str(item.get("key", "")),
            ),
        )
        return ranked[: max(0, int(limit))]

    @staticmethod
    def _item_key(value: Any) -> str:
        try:
            return hashlib.sha256(
                json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
        except TypeError:
            return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    @staticmethod
    def _coerce_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _slugify(value: str) -> str:
        lowered = _NON_ALNUM_RE.sub("-", value.strip().lower()).strip("-")
        return lowered or "target"

    @staticmethod
    def _host_or_target(target: str) -> str:
        raw = str(target).strip().lower()
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return (parsed.hostname or parsed.netloc).lower()
        if ":" in raw and raw.count(":") == 1:
            host, _port = raw.split(":", maxsplit=1)
            return host.strip().lower() or raw
        return raw

    @staticmethod
    def _dedupe_strings(values: list[Any]) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        for item in values:
            normalized = str(item).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)
        return output

    @staticmethod
    def _dedupe_json_rows(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in values:
            marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(item)
        return output

    def _compose_summary(self, payload: dict[str, Any]) -> str:
        recon_origins = len(self._get_items(payload, "recon_memory", "origins"))
        recon_services = len(self._get_items(payload, "recon_memory", "services"))
        tech_stack = [
            str(item.get("value", "")).strip()
            for item in self._top_items(self._get_items(payload, "recon_memory", "tech_stack"), limit=4)
        ]
        rag_hits = len(self._get_items(payload, "exploit_memory", "rag_intel_hits"))
        findings = len(self._get_items(payload, "exploit_memory", "findings"))
        return (
            f"Recon origins={recon_origins}, services={recon_services}, tech_stack={','.join(tech_stack) or 'none'}, "
            f"exploit_signals={findings}, rag_hits={rag_hits}."
        )
