"""LLM-assisted decision engine for scope-safe security audit orchestration."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from typing import Any, Callable, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from autosecaudit.agent_safety import (
    DEFAULT_AGENT_SAFETY_GRADE,
    SAFETY_GRADE_ACTION_LIMITS,
    SAFETY_GRADE_DENIED_TOOLS,
    normalize_safety_grade,
)
from autosecaudit.agent_core.builtin_tools import load_builtin_agent_tools
from autosecaudit.agent_core.cve_service import NvdCveService
from autosecaudit.agent_core.skill_loader import SkillRegistry, load_builtin_skill_registry
from autosecaudit.agent_core.skill_planner import SkillDrivenPlanner
from autosecaudit.agent_core.template_capability_index import TemplateCapabilityIndex
from autosecaudit.agent_core.tool_registry import get_tool

from .defaults import (
    DEFAULT_AVAILABLE_TOOLS,
    DEFAULT_TOOL_COSTS,
    DEFAULT_TOOL_PRIORITIES,
    DEFAULT_TOOL_SELECTION_CAPS,
    PATH_CAPPED_TOOLS,
    STANDARD_PORT_PRIORITY,
)
from .models import (
    IPAddress,
    IPNetwork,
    ActionPlan,
    CandidateAction as _CandidateAction,
    DecisionRecommendation,
    PlannedAction,
    ResolvedTarget as _ResolvedTarget,
    ScopeModel as _ScopeModel,
)


HistoryTerminalStatus = {"completed", "failed", "error"}

_NMAP_PORT_AWARE_TOOLS = frozenset(
    {
        "passive_config_audit",
        "git_exposure_check",
        "source_map_detector",
        "error_page_analyzer",
        "waf_detector",
        "security_txt_check",
        "tech_stack_fingerprint",
        "login_form_detector",
        "js_endpoint_extractor",
        "http_security_headers",
        "ssl_expiry_check",
        "tls_service_probe",
        "cors_misconfiguration",
        "cookie_security_audit",
        "csp_evaluator",
        "dynamic_crawl",
        "active_web_crawler",
        "dirsearch_scan",
        "api_schema_discovery",
        "page_vision_analyzer",
        "nuclei_exploit_check",
    }
)

_NMAP_PORT_SELECTION_CAPS = {
    "conservative": 2,
    "balanced": 3,
    "aggressive": 5,
}


class AuditDecisionMaker:
    """Produce safe, scope-bound next-step audit actions."""

    DEFAULT_TOOL_COSTS: dict[str, int] = DEFAULT_TOOL_COSTS
    DEFAULT_TOOL_PRIORITIES: dict[str, int] = DEFAULT_TOOL_PRIORITIES
    DEFAULT_AVAILABLE_TOOLS: tuple[str, ...] = DEFAULT_AVAILABLE_TOOLS
    DEFAULT_TOOL_SELECTION_CAPS: dict[str, dict[str, int]] = DEFAULT_TOOL_SELECTION_CAPS
    _PATH_CAPPED_TOOLS: dict[str, int] = PATH_CAPPED_TOOLS
    _STANDARD_PORT_PRIORITY: dict[tuple[str, int], int] = STANDARD_PORT_PRIORITY

    def __init__(
        self,
        llm_callable: Callable[[str], str] | None = None,
        allowed_tools: Sequence[str] | None = None,
        available_tools: Sequence[str] | None = None,
        cost_overrides: dict[str, int] | None = None,
        default_crawl_depth: int = 2,
        dns_resolver: Callable[[str], Sequence[str]] | None = None,
        safety_grade: str = DEFAULT_AGENT_SAFETY_GRADE,
        skill_registry: SkillRegistry | None = None,
        skill_planner: SkillDrivenPlanner | None = None,
    ) -> None:
        load_builtin_agent_tools()
        self._llm_callable = llm_callable
        self._llm_allowed_tools = list(
            allowed_tools or ("nmap_scripts", "web_fingerprint", "ssl_check")
        )
        if not self._llm_allowed_tools:
            raise ValueError("allowed_tools must not be empty")

        self._available_tools = list(available_tools or self.DEFAULT_AVAILABLE_TOOLS)
        if not self._available_tools:
            raise ValueError("available_tools must not be empty")

        self._tool_costs = dict(self.DEFAULT_TOOL_COSTS)
        if cost_overrides:
            for tool_name, cost in cost_overrides.items():
                self._tool_costs[tool_name] = max(1, int(cost))

        self._tool_priorities = dict(self.DEFAULT_TOOL_PRIORITIES)
        self._default_crawl_depth = max(1, int(default_crawl_depth))
        self._dns_resolver = dns_resolver
        self._safety_grade = normalize_safety_grade(safety_grade)
        self._skill_registry = skill_registry if skill_registry is not None else load_builtin_skill_registry()
        self._skill_planner = skill_planner or SkillDrivenPlanner()

    def build_prompt(self, target: str, services: Sequence[str]) -> str:
        """Build lightweight compatibility prompt for external tool suggestion."""
        normalized_target = target.strip()
        if not normalized_target:
            raise ValueError("target must not be empty")

        rendered_services = ", ".join(item.strip() for item in services if item.strip())
        if not rendered_services:
            rendered_services = "no identified services yet"

        allowed_repr = ", ".join(self._llm_allowed_tools)
        return (
            f"In an authorized assessment, target {normalized_target} exposes services: "
            f"{rendered_services}. Which standard compliance checks should run next? "
            f"Choose only from [{allowed_repr}]. "
            'Return JSON only: {"tools": ["tool_name"], "reason": "short rationale"}'
        )

    def decide_next_actions(self, target: str, services: Sequence[str]) -> DecisionRecommendation:
        """Call classic LLM prompt and parse suggested tool names."""
        if self._llm_callable is None:
            raise RuntimeError("llm_callable is required for decide_next_actions")

        prompt = self.build_prompt(target=target, services=services)
        raw_response = self._llm_callable(prompt)
        suggested, rejected, reason, parse_error = self.parse_suggestions(raw_response)
        return DecisionRecommendation(
            target=target,
            prompt=prompt,
            raw_response=raw_response,
            suggested_tools=suggested,
            rejected_tools=rejected,
            reason=reason,
            parse_error=parse_error,
        )

    def build_hardened_prompt(
        self,
        audit_state: dict[str, Any],
        *,
        available_tools: Sequence[str] | None = None,
    ) -> str:
        """Build hardened system prompt for optional LLM hinting."""
        prompt_state = self._compact_state_for_llm(audit_state)
        state_json = json.dumps(
            prompt_state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        effective_grade = self._effective_safety_grade(audit_state)
        active_tools = self._effective_available_tools(available_tools, audit_state=audit_state)
        tool_lines = self._render_available_tool_lines(active_tools)
        return (
            "Security Audit Agent System Prompt (Hardened)\n\n"
            "Role\n"
            "You are an Authorized Security Assessment Orchestrator. You analyze the current "
            "audit state and propose the next best actions. Prioritize low-cost, high-value "
            "discovery and non-destructive verification.\n\n"
            "Hard Constraints (MUST)\n"
            "1) Authorization & Scope\n"
            "- Only operate on targets explicitly in scope.\n"
            "- Do NOT invent new domains/URLs.\n"
            "- Action targets must come from scope, breadcrumbs, or crawler outputs.\n"
            "- If a domain resolves to IPs outside allowed scope, block it (fail-closed).\n"
            "2) Safety\n"
            "- No destructive actions, exploitation, credential brute-force, auth bypass, or DoS.\n"
            "- SQL/XSS checks are low-risk probes only: minimal requests, stop-on-hit, no extraction.\n"
            f"- Current safety_grade is `{effective_grade}`; only use tools consistent with this posture.\n"
            "3) Efficiency / Idempotency\n"
            "- Do not suggest actions already done.\n"
            "- idempotency_key = sha256(tool_name + target + canonical_json(options)).\n"
            "- If same idempotency_key exists in completed/failed/error, do not suggest again.\n"
            "4) Budget\n"
            "- Each action must include integer cost.\n"
            "- Total action costs must be <= budget_remaining.\n"
            "- If budget_remaining < 10, propose only priority 0 actions.\n\n"
            "CVE Verification Guidance\n"
            "- When proposing cve_verify, choose explicit cve_ids from surface.cve_candidates.\n"
            "- Prefer CVEs with higher cvss_score/severity and automation support evidence.\n"
            "- Keep cve_verify focused (small cve_ids list) for reproducible validation.\n\n"
            "Available Tools (only these)\n"
            f"{tool_lines}\n\n"
            "Output JSON ONLY with schema:\n"
            "{\n"
            '  "decision_summary": "short summary",\n'
            '  "actions": [\n'
            "    {\n"
            '      "action_id": "A1",\n'
            '      "tool_name": "passive_config_audit",\n'
            '      "target": "http://example.com",\n'
            '      "options": {},\n'
            '      "priority": 0,\n'
            '      "cost": 3,\n'
            '      "capabilities": ["network_read"],\n'
            '      "idempotency_key": "<sha256>",\n'
            '      "reason": "brief reason",\n'
            '      "preconditions": ["target_in_scope", "not_already_done"],\n'
            '      "stop_conditions": ["budget_exhausted", "scope_violation_detected"]\n'
            "    }\n"
            "  ]\n"
            "}\n\n"
            "InputState JSON:\n"
            f"{state_json}"
        )

    def _compact_state_for_llm(self, audit_state: dict[str, Any]) -> dict[str, Any]:
        """Build a compact planning state to reduce prompt bloat."""
        surface = self._normalize_surface_for_planning(audit_state)
        memory_context = audit_state.get("memory_context", {})
        memory_context = memory_context if isinstance(memory_context, dict) else {}
        history = audit_state.get("history", [])
        breadcrumbs = audit_state.get("breadcrumbs", [])
        compact_history: list[dict[str, Any]] = []
        compact_breadcrumbs: list[dict[str, Any]] = []

        if isinstance(history, list):
            for item in history[-10:]:
                if not isinstance(item, dict):
                    continue
                compact_history.append(
                    {
                        "tool": str(item.get("tool", "")).strip(),
                        "target": str(item.get("target", "")).strip(),
                        "status": str(item.get("status", "")).strip().lower(),
                    }
                )
        if isinstance(breadcrumbs, list):
            for item in breadcrumbs[-15:]:
                if not isinstance(item, dict):
                    continue
                compact_breadcrumbs.append(
                    {
                        "type": str(item.get("type", "")).strip().lower(),
                        "data": str(item.get("data", "")).strip(),
                    }
                )

        compact_surface = {
            "tech_stack": list(surface.get("tech_stack", []))[:10] if isinstance(surface.get("tech_stack", []), list) else [],
            "nmap_services": list(surface.get("nmap_services", []))[:10] if isinstance(surface.get("nmap_services", []), list) else [],
            "service_banners": list(surface.get("service_banners", []))[:10] if isinstance(surface.get("service_banners", []), list) else [],
            "nmap_http_origins": list(surface.get("nmap_http_origins", []))[:10] if isinstance(surface.get("nmap_http_origins", []), list) else [],
            "nmap_https_origins": list(surface.get("nmap_https_origins", []))[:10] if isinstance(surface.get("nmap_https_origins", []), list) else [],
            "api_endpoints_count": len(surface.get("api_endpoints", [])) if isinstance(surface.get("api_endpoints", []), list) else 0,
            "discovered_urls_count": len(surface.get("discovered_urls", [])) if isinstance(surface.get("discovered_urls", []), list) else 0,
            "url_parameters_count": len(surface.get("url_parameters", {})) if isinstance(surface.get("url_parameters", {}), dict) else 0,
            "cve_candidates_count": len(surface.get("cve_candidates", [])) if isinstance(surface.get("cve_candidates", []), list) else 0,
        }

        return {
            "target": str(audit_state.get("target", "")).strip(),
            "scope": [str(item).strip() for item in audit_state.get("scope", []) if str(item).strip()][:20],
            "budget_remaining": self._coerce_budget(audit_state.get("budget_remaining", 0)),
            "total_budget": self._coerce_budget(audit_state.get("total_budget", audit_state.get("budget_remaining", 0))),
            "safety_grade": self._effective_safety_grade(audit_state),
            "current_phase": str(audit_state.get("current_phase", "")).strip(),
            "iteration_count": max(0, int(audit_state.get("iteration_count", 0) or 0)),
            "findings_count": max(0, int(audit_state.get("findings_count", 0) or 0)),
            "feedback": audit_state.get("feedback", {}) if isinstance(audit_state.get("feedback", {}), dict) else {},
            "memory_context": memory_context,
            "history_recent": compact_history,
            "breadcrumbs_recent": compact_breadcrumbs,
            "surface_summary": compact_surface,
            "compression_notice": {
                "history_total": len(history) if isinstance(history, list) else 0,
                "breadcrumbs_total": len(breadcrumbs) if isinstance(breadcrumbs, list) else 0,
                "surface_keys": sorted(str(key) for key in surface.keys())[:40],
                "mode": "compact_prompt_state_v1",
            },
        }

    def _merge_memory_surface_hints(self, surface: dict[str, Any], memory_context: dict[str, Any]) -> dict[str, Any]:
        """Use non-stale memory hints to supplement sparse live surface data."""
        if not isinstance(surface, dict):
            surface = {}
        planning_hints = memory_context.get("planning_hints", {}) if isinstance(memory_context.get("planning_hints", {}), dict) else {}
        merged = dict(surface)
        if not merged.get("tech_stack"):
            tech_stack = [
                str(item).strip()
                for item in planning_hints.get("tech_stack", [])
                if str(item).strip()
            ]
            if tech_stack:
                merged["tech_stack"] = tech_stack
        if not merged.get("rag_intel_hits"):
            rag_hits = planning_hints.get("rag_intel_hits", [])
            if isinstance(rag_hits, list) and rag_hits:
                merged["rag_intel_hits"] = rag_hits
        if not merged.get("rag_recommended_tools"):
            rag_tools = [
                str(item).strip()
                for item in planning_hints.get("rag_recommended_tools", [])
                if str(item).strip()
            ]
            if rag_tools:
                merged["rag_recommended_tools"] = rag_tools
        return merged

    def _merge_memory_feedback_hints(self, feedback: dict[str, Any], memory_context: dict[str, Any]) -> dict[str, Any]:
        """Merge persisted follow-up hints into planner feedback."""
        merged = dict(feedback) if isinstance(feedback, dict) else {}
        current_follow_ups = merged.get("follow_up_tools", [])
        if not isinstance(current_follow_ups, list):
            current_follow_ups = []
        merged["follow_up_tools"] = self._merge_tool_hints(
            self._memory_tool_hints(memory_context),
            current_follow_ups,
        )
        return merged

    def _memory_tool_hints(self, memory_context: dict[str, Any]) -> list[str]:
        """Extract ranked tool hints from segmented memory context."""
        if not isinstance(memory_context, dict):
            return []
        planning_hints = memory_context.get("planning_hints", {}) if isinstance(memory_context.get("planning_hints", {}), dict) else {}
        return self._merge_tool_hints(
            planning_hints.get("follow_up_tools", []),
            planning_hints.get("rag_recommended_tools", []),
        )

    def _skill_surface_follow_up_hints(self, surface: dict[str, Any], active_tools: Sequence[str]) -> list[str]:
        """Resolve follow-up tool hints from declarative skill surface rules."""
        if not isinstance(surface, dict) or not self._skill_registry:
            return []
        active = {str(item).strip() for item in active_tools if str(item).strip()}
        hints: list[str] = []
        for skill in self._skill_registry.list():
            for tool_name in self._skill_planner.resolve_surface_follow_ups(skill, surface):
                if tool_name in active:
                    hints.append(tool_name)
        return self._merge_tool_hints(hints, [])

    def plan_from_state(
        self,
        audit_state: dict[str, Any],
        use_llm_hints: bool = True,
        available_tools: Sequence[str] | None = None,
    ) -> ActionPlan:
        """Produce hardened next-step action plan from audit state."""
        scope_items = [str(item).strip() for item in audit_state.get("scope", []) if str(item).strip()]
        breadcrumbs = audit_state.get("breadcrumbs", [])
        history = audit_state.get("history", [])
        budget_remaining = self._coerce_budget(audit_state.get("budget_remaining", 0))

        active_tools = self._effective_available_tools(available_tools, audit_state=audit_state)
        effective_safety_grade = self._effective_safety_grade(audit_state)
        scope_model = self._parse_scope(scope_items)
        history_keys = self._collect_terminal_history_keys(history)
        surface = self._normalize_surface_for_planning(audit_state)
        memory_context = audit_state.get("memory_context", {}) if isinstance(audit_state.get("memory_context", {}), dict) else {}
        surface = self._merge_memory_surface_hints(surface, memory_context)
        service_urls, endpoint_urls = self._extract_breadcrumb_urls(breadcrumbs)
        nmap_service_urls = self._extract_nmap_service_urls(surface)
        preferred_origins = self._surface_preferred_origins(surface)
        service_urls = self._dedupe_urls([*preferred_origins, *service_urls, *nmap_service_urls])
        focus_ports = self._surface_focus_ports(surface)
        if focus_ports:
            service_urls = self._filter_urls_by_ports(service_urls, focus_ports)
            endpoint_urls = self._filter_urls_by_ports(endpoint_urls, focus_ports)
        feedback = audit_state.get("feedback", {}) if isinstance(audit_state.get("feedback", {}), dict) else {}
        feedback = self._merge_memory_feedback_hints(feedback, memory_context)
        phase_name = str(audit_state.get("current_phase", "")).strip()
        audit_target = str(audit_state.get("target", "")).strip()
        authorization_confirmed = self._coerce_bool(
            audit_state.get("authorization_confirmed", None),
            default=self._coerce_bool(surface.get("authorization_confirmed", False), default=False),
        )
        cve_safe_only = self._coerce_bool(
            audit_state.get("cve_safe_only", None),
            default=self._coerce_bool(surface.get("safe_only", True), default=True),
        )
        cve_allow_high_risk = self._coerce_bool(
            audit_state.get("cve_allow_high_risk", None),
            default=self._coerce_bool(surface.get("allow_high_risk", False), default=False),
        )
        approval_granted = self._coerce_bool(
            audit_state.get("approval_granted", None),
            default=self._coerce_bool(surface.get("approval_granted", False), default=False),
        )

        origins = sorted(
            {
                self._url_origin(url)
                for url in service_urls + endpoint_urls
                if self._is_http_url(url) and self._url_origin(url)
            }
        )
        nmap_service_origins = {
            self._url_origin(url)
            for url in nmap_service_urls
            if self._is_http_url(url) and self._url_origin(url)
        }

        endpoint_params: dict[str, dict[str, str]] = {}
        for endpoint_url in endpoint_urls:
            parsed = urlparse(endpoint_url)
            params = {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}
            if not params:
                continue
            endpoint_base = urlunparse((parsed.scheme, self._canonical_netloc(parsed), parsed.path or "/", "", "", ""))
            endpoint_params[endpoint_base] = params
        surface_endpoint_params, surface_confirmed_endpoints = self._extract_surface_endpoint_params(surface)
        for endpoint, params in surface_endpoint_params.items():
            merged = endpoint_params.setdefault(endpoint, {})
            for key, value in params.items():
                merged.setdefault(key, value)

        candidates: list[_CandidateAction] = []
        nuclei_targets = self._derive_nuclei_targets(
            service_urls=service_urls,
            endpoint_urls=endpoint_urls,
            surface=surface,
        )
        surface_skill_hints = self._skill_surface_follow_up_hints(surface, active_tools)
        for tool_name in active_tools:
            tool = self._resolve_tool_instance(tool_name)
            candidates.extend(
                self._build_candidates_for_tool(
                    tool_name=tool_name,
                    tool=tool,
                    origins=origins,
                    endpoint_params=endpoint_params,
                    surface_confirmed_endpoints=surface_confirmed_endpoints,
                    scope_items=scope_items,
                    scope_model=scope_model,
                    service_urls=service_urls,
                    nuclei_targets=nuclei_targets,
                    surface=surface if isinstance(surface, dict) else {},
                    audit_target=audit_target,
                    history=history,
                    phase_name=phase_name,
                    feedback=feedback,
                    authorization_confirmed=authorization_confirmed,
                    cve_safe_only=cve_safe_only,
                    cve_allow_high_risk=cve_allow_high_risk,
                    approval_granted=approval_granted,
                    safety_grade=effective_safety_grade,
                )
            )

        hints: list[str] = []
        llm_preferred_cve_ids: list[str] = []
        # Deterministic fast path: skip the expensive LLM call when the
        # rule-based engine already produced enough diverse candidates.
        # The LLM is most valuable when the candidate pool is thin.
        _unique_candidate_tools = {c.tool_name for c in candidates}
        _skip_llm = len(_unique_candidate_tools) >= 3
        if use_llm_hints and self._llm_callable is not None and not _skip_llm:
            hints, llm_preferred_cve_ids = self._get_llm_guidance(
                audit_state,
                available_tools=active_tools,
            )
        hints = self._merge_tool_hints(surface_skill_hints, hints)
        hints = self._merge_tool_hints(self._memory_tool_hints(memory_context), hints)
        if isinstance(feedback, dict):
            hints = self._merge_tool_hints(feedback.get("follow_up_tools", []), hints)
        candidates = self._apply_llm_cve_preferences(
            candidates,
            llm_preferred_cve_ids=llm_preferred_cve_ids,
        )

        actions = self._select_actions(
            candidates=candidates,
            history_keys=history_keys,
            budget_remaining=budget_remaining,
            llm_tool_hints=hints,
            scope_model=scope_model,
            available_tools=active_tools,
            safety_grade=effective_safety_grade,
            nmap_service_origins=nmap_service_origins,
        )

        if not actions:
            return ActionPlan(
                decision_summary=(
                    "No safe in-scope actions selected. Possible reasons: budget exhausted, "
                    "all actions already executed, or scope constraints."
                ),
                actions=[],
            )

        total_cost = sum(item.cost for item in actions)
        summary = (
            f"Proposed {len(actions)} safe action(s), total estimated cost {total_cost}, "
            f"remaining budget after plan {max(0, budget_remaining - total_cost)}."
        )
        return ActionPlan(decision_summary=summary, actions=actions)

    def _build_candidates_for_tool(
        self,
        *,
        tool_name: str,
        tool: Any | None,
        origins: list[str],
        endpoint_params: dict[str, dict[str, str]],
        surface_confirmed_endpoints: set[str],
        scope_items: list[str],
        scope_model: _ScopeModel,
        service_urls: list[str],
        nuclei_targets: list[str],
        surface: dict[str, Any],
        audit_target: str,
        history: list[dict[str, Any]],
        phase_name: str,
        feedback: dict[str, Any],
        authorization_confirmed: bool,
        cve_safe_only: bool,
        cve_allow_high_risk: bool,
        approval_granted: bool,
        safety_grade: str,
    ) -> list[_CandidateAction]:
        skill = self._skill_registry.for_tool(tool_name) if self._skill_registry else None
        if skill is not None:
            try:
                planning_context = {
                    "scope_items": scope_items,
                    "origins": origins,
                    "endpoint_params": endpoint_params,
                    "surface_confirmed_endpoints": surface_confirmed_endpoints,
                    "service_urls": service_urls,
                    "nuclei_targets": nuclei_targets,
                    "surface": surface,
                    "audit_target": audit_target,
                    "authorization_confirmed": authorization_confirmed,
                    "safe_only": cve_safe_only,
                    "allow_high_risk": cve_allow_high_risk,
                    "approval_granted": approval_granted,
                    "safety_grade": safety_grade,
                    "history_tools": {
                        str(entry.get("tool", "")).strip()
                        for entry in history
                        if str(entry.get("tool", "")).strip()
                        and str(entry.get("status", "")).strip().lower() in HistoryTerminalStatus
                    },
                    "resolve_targets": lambda target_types: self._resolve_candidate_targets(
                        target_types=target_types,
                        origins=origins,
                        endpoint_params=endpoint_params,
                        surface_confirmed_endpoints=surface_confirmed_endpoints,
                        scope_items=scope_items,
                        scope_model=scope_model,
                        service_urls=service_urls,
                        nuclei_targets=nuclei_targets,
                        surface=surface,
                        audit_target=audit_target,
                        authorization_confirmed=authorization_confirmed,
                        cve_safe_only=cve_safe_only,
                        cve_allow_high_risk=cve_allow_high_risk,
                        approval_granted=approval_granted,
                        safety_grade=safety_grade,
                    ),
                }
                skill_candidates = self._skill_planner.generate_candidates_for_skill(
                    skill=skill,
                    tool=tool,
                    phase=phase_name,
                    planning_context=planning_context,
                )
            except Exception:  # noqa: BLE001
                skill_candidates = []
                skill = None
            else:
                candidates: list[_CandidateAction] = []
                for candidate in skill_candidates:
                    candidates.append(
                        self._make_candidate(
                            tool_name=tool_name,
                            tool=tool,
                            target=candidate.target,
                            options=candidate.options,
                            feedback=feedback,
                            crawler_confirmed=bool(candidate.context.get("crawler_confirmed", False)),
                            target_type=candidate.target_type,
                            reason_override=candidate.reason,
                            preconditions_override=candidate.preconditions,
                            stop_conditions_override=candidate.stop_conditions,
                        )
                    )
                return candidates

        candidates: list[_CandidateAction] = []
        resolved_targets = self._resolve_candidate_targets(
            target_types=self._target_types_for_tool(tool_name, tool),
            origins=origins,
            endpoint_params=endpoint_params,
            surface_confirmed_endpoints=surface_confirmed_endpoints,
            scope_items=scope_items,
            scope_model=scope_model,
            service_urls=service_urls,
            nuclei_targets=nuclei_targets,
            surface=surface,
            audit_target=audit_target,
            authorization_confirmed=authorization_confirmed,
            cve_safe_only=cve_safe_only,
            cve_allow_high_risk=cve_allow_high_risk,
            approval_granted=approval_granted,
            safety_grade=safety_grade,
        )
        for resolved in resolved_targets:
            options = self._build_candidate_options(
                tool=tool,
                target=resolved.target,
                target_type=resolved.target_type,
                context=resolved.context,
            )
            candidates.append(
                self._make_candidate(
                    tool_name=tool_name,
                    tool=tool,
                    target=resolved.target,
                    options=options,
                    feedback=feedback,
                    crawler_confirmed=bool(resolved.context.get("crawler_confirmed", False)),
                    target_type=resolved.target_type,
                )
            )
        return candidates

    def _resolve_candidate_targets(
        self,
        *,
        target_types: list[str],
        origins: list[str],
        endpoint_params: dict[str, dict[str, str]],
        surface_confirmed_endpoints: set[str],
        scope_items: list[str],
        scope_model: _ScopeModel,
        service_urls: list[str],
        nuclei_targets: list[str],
        surface: dict[str, Any],
        audit_target: str,
        authorization_confirmed: bool,
        cve_safe_only: bool,
        cve_allow_high_risk: bool,
        approval_granted: bool,
        safety_grade: str,
    ) -> list[_ResolvedTarget]:
        resolvers: dict[str, Callable[[], list[_ResolvedTarget]]] = {
            "origin_url": lambda: self._resolve_origin_targets(origins, scope_model),
            "https_origin": lambda: self._resolve_https_origin_targets(origins, scope_model),
            "service_port": lambda: self._resolve_service_port_targets(surface, scope_model),
            "scope_host": lambda: self._resolve_scope_host_targets(scope_items, surface, scope_model),
            "parameterized_endpoint": lambda: self._resolve_parameterized_endpoint_targets(
                endpoint_params,
                surface_confirmed_endpoints,
                scope_model,
            ),
            "domain": lambda: self._resolve_domain_targets(scope_items, scope_model),
            "host_seed": lambda: self._resolve_host_seed_targets(scope_items, scope_model, service_urls),
            "nuclei_target": lambda: self._resolve_nuclei_targets(nuclei_targets, scope_model, surface),
            "tech_component": lambda: self._resolve_tech_component_targets(
                surface=surface,
                origins=origins,
                scope_items=scope_items,
                scope_model=scope_model,
                audit_target=audit_target,
                authorization_confirmed=authorization_confirmed,
                cve_safe_only=cve_safe_only,
                cve_allow_high_risk=cve_allow_high_risk,
                approval_granted=approval_granted,
                safety_grade=safety_grade,
            ),
            "cve_candidate": lambda: self._resolve_cve_candidate_targets(
                surface=surface,
                origins=origins,
                scope_items=scope_items,
                scope_model=scope_model,
                audit_target=audit_target,
                authorization_confirmed=authorization_confirmed,
                cve_safe_only=cve_safe_only,
                cve_allow_high_risk=cve_allow_high_risk,
                approval_granted=approval_granted,
                safety_grade=safety_grade,
            ),
        }
        resolved: list[_ResolvedTarget] = []
        for target_type in target_types:
            resolver = resolvers.get(target_type)
            if resolver is None:
                continue
            resolved.extend(resolver())
        return resolved

    def _make_candidate(
        self,
        *,
        tool_name: str,
        tool: Any | None,
        target: str,
        options: dict[str, Any],
        feedback: dict[str, Any],
        crawler_confirmed: bool,
        target_type: str,
        reason_override: str | None = None,
        preconditions_override: list[str] | None = None,
        stop_conditions_override: list[str] | None = None,
    ) -> _CandidateAction:
        base_priority = self._priority_for(tool_name, tool=tool)
        priority_delta = self._priority_delta_for_feedback(tool_name, feedback)
        if crawler_confirmed and target_type == "parameterized_endpoint":
            priority_delta -= 2
        priority = max(0, base_priority + priority_delta)
        cost = self._cost_for(tool_name, tool=tool, options=options)
        return _CandidateAction(
            tool_name=tool_name,
            target=target,
            options=options,
            priority=priority,
            cost=cost,
            reason=reason_override or self._reason_for_candidate(tool_name, tool, target_type, crawler_confirmed),
            preconditions=preconditions_override or self._preconditions_for_candidate(tool_name, tool, target_type, crawler_confirmed),
            stop_conditions=stop_conditions_override or self._stop_conditions_for_candidate(tool_name, tool, target_type),
            capabilities=self._capabilities_for_tool(tool),
        )

    def _build_candidate_options(
        self,
        tool: Any | None,
        target: str,
        target_type: str,
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        options = dict(getattr(tool, "get_default_options", lambda: {})())
        rendered = self._render_option_template(
            value=options,
            target=target,
            target_type=target_type,
            context=context or {},
        )
        return rendered if isinstance(rendered, dict) else {}

    def _render_option_template(
        self,
        *,
        value: Any,
        target: str,
        target_type: str,
        context: dict[str, Any],
    ) -> Any:
        if isinstance(value, dict):
            return {
                str(key): self._render_option_template(
                    value=item,
                    target=target,
                    target_type=target_type,
                    context=context,
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._render_option_template(
                    value=item,
                    target=target,
                    target_type=target_type,
                    context=context,
                )
                for item in value
            ]
        if isinstance(value, str):
            parsed = urlparse(target)
            replacements: dict[str, Any] = {
                "$target": target,
                "$target_type": target_type,
                "$target_host": (parsed.hostname or "").lower(),
                "$target_scheme": parsed.scheme.lower(),
                "$target_origin": self._url_origin(target) or target,
                "$params": dict(context.get("params", {})),
                "$port": int(context.get("port", 0) or 0),
                "$service": str(context.get("service", "")).strip().lower(),
                "$component": context.get("component"),
                "$version": context.get("version"),
                "$cve_ids": list(context.get("cve_ids", [])) if isinstance(context.get("cve_ids", []), list) else [],
                "$cve_id": str(context.get("cve_id", "")).strip().upper(),
                "$safe_only": bool(context.get("safe_only", True)),
                "$authorization_confirmed": bool(context.get("authorization_confirmed", False)),
                "$allow_high_risk": bool(context.get("allow_high_risk", False)),
                "$approval_granted": bool(context.get("approval_granted", False)),
                "$safety_grade": str(context.get("safety_grade", "balanced")).strip().lower() or "balanced",
                "$rag_intel_hits": list(context.get("rag_intel_hits", [])) if isinstance(context.get("rag_intel_hits", []), list) else [],
                "$rag_recommended_tools": list(context.get("rag_recommended_tools", [])) if isinstance(context.get("rag_recommended_tools", []), list) else [],
                "$poc_template": str(context.get("poc_template", "")).strip().lower() or "auto",
                "$nuclei_templates": list(context.get("nuclei_templates", [])) if isinstance(context.get("nuclei_templates", []), list) else [],
                "$nuclei_template_ids": list(context.get("nuclei_template_ids", [])) if isinstance(context.get("nuclei_template_ids", []), list) else [],
                "$nuclei_severity": list(context.get("nuclei_severity", [])) if isinstance(context.get("nuclei_severity", []), list) else ["medium"],
            }
            return replacements.get(value, value)
        return value

    def _preconditions_for_candidate(
        self,
        tool_name: str,
        tool: Any | None,
        target_type: str,
        crawler_confirmed: bool,
    ) -> list[str]:
        preconditions = ["target_in_scope", "not_already_done"]
        if target_type in {"origin_url"}:
            preconditions.append("http_service_confirmed")
        elif target_type == "https_origin":
            preconditions.append("https_service_confirmed")
        elif target_type == "parameterized_endpoint":
            preconditions.append("params_available")
            if crawler_confirmed or any(
                dependency in {"dynamic_crawl", "active_web_crawler", "js_endpoint_extractor", "api_schema_discovery"}
                for dependency in getattr(tool, "depends_on", [])
            ):
                preconditions.append("crawler_signal_present")
        elif target_type == "domain":
            preconditions.append("domain_scope_declared")
        elif target_type == "nuclei_target":
            preconditions.append("hints_detected")
        elif target_type == "tech_component":
            preconditions.append("tech_stack_available")
        elif target_type == "cve_candidate":
            preconditions.append("authorization_confirmed")
            if tool_name == "poc_sandbox_exec":
                preconditions.append("approval_granted")
        return preconditions

    def _stop_conditions_for_candidate(self, tool_name: str, tool: Any | None, target_type: str) -> list[str]:
        stop_conditions = ["budget_exhausted", "scope_violation_detected"]
        risk_level = str(getattr(tool, "risk_level", "safe")).strip().lower()
        if target_type == "parameterized_endpoint" or risk_level in {"medium", "high"}:
            stop_conditions.append("signal_detected")
        return stop_conditions

    def _reason_for_candidate(
        self,
        tool_name: str,
        tool: Any | None,
        target_type: str,
        crawler_confirmed: bool,
    ) -> str:
        description = str(getattr(tool, "description", "")).strip() or tool_name
        if target_type == "parameterized_endpoint" and crawler_confirmed:
            return f"{description} on crawler-confirmed parameterized endpoint."
        if target_type == "parameterized_endpoint":
            return f"{description} on parameterized endpoint."
        if target_type == "nuclei_target":
            return f"{description} after fingerprint/path hints."
        if target_type == "host_seed":
            return f"{description} for initial service discovery."
        if target_type == "tech_component":
            return f"{description} from detected technology stack."
        if target_type == "cve_candidate":
            return f"{description} for discovered CVE candidates."
        return description

    def _capabilities_for_tool(self, tool: Any | None) -> list[str]:
        capabilities = getattr(tool, "capabilities", None)
        if isinstance(capabilities, list) and capabilities:
            return [str(item) for item in capabilities if str(item).strip()]
        return ["network_read"]

    def _priority_delta_for_feedback(self, tool_name: str, feedback: dict[str, Any]) -> int:
        priority_overrides = feedback.get("priority_overrides", {}) if isinstance(feedback, dict) else {}
        try:
            return int(priority_overrides.get(tool_name, 0))
        except (TypeError, ValueError):
            return 0

    def _target_types_for_tool(self, tool_name: str, tool: Any | None) -> list[str]:
        target_types = getattr(tool, "target_types", None)
        if isinstance(target_types, list) and target_types:
            return [str(item).strip() for item in target_types if str(item).strip()]
        fallback = {
            "nmap_scan": ["host_seed"],
            "service_banner_probe": ["service_port"],
            "ssl_expiry_check": ["https_origin"],
            "subdomain_enum_passive": ["domain"],
            "nuclei_exploit_check": ["nuclei_target"],
            "sql_sanitization_audit": ["parameterized_endpoint"],
            "xss_protection_audit": ["parameterized_endpoint"],
            "param_fuzzer": ["parameterized_endpoint"],
            "cve_lookup": ["tech_component"],
            "cve_verify": ["cve_candidate"],
            "poc_sandbox_exec": ["cve_candidate"],
        }
        return fallback.get(tool_name, ["origin_url"])

    def _resolve_origin_targets(self, origins: list[str], scope_model: _ScopeModel) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        for origin in origins:
            host = urlparse(origin).hostname or ""
            if not self._is_host_in_scope(host, scope_model):
                continue
            resolved.append(_ResolvedTarget(target=origin, target_type="origin_url"))
        return resolved

    def _resolve_https_origin_targets(self, origins: list[str], scope_model: _ScopeModel) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        for origin in origins:
            parsed = urlparse(origin)
            host = parsed.hostname or ""
            if parsed.scheme != "https" or not self._is_host_in_scope(host, scope_model):
                continue
            resolved.append(_ResolvedTarget(target=origin, target_type="https_origin"))
        return resolved

    def _resolve_service_port_targets(
        self,
        surface: dict[str, Any],
        scope_model: _ScopeModel,
    ) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        if not isinstance(surface, dict):
            return resolved

        seen: set[tuple[str, int, str]] = set()
        focus_ports = set(self._surface_focus_ports(surface))

        def add_target(host: str, port_value: Any, service_value: Any, scheme_value: Any = "") -> None:
            normalized_host = str(host).strip().lower()
            if not normalized_host or not self._target_in_scope(normalized_host, scope_model):
                return
            try:
                port = int(port_value or 0)
            except (TypeError, ValueError):
                return
            if port < 1 or port > 65535:
                return
            if focus_ports and port not in focus_ports:
                return
            service = str(service_value).strip().lower()
            scheme = str(scheme_value).strip().lower()
            if scheme in {"http", "https"} or "http" in service:
                return
            marker = (normalized_host, port, service)
            if marker in seen:
                return
            seen.add(marker)
            resolved.append(
                _ResolvedTarget(
                    target=normalized_host,
                    target_type="service_port",
                    context={
                        "host": normalized_host,
                        "port": port,
                        "service": service,
                    },
                )
            )

        raw_services = surface.get("nmap_services", [])
        if isinstance(raw_services, list):
            for item in raw_services:
                if not isinstance(item, dict):
                    continue
                add_target(
                    item.get("host", ""),
                    item.get("port", 0),
                    item.get("service", ""),
                    item.get("scheme", ""),
                )

        raw_assets = surface.get("assets", [])
        if isinstance(raw_assets, list):
            for item in raw_assets:
                if not isinstance(item, dict):
                    continue
                if str(item.get("kind", "")).strip().lower() != "service":
                    continue
                attributes = item.get("attributes", {})
                if not isinstance(attributes, dict):
                    attributes = {}
                add_target(
                    attributes.get("host", ""),
                    attributes.get("port", 0),
                    attributes.get("service", ""),
                    attributes.get("scheme", ""),
                )

        if resolved:
            return sorted(
                resolved,
                key=lambda item: (
                    int(item.context.get("port", 0) or 0),
                    str(item.target),
                    str(item.context.get("service", "")),
                ),
            )

        for host in surface.get("nmap_hosts", []):
            if not isinstance(host, dict):
                continue
            host_token = ""
            hostnames = host.get("hostnames", [])
            if isinstance(hostnames, list) and hostnames:
                host_token = str(hostnames[0]).strip()
            if not host_token:
                addresses = host.get("addresses", [])
                if isinstance(addresses, list) and addresses:
                    first = addresses[0]
                    if isinstance(first, dict) and first.get("addr"):
                        host_token = str(first.get("addr", "")).strip()
            if not host_token:
                continue
            for port_entry in host.get("open_ports", []):
                if not isinstance(port_entry, dict):
                    continue
                add_target(
                    host_token,
                    port_entry.get("port", 0),
                    port_entry.get("service", ""),
                )

        return sorted(
            resolved,
            key=lambda item: (
                int(item.context.get("port", 0) or 0),
                str(item.target),
                str(item.context.get("service", "")),
            ),
        )

    def _resolve_parameterized_endpoint_targets(
        self,
        endpoint_params: dict[str, dict[str, str]],
        surface_confirmed_endpoints: set[str],
        scope_model: _ScopeModel,
    ) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        for endpoint, params in sorted(endpoint_params.items(), key=lambda item: item[0]):
            host = urlparse(endpoint).hostname or ""
            if not self._is_host_in_scope(host, scope_model):
                continue
            resolved.append(
                _ResolvedTarget(
                    target=endpoint,
                    target_type="parameterized_endpoint",
                    context={
                        "params": dict(params),
                        "crawler_confirmed": endpoint in surface_confirmed_endpoints,
                    },
                )
            )
        return resolved

    def _resolve_domain_targets(self, scope_items: list[str], scope_model: _ScopeModel) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        for domain in self._scope_domain_seeds(scope_items):
            if not self._is_host_in_scope(domain, scope_model):
                continue
            resolved.append(_ResolvedTarget(target=domain, target_type="domain"))
        return resolved

    def _resolve_host_seed_targets(
        self,
        scope_items: list[str],
        scope_model: _ScopeModel,
        service_urls: list[str],
    ) -> list[_ResolvedTarget]:
        if service_urls:
            return []
        resolved: list[_ResolvedTarget] = []
        for seed in self._scope_scan_seeds(scope_items):
            if not self._target_in_scope(seed, scope_model):
                continue
            resolved.append(_ResolvedTarget(target=seed, target_type="host_seed"))
        return resolved

    def _resolve_scope_host_targets(
        self,
        scope_items: list[str],
        surface: dict[str, Any],
        scope_model: _ScopeModel,
    ) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        seen: set[str] = set()

        def add_target(candidate: Any) -> None:
            token = str(candidate).strip().lower()
            if not token or token in seen or not self._target_in_scope(token, scope_model):
                return
            seen.add(token)
            resolved.append(_ResolvedTarget(target=token, target_type="scope_host"))

        for seed in self._scope_scan_seeds(scope_items):
            add_target(seed)

        if isinstance(surface, dict):
            for asset in surface.get("assets", []):
                if not isinstance(asset, dict):
                    continue
                attributes = asset.get("attributes", {})
                if not isinstance(attributes, dict):
                    attributes = {}
                add_target(attributes.get("host"))
                add_target(attributes.get("address"))
            for host in surface.get("nmap_hosts", []):
                if not isinstance(host, dict):
                    continue
                hostnames = host.get("hostnames", [])
                if isinstance(hostnames, list):
                    for hostname in hostnames:
                        add_target(hostname)
                addresses = host.get("addresses", [])
                if isinstance(addresses, list):
                    for address in addresses:
                        if isinstance(address, dict):
                            add_target(address.get("addr"))

        return sorted(resolved, key=lambda item: str(item.target))

    def _resolve_nuclei_targets(
        self,
        nuclei_targets: list[str],
        scope_model: _ScopeModel,
        surface: dict[str, Any],
    ) -> list[_ResolvedTarget]:
        resolved: list[_ResolvedTarget] = []
        for nuclei_target in nuclei_targets:
            normalized_target = self._normalize_url(nuclei_target) or str(nuclei_target).strip()
            parsed = urlparse(normalized_target)
            if parsed.scheme in {"http", "https"} and parsed.path == "/" and not parsed.query:
                normalized_target = self._url_origin(normalized_target) or normalized_target
                parsed = urlparse(normalized_target)
            host = parsed.hostname or ""
            if not self._is_host_in_scope(host, scope_model):
                continue
            resolved.append(
                _ResolvedTarget(
                    target=normalized_target,
                    target_type="nuclei_target",
                    context=self._match_nuclei_target_context(surface=surface, target=normalized_target),
                )
            )
        return resolved

    def _match_nuclei_target_context(self, *, surface: dict[str, Any], target: str) -> dict[str, Any]:
        def _default_context(component_row: dict[str, Any] | None = None) -> dict[str, Any]:
            row = component_row if isinstance(component_row, dict) else {}
            return {
                "component": str(row.get("component", "")).strip().lower() or None,
                "version": str(row.get("version", "")).strip() or None,
                "service": str(row.get("service", "")).strip().lower() or None,
                "nuclei_templates": [],
                "nuclei_template_ids": [],
                "nuclei_severity": ["medium"],
            }

        def _protocol_aliases(value: Any) -> set[str]:
            normalized = str(value or "").strip().lower()
            if not normalized:
                return set()
            aliases = {normalized}
            alias_groups = (
                {"ssh", "openssh"},
                {"tls", "ssl", "https"},
                {"postgres", "postgresql"},
                {"mysql", "mariadb"},
                {"redis"},
                {"memcached"},
            )
            for group in alias_groups:
                if normalized in group:
                    aliases.update(group)
                    break
            return aliases

        if not isinstance(surface, dict):
            return _default_context()

        parsed = urlparse(target)
        normalized_target = self._normalize_url(target) or str(target).strip()
        target_origin = self._url_origin(normalized_target) or normalized_target
        target_host = (parsed.hostname or "").strip().lower()
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else 0)

        matching_components: list[dict[str, Any]] = []
        for entry in surface.get("tech_components", []):
            if not isinstance(entry, dict):
                continue
            component_host = str(entry.get("host", "")).strip().lower()
            explicit_target = str(entry.get("target", "")).strip() or str(entry.get("origin", "")).strip()
            normalized_explicit = self._normalize_url(explicit_target) if self._is_http_url(explicit_target) else explicit_target
            entry_service = str(entry.get("service", "")).strip().lower()
            try:
                entry_port = int(entry.get("port", 0) or 0)
            except (TypeError, ValueError):
                entry_port = 0
            same_target = bool(normalized_explicit and normalized_explicit == normalized_target)
            same_origin = bool(normalized_explicit and self._url_origin(normalized_explicit) == target_origin)
            same_host = bool(component_host and component_host == target_host)
            same_port = not entry_port or not target_port or entry_port == target_port
            if same_target or same_origin or (same_host and same_port):
                matching_components.append(entry)

        primary_component = matching_components[0] if matching_components else None

        template_capability_index = surface.get("template_capability_index", {})
        if not isinstance(template_capability_index, dict):
            template_capability_index = {}

        candidate_rows: list[dict[str, Any]] = []
        for raw in surface.get("cve_candidates", []):
            if not isinstance(raw, dict):
                continue
            raw_target = str(raw.get("target", "")).strip()
            normalized_raw_target = self._normalize_url(raw_target) if self._is_http_url(raw_target) else raw_target.strip().lower()
            raw_host = (urlparse(normalized_raw_target).hostname or "").strip().lower() if self._is_http_url(normalized_raw_target) else normalized_raw_target
            raw_component = str(raw.get("component", "")).strip().lower()
            raw_service = str(raw.get("service", "")).strip().lower()
            same_target = bool(normalized_raw_target and normalized_raw_target == normalized_target)
            same_origin = bool(self._is_http_url(normalized_raw_target) and self._url_origin(normalized_raw_target) == target_origin)
            same_host = bool(target_host and raw_host and raw_host == target_host)
            component_match = any(
                raw_component and raw_component == str(entry.get("component", "")).strip().lower()
                for entry in matching_components
            )
            service_match = any(
                raw_service and raw_service == str(entry.get("service", "")).strip().lower()
                for entry in matching_components
            )
            if not (same_target or same_origin or same_host or component_match or service_match):
                continue
            cve_id = str(raw.get("cve_id", "")).strip().upper()
            if not cve_id:
                continue
            capability = raw.get("template_capability", {})
            if not isinstance(capability, dict) or not capability:
                capability = template_capability_index.get(cve_id, {})
            if not isinstance(capability, dict) or not capability:
                capability = TemplateCapabilityIndex.get_capability(cve_id)
            if not bool(capability.get("has_template", False)):
                continue
            candidate_rows.append(
                {
                    "cve_id": cve_id,
                    "severity": str(raw.get("severity", "medium")).strip().lower() or "medium",
                    "rank": int(raw.get("rank", 0) or 0),
                    "capability": capability,
                    "component": raw_component or None,
                    "service": raw_service or None,
                }
            )

        if not candidate_rows:
            return _default_context(primary_component)

        def candidate_score(item: dict[str, Any]) -> tuple[float, int, int, str]:
            capability = item.get("capability", {})
            tags = {
                str(tag).strip().lower()
                for tag in capability.get("protocol_tags", [])
                if str(tag).strip()
            } if isinstance(capability, dict) else set()
            expanded_tags: set[str] = set()
            for tag in tags:
                expanded_tags.update(_protocol_aliases(tag))
            weighted = 0.0
            weighted += min(int(capability.get("template_count", 0) or 0), 5)
            weighted += {
                "critical": 8.0,
                "high": 6.0,
                "medium": 4.0,
                "low": 2.0,
                "info": 1.0,
            }.get(str(item.get("severity", "medium")).strip().lower(), 0.0)
            component_name = str(item.get("component", "")).strip().lower()
            service_name = str(item.get("service", "")).strip().lower()
            for entry in matching_components:
                entry_component = str(entry.get("component", "")).strip().lower()
                entry_service = str(entry.get("service", "")).strip().lower()
                if entry_component and (_protocol_aliases(entry_component) & expanded_tags):
                    weighted += 4.0
                if entry_service and (_protocol_aliases(entry_service) & expanded_tags):
                    weighted += 3.5
                if component_name and component_name == entry_component:
                    weighted += 2.0
                if service_name and service_name == entry_service:
                    weighted += 2.0
            return (weighted, int(item.get("rank", 0) or 0) * -1, int(capability.get("template_count", 0) or 0), str(item.get("cve_id", "")))

        ordered = sorted(candidate_rows, key=candidate_score, reverse=True)
        selected_template_ids: list[str] = []
        selected_templates: list[str] = []
        selected_severity: list[str] = []
        seen_ids: set[str] = set()
        seen_templates: set[str] = set()
        seen_severity: set[str] = set()
        capability_summary: dict[str, dict[str, Any]] = {}
        severity_order = ["info", "low", "medium", "high", "critical"]
        for row in ordered:
            cve_id = str(row.get("cve_id", "")).strip().upper()
            capability = row.get("capability", {}) if isinstance(row.get("capability", {}), dict) else {}
            capability_summary[cve_id] = capability
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                selected_template_ids.append(cve_id)
            for path in capability.get("template_paths", []) if isinstance(capability.get("template_paths", []), list) else []:
                normalized = str(path).strip()
                if not normalized or normalized in seen_templates:
                    continue
                seen_templates.add(normalized)
                selected_templates.append(normalized)
            severity = str(row.get("severity", "medium")).strip().lower() or "medium"
            if severity in severity_order and severity not in seen_severity:
                seen_severity.add(severity)
                selected_severity.append(severity)

        selected_severity = [level for level in severity_order if level in set(selected_severity)] or ["medium"]
        return {
            "component": str(primary_component.get("component", "")).strip().lower() or None if primary_component else None,
            "version": str(primary_component.get("version", "")).strip() or None if primary_component else None,
            "service": str(primary_component.get("service", "")).strip().lower() or None if primary_component else None,
            "nuclei_templates": selected_templates[:20],
            "nuclei_template_ids": selected_template_ids[:10],
            "nuclei_severity": selected_severity,
            "template_capability_index": capability_summary,
        }

    def _resolve_tech_component_targets(
        self,
        *,
        surface: dict[str, Any],
        origins: list[str],
        scope_items: list[str],
        scope_model: _ScopeModel,
        audit_target: str,
        authorization_confirmed: bool,
        cve_safe_only: bool,
        cve_allow_high_risk: bool,
        approval_granted: bool,
        safety_grade: str,
    ) -> list[_ResolvedTarget]:
        components = surface.get("tech_stack", []) if isinstance(surface, dict) else []
        structured_components = surface.get("tech_components", []) if isinstance(surface, dict) else []
        if not isinstance(components, list):
            components = []
        if not isinstance(structured_components, list):
            structured_components = []
        fallback_target = self._fallback_http_target(
            origins=origins,
            scope_items=scope_items,
            scope_model=scope_model,
            audit_target=audit_target,
        )

        resolved: list[_ResolvedTarget] = []
        seen: set[str] = set()
        for entry in structured_components:
            if not isinstance(entry, dict):
                continue
            component = str(entry.get("component", "")).strip().lower()
            version = str(entry.get("version", "")).strip() or None
            explicit_target = str(entry.get("target", "")).strip()
            if not explicit_target:
                explicit_target = str(entry.get("origin", "")).strip() or str(entry.get("host", "")).strip().lower()
            target = explicit_target or fallback_target
            if not component or not target or not self._target_in_scope(target, scope_model):
                continue
            try:
                port = int(entry.get("port", 0) or 0)
            except (TypeError, ValueError):
                port = 0
            marker = json.dumps(
                {
                    "target": target,
                    "component": component,
                    "version": version,
                    "service": str(entry.get("service", "")).strip().lower(),
                    "port": port or None,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            if marker in seen:
                continue
            seen.add(marker)
            cve_context = self._match_tech_component_cve_context(
                surface=surface,
                target=target,
                host=str(entry.get("host", "")).strip().lower() or None,
                component=component,
                version=version,
                service=str(entry.get("service", "")).strip().lower() or None,
                authorization_confirmed=authorization_confirmed,
                cve_safe_only=cve_safe_only,
                cve_allow_high_risk=cve_allow_high_risk,
                approval_granted=approval_granted,
                safety_grade=safety_grade,
            )
            rag_context = self._match_tech_component_rag_context(
                surface=surface,
                target=target,
                host=str(entry.get("host", "")).strip().lower() or None,
                component=component,
                version=version,
                service=str(entry.get("service", "")).strip().lower() or None,
            )
            resolved.append(
                _ResolvedTarget(
                    target=target,
                    target_type="tech_component",
                    context={
                        "component": component,
                        "version": version,
                        "service": str(entry.get("service", "")).strip().lower() or None,
                        "host": str(entry.get("host", "")).strip().lower() or None,
                        "port": port or None,
                        "source_tool": str(entry.get("source_tool", "")).strip() or None,
                        "poc_template": self._preferred_poc_template(
                            target=target,
                            component=component,
                            service=str(entry.get("service", "")).strip().lower() or None,
                            port=port or None,
                        ),
                    }
                    | rag_context
                    | cve_context,
                )
            )

        for raw_component in components:
            component_text = str(raw_component).strip()
            if not component_text:
                continue
            lowered = component_text.lower()
            component, version = self._split_component_token(component_text)
            target = fallback_target
            if not component or not target:
                continue
            marker = json.dumps(
                {"target": target, "component": component, "version": version},
                ensure_ascii=False,
                sort_keys=True,
            )
            if marker in seen:
                continue
            seen.add(marker)
            cve_context = self._match_tech_component_cve_context(
                surface=surface,
                target=target,
                host=urlparse(target).hostname if self._is_http_url(target) else str(target).strip().lower(),
                component=component,
                version=version,
                service=None,
                authorization_confirmed=authorization_confirmed,
                cve_safe_only=cve_safe_only,
                cve_allow_high_risk=cve_allow_high_risk,
                approval_granted=approval_granted,
                safety_grade=safety_grade,
            )
            rag_context = self._match_tech_component_rag_context(
                surface=surface,
                target=target,
                host=urlparse(target).hostname if self._is_http_url(target) else str(target).strip().lower(),
                component=component,
                version=version,
                service=None,
            )
            resolved.append(
                _ResolvedTarget(
                    target=target,
                    target_type="tech_component",
                    context={
                        "component": component,
                        "version": version,
                        "poc_template": self._preferred_poc_template(
                            target=target,
                            component=component,
                            service=None,
                            port=None,
                        ),
                    }
                    | rag_context
                    | cve_context,
                )
            )
        return resolved

    def _match_tech_component_cve_context(
        self,
        *,
        surface: dict[str, Any],
        target: str,
        host: str | None,
        component: str,
        version: str | None,
        service: str | None,
        authorization_confirmed: bool,
        cve_safe_only: bool,
        cve_allow_high_risk: bool,
        approval_granted: bool,
        safety_grade: str,
    ) -> dict[str, Any]:
        candidates = surface.get("cve_candidates", []) if isinstance(surface, dict) else []
        if not isinstance(candidates, list):
            candidates = []
        rag_hits = surface.get("rag_intel_hits", []) if isinstance(surface.get("rag_intel_hits", []), list) else []
        rag_recommended_tools = surface.get("rag_recommended_tools", []) if isinstance(surface.get("rag_recommended_tools", []), list) else []
        target_host = (urlparse(target).hostname or "").strip().lower() if self._is_http_url(target) else str(target).strip().lower()
        normalized_component = str(component).strip().lower()
        normalized_version = str(version or "").strip()
        normalized_service = str(service or "").strip().lower()
        matched_items: list[dict[str, Any]] = []
        candidate_safe_only_values: list[bool] = []
        candidate_allow_high_risk_values: list[bool] = []
        candidate_authorization_values: list[bool] = []
        candidate_approval_values: list[bool] = []

        for raw in candidates:
            if not isinstance(raw, dict):
                continue
            raw_target = str(raw.get("target", "")).strip()
            raw_host = (urlparse(raw_target).hostname or "").strip().lower() if self._is_http_url(raw_target) else raw_target.lower()
            raw_component = str(raw.get("component", "")).strip().lower()
            raw_version = str(raw.get("version", "")).strip()
            raw_service = str(raw.get("service", "")).strip().lower()

            same_target = bool(raw_target and raw_target == target)
            same_host = bool(target_host and raw_host and raw_host == target_host)
            same_component = bool(raw_component and raw_component == normalized_component)
            same_service = bool(normalized_service and raw_service and raw_service == normalized_service)
            version_compatible = not normalized_version or not raw_version or raw_version == normalized_version
            if not (same_target or same_host or (same_component and version_compatible) or (same_service and same_host)):
                continue

            cve_ids = self._normalize_cve_id_list(raw.get("cve_ids"))
            cve_id = str(raw.get("cve_id", "")).strip().upper()
            if cve_id and cve_id not in cve_ids:
                cve_ids.append(cve_id)
            item_severity = str(raw.get("severity", "info")).strip().lower()
            item_cvss = self._coerce_float(raw.get("cvss_score"))
            for candidate_id in cve_ids:
                matched_items.append(
                    {
                        "cve_id": candidate_id,
                        "severity": item_severity,
                        "cvss_score": item_cvss,
                        "has_nuclei_template": bool(raw.get("has_nuclei_template", False)),
                        "template_capability": raw.get("template_capability", {}),
                    }
                )
            if "safe_only" in raw:
                candidate_safe_only_values.append(self._coerce_bool(raw.get("safe_only"), default=True))
            if "allow_high_risk" in raw:
                candidate_allow_high_risk_values.append(self._coerce_bool(raw.get("allow_high_risk"), default=False))
            if "authorization_confirmed" in raw:
                candidate_authorization_values.append(self._coerce_bool(raw.get("authorization_confirmed"), default=False))
            if "approval_granted" in raw:
                candidate_approval_values.append(self._coerce_bool(raw.get("approval_granted"), default=False))

        ranked_candidates = NvdCveService.rank_cve_candidates(
            matched_items,
            component=normalized_component or None,
            version=normalized_version or None,
            service=normalized_service or None,
            rag_hits=rag_hits,
            rag_recommended_tools=rag_recommended_tools,
        )
        ranked_ids = [
            str(item.get("cve_id", "")).strip().upper()
            for item in ranked_candidates
            if str(item.get("cve_id", "")).strip()
        ]
        return {
            "cve_id": ranked_ids[0] if ranked_ids else "",
            "cve_ids": ranked_ids[:10],
            "template_capability_index": {
                str(item.get("cve_id", "")).strip().upper(): item.get("template_capability", {})
                for item in ranked_candidates
                if str(item.get("cve_id", "")).strip()
            },
            "safe_only": (
                cve_safe_only
                if "safe_only" in surface
                else not any(value is False for value in candidate_safe_only_values)
            ),
            "allow_high_risk": (
                cve_allow_high_risk
                if "allow_high_risk" in surface
                else any(bool(value) for value in candidate_allow_high_risk_values)
            ),
            "authorization_confirmed": (
                authorization_confirmed
                if "authorization_confirmed" in surface
                else authorization_confirmed or any(bool(value) for value in candidate_authorization_values)
            ),
            "approval_granted": (
                approval_granted
                if "approval_granted" in surface
                else approval_granted or any(bool(value) for value in candidate_approval_values)
            ),
            "safety_grade": safety_grade,
            "host": host or target_host or None,
        }

    def _match_tech_component_rag_context(
        self,
        *,
        surface: dict[str, Any],
        target: str,
        host: str | None,
        component: str,
        version: str | None,
        service: str | None,
    ) -> dict[str, Any]:
        rag_hits = surface.get("rag_intel_hits", []) if isinstance(surface, dict) else []
        rag_contexts = surface.get("rag_recommendation_contexts", []) if isinstance(surface, dict) else []
        global_recommended_tools = surface.get("rag_recommended_tools", []) if isinstance(surface, dict) else []
        if not isinstance(rag_hits, list):
            rag_hits = []
        if not isinstance(rag_contexts, list):
            rag_contexts = []
        if not isinstance(global_recommended_tools, list):
            global_recommended_tools = []

        target_host = (urlparse(target).hostname or "").strip().lower() if self._is_http_url(target) else str(target).strip().lower()
        normalized_component = str(component).strip().lower()
        normalized_version = str(version or "").strip().lower()
        normalized_service = str(service or "").strip().lower()

        matched_hits: list[dict[str, Any]] = []
        recommended_tools: list[str] = []
        seen_tools: set[str] = set()

        for raw in rag_hits:
            if not isinstance(raw, dict):
                continue
            tags = {
                str(item).strip().lower()
                for item in raw.get("tags", [])
                if str(item).strip()
            } if isinstance(raw.get("tags", []), list) else set()
            text_blob = " ".join(
                [
                    str(raw.get("title", "")).strip().lower(),
                    str(raw.get("summary", "")).strip().lower(),
                    str(raw.get("snippet", "")).strip().lower(),
                ]
            )
            if not (
                (normalized_component and (normalized_component in tags or normalized_component in text_blob))
                or (normalized_service and (normalized_service in tags or normalized_service in text_blob))
                or (normalized_version and normalized_version in text_blob)
            ):
                continue
            matched_hits.append(raw)
            raw_tools = raw.get("recommended_tools", [])
            if not isinstance(raw_tools, list):
                continue
            for tool_name in raw_tools:
                normalized = str(tool_name).strip()
                lowered = normalized.lower()
                if not normalized or lowered in seen_tools:
                    continue
                seen_tools.add(lowered)
                recommended_tools.append(normalized)

        for raw in rag_contexts:
            if not isinstance(raw, dict):
                continue
            tool_name = str(raw.get("tool", "")).strip()
            lowered = tool_name.lower()
            if not tool_name or lowered in seen_tools:
                continue
            raw_target = str(raw.get("target", "")).strip()
            raw_component = str(raw.get("component", "")).strip().lower()
            raw_version = str(raw.get("version", "")).strip().lower()
            raw_host = (urlparse(raw_target).hostname or "").strip().lower() if self._is_http_url(raw_target) else raw_target.lower()
            same_target = bool(raw_target and raw_target == target)
            same_host = bool(target_host and raw_host and raw_host == target_host)
            same_component = bool(normalized_component and raw_component and raw_component == normalized_component)
            version_compatible = not normalized_version or not raw_version or raw_version == normalized_version
            if same_target or same_host or (same_component and version_compatible):
                seen_tools.add(lowered)
                recommended_tools.append(tool_name)

        if matched_hits:
            for tool_name in global_recommended_tools:
                normalized = str(tool_name).strip()
                lowered = normalized.lower()
                if not normalized or lowered in seen_tools:
                    continue
                seen_tools.add(lowered)
                recommended_tools.append(normalized)

        return {
            "rag_intel_hits": matched_hits[:8],
            "rag_recommended_tools": recommended_tools[:8],
        }

    def _preferred_poc_template(
        self,
        *,
        target: str,
        component: str | None,
        service: str | None,
        port: int | None,
    ) -> str:
        parsed = urlparse(target if "://" in target else "")
        normalized_component = str(component or "").strip().lower()
        normalized_service = str(service or "").strip().lower()
        normalized_port = int(port or 0)
        if normalized_service == "redis" or normalized_component == "redis" or normalized_port == 6379:
            return "redis_ping_info_probe"
        if normalized_service == "memcached" or normalized_component == "memcached" or normalized_port == 11211:
            return "memcached_stats_probe"
        if normalized_service == "ssh" or normalized_component in {"ssh", "openssh", "dropbear"} or normalized_port == 22:
            return "ssh_banner_probe"
        if (
            normalized_service in {"tls", "ssl", "https"}
            or normalized_component in {"tls", "ssl"}
            or parsed.scheme == "https"
            or normalized_port in {443, 8443, 9443}
        ):
            return "tls_handshake_probe"
        if parsed.scheme in {"http", "https"}:
            return "http_probe"
        return "tcp_banner_probe"

    def _resolve_cve_candidate_targets(
        self,
        *,
        surface: dict[str, Any],
        origins: list[str],
        scope_items: list[str],
        scope_model: _ScopeModel,
        audit_target: str,
        authorization_confirmed: bool,
        cve_safe_only: bool,
        cve_allow_high_risk: bool,
        approval_granted: bool,
        safety_grade: str,
    ) -> list[_ResolvedTarget]:
        if not isinstance(surface, dict):
            return []
        candidates = surface.get("cve_candidates", [])
        if not isinstance(candidates, list):
            return []
        explicit_authorization = "authorization_confirmed" in surface
        explicit_safe_only = "safe_only" in surface
        explicit_allow_high_risk = "allow_high_risk" in surface
        explicit_approval = "approval_granted" in surface
        rag_hits = surface.get("rag_intel_hits", []) if isinstance(surface.get("rag_intel_hits", []), list) else []
        rag_recommended_tools = surface.get("rag_recommended_tools", []) if isinstance(surface.get("rag_recommended_tools", []), list) else []
        fallback_target = self._fallback_http_target(
            origins=origins,
            scope_items=scope_items,
            scope_model=scope_model,
            audit_target=audit_target,
        )
        grouped: dict[str, dict[str, Any]] = {}
        for raw in candidates:
            if not isinstance(raw, dict):
                continue
            target = str(raw.get("target", "")).strip() or fallback_target
            if not target:
                continue
            normalized_target = self._normalize_url(target) if self._is_http_url(target) else str(target).strip().lower()
            if not normalized_target:
                continue
            scope_host = urlparse(normalized_target).hostname or "" if self._is_http_url(normalized_target) else normalized_target
            if not self._is_host_in_scope(scope_host, scope_model):
                continue

            cve_id = str(raw.get("cve_id", "")).strip().upper()
            cve_ids = raw.get("cve_ids", [])
            normalized_cve_ids: list[str] = []
            if isinstance(cve_ids, list):
                for item in cve_ids:
                    token = str(item).strip().upper()
                    if token and re.fullmatch(r"CVE-\d{4}-\d{4,8}", token) and token not in normalized_cve_ids:
                        normalized_cve_ids.append(token)
            if cve_id and re.fullmatch(r"CVE-\d{4}-\d{4,8}", cve_id) and cve_id not in normalized_cve_ids:
                normalized_cve_ids.append(cve_id)
            if not normalized_cve_ids:
                continue

            item_severity = str(raw.get("severity", "info")).strip().lower()
            item_cvss = self._coerce_float(raw.get("cvss_score"))
            group = grouped.setdefault(
                normalized_target,
                {
                    "target": normalized_target,
                    "component": str(raw.get("component", "")).strip() or None,
                    "version": str(raw.get("version", "")).strip() or None,
                    "service": str(raw.get("service", "")).strip().lower() or None,
                    "items": [],
                    "authorization_confirmed_values": [],
                    "safe_only_values": [],
                    "allow_high_risk_values": [],
                    "approval_granted_values": [],
                },
            )
            if "authorization_confirmed" in raw:
                group["authorization_confirmed_values"].append(
                    self._coerce_bool(raw.get("authorization_confirmed"), default=False)
                )
            if "safe_only" in raw:
                group["safe_only_values"].append(
                    self._coerce_bool(raw.get("safe_only"), default=True)
                )
            if "allow_high_risk" in raw:
                group["allow_high_risk_values"].append(
                    self._coerce_bool(raw.get("allow_high_risk"), default=False)
                )
            if "approval_granted" in raw:
                group["approval_granted_values"].append(
                    self._coerce_bool(raw.get("approval_granted"), default=False)
                )
            for candidate_id in normalized_cve_ids:
                group["items"].append(
                    {
                        "cve_id": candidate_id,
                        "severity": item_severity,
                        "cvss_score": item_cvss,
                        "has_nuclei_template": bool(raw.get("has_nuclei_template", False)),
                        "template_capability": raw.get("template_capability", {}),
                    }
                )

        resolved: list[_ResolvedTarget] = []
        for target_key, group in grouped.items():
            ranked_candidates = NvdCveService.rank_cve_candidates(
                group.get("items", []),
                component=group.get("component"),
                version=group.get("version"),
                service=group.get("service"),
                rag_hits=rag_hits,
                rag_recommended_tools=rag_recommended_tools,
            )
            ranked_ids = [
                str(item.get("cve_id", "")).strip().upper()
                for item in ranked_candidates
                if str(item.get("cve_id", "")).strip()
            ]
            if not ranked_ids:
                continue
            item_authorization_values = group.get("authorization_confirmed_values", [])
            item_safe_only_values = group.get("safe_only_values", [])
            item_allow_high_risk_values = group.get("allow_high_risk_values", [])
            item_approval_values = group.get("approval_granted_values", [])
            resolved_authorization = (
                authorization_confirmed
                if explicit_authorization
                else any(bool(item) for item in item_authorization_values)
            )
            resolved_safe_only = (
                cve_safe_only
                if explicit_safe_only
                else not any(item is False for item in item_safe_only_values)
            )
            resolved_allow_high_risk = (
                cve_allow_high_risk
                if explicit_allow_high_risk
                else any(bool(item) for item in item_allow_high_risk_values)
            )
            resolved_approval = (
                approval_granted
                if explicit_approval
                else any(bool(item) for item in item_approval_values)
            )
            resolved.append(
                _ResolvedTarget(
                    target=target_key,
                    target_type="cve_candidate",
                    context={
                        "cve_id": ranked_ids[0],
                        "cve_ids": ranked_ids[:10],
                        "component": group.get("component"),
                        "version": group.get("version"),
                        "service": group.get("service"),
                        "template_capability_index": {
                            str(item.get("cve_id", "")).strip().upper(): item.get("template_capability", {})
                            for item in ranked_candidates
                            if str(item.get("cve_id", "")).strip()
                        },
                        "rag_intel_hits": rag_hits[:10],
                        "rag_recommended_tools": rag_recommended_tools[:10],
                        "safe_only": resolved_safe_only,
                        "allow_high_risk": resolved_allow_high_risk,
                        "authorization_confirmed": resolved_authorization,
                        "approval_granted": resolved_approval,
                        "safety_grade": safety_grade,
                    },
                )
            )
        return resolved

    def _normalize_surface_for_planning(self, audit_state: dict[str, Any]) -> dict[str, Any]:
        """Build planner surface view by merging top-level compatibility fields."""
        raw_surface = audit_state.get("surface", {})
        surface = dict(raw_surface) if isinstance(raw_surface, dict) else {}

        if "authorization_confirmed" in audit_state and "authorization_confirmed" not in surface:
            surface["authorization_confirmed"] = audit_state.get("authorization_confirmed")
        if "cve_safe_only" in audit_state and "safe_only" not in surface:
            surface["safe_only"] = audit_state.get("cve_safe_only")
        if "cve_allow_high_risk" in audit_state and "allow_high_risk" not in surface:
            surface["allow_high_risk"] = audit_state.get("cve_allow_high_risk")
        if "approval_granted" in audit_state and "approval_granted" not in surface:
            surface["approval_granted"] = audit_state.get("approval_granted")
        if "cve_candidates" in audit_state and "cve_candidates" not in surface:
            candidates = audit_state.get("cve_candidates", [])
            if isinstance(candidates, list):
                surface["cve_candidates"] = candidates
        return surface

    def _fallback_http_target(
        self,
        *,
        origins: list[str],
        scope_items: list[str],
        scope_model: _ScopeModel,
        audit_target: str,
    ) -> str:
        for origin in origins:
            parsed = urlparse(origin)
            host = parsed.hostname or ""
            if parsed.scheme in {"http", "https"} and self._is_host_in_scope(host, scope_model):
                normalized = self._normalize_url(origin)
                if normalized:
                    return normalized
        parsed_target = urlparse(audit_target if "://" in audit_target else f"https://{audit_target}")
        if parsed_target.scheme in {"http", "https"} and parsed_target.hostname:
            candidate = f"{parsed_target.scheme}://{self._canonical_netloc(parsed_target)}"
            host = parsed_target.hostname or ""
            if self._is_host_in_scope(host, scope_model):
                normalized = self._normalize_url(candidate)
                if normalized:
                    return normalized
        for token in self._scope_domain_seeds(scope_items):
            if self._is_host_in_scope(token, scope_model):
                return f"https://{token}"
        return ""

    @staticmethod
    def _split_component_token(raw_component: str) -> tuple[str, str | None]:
        normalized = str(raw_component).strip()
        if not normalized:
            return "", None
        for sep in ("/", " ", ":"):
            if sep in normalized:
                left, right = normalized.split(sep, maxsplit=1)
                return left.strip().lower(), right.strip() or None
        return normalized.lower(), None

    def _apply_llm_cve_preferences(
        self,
        candidates: list[_CandidateAction],
        *,
        llm_preferred_cve_ids: list[str],
    ) -> list[_CandidateAction]:
        """Bias/trim cve_verify candidates based on explicit LLM-selected CVE IDs."""
        preferred = set(self._dedupe_cve_ids(llm_preferred_cve_ids))
        if not preferred:
            return candidates

        remapped: list[_CandidateAction] = []
        matched_any = False
        for candidate in candidates:
            if candidate.tool_name != "cve_verify":
                remapped.append(candidate)
                continue
            option_ids = self._normalize_cve_id_list(candidate.options.get("cve_ids"))
            matched_ids = [item for item in option_ids if item in preferred]
            if matched_ids:
                matched_any = True
                updated_options = dict(candidate.options)
                updated_options["cve_ids"] = matched_ids
                remapped.append(
                    _CandidateAction(
                        tool_name=candidate.tool_name,
                        target=candidate.target,
                        options=updated_options,
                        priority=max(0, int(candidate.priority) - 8),
                        cost=candidate.cost,
                        reason=(
                            f"{candidate.reason} LLM selected CVE focus: "
                            f"{', '.join(matched_ids[:4])}."
                        ),
                        preconditions=list(candidate.preconditions),
                        stop_conditions=list(candidate.stop_conditions),
                        capabilities=list(candidate.capabilities),
                    )
                )
                continue
            remapped.append(
                _CandidateAction(
                    tool_name=candidate.tool_name,
                    target=candidate.target,
                    options=dict(candidate.options),
                    priority=int(candidate.priority) + 20,
                    cost=candidate.cost,
                    reason=candidate.reason,
                    preconditions=list(candidate.preconditions),
                    stop_conditions=list(candidate.stop_conditions),
                    capabilities=list(candidate.capabilities),
                )
            )
        return remapped if matched_any else candidates

    @staticmethod
    def _normalize_cve_id_list(value: Any) -> list[str]:
        if isinstance(value, list):
            raw_values = [str(item).strip() for item in value if str(item).strip()]
        elif isinstance(value, str):
            raw_values = [item.strip() for item in value.split(",") if item.strip()]
        else:
            raw_values = []
        output: list[str] = []
        seen: set[str] = set()
        for raw in raw_values:
            token = raw.upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,8}", token):
                continue
            if token in seen:
                continue
            seen.add(token)
            output.append(token)
        return output

    def _rank_cve_ids(self, entries: list[dict[str, Any]]) -> list[str]:
        scored: dict[str, tuple[float, int]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cve_id = str(entry.get("cve_id", "")).strip().upper()
            if not cve_id:
                continue
            cvss_score = self._coerce_float(entry.get("cvss_score"))
            severity_rank = self._severity_rank(str(entry.get("severity", "info")))
            composite = cvss_score if cvss_score is not None else float(severity_rank)
            existing = scored.get(cve_id)
            if existing is None or composite > existing[0]:
                scored[cve_id] = (composite, severity_rank)
        return [
            key
            for key, _value in sorted(
                scored.items(),
                key=lambda item: (-item[1][0], -item[1][1], item[0]),
            )
        ]

    @staticmethod
    def _severity_rank(value: str) -> int:
        mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return mapping.get(str(value).strip().lower(), 0)

    @staticmethod
    def _coerce_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_bool(value: Any, *, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return bool(default)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
            return bool(default)
        return bool(value)

    @staticmethod
    def _dedupe_cve_ids(values: list[str]) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        for item in values:
            token = str(item).strip().upper()
            if not token or token in seen:
                continue
            seen.add(token)
            output.append(token)
        return output

    def _resolve_tool_instance(self, tool_name: str) -> Any | None:
        try:
            return get_tool(tool_name)
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _merge_tool_hints(primary: Sequence[str], secondary: Sequence[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for candidate in [*primary, *secondary]:
            normalized = str(candidate).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            merged.append(normalized)
        return merged

    def parse_suggestions(
        self,
        llm_response: str,
    ) -> tuple[list[str], list[str], str | None, str | None]:
        """Parse classic tool-name suggestions from LLM JSON."""
        try:
            payload = self._parse_json_payload(llm_response)
        except ValueError as exc:
            return [], [], None, str(exc)

        suggested_raw = self._extract_tool_candidates(payload)
        reason = self._extract_reason(payload)

        suggested: list[str] = []
        rejected: list[str] = []
        seen: set[str] = set()
        allowed = set(self._llm_allowed_tools)

        for candidate in suggested_raw:
            if candidate in seen:
                continue
            seen.add(candidate)
            if candidate in allowed:
                suggested.append(candidate)
            else:
                rejected.append(candidate)

        return suggested, rejected, reason, None

    def compute_idempotency_key(self, tool_name: str, target: str, options: dict[str, Any]) -> str:
        """Compute deterministic action deduplication key."""
        canonical = self.canonical_json(options)
        payload = f"{tool_name}{target}{canonical}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def canonical_json(self, value: dict[str, Any]) -> str:
        """Render canonical JSON for deterministic key generation."""
        canonical_value = self._canonicalize_options(value)
        return json.dumps(canonical_value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def _get_llm_guidance(
        self,
        audit_state: dict[str, Any],
        *,
        available_tools: Sequence[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        """Query LLM for optional tool-priority hints and CVE preferences."""
        active_tools = self._effective_available_tools(available_tools)
        prompt = self.build_hardened_prompt(audit_state, available_tools=active_tools)
        try:
            raw_response = self._llm_callable(prompt) if self._llm_callable is not None else ""
        except Exception:  # noqa: BLE001
            return [], []
        if not raw_response.strip():
            return [], []

        try:
            payload = self._parse_json_payload(raw_response)
        except ValueError:
            return [], []

        tool_hints: list[str] = []
        preferred_cve_ids: list[str] = []
        tools = payload.get("tools")
        if isinstance(tools, list):
            for item in tools:
                if isinstance(item, str):
                    tool_hints.append(item.strip())

        actions = payload.get("actions")
        if isinstance(actions, list):
            for item in actions:
                if not isinstance(item, dict):
                    continue
                tool_name = str(item.get("tool_name", "")).strip()
                if tool_name:
                    tool_hints.append(tool_name)
                if tool_name == "cve_verify":
                    options = item.get("options", {})
                    if isinstance(options, dict):
                        preferred_cve_ids.extend(self._normalize_cve_id_list(options.get("cve_ids")))
                    preferred_cve_ids.extend(self._normalize_cve_id_list(item.get("cve_ids")))
        preferred_cve_ids.extend(self._normalize_cve_id_list(payload.get("cve_ids")))

        allowed = set(active_tools)
        deduped: list[str] = []
        seen: set[str] = set()
        for item in tool_hints:
            if not item or item in seen or item not in allowed:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped, self._dedupe_cve_ids(preferred_cve_ids)

    def _get_llm_tool_hints(
        self,
        audit_state: dict[str, Any],
        *,
        available_tools: Sequence[str] | None = None,
    ) -> list[str]:
        """Backward-compatible wrapper for tool-hints-only callers."""
        hints, _cve_ids = self._get_llm_guidance(audit_state, available_tools=available_tools)
        return hints

    def _select_actions(
        self,
        candidates: list[_CandidateAction],
        history_keys: set[str],
        budget_remaining: int,
        llm_tool_hints: list[str],
        scope_model: _ScopeModel,
        available_tools: Sequence[str] | None = None,
        safety_grade: str | None = None,
        nmap_service_origins: set[str] | None = None,
    ) -> list[PlannedAction]:
        """Apply hard constraints: scope, dedupe, budget, deterministic ordering."""
        active_tools = self._effective_available_tools(available_tools)
        effective_grade = normalize_safety_grade(safety_grade or self._safety_grade)
        tool_rank = {name: idx for idx, name in enumerate(llm_tool_hints)}

        scoped_candidates: list[tuple[_CandidateAction, str]] = []
        seen_plan_keys: set[str] = set()
        for candidate in candidates:
            if candidate.tool_name not in active_tools:
                continue
            if not self._target_in_scope(candidate.target, scope_model):
                continue

            normalized_target = self._normalize_target_for_key(candidate.tool_name, candidate.target)
            normalized_options = self._canonicalize_options(candidate.options)
            key = self.compute_idempotency_key(candidate.tool_name, normalized_target, normalized_options)
            if key in history_keys or key in seen_plan_keys:
                continue

            seen_plan_keys.add(key)
            scoped_candidates.append((candidate, key))

        scoped_candidates.sort(
            key=lambda item: (
                item[0].priority,
                tool_rank.get(item[0].tool_name, 999),
                self._target_selection_rank(item[0].target, nmap_service_origins=nmap_service_origins),
                item[0].cost,
                item[0].tool_name,
                item[0].target,
            )
        )

        selected: list[PlannedAction] = []
        spent = 0
        max_actions = SAFETY_GRADE_ACTION_LIMITS.get(effective_grade, SAFETY_GRADE_ACTION_LIMITS[DEFAULT_AGENT_SAFETY_GRADE])
        selected_counts: dict[str, int] = {}
        selected_keys: set[str] = set()

        path_capped_seen: dict[str, dict[str, set[str]]] = {}
        max_rounds = max(
            (
                self._tool_selection_cap(
                    candidate.tool_name,
                    effective_grade,
                    nmap_service_origins=nmap_service_origins,
                )
                for candidate, _key in scoped_candidates
            ),
            default=0,
        )
        for round_limit in range(1, max_rounds + 1):
            made_progress = False
            for candidate, key in scoped_candidates:
                if len(selected) >= max_actions:
                    break
                if key in selected_keys:
                    continue
                tool_cap = self._tool_selection_cap(
                    candidate.tool_name,
                    effective_grade,
                    nmap_service_origins=nmap_service_origins,
                )
                if selected_counts.get(candidate.tool_name, 0) >= round_limit:
                    continue
                if selected_counts.get(candidate.tool_name, 0) >= tool_cap:
                    continue
                if budget_remaining < 10 and candidate.priority != 0:
                    continue
                if spent + candidate.cost > budget_remaining:
                    continue
                path_cap = self._path_selection_cap(candidate.tool_name)
                if path_cap > 0:
                    path_scope = self._path_scope_key(candidate.target)
                    if path_scope is not None:
                        host_key, path_key = path_scope
                        tool_paths = path_capped_seen.setdefault(candidate.tool_name, {})
                        host_paths = tool_paths.setdefault(host_key, set())
                        if path_key not in host_paths and len(host_paths) >= path_cap:
                            continue

                selected.append(
                    PlannedAction(
                        action_id=f"A{len(selected) + 1}",
                        tool_name=candidate.tool_name,
                        target=self._normalize_target_for_key(candidate.tool_name, candidate.target),
                        options=self._canonicalize_options(candidate.options),
                        priority=candidate.priority,
                        cost=candidate.cost,
                        capabilities=list(candidate.capabilities),
                        idempotency_key=key,
                        reason=candidate.reason,
                        preconditions=list(candidate.preconditions),
                        stop_conditions=list(candidate.stop_conditions),
                    )
                )
                selected_counts[candidate.tool_name] = selected_counts.get(candidate.tool_name, 0) + 1
                selected_keys.add(key)
                spent += candidate.cost
                if path_cap > 0:
                    path_scope = self._path_scope_key(candidate.target)
                    if path_scope is not None:
                        host_key, path_key = path_scope
                        tool_paths = path_capped_seen.setdefault(candidate.tool_name, {})
                        host_paths = tool_paths.setdefault(host_key, set())
                        host_paths.add(path_key)
                made_progress = True
            if len(selected) >= max_actions or not made_progress:
                break
        return selected

    def _effective_available_tools(
        self,
        override: Sequence[str] | None = None,
        *,
        audit_state: dict[str, Any] | None = None,
    ) -> tuple[str, ...]:
        """Resolve runtime-available tools for one planning cycle."""
        active = tuple(str(item).strip() for item in (override or self._available_tools) if str(item).strip())
        if not active:
            active = tuple(self._available_tools)
        denied = SAFETY_GRADE_DENIED_TOOLS.get(self._effective_safety_grade(audit_state), frozenset())
        filtered = tuple(item for item in active if item not in denied)
        return filtered

    def _effective_safety_grade(self, audit_state: dict[str, Any] | None = None) -> str:
        """Resolve one effective safety grade, allowing state override for resumes."""
        if isinstance(audit_state, dict):
            return normalize_safety_grade(audit_state.get("safety_grade", self._safety_grade))
        return self._safety_grade

    @staticmethod
    def _render_available_tool_lines(available_tools: Sequence[str]) -> str:
        """Render one tool list section for the hardened prompt."""
        descriptions = {
            "nmap_scan": "- nmap_scan(target, options)",
            "service_banner_probe": "- service_banner_probe(host, port, service, safe banner grab)",
            "tech_stack_fingerprint": "- tech_stack_fingerprint(url base origin only)",
            "js_endpoint_extractor": "- js_endpoint_extractor(url base origin only)",
            "login_form_detector": "- login_form_detector(url base origin only)",
            "git_exposure_check": "- git_exposure_check(url base origin only)",
            "source_map_detector": "- source_map_detector(url base origin only)",
            "error_page_analyzer": "- error_page_analyzer(url base origin only)",
            "waf_detector": "- waf_detector(url base origin only)",
            "security_txt_check": "- security_txt_check(url base origin only)",
            "dynamic_crawl": "- dynamic_crawl(url, max_depth, allow_domain)",
            "active_web_crawler": "- active_web_crawler(url, max_depth, allow_domain, limit)",
            "api_schema_discovery": "- api_schema_discovery(url base origin only)",
            "http_security_headers": "- http_security_headers(url base origin only)",
            "ssl_expiry_check": "- ssl_expiry_check(host or https origin only)",
            "subdomain_enum_passive": "- subdomain_enum_passive(domain only)",
            "cors_misconfiguration": "- cors_misconfiguration(url base origin only)",
            "dirsearch_scan": "- dirsearch_scan(url base origin only, safe options only)",
            "sql_sanitization_audit": "- sql_sanitization_audit(url, method, params)",
            "xss_protection_audit": "- xss_protection_audit(url, method, params)",
            "param_fuzzer": "- param_fuzzer(url, method=GET, params, mode=lightweight)",
            "cookie_security_audit": "- cookie_security_audit(url base origin only)",
            "csp_evaluator": "- csp_evaluator(url base origin only)",
            "passive_config_audit": "- passive_config_audit(url base origin only)",
            "nuclei_exploit_check": "- nuclei_exploit_check(url, templates/severity/template_id)",
            "cve_lookup": "- cve_lookup(tech_component from detected stack)",
            "cve_verify": "- cve_verify(url, cve_ids, authorization_confirmed)",
            "rag_intel_lookup": "- rag_intel_lookup(url, component/version/query)",
            "page_vision_analyzer": "- page_vision_analyzer(url, screenshot+ui analysis)",
            "poc_sandbox_exec": "- poc_sandbox_exec(url, cve_id/code_template, approval_granted)",
        }
        rendered = [descriptions[name] for name in available_tools if name in descriptions]
        return "\n".join(rendered)

    def _collect_terminal_history_keys(self, history: list[dict[str, Any]]) -> set[str]:
        """Collect idempotency keys of finished actions for deduplication."""
        keys: set[str] = set()
        for item in history:
            status = str(item.get("status", "")).strip().lower()
            if status not in HistoryTerminalStatus:
                continue

            key = str(item.get("idempotency_key", "")).strip()
            if key:
                keys.add(key)
                continue

            tool_name = str(item.get("tool", "")).strip()
            target = str(item.get("target", "")).strip()
            options = item.get("options", {})
            if tool_name and target and isinstance(options, dict):
                normalized_target = self._normalize_target_for_key(tool_name, target)
                keys.add(self.compute_idempotency_key(tool_name, normalized_target, options))
        return keys

    def _parse_scope(self, scope_items: list[str]) -> _ScopeModel:
        """Parse scope strings into domains, IPs, and networks."""
        domains: set[str] = set()
        ips: set[IPAddress] = set()
        networks: list[IPNetwork] = []

        for raw_entry in scope_items:
            token = self._extract_host_or_token(raw_entry)
            if not token:
                continue

            try:
                networks.append(ipaddress.ip_network(token, strict=False))
                continue
            except ValueError:
                pass
            try:
                ips.add(ipaddress.ip_address(token))
                continue
            except ValueError:
                pass
            domains.add(token.lower().lstrip("."))

        return _ScopeModel(domains=domains, ips=ips, networks=networks)

    def _extract_breadcrumb_urls(self, breadcrumbs: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
        """Extract service URLs and endpoint URLs from breadcrumbs."""
        service_urls: list[str] = []
        endpoint_urls: list[str] = []

        for item in breadcrumbs:
            raw_type = str(item.get("type", "")).strip().lower()
            raw_data = str(item.get("data", "")).strip()
            if not raw_data or not self._is_http_url(raw_data):
                continue

            normalized = self._normalize_url(raw_data)
            if not normalized:
                continue
            if raw_type == "service":
                service_urls.append(normalized)
            else:
                endpoint_urls.append(normalized)

        return service_urls, endpoint_urls

    def _extract_nmap_service_urls(self, surface: dict[str, Any]) -> list[str]:
        """Extract normalized HTTP(S) service origins discovered by nmap."""
        if not isinstance(surface, dict):
            return []

        discovered: list[str] = []
        for field in ("nmap_service_origins", "nmap_http_origins", "nmap_https_origins"):
            values = surface.get(field, [])
            if not isinstance(values, list):
                continue
            for item in values:
                if isinstance(item, str):
                    discovered.append(item)

        for item in surface.get("nmap_services", []):
            if not isinstance(item, dict):
                continue
            origin = str(item.get("origin", "")).strip()
            if origin:
                discovered.append(origin)

        if discovered:
            return self._dedupe_urls(discovered)

        hosts = surface.get("nmap_hosts", [])
        if not isinstance(hosts, list):
            return []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            host_token = ""
            hostnames = host.get("hostnames", [])
            if isinstance(hostnames, list) and hostnames:
                host_token = str(hostnames[0]).strip()
            if not host_token:
                addresses = host.get("addresses", [])
                if isinstance(addresses, list) and addresses:
                    first = addresses[0]
                    if isinstance(first, dict):
                        host_token = str(first.get("addr", "")).strip()
            if not host_token:
                continue
            for port_entry in host.get("open_ports", []):
                if not isinstance(port_entry, dict):
                    continue
                port = int(port_entry.get("port", 0) or 0)
                service = str(port_entry.get("service", "")).lower()
                scheme = ""
                if "https" in service or port in {443, 8443}:
                    scheme = "https"
                elif "http" in service or port in {80, 8080, 8000, 8008, 8888}:
                    scheme = "http"
                if scheme:
                    discovered.append(f"{scheme}://{host_token}:{port}")
        return self._dedupe_urls(discovered)

    def _surface_focus_ports(self, surface: dict[str, Any]) -> list[int]:
        if not isinstance(surface, dict):
            return []
        values = surface.get("focus_ports", [])
        if not isinstance(values, list):
            return []
        output: list[int] = []
        seen: set[int] = set()
        for item in values:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if port < 1 or port > 65535 or port in seen:
                continue
            seen.add(port)
            output.append(port)
        return output

    def _surface_preferred_origins(self, surface: dict[str, Any]) -> list[str]:
        if not isinstance(surface, dict):
            return []
        values = surface.get("preferred_origins", [])
        if not isinstance(values, list):
            return []
        return self._dedupe_urls([str(item).strip() for item in values if str(item).strip()])

    def _filter_urls_by_ports(self, urls: list[str], focus_ports: list[int]) -> list[str]:
        if not focus_ports:
            return list(urls)
        allowed = set(focus_ports)
        filtered: list[str] = []
        for item in urls:
            parsed = urlparse(item)
            if not parsed.scheme or not parsed.netloc:
                continue
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            if port in allowed:
                filtered.append(item)
        return self._dedupe_urls(filtered)

    def _derive_nuclei_targets(
        self,
        *,
        service_urls: list[str],
        endpoint_urls: list[str],
        surface: Any,
    ) -> list[str]:
        """
        Pick nuclei targets from concrete discovered evidence only.

        Strategy:
        - only consider known URLs from services/endpoints/surface outputs
        - trigger on keyword hints (stack/login/admin/sensitive paths)
        - dedupe to origin-level targets for cost control
        """
        candidates: set[str] = set()
        source_urls: list[str] = [*service_urls, *endpoint_urls]
        stack_hints = self._surface_tech_stack_hints(surface)
        rag_wants_nuclei = False
        tech_component_origins: set[str] = set()

        if isinstance(surface, dict):
            rag_wants_nuclei = "nuclei_exploit_check" in {
                str(item).strip().lower()
                for item in surface.get("rag_recommended_tools", [])
                if str(item).strip()
            }
            for item in surface.get("discovered_urls", []):
                if isinstance(item, str):
                    source_urls.append(item)
            for item in surface.get("api_endpoints", []):
                if isinstance(item, dict):
                    source_urls.append(str(item.get("url", "")))
                elif isinstance(item, str):
                    source_urls.append(item)
            for entry in surface.get("tech_components", []):
                if not isinstance(entry, dict):
                    continue
                explicit_target = str(entry.get("target", "")).strip() or str(entry.get("origin", "")).strip()
                service = str(entry.get("service", "")).strip().lower()
                host = str(entry.get("host", "")).strip().lower()
                try:
                    port = int(entry.get("port", 0) or 0)
                except (TypeError, ValueError):
                    port = 0
                if self._is_http_url(explicit_target):
                    normalized_target = self._normalize_url(explicit_target)
                    if normalized_target:
                        source_urls.append(normalized_target)
                        origin = self._url_origin(normalized_target)
                        if origin:
                            tech_component_origins.add(origin)
                    continue
                if not host:
                    continue
                derived_url = ""
                if service in {"https", "tls"} or port in {443, 8443, 9443}:
                    derived_url = f"https://{host}" if port in {0, 443} else f"https://{host}:{port}"
                elif service == "http" or port in {80, 8080, 8000, 8008, 8888}:
                    derived_url = f"http://{host}" if port in {0, 80} else f"http://{host}:{port}"
                if derived_url:
                    source_urls.append(derived_url)
                    origin = self._url_origin(derived_url)
                    if origin:
                        tech_component_origins.add(origin)

        for raw_url in source_urls:
            if not self._is_http_url(raw_url):
                continue
            normalized = self._normalize_url(raw_url)
            if not normalized:
                continue
            origin = self._url_origin(normalized)
            if not origin:
                continue
            if stack_hints or self._looks_nuclei_worthy(normalized) or (rag_wants_nuclei and origin in tech_component_origins):
                candidates.add(origin)

        return sorted(candidates)

    def _extract_surface_endpoint_params(self, surface: Any) -> tuple[dict[str, dict[str, str]], set[str]]:
        """Merge crawler-provided API endpoints and parameter origins into endpoint params."""
        if not isinstance(surface, dict):
            return {}, set()

        merged: dict[str, dict[str, str]] = {}
        confirmed: set[str] = set()
        parameter_values: dict[str, str] = {}

        raw_url_parameters = surface.get("url_parameters", {})
        if isinstance(raw_url_parameters, dict):
            for key, values in raw_url_parameters.items():
                name = str(key).strip()
                if not name:
                    continue
                if isinstance(values, list) and values:
                    parameter_values[name] = str(values[0])
                elif values not in (None, ""):
                    parameter_values[name] = str(values)

        def merge_url_params(raw_url: str, params: dict[str, Any]) -> None:
            normalized = self._normalize_url(raw_url)
            if not normalized:
                return
            parsed = urlparse(normalized)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return
            endpoint_base = urlunparse((parsed.scheme, self._canonical_netloc(parsed), parsed.path or "/", "", "", ""))
            normalized_params = merged.setdefault(endpoint_base, {})
            for key, value in params.items():
                name = str(key).strip()
                if not name:
                    continue
                normalized_params.setdefault(name, str(value))
            if normalized_params:
                confirmed.add(endpoint_base)

        for item in surface.get("api_endpoints", []):
            if not isinstance(item, dict):
                continue
            method = str(item.get("method", "GET")).strip().upper() or "GET"
            if method != "GET":
                continue
            raw_url = str(item.get("url", "")).strip()
            if not raw_url:
                continue
            parsed = urlparse(raw_url)
            params = {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
            raw_params = item.get("params", {})
            if isinstance(raw_params, dict):
                for key, value in raw_params.items():
                    params.setdefault(str(key), str(value))
            merge_url_params(raw_url, params)

        raw_parameter_origins = surface.get("parameter_origins", {})
        if isinstance(raw_parameter_origins, dict):
            for key, origins in raw_parameter_origins.items():
                name = str(key).strip()
                if not name:
                    continue
                raw_value = parameter_values.get(name, "1")
                values = origins if isinstance(origins, list) else [origins]
                for origin in values:
                    merge_url_params(str(origin), {name: raw_value})

        return {key: value for key, value in merged.items() if value}, confirmed

    def _surface_tech_stack_hints(self, surface: Any) -> bool:
        """Return whether surface tech-stack hints warrant nuclei checks."""
        if not isinstance(surface, dict):
            return False
        tech_stack = surface.get("tech_stack", [])
        tech_components = surface.get("tech_components", [])
        hinted = {"wordpress", "spring", "jenkins", "grafana", "struts", "drupal", "joomla"}
        if isinstance(tech_stack, list):
            for item in tech_stack:
                lowered = str(item).strip().lower()
                if lowered in hinted:
                    return True
        if isinstance(tech_components, list):
            for item in tech_components:
                if isinstance(item, dict):
                    lowered = str(item.get("component", "")).strip().lower()
                else:
                    lowered = str(item).strip().lower()
                if lowered in hinted:
                    return True
        return False

    def _looks_nuclei_worthy(self, url: str) -> bool:
        """Heuristic hints for when template-based vuln checks are worth running."""
        lowered = url.lower()
        keywords = (
            "wp-admin",
            "wordpress",
            "xmlrpc.php",
            "struts",
            "spring",
            "actuator",
            "grafana",
            "jenkins",
            "kibana",
            "phpmyadmin",
            "login",
            "signin",
            "admin",
            "manager",
            "console",
        )
        return any(token in lowered for token in keywords)

    def _scope_scan_seeds(self, scope_items: list[str]) -> list[str]:
        """Choose conservative nmap seeds directly from scope declarations."""
        seeds: list[str] = []
        seen: set[str] = set()
        for raw_entry in scope_items:
            token = self._extract_host_or_token(raw_entry)
            if not token or "/" in token or token in seen:
                continue
            seen.add(token)
            seeds.append(token)
        return sorted(seeds)

    def _scope_domain_seeds(self, scope_items: list[str]) -> list[str]:
        """Choose domain-only seeds for passive subdomain enumeration."""
        seeds: list[str] = []
        seen: set[str] = set()
        for raw_entry in scope_items:
            token = self._extract_host_or_token(raw_entry)
            if not token or token in seen or "/" in token:
                continue
            try:
                ipaddress.ip_network(token, strict=False)
                continue
            except ValueError:
                pass
            try:
                ipaddress.ip_address(token)
                continue
            except ValueError:
                pass
            seen.add(token)
            seeds.append(token)
        return sorted(seeds)

    def _target_in_scope(self, target: str, scope_model: _ScopeModel) -> bool:
        """Validate target string (URL/host/IP) against scope model."""
        if self._is_http_url(target):
            return self._is_host_in_scope(urlparse(target).hostname or "", scope_model)
        return self._is_host_in_scope(target, scope_model)

    def _is_host_in_scope(self, host: str, scope_model: _ScopeModel) -> bool:
        """Evaluate host against domain/IP/network scope rules."""
        normalized_host = host.strip().lower()
        if not normalized_host:
            return False

        try:
            ip_value = ipaddress.ip_address(normalized_host)
        except ValueError:
            ip_value = None

        if ip_value is not None:
            if ip_value in scope_model.ips:
                return True
            return any(ip_value in network for network in scope_model.networks)

        domain_allowed = any(
            normalized_host == domain or normalized_host.endswith(f".{domain}")
            for domain in scope_model.domains
        )
        if not domain_allowed:
            return False

        if scope_model.ips or scope_model.networks:
            resolved_ips = self._resolve_domain_ips(normalized_host)
            if not resolved_ips:
                return False
            for ip_str in resolved_ips:
                try:
                    resolved = ipaddress.ip_address(ip_str)
                except ValueError:
                    return False
                if resolved in scope_model.ips:
                    continue
                if any(resolved in network for network in scope_model.networks):
                    continue
                return False
        return True

    def _resolve_domain_ips(self, domain: str) -> list[str]:
        """Resolve domain to IP addresses using injected resolver or socket."""
        if self._dns_resolver is not None:
            try:
                resolved = [str(item).strip() for item in self._dns_resolver(domain)]
                return sorted({item for item in resolved if item})
            except Exception:
                return []

        try:
            info = socket.getaddrinfo(domain, None)
        except OSError:
            return []
        ips = {
            entry[4][0]
            for entry in info
            if isinstance(entry, tuple) and len(entry) > 4 and entry[4]
        }
        return sorted(ips)

    def _normalize_target_for_key(self, tool_name: str, target: str) -> str:
        """Normalize target for idempotency stability."""
        raw = target.strip()
        parsed = urlparse(raw)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            scheme = parsed.scheme.lower()
            netloc = self._canonical_netloc(parsed)
            if tool_name in {"passive_config_audit", "dirsearch_scan"}:
                return urlunparse((scheme, netloc, "", "", "", ""))
            path = parsed.path or "/"
            query = urlencode(
                sorted(parse_qsl(parsed.query, keep_blank_values=True), key=lambda item: item[0]),
                doseq=True,
            )
            return urlunparse((scheme, netloc, path, "", query, ""))

        return self._extract_host_or_token(raw).lower()

    def _is_http_url(self, value: str) -> bool:
        """Return whether value is an HTTP(S) URL."""
        parsed = urlparse(value.strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _normalize_url(self, value: str) -> str:
        """Normalize URL for deterministic comparisons."""
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        path = parsed.path or "/"
        netloc = self._canonical_netloc(parsed)
        query = urlencode(
            sorted(parse_qsl(parsed.query, keep_blank_values=True), key=lambda item: item[0]),
            doseq=True,
        )
        return urlunparse((parsed.scheme.lower(), netloc, path, "", query, ""))

    def _url_origin(self, value: str) -> str:
        """Return scheme+host+port origin."""
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        netloc = self._canonical_netloc(parsed)
        return urlunparse((parsed.scheme.lower(), netloc, "", "", "", ""))

    def _canonical_netloc(self, parsed: Any) -> str:
        """Render netloc using explicit default ports for origin deduplication."""
        host = (parsed.hostname or "").lower()
        if not host:
            return parsed.netloc.lower()
        port = parsed.port
        if port is None:
            if parsed.scheme.lower() == "http":
                port = 80
            elif parsed.scheme.lower() == "https":
                port = 443
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{port}" if port is not None else host

    def _extract_host_or_token(self, raw: str) -> str:
        """Extract host-like token from scope string or URL."""
        candidate = raw.strip()
        if not candidate:
            return ""

        if "://" in candidate:
            return (urlparse(candidate).hostname or "").strip().lower()

        try:
            ipaddress.ip_address(candidate)
            return candidate.lower()
        except ValueError:
            pass

        if ":" in candidate and candidate.count(":") == 1:
            return candidate.split(":", maxsplit=1)[0].strip().lower()
        return candidate.lower()

    def _coerce_budget(self, value: Any) -> int:
        """Convert budget input to non-negative integer."""
        try:
            budget = int(float(value))
        except (TypeError, ValueError):
            return 0
        return max(0, budget)

    def _cost_for(
        self,
        tool_name: str,
        *,
        tool: Any | None = None,
        options: dict[str, Any] | None = None,
    ) -> int:
        """Return configured tool cost."""
        if tool_name == "dynamic_crawl":
            max_depth = int((options or {}).get("max_depth", self._default_crawl_depth))
            return self._cost_for_dynamic_crawl(max_depth)
        configured = self._tool_costs.get(tool_name)
        if configured is not None:
            return max(1, int(configured))
        metadata_cost = getattr(tool, "cost", None)
        if metadata_cost is not None:
            return max(1, int(metadata_cost))
        return 5

    def _cost_for_dynamic_crawl(self, max_depth: int) -> int:
        """Return dynamic_crawl cost with bounded depth adjustment."""
        base = max(1, int(self._tool_costs.get("dynamic_crawl", getattr(self._resolve_tool_instance("dynamic_crawl"), "cost", 12))))
        if max_depth <= 2:
            return base
        return base + (max_depth - 2) * 2

    def _tool_selection_cap(
        self,
        tool_name: str,
        safety_grade: str,
        *,
        nmap_service_origins: set[str] | None = None,
    ) -> int:
        """Return max times one tool may appear in a single plan."""
        grade_caps = self.DEFAULT_TOOL_SELECTION_CAPS.get(
            normalize_safety_grade(safety_grade),
            self.DEFAULT_TOOL_SELECTION_CAPS[DEFAULT_AGENT_SAFETY_GRADE],
        )
        base_cap = max(0, int(grade_caps.get(tool_name, 1)))
        if tool_name not in _NMAP_PORT_AWARE_TOOLS:
            return base_cap
        service_count = len(nmap_service_origins or set())
        if service_count <= 1:
            return base_cap
        grade_limit = _NMAP_PORT_SELECTION_CAPS.get(
            normalize_safety_grade(safety_grade),
            _NMAP_PORT_SELECTION_CAPS[DEFAULT_AGENT_SAFETY_GRADE],
        )
        return max(base_cap, min(service_count, grade_limit))

    def _path_selection_cap(self, tool_name: str) -> int:
        """Return max distinct paths one host may get for one verification tool."""
        return max(0, int(self._PATH_CAPPED_TOOLS.get(tool_name, 0)))

    def _path_scope_key(self, target: str) -> tuple[str, str] | None:
        """Collapse HTTP targets to host + normalized path for path-level rate control."""
        parsed = urlparse(str(target).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            return None
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        return parsed.hostname.lower(), path

    def _target_selection_rank(
        self,
        target: str,
        *,
        nmap_service_origins: set[str] | None = None,
    ) -> int:
        """Prefer nmap-confirmed ports, then canonical ports, then fringe HTTP-like ports."""
        parsed = urlparse(str(target).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return 1000
        origin = self._url_origin(target)
        source_bias = 0 if origin and origin in (nmap_service_origins or set()) else 10_000
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return source_bias + self._STANDARD_PORT_PRIORITY.get((parsed.scheme.lower(), int(port)), 100 + int(port))

    def _dedupe_urls(self, values: list[str]) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for item in values:
            normalized = self._normalize_url(str(item))
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    def _priority_for(self, tool_name: str, *, tool: Any | None = None) -> int:
        """Return configured tool priority (0 is highest)."""
        configured = self._tool_priorities.get(tool_name)
        if configured is not None:
            return int(configured)
        metadata_priority = getattr(tool, "priority", None)
        if metadata_priority is not None:
            return int(metadata_priority)
        return 50

    def _canonicalize_options(self, value: Any) -> Any:
        """Recursively normalize options for stable serialization."""
        if isinstance(value, dict):
            return {
                str(key): self._canonicalize_options(value[key])
                for key in sorted(value.keys(), key=lambda item: str(item))
            }
        if isinstance(value, list):
            return [self._canonicalize_options(item) for item in value]
        if isinstance(value, tuple):
            return [self._canonicalize_options(item) for item in value]
        return value

    def _parse_json_payload(self, llm_response: str) -> dict[str, Any]:
        """Parse JSON payload from possibly noisy LLM text."""
        raw = llm_response.strip()
        if not raw:
            raise ValueError("LLM response is empty")

        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        fenced = self._extract_fenced_json(raw)
        if fenced:
            try:
                parsed = json.loads(fenced)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        decoder = json.JSONDecoder()
        for idx, char in enumerate(raw):
            if char != "{":
                continue
            try:
                parsed_obj, _end = decoder.raw_decode(raw[idx:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed_obj, dict):
                return parsed_obj

        raise ValueError("Unable to parse JSON object from LLM response")

    @staticmethod
    def _extract_fenced_json(text: str) -> str | None:
        """Extract first markdown fenced block as JSON."""
        marker = "```"
        first = text.find(marker)
        if first < 0:
            return None
        second = text.find(marker, first + len(marker))
        if second < 0:
            return None

        block = text[first + len(marker) : second].strip()
        if block.lower().startswith("json"):
            block = block[4:].strip()
        return block or None

    def _extract_tool_candidates(self, payload: dict[str, Any]) -> list[str]:
        """Extract tool names from several JSON shapes."""
        raw_tools: list[str] = []

        if isinstance(payload.get("tool"), str):
            raw_tools.append(payload["tool"].strip())

        tools_field = payload.get("tools")
        if isinstance(tools_field, list):
            for item in tools_field:
                if isinstance(item, str):
                    raw_tools.append(item.strip())
                elif isinstance(item, dict) and isinstance(item.get("tool"), str):
                    raw_tools.append(item["tool"].strip())

        rec_field = payload.get("recommendations")
        if isinstance(rec_field, list):
            for item in rec_field:
                if isinstance(item, str):
                    raw_tools.append(item.strip())
                elif isinstance(item, dict) and isinstance(item.get("tool"), str):
                    raw_tools.append(item["tool"].strip())

        return [item for item in raw_tools if item]

    @staticmethod
    def _extract_reason(payload: dict[str, Any]) -> str | None:
        """Extract optional reason field."""
        reason = payload.get("reason")
        if isinstance(reason, str):
            reason_text = reason.strip()
            return reason_text or None
        return None
