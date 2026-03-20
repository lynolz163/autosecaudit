"""Feedback-driven planning adjustments for the agent loop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .skill_loader import SkillRegistry, load_builtin_skill_registry
from .skill_planner import SkillDrivenPlanner


@dataclass(frozen=True)
class FollowUpAction:
    """Suggested follow-up planning hint."""

    tool_name: str
    reason: str
    priority_delta: int = 0


class FeedbackEngine:
    """Analyze execution output and shape subsequent planning."""

    _LEGACY_STACK_TO_TOOL_HINTS: dict[str, tuple[str, ...]] = {
        "wordpress": ("nuclei_exploit_check", "dirsearch_scan"),
        "drupal": ("nuclei_exploit_check",),
        "joomla": ("nuclei_exploit_check",),
        "grafana": ("nuclei_exploit_check",),
        "jenkins": ("nuclei_exploit_check",),
        "spring": ("passive_config_audit", "nuclei_exploit_check"),
        "django": ("passive_config_audit", "api_schema_discovery"),
        "flask": ("passive_config_audit", "api_schema_discovery"),
        "express": ("api_schema_discovery", "cookie_security_audit"),
        "laravel": ("passive_config_audit", "dirsearch_scan"),
        "rails": ("passive_config_audit", "cookie_security_audit"),
        "react": ("source_map_detector", "api_schema_discovery"),
        "vue": ("source_map_detector", "api_schema_discovery"),
        "angular": ("source_map_detector", "api_schema_discovery"),
        "nginx": ("http_security_headers", "csp_evaluator"),
        "apache": ("http_security_headers", "csp_evaluator"),
    }

    def __init__(
        self,
        *,
        skill_registry: SkillRegistry | None = None,
        skill_planner: SkillDrivenPlanner | None = None,
    ) -> None:
        self._skill_registry = skill_registry if skill_registry is not None else load_builtin_skill_registry()
        self._skill_planner = skill_planner or SkillDrivenPlanner()

    def analyze_findings(self, findings: list[dict[str, Any]]) -> list[FollowUpAction]:
        """Suggest follow-up tools from normalized findings."""
        suggestions: list[FollowUpAction] = []
        pseudo_result = {
            "status": "completed",
            "findings": findings,
            "surface_delta": {},
            "breadcrumbs_delta": [],
        }
        for skill in self._skill_registry.list():
            for follow_up in self._skill_planner.match_result_follow_ups(skill, pseudo_result):
                for tool_name in follow_up.trigger:
                    suggestions.append(
                        FollowUpAction(
                            tool_name=tool_name,
                            reason=follow_up.reason or f"Skill follow-up from {skill.tool}.",
                            priority_delta=-4,
                        )
                    )
        for finding in findings:
            text = " ".join(
                str(finding.get(key, ""))
                for key in ("title", "description", "category", "tool", "severity", "cwe_id")
            ).lower()
            if "sql" in text or "cwe-89" in text or "cwe_89" in text:
                suggestions.append(FollowUpAction("sql_sanitization_audit", "SQL-related signal requires confirmation.", -6))
            if "xss" in text or "cross-site scripting" in text or "cwe-79" in text or "cwe_79" in text:
                suggestions.append(FollowUpAction("xss_protection_audit", "XSS-related signal requires confirmation.", -6))
            if any(token in text for token in ("config", "info leak", "exposure", "source map", "stack trace")):
                suggestions.append(FollowUpAction("passive_config_audit", "Information leakage warrants broader passive validation.", -4))
            if any(token in text for token in ("cookie", "session")):
                suggestions.append(FollowUpAction("cookie_security_audit", "Session handling findings should trigger cookie review.", -4))
            if any(token in text for token in ("csp", "content-security-policy")):
                suggestions.append(FollowUpAction("csp_evaluator", "CSP findings should trigger policy analysis.", -4))
            if "cve-" in text:
                suggestions.append(FollowUpAction("cve_verify", "CVE findings should be validated with nuclei templates.", -6))
        return self._dedupe_follow_ups(suggestions)

    def adjust_priorities(
        self,
        history: list[dict[str, Any]],
        surface: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, int]:
        """Return priority overrides keyed by tool name."""
        overrides: dict[str, int] = {}
        findings = findings or []

        tech_stack = {
            str(item).strip().lower()
            for item in surface.get("tech_stack", [])
            if str(item).strip()
        }
        dynamic_surface_follow_ups = self._surface_follow_ups_from_skills(surface)
        for item in dynamic_surface_follow_ups:
            overrides[item.tool_name] = min(overrides.get(item.tool_name, 0), item.priority_delta)
        for tech in tech_stack:
            for tool_name in self._LEGACY_STACK_TO_TOOL_HINTS.get(tech, ()):
                overrides[tool_name] = min(overrides.get(tool_name, 0), -5)

        url_parameters = surface.get("url_parameters", {})
        parameter_origins = surface.get("parameter_origins", {})
        if url_parameters or parameter_origins:
            for tool_name in ("sql_sanitization_audit", "xss_protection_audit", "param_fuzzer"):
                overrides[tool_name] = min(overrides.get(tool_name, 0), -5)

        if surface.get("api_endpoints"):
            overrides["api_schema_discovery"] = min(overrides.get("api_schema_discovery", 0), -4)
        if tech_stack and not surface.get("rag_intel_hits"):
            overrides["rag_intel_lookup"] = min(overrides.get("rag_intel_lookup", 0), -4)
        if surface.get("discovered_urls") and not surface.get("vision_snapshots"):
            overrides["page_vision_analyzer"] = min(overrides.get("page_vision_analyzer", 0), -3)
        waf_summary = surface.get("waf", {}) if isinstance(surface.get("waf", {}), dict) else {}
        waf_vendors = surface.get("waf_vendors", []) if isinstance(surface.get("waf_vendors", []), list) else []
        if bool(waf_summary.get("detected")) or any(str(item).strip() for item in waf_vendors):
            for tool_name in ("http_security_headers", "security_txt_check", "passive_config_audit", "ssl_expiry_check", "cors_misconfiguration"):
                overrides[tool_name] = min(overrides.get(tool_name, 0), -6)
            for tool_name in ("param_fuzzer", "sql_sanitization_audit", "xss_protection_audit", "dirsearch_scan"):
                overrides[tool_name] = max(overrides.get(tool_name, 0), 3)
        cve_candidates = surface.get("cve_candidates", []) if isinstance(surface, dict) else []
        if isinstance(cve_candidates, list) and any(isinstance(item, dict) for item in cve_candidates):
            overrides["cve_verify"] = min(overrides.get("cve_verify", 0), -6)
            authorization_confirmed = bool(surface.get("authorization_confirmed", False))
            approval_granted = bool(surface.get("approval_granted", False))
            if authorization_confirmed and approval_granted:
                overrides["poc_sandbox_exec"] = min(overrides.get("poc_sandbox_exec", 0), -3)
        if tech_stack and not cve_candidates:
            overrides["cve_lookup"] = min(overrides.get("cve_lookup", 0), -5)

        follow_ups = self.analyze_findings(findings)
        for item in follow_ups:
            overrides[item.tool_name] = min(overrides.get(item.tool_name, 0), item.priority_delta)

        recent_failures = {
            str(entry.get("tool", "")).strip()
            for entry in history[-5:]
            if str(entry.get("status", "")).strip().lower() in {"failed", "error"}
        }
        for tool_name in recent_failures:
            overrides[tool_name] = max(overrides.get(tool_name, 0), 5)
        return overrides

    def evaluate_risk_escalation(self, findings: list[dict[str, Any]]) -> str:
        """Return risk control signal based on observed findings."""
        severities = {str(item.get("severity", "")).strip().lower() for item in findings}
        if "critical" in severities:
            return "pause"
        if "high" in severities:
            return "tighten"
        return "none"

    def build_feedback(
        self,
        *,
        history: list[dict[str, Any]],
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        tool_follow_up_hints: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build serializable feedback state for the next planning cycle."""
        follow_up_tools = [item.tool_name for item in self.analyze_findings(findings)]
        for item in tool_follow_up_hints or []:
            candidate = str(item).strip()
            if candidate:
                follow_up_tools.append(candidate)
        deduped_follow_up_tools = self._dedupe_strings(follow_up_tools)
        return {
            "follow_up_tools": deduped_follow_up_tools,
            "priority_overrides": self.adjust_priorities(history, surface, findings),
            "risk_signal": self.evaluate_risk_escalation(findings),
        }

    def merge_feedback(
        self,
        existing: dict[str, Any] | None,
        incoming: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Merge persisted feedback with the latest signals."""
        existing = existing or {}
        incoming = incoming or {}
        merged_priority = dict(existing.get("priority_overrides", {}))
        for tool_name, delta in dict(incoming.get("priority_overrides", {})).items():
            try:
                merged_priority[str(tool_name)] = int(delta)
            except (TypeError, ValueError):
                continue
        risk_signal = str(existing.get("risk_signal", "none")).strip().lower()
        incoming_risk = str(incoming.get("risk_signal", "none")).strip().lower()
        risk_order = {"none": 0, "tighten": 1, "pause": 2}
        if risk_order.get(incoming_risk, 0) > risk_order.get(risk_signal, 0):
            risk_signal = incoming_risk
        return {
            "follow_up_tools": self._dedupe_strings(
                [*existing.get("follow_up_tools", []), *incoming.get("follow_up_tools", [])]
            ),
            "priority_overrides": merged_priority,
            "risk_signal": risk_signal,
        }

    @staticmethod
    def _dedupe_strings(values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in values:
            normalized = str(item).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    def _dedupe_follow_ups(self, items: list[FollowUpAction]) -> list[FollowUpAction]:
        deduped: dict[str, FollowUpAction] = {}
        for item in items:
            existing = deduped.get(item.tool_name)
            if existing is None or item.priority_delta < existing.priority_delta:
                deduped[item.tool_name] = item
        return list(deduped.values())

    def _surface_follow_ups_from_skills(self, surface: dict[str, Any]) -> list[FollowUpAction]:
        suggestions: list[FollowUpAction] = []
        for skill in self._skill_registry.list():
            for follow_up in self._skill_planner.match_surface_follow_ups(skill, surface):
                for tool_name in follow_up.trigger:
                    suggestions.append(
                        FollowUpAction(
                            tool_name=tool_name,
                            reason=follow_up.reason or f"Skill surface follow-up from {skill.tool}.",
                            priority_delta=-5,
                        )
                    )
        return self._dedupe_follow_ups(suggestions)
