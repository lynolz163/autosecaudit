"""Skill-driven candidate generation and result interpretation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from typing import Any
from urllib.parse import urlparse

from .skill_loader import SkillDefinition, SkillFollowUp


@dataclass(frozen=True)
class SkillCandidateSpec:
    """One candidate action derived from a skill definition."""

    tool_name: str
    target: str
    target_type: str
    options: dict[str, Any]
    context: dict[str, Any]
    reason: str | None = None
    preconditions: list[str] | None = None
    stop_conditions: list[str] | None = None


class SkillDrivenPlanner:
    """Use structured skills to drive planning and result interpretation."""

    _SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    _CRAWLER_TOOLS = {"dynamic_crawl", "active_web_crawler", "js_endpoint_extractor", "api_schema_discovery"}

    def generate_candidates_for_skill(
        self,
        *,
        skill: SkillDefinition,
        tool: Any | None,
        phase: str,
        planning_context: dict[str, Any],
    ) -> list[SkillCandidateSpec]:
        """Generate candidate specs for one skill when its triggers match."""
        if not self._phase_matches(skill, phase):
            return []
        if not self._global_conditions_match(skill, planning_context):
            return []

        resolver = planning_context.get("resolve_targets")
        if not callable(resolver):
            return []
        resolved_targets = resolver([skill.triggers.target_type])
        candidates: list[SkillCandidateSpec] = []
        for resolved in resolved_targets:
            target = str(getattr(resolved, "target", "")).strip()
            target_type = str(getattr(resolved, "target_type", skill.triggers.target_type)).strip()
            context = dict(getattr(resolved, "context", {}) or {})
            if not target or not self._target_conditions_match(skill, context, planning_context):
                continue
            options = self._render_option_template(
                skill.parameters.defaults,
                target=target,
                target_type=target_type,
                context=context,
            )
            candidates.append(
                SkillCandidateSpec(
                    tool_name=skill.tool,
                    target=target,
                    target_type=target_type,
                    options=options if isinstance(options, dict) else {},
                    context=context,
                    reason=self._reason_for_candidate(skill, target_type, context),
                    preconditions=self._preconditions_for_candidate(skill, target_type),
                    stop_conditions=self._stop_conditions_for_candidate(skill, tool, target_type),
                )
            )
        return candidates

    def interpret_result(
        self,
        skill: SkillDefinition,
        normalized_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Enrich normalized tool output using skill rules."""
        interpreted = deepcopy(normalized_result)
        findings = interpreted.get("findings", [])
        if not isinstance(findings, list):
            findings = []
            interpreted["findings"] = findings
        self._apply_severity_mapping(skill, findings)

        breadcrumbs_delta = interpreted.get("breadcrumbs_delta", [])
        if not isinstance(breadcrumbs_delta, list):
            breadcrumbs_delta = []
            interpreted["breadcrumbs_delta"] = breadcrumbs_delta
        surface_delta = interpreted.get("surface_delta", {})
        if not isinstance(surface_delta, dict):
            surface_delta = {}
            interpreted["surface_delta"] = surface_delta

        for rule in skill.result_interpretation.output_extraction.get("surface_updates", []):
            if not rule.field or rule.field in surface_delta:
                continue
            value = self._extract_path({"result": interpreted, **interpreted}, rule.source)
            if value is not None:
                surface_delta[rule.field] = value

        if not breadcrumbs_delta:
            for rule in skill.result_interpretation.output_extraction.get("breadcrumbs", []):
                if rule.extractor == "nmap_http_services":
                    breadcrumbs_delta.extend(self._extract_nmap_http_services(interpreted))

        follow_up_hints = interpreted.get("follow_up_hints", [])
        if not isinstance(follow_up_hints, list):
            follow_up_hints = []
        interpreted["follow_up_hints"] = self._dedupe_strings(
            [*follow_up_hints, *self.resolve_follow_ups(skill, interpreted)]
        )
        metadata = interpreted.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        metadata.setdefault("skill_name", skill.name)
        metadata.setdefault("skill_version", skill.version)
        interpreted["metadata"] = metadata
        return interpreted

    def resolve_follow_ups(self, skill: SkillDefinition, result: dict[str, Any]) -> list[str]:
        """Resolve result-driven follow-up tool names from one skill."""
        return self._dedupe_strings(
            [
                tool_name
                for rule in self.match_result_follow_ups(skill, result)
                for tool_name in rule.trigger
            ]
        )

    def resolve_surface_follow_ups(self, skill: SkillDefinition, surface: dict[str, Any]) -> list[str]:
        """Resolve surface-driven follow-up tool names from one skill."""
        return self._dedupe_strings(
            [
                tool_name
                for rule in self.match_surface_follow_ups(skill, surface)
                for tool_name in rule.trigger
            ]
        )

    def match_result_follow_ups(self, skill: SkillDefinition, result: dict[str, Any]) -> list[SkillFollowUp]:
        """Return follow-up rules whose result conditions match."""
        matched: list[SkillFollowUp] = []
        for follow_up in skill.follow_up.values():
            rule_name = (follow_up.when_result or follow_up.condition or "").strip()
            if rule_name and self._result_condition_matches(rule_name, result):
                matched.append(follow_up)
        return matched

    def match_surface_follow_ups(self, skill: SkillDefinition, surface: dict[str, Any]) -> list[SkillFollowUp]:
        """Return follow-up rules whose surface conditions match."""
        matched: list[SkillFollowUp] = []
        for follow_up in skill.follow_up.values():
            if self._surface_condition_matches(follow_up.when_surface_contains, surface):
                matched.append(follow_up)
        return matched

    def _phase_matches(self, skill: SkillDefinition, phase: str) -> bool:
        if not phase:
            return True
        allowed = {item.strip() for item in skill.triggers.phase if item.strip()}
        return "any" in allowed or phase in allowed

    def _global_conditions_match(self, skill: SkillDefinition, planning_context: dict[str, Any]) -> bool:
        surface = planning_context.get("surface", {})
        surface = surface if isinstance(surface, dict) else {}
        for item in skill.triggers.when:
            if item.condition == "not_already_done":
                continue
            if item.condition == "service_port_matches":
                continue
            if item.condition == "has_scope_target" and planning_context.get("scope_items"):
                continue
            if item.condition == "has_http_origin" and planning_context.get("origins"):
                continue
            if item.condition == "has_https_origin" and any(
                str(origin).startswith("https://") for origin in planning_context.get("origins", [])
            ):
                continue
            if item.condition == "has_parameterized_endpoints" and planning_context.get("endpoint_params"):
                continue
            if item.condition == "has_nuclei_targets" and planning_context.get("nuclei_targets"):
                continue
            if item.condition == "has_tech_stack":
                tech_stack = surface.get("tech_stack", [])
                tech_components = surface.get("tech_components", [])
                if isinstance(tech_stack, list) and any(str(entry).strip() for entry in tech_stack):
                    continue
                if isinstance(tech_components, list) and any(
                    (
                        isinstance(entry, dict)
                        and (
                            str(entry.get("component", "")).strip()
                            or str(entry.get("name", "")).strip()
                        )
                    )
                    or (not isinstance(entry, dict) and str(entry).strip())
                    for entry in tech_components
                ):
                    continue
            if item.condition == "has_cve_candidates":
                candidates = surface.get("cve_candidates", [])
                if isinstance(candidates, list) and any(isinstance(entry, dict) for entry in candidates):
                    continue
            if item.condition == "rag_tool_recommended":
                raw_requested_tools = item.config.get("tools", [])
                if isinstance(raw_requested_tools, list):
                    requested_tools = [
                        str(candidate).strip().lower()
                        for candidate in raw_requested_tools
                        if str(candidate).strip()
                    ]
                elif str(raw_requested_tools).strip():
                    requested_tools = [str(raw_requested_tools).strip().lower()]
                else:
                    requested_tools = []
                fallback_tool = str(item.config.get("tool", "")).strip().lower()
                if fallback_tool and fallback_tool not in requested_tools:
                    requested_tools.append(fallback_tool)
                observed_tools = {
                    str(candidate).strip().lower()
                    for candidate in (
                        surface.get("rag_recommended_tools", [])
                        if isinstance(surface.get("rag_recommended_tools", []), list)
                        else [surface.get("rag_recommended_tools")]
                    )
                    if str(candidate).strip()
                }
                if requested_tools and observed_tools.intersection(requested_tools):
                    continue
            if item.condition == "authorization_confirmed":
                if self._bool_value(
                    planning_context.get("authorization_confirmed")
                    or surface.get("authorization_confirmed")
                    or item.config.get("value"),
                    default=False,
                ):
                    continue
            if item.condition == "approval_granted":
                if self._bool_value(
                    planning_context.get("approval_granted")
                    or surface.get("approval_granted")
                    or item.config.get("value"),
                    default=False,
                ):
                    continue
            if item.condition == "crawler_signal_present":
                history_tools = set(planning_context.get("history_tools", set()))
                if planning_context.get("surface_confirmed_endpoints") or (
                    set(skill.dependencies.tools) & self._CRAWLER_TOOLS
                    and history_tools & self._CRAWLER_TOOLS
                ):
                    continue
            return False
        return True

    def _target_conditions_match(
        self,
        skill: SkillDefinition,
        context: dict[str, Any],
        planning_context: dict[str, Any],
    ) -> bool:
        for item in skill.triggers.when:
            if item.condition != "crawler_signal_present":
                if item.condition == "service_port_matches":
                    if self._service_port_matches(context, item.config):
                        continue
                    return False
                continue
            history_tools = set(planning_context.get("history_tools", set()))
            if context.get("crawler_confirmed", False):
                continue
            if set(skill.dependencies.tools) & self._CRAWLER_TOOLS and history_tools & self._CRAWLER_TOOLS:
                continue
            return False
        return True

    def _service_port_matches(self, context: dict[str, Any], config: dict[str, Any]) -> bool:
        service = str(context.get("service", "")).strip().lower()
        try:
            port = int(context.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        allowed_services = {
            str(item).strip().lower()
            for item in config.get("services", [])
            if str(item).strip()
        }
        allowed_ports: set[int] = set()
        for item in config.get("ports", []):
            try:
                candidate = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= candidate <= 65535:
                allowed_ports.add(candidate)
        if not allowed_services and not allowed_ports:
            return False
        return service in allowed_services or port in allowed_ports

    def _preconditions_for_candidate(self, skill: SkillDefinition, target_type: str) -> list[str]:
        preconditions = ["target_in_scope", "not_already_done"]
        declared = {item.condition for item in skill.triggers.when}
        if target_type == "origin_url":
            preconditions.append("http_service_confirmed")
        elif target_type == "https_origin":
            preconditions.append("https_service_confirmed")
        elif target_type == "parameterized_endpoint":
            preconditions.append("params_available")
        elif target_type == "domain":
            preconditions.append("domain_scope_declared")
        elif target_type == "nuclei_target":
            preconditions.append("hints_detected")
        elif target_type == "tech_component":
            preconditions.append("tech_stack_available")
        elif target_type == "cve_candidate":
            preconditions.append("authorization_confirmed")
        if "crawler_signal_present" in declared or (set(skill.dependencies.tools) & self._CRAWLER_TOOLS):
            preconditions.append("crawler_signal_present")
        if "authorization_confirmed" in declared:
            preconditions.append("authorization_confirmed")
        if "approval_granted" in declared:
            preconditions.append("approval_granted")
        if "rag_tool_recommended" in declared:
            preconditions.append("rag_tool_recommended")
        return self._dedupe_strings(preconditions)

    def _stop_conditions_for_candidate(self, skill: SkillDefinition, tool: Any | None, target_type: str) -> list[str]:
        stop_conditions = ["budget_exhausted", "scope_violation_detected"]
        risk_level = str(getattr(tool, "risk_level", skill.risk.level)).strip().lower()
        if target_type == "parameterized_endpoint" or risk_level in {"medium", "high"}:
            stop_conditions.append("signal_detected")
        return self._dedupe_strings(stop_conditions)

    def _reason_for_candidate(
        self,
        skill: SkillDefinition,
        target_type: str,
        context: dict[str, Any],
    ) -> str:
        description = next((line.strip() for line in skill.description.splitlines() if line.strip()), skill.tool)
        if target_type == "parameterized_endpoint" and context.get("crawler_confirmed", False):
            return f"{description} on crawler-confirmed parameterized endpoint."
        if target_type == "parameterized_endpoint":
            return f"{description} on parameterized endpoint."
        if target_type == "nuclei_target":
            return f"{description} after fingerprint/path hints."
        if target_type == "host_seed":
            return f"{description} for initial service discovery."
        if target_type == "service_port":
            port = int(context.get("port", 0) or 0)
            service = str(context.get("service", "")).strip().lower() or "tcp"
            return f"{description} on discovered {service} service port {port}."
        if target_type == "tech_component":
            return f"{description} based on detected technology stack."
        if target_type == "cve_candidate":
            return f"{description} for discovered CVE candidates."
        return description

    def _render_option_template(
        self,
        value: Any,
        *,
        target: str,
        target_type: str,
        context: dict[str, Any],
    ) -> Any:
        if isinstance(value, dict):
            return {
                str(key): self._render_option_template(
                    item,
                    target=target,
                    target_type=target_type,
                    context=context,
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._render_option_template(
                    item,
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
                "$safe_only": self._bool_value(context.get("safe_only"), default=True),
                "$authorization_confirmed": self._bool_value(
                    context.get("authorization_confirmed"),
                    default=False,
                ),
                "$allow_high_risk": self._bool_value(context.get("allow_high_risk"), default=False),
                "$approval_granted": self._bool_value(context.get("approval_granted"), default=False),
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

    def _apply_severity_mapping(self, skill: SkillDefinition, findings: list[dict[str, Any]]) -> None:
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            haystack = self._finding_text(finding)
            for token, severity in skill.result_interpretation.severity_mapping.items():
                if token and token.lower() in haystack:
                    finding["severity"] = severity
            for rule in skill.result_interpretation.severity_escalation:
                if any(token.lower() in haystack for token in rule.if_finding_contains):
                    finding["severity"] = self._max_severity(
                        str(finding.get("severity", "info")).strip().lower(),
                        rule.escalate_to,
                    )

    def _result_condition_matches(self, rule_name: str, result: dict[str, Any]) -> bool:
        normalized = rule_name.strip().lower()
        findings = result.get("findings", [])
        findings = findings if isinstance(findings, list) else []
        if normalized == "findings_present":
            return bool(findings)
        if normalized == "clean_run":
            return str(result.get("status", "")).strip().lower() == "completed" and not findings
        if normalized == "findings_contain_sql_signal":
            return any(
                any(token in self._finding_text(item) for token in ("sql", "sqlstate", "syntax error", "cwe-89", "cwe_89"))
                for item in findings
                if isinstance(item, dict)
            )
        if normalized == "findings_contain_xss_signal":
            return any(
                any(token in self._finding_text(item) for token in ("xss", "cross-site scripting", "cwe-79", "cwe_79"))
                for item in findings
                if isinstance(item, dict)
            )
        if normalized == "http_service_found":
            breadcrumbs = result.get("breadcrumbs_delta", [])
            return any(str(item.get("data", "")).startswith("http://") for item in breadcrumbs if isinstance(item, dict)) or bool(self._extract_nmap_http_services(result, schemes={"http"}))
        if normalized == "https_service_found":
            breadcrumbs = result.get("breadcrumbs_delta", [])
            return any(str(item.get("data", "")).startswith("https://") for item in breadcrumbs if isinstance(item, dict)) or bool(self._extract_nmap_http_services(result, schemes={"https"}))
        if normalized == "login_form_found":
            surface_delta = result.get("surface_delta", {})
            return isinstance(surface_delta, dict) and bool(surface_delta.get("login_forms"))
        if normalized == "js_endpoints_found":
            surface_delta = result.get("surface_delta", {})
            return isinstance(surface_delta, dict) and bool(surface_delta.get("api_endpoints"))
        if normalized == "api_schema_found":
            surface_delta = result.get("surface_delta", {})
            return isinstance(surface_delta, dict) and bool(surface_delta.get("api_schema"))
        if normalized == "cookie_findings_present":
            return any("cookie" in self._finding_text(item) for item in findings if isinstance(item, dict))
        if normalized == "csp_findings_present":
            return any("content-security-policy" in self._finding_text(item) or "csp" in self._finding_text(item) for item in findings if isinstance(item, dict))
        if normalized == "cve_candidates_present":
            surface_delta = result.get("surface_delta", {})
            if isinstance(surface_delta, dict):
                candidates = surface_delta.get("cve_candidates", [])
                return isinstance(candidates, list) and any(isinstance(item, dict) for item in candidates)
            return False
        return False

    def _surface_condition_matches(self, conditions: dict[str, list[str]], surface: dict[str, Any]) -> bool:
        if not conditions:
            return False
        for field, expected_values in conditions.items():
            observed = surface.get(field)
            if isinstance(observed, list):
                observed_values: set[str] = set()
                for item in observed:
                    if isinstance(item, dict):
                        for candidate in (
                            item.get("component"),
                            item.get("name"),
                            item.get("kind"),
                            item.get("service"),
                            item.get("source_tool"),
                        ):
                            normalized = str(candidate).strip().lower()
                            if normalized:
                                observed_values.add(normalized)
                        continue
                    normalized = str(item).strip().lower()
                    if normalized:
                        observed_values.add(normalized)
            else:
                observed_values = {str(observed).strip().lower()} if str(observed).strip() else set()
            expected = {str(item).strip().lower() for item in expected_values if str(item).strip()}
            if not (observed_values & expected):
                return False
        return True

    def _extract_nmap_http_services(
        self,
        result: dict[str, Any],
        *,
        schemes: set[str] | None = None,
    ) -> list[dict[str, str]]:
        hosts = self._extract_path({"result": result, **result}, "payload.data.hosts")
        if not isinstance(hosts, list):
            return []
        extracted: list[dict[str, str]] = []
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
                    first_address = addresses[0]
                    if isinstance(first_address, dict):
                        host_token = str(first_address.get("addr", "")).strip()
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
                if not scheme or (schemes is not None and scheme not in schemes):
                    continue
                extracted.append({"type": "service", "data": f"{scheme}://{host_token}:{port}"})
        return extracted

    def _extract_path(self, payload: dict[str, Any], path: str) -> Any:
        normalized = str(path or "").strip()
        if not normalized:
            return None
        current: list[Any] = [payload]
        for raw_part in normalized.split("."):
            part = raw_part.strip()
            if not part:
                continue
            wants_many = part.endswith("[]")
            key = part[:-2] if wants_many else part
            next_values: list[Any] = []
            for item in current:
                if not isinstance(item, dict) or key not in item:
                    continue
                value = item.get(key)
                if wants_many:
                    if isinstance(value, list):
                        next_values.extend(value)
                    elif value is not None:
                        next_values.append(value)
                else:
                    next_values.append(value)
            current = next_values
            if not current:
                return None
        if len(current) == 1:
            return current[0]
        return current

    def _finding_text(self, finding: dict[str, Any]) -> str:
        evidence = finding.get("evidence", {})
        evidence_text = json.dumps(evidence, ensure_ascii=False, sort_keys=True) if isinstance(evidence, (dict, list)) else str(evidence)
        return " ".join(
            str(finding.get(key, ""))
            for key in ("id", "name", "title", "description", "category", "tool", "severity", "cwe_id")
        ).lower() + " " + evidence_text.lower()

    def _max_severity(self, left: str, right: str) -> str:
        return left if self._SEVERITY_ORDER.get(left, 0) >= self._SEVERITY_ORDER.get(right, 0) else right

    def _dedupe_strings(self, values: list[str]) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for item in values:
            normalized = str(item).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    def _url_origin(self, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    @staticmethod
    def _bool_value(value: Any, *, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        return bool(default)
