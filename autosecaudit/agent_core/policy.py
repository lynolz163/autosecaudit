"""Policy engine for validating agent action plans."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
import socket
from typing import Any, Callable, Iterable, Protocol, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from autosecaudit.agent_safety import (
    DEFAULT_AGENT_SAFETY_GRADE,
    SAFETY_GRADE_DENIED_TOOLS,
    normalize_safety_grade,
)
from .autonomy import (
    apply_autonomy_option_caps,
    autonomy_allowed_risk_levels,
    autonomy_denied_tools,
    normalize_autonomy_mode,
)
from .scheduler import Action


TERMINAL_HISTORY_STATUSES = {"completed", "failed", "error"}
DEFAULT_TOOL_WHITELIST = {
    "nmap_scan",
    "service_banner_probe",
    "tls_service_probe",
    "dns_zone_audit",
    "reverse_dns_probe",
    "ssh_auth_audit",
    "smtp_security_check",
    "mysql_handshake_probe",
    "postgres_handshake_probe",
    "redis_exposure_check",
    "memcached_exposure_check",
    "dynamic_crawl",
    "active_web_crawler",
    "js_endpoint_extractor",
    "tech_stack_fingerprint",
    "login_form_detector",
    "param_fuzzer",
    "sql_sanitization_audit",
    "xss_protection_audit",
    "passive_config_audit",
    "git_exposure_check",
    "source_map_detector",
    "error_page_analyzer",
    "api_schema_discovery",
    "page_vision_analyzer",
    "waf_detector",
    "security_txt_check",
    "cookie_security_audit",
    "csp_evaluator",
    "dirsearch_scan",
    "nuclei_exploit_check",
    "cors_misconfiguration",
    "ssl_expiry_check",
    "http_security_headers",
    "subdomain_enum_passive",
    "cve_lookup",
    "cve_verify",
    "rag_intel_lookup",
    "poc_sandbox_exec",
}


@dataclass(frozen=True)
class PolicyBlock:
    """Blocked action with reason for auditability."""

    action: Action
    reason: str


@dataclass(frozen=True)
class _ScopeModel:
    """Parsed scope representation."""

    domains: set[str]
    ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address]
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]


class ToolOptionSchema(Protocol):
    """Protocol for per-tool option schema validation."""

    tool_name: str

    def validate(self, action: Action, scope_model: _ScopeModel) -> str | None:
        """Validate one action against the tool's option schema."""
        ...


@dataclass(frozen=True)
class _CallableToolOptionSchema:
    """Simple callable-backed tool option schema."""

    tool_name: str
    validator: Callable[[Action, _ScopeModel], str | None]

    def validate(self, action: Action, scope_model: _ScopeModel) -> str | None:
        return self.validator(action, scope_model)


class PolicyEngine:
    """
    Hardened policy engine for action validation.

    Validation dimensions:
    - Tool whitelist
    - Target provenance
    - Scope fail-closed resolution checks
    - Budget constraints
    - Idempotency constraints
    - Per-tool option schema checks
    """

    def __init__(
        self,
        tool_whitelist: Sequence[str] | None = None,
        dns_resolver: Callable[[str], Sequence[str]] | None = None,
        safety_grade: str = DEFAULT_AGENT_SAFETY_GRADE,
    ) -> None:
        self._tool_whitelist = set(tool_whitelist or DEFAULT_TOOL_WHITELIST)
        self._dns_resolver = dns_resolver
        self._safety_grade = normalize_safety_grade(safety_grade)
        self._schemas: dict[str, ToolOptionSchema] = {}
        self._register_builtin_schemas()

    def validate_plan(
        self,
        plan: Any,
        state: dict[str, Any],
        tool_getter: Callable[[str], Any] | None = None,
    ) -> tuple[list[Action], list[PolicyBlock]]:
        """
        Validate planner output and return allowed + blocked actions.

        Args:
            plan: ActionPlan-like object (`plan.actions`) or dict with `actions`.
            state: Current agent state containing at least scope/history/budget.
        """
        raw_actions = self._extract_actions(plan)
        scope_items = [str(item).strip() for item in state.get("scope", []) if str(item).strip()]
        history = state.get("history", [])
        remaining_budget = int(max(0, int(float(state.get("budget_remaining", 0)))))

        scope_model = self._parse_scope(scope_items)
        safety_grade = normalize_safety_grade(state.get("safety_grade", self._safety_grade))
        allowed_actions: list[Action] = []
        blocked_actions: list[PolicyBlock] = []

        for index, raw in enumerate(raw_actions, start=1):
            action = self._coerce_action(raw, index=index)
            tool = self._resolve_tool(action.tool_name, tool_getter)

            action.target = self.normalize_target(action.tool_name, action.target)
            action.options = self._canonicalize_object(action.options)
            action.idempotency_key = self.compute_idempotency_key(
                action.tool_name,
                action.target,
                action.options,
            )

            reason = self.validate_tool_whitelist(action)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_safety_grade(action, safety_grade=safety_grade)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_autonomy_mode(action, state, tool=tool, safety_grade=safety_grade)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            action.options, _adjustments = self._apply_autonomy_caps(action, state, tool=tool, safety_grade=safety_grade)
            action.idempotency_key = self.compute_idempotency_key(
                action.tool_name,
                action.target,
                action.options,
            )

            reason = self.validate_target_provenance(action, state)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_scope_fail_closed(action, scope_model)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_idempotency(action, history)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_options_schema(action, scope_model, tool=tool)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_preconditions(action, state, tool=tool)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            reason = self.validate_budget(action, remaining_budget)
            if reason is not None:
                blocked_actions.append(PolicyBlock(action=action, reason=reason))
                continue

            allowed_actions.append(action)

        return allowed_actions, blocked_actions

    def validate_tool_whitelist(self, action: Action) -> str | None:
        """Validate action tool against strict whitelist."""
        if action.tool_name not in self._tool_whitelist:
            return "tool_not_in_whitelist"
        return None

    def validate_safety_grade(self, action: Action, *, safety_grade: str | None = None) -> str | None:
        """Apply coarse safety-grade deny lists before deeper validation."""
        denied = SAFETY_GRADE_DENIED_TOOLS.get(normalize_safety_grade(safety_grade or self._safety_grade), frozenset())
        if action.tool_name in denied:
            return f"safety_grade_denied:{normalize_safety_grade(safety_grade or self._safety_grade)}"
        return None

    def validate_autonomy_mode(
        self,
        action: Action,
        state: dict[str, Any],
        *,
        tool: Any | None = None,
        safety_grade: str | None = None,
    ) -> str | None:
        """Validate tool admission against the normalized autonomy profile."""
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        autonomy_mode = normalize_autonomy_mode(
            state.get("autonomy_mode", surface.get("autonomy_mode", None)),
            safety_grade=safety_grade or state.get("safety_grade", self._safety_grade),
        )
        disabled_tools = {
            str(item).strip()
            for item in surface.get("disabled_tools", [])
            if str(item).strip()
        } if isinstance(surface.get("disabled_tools", []), list) else set()
        if action.tool_name in disabled_tools:
            return "mission_disabled_tool"

        if action.tool_name in autonomy_denied_tools(autonomy_mode):
            return f"autonomy_mode_denied:{autonomy_mode}"

        risk_level = str(getattr(tool, "risk_level", "safe")).strip().lower() or "safe"
        if risk_level not in autonomy_allowed_risk_levels(autonomy_mode):
            return f"autonomy_risk_denied:{autonomy_mode}:{risk_level}"
        return None

    def validate_target_provenance(self, action: Action, state: dict[str, Any]) -> str | None:
        """
        Validate target provenance.

        Target must be derived from scope, breadcrumbs, or surface outputs.
        """
        provenance = self._collect_provenance_tokens(state)
        normalized_target = action.target
        target_host = self._extract_host_or_token(normalized_target)
        target_origin = self._origin_if_url(normalized_target)

        scope_model = self._parse_scope(
            [str(item).strip() for item in state.get("scope", []) if str(item).strip()]
        )

        if normalized_target in provenance:
            return None
        if target_origin and target_origin in provenance:
            return None
        if target_host and target_host in provenance:
            return None

        # Scope itself is a valid provenance source.
        if target_host and self._host_matches_scope_domain(target_host, scope_model.domains):
            return None
        if self._token_in_ip_scope(target_host, scope_model):
            return None

        return "target_not_from_scope_breadcrumbs_or_surface"

    def _apply_autonomy_caps(
        self,
        action: Action,
        state: dict[str, Any],
        *,
        tool: Any | None = None,
        safety_grade: str | None = None,
    ) -> tuple[dict[str, Any], list[str]]:
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        autonomy_mode = normalize_autonomy_mode(
            state.get("autonomy_mode", surface.get("autonomy_mode", None)),
            safety_grade=safety_grade or state.get("safety_grade", self._safety_grade),
        )
        return apply_autonomy_option_caps(
            tool_name=action.tool_name,
            options=action.options,
            autonomy_mode=autonomy_mode,
        )

    def validate_scope_fail_closed(self, action: Action, scope_model: _ScopeModel) -> str | None:
        """Validate target against scope and DNS fail-closed rule."""
        target_token = self._extract_host_or_token(action.target)
        if not target_token:
            return "target_parse_failed"

        try:
            ip_value = ipaddress.ip_address(target_token)
        except ValueError:
            ip_value = None

        if ip_value is not None:
            if ip_value in scope_model.ips:
                return None
            if any(ip_value in network for network in scope_model.networks):
                return None
            return "ip_target_out_of_scope"

        domain_allowed = self._host_matches_scope_domain(target_token, scope_model.domains)
        resolved_ips = self._resolve_domain_ips(target_token)
        if not resolved_ips:
            return "scope_fail_closed_resolution_failed"

        # If no explicit IP/network scope exists, domain-level scope is sufficient.
        if not scope_model.ips and not scope_model.networks:
            if domain_allowed:
                return None
            return "domain_not_in_scope"

        # With explicit IP/network scope, all resolved IPs must be inside scope.
        for resolved_ip_text in resolved_ips:
            try:
                resolved_ip = ipaddress.ip_address(resolved_ip_text)
            except ValueError:
                return "scope_fail_closed_invalid_resolved_ip"
            in_ip_scope = resolved_ip in scope_model.ips or any(
                resolved_ip in network for network in scope_model.networks
            )
            if not in_ip_scope:
                return "scope_fail_closed_resolved_ip_out_of_scope"
        return None

    def validate_budget(self, action: Action, remaining_budget: int) -> str | None:
        """Validate action cost against remaining budget rules."""
        if action.cost > remaining_budget:
            return "insufficient_budget"
        if remaining_budget < 10 and action.priority != 0:
            return "low_budget_priority_restriction"
        return None

    def validate_idempotency(self, action: Action, history: Iterable[dict[str, Any]]) -> str | None:
        """Block action if equivalent terminal history item exists."""
        for item in history:
            status = str(item.get("status", "")).strip().lower()
            if status not in TERMINAL_HISTORY_STATUSES:
                continue

            history_key = str(item.get("idempotency_key", "")).strip()
            if history_key and history_key == action.idempotency_key:
                return "idempotency_conflict_terminal_history"

            tool = str(item.get("tool", "")).strip()
            target = str(item.get("target", "")).strip()
            options = item.get("options", {})
            if tool and target and isinstance(options, dict):
                derived = self.compute_idempotency_key(
                    tool_name=tool,
                    target=self.normalize_target(tool, target),
                    options=options,
                )
                if derived == action.idempotency_key:
                    return "idempotency_conflict_terminal_history"
        return None

    def validate_preconditions(
        self,
        action: Action,
        state: dict[str, Any],
        *,
        tool: Any | None = None,
    ) -> str | None:
        """Validate declared preconditions and tool dependencies against current state."""
        scope_model = self._parse_scope(
            [str(item).strip() for item in state.get("scope", []) if str(item).strip()]
        )
        parsed = urlparse(action.target)
        feedback = state.get("feedback", {}) if isinstance(state.get("feedback", {}), dict) else {}
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}

        for condition in action.preconditions:
            if condition == "target_in_scope":
                if not self._target_in_scope(action.target, scope_model):
                    return "precondition_failed:target_in_scope"
            elif condition == "http_service_confirmed":
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    return "precondition_failed:http_service_confirmed"
            elif condition == "https_service_confirmed":
                if parsed.scheme != "https" or not parsed.netloc:
                    return "precondition_failed:https_service_confirmed"
            elif condition == "params_available":
                params = action.options.get("params")
                if not isinstance(params, dict) or not params:
                    return "precondition_failed:params_available"
            elif condition == "crawler_signal_present":
                if not self._has_crawler_signal(action.target, state):
                    return "precondition_failed:crawler_signal_present"
            elif condition == "hints_detected":
                if not self._has_hints(surface, feedback, action.tool_name):
                    return "precondition_failed:hints_detected"
            elif condition == "tech_stack_available":
                tech_stack = surface.get("tech_stack", []) if isinstance(surface, dict) else []
                if not isinstance(tech_stack, list) or not any(str(item).strip() for item in tech_stack):
                    return "precondition_failed:tech_stack_available"
            elif condition == "authorization_confirmed":
                authorization_confirmed = self._coerce_bool(
                    action.options.get("authorization_confirmed", None),
                    default=self._state_runtime_bool(
                        state,
                        top_key="authorization_confirmed",
                        surface_key="authorization_confirmed",
                        default=False,
                    ),
                )
                if not authorization_confirmed:
                    return "precondition_failed:authorization_confirmed"
            elif condition == "approval_granted":
                approval_granted = self._coerce_bool(
                    action.options.get("approval_granted", None),
                    default=self._state_runtime_bool(
                        state,
                        top_key="approval_granted",
                        surface_key="approval_granted",
                        default=False,
                    ),
                )
                if not approval_granted:
                    return "precondition_failed:approval_granted"
            elif condition == "domain_scope_declared":
                token = self._extract_host_or_token(action.target)
                if not token or not scope_model.domains:
                    return "precondition_failed:domain_scope_declared"
                try:
                    ipaddress.ip_address(token)
                    return "precondition_failed:domain_scope_declared"
                except ValueError:
                    if not self._host_matches_scope_domain(token, scope_model.domains):
                        return "precondition_failed:domain_scope_declared"
            elif condition == "not_already_done":
                reason = self.validate_idempotency(action, state.get("history", []))
                if reason is not None:
                    return "precondition_failed:not_already_done"

        if action.tool_name == "cve_verify":
            authorization_confirmed = self._coerce_bool(
                action.options.get("authorization_confirmed", None),
                default=self._state_runtime_bool(
                    state,
                    top_key="authorization_confirmed",
                    surface_key="authorization_confirmed",
                    default=False,
                ),
            )
            if not authorization_confirmed:
                return "precondition_failed:authorization_confirmed"
            allow_high_risk = self._coerce_bool(
                action.options.get("allow_high_risk", None),
                default=self._state_runtime_bool(
                    state,
                    top_key="cve_allow_high_risk",
                    surface_key="allow_high_risk",
                    default=False,
                ),
            )
            safety_grade = normalize_safety_grade(state.get("safety_grade", self._safety_grade))
            if allow_high_risk and safety_grade != "aggressive":
                return "precondition_failed:allow_high_risk_requires_aggressive_grade"
        if action.tool_name == "poc_sandbox_exec":
            authorization_confirmed = self._coerce_bool(
                action.options.get("authorization_confirmed", None),
                default=self._state_runtime_bool(
                    state,
                    top_key="authorization_confirmed",
                    surface_key="authorization_confirmed",
                    default=False,
                ),
            )
            if not authorization_confirmed:
                return "precondition_failed:authorization_confirmed"
            approval_granted = self._coerce_bool(
                action.options.get("approval_granted", None),
                default=self._state_runtime_bool(
                    state,
                    top_key="approval_granted",
                    surface_key="approval_granted",
                    default=False,
                ),
            )
            if not approval_granted:
                return "precondition_failed:approval_granted"
            safety_grade = normalize_safety_grade(state.get("safety_grade", self._safety_grade))
            if safety_grade != "aggressive":
                return "precondition_failed:poc_requires_aggressive_grade"

        depends_on = getattr(tool, "depends_on", []) if tool is not None else []
        for dependency in depends_on:
            if not self._dependency_satisfied(str(dependency), action, state):
                return f"dependency_unsatisfied:{dependency}"
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

    def _state_runtime_bool(
        self,
        state: dict[str, Any],
        *,
        top_key: str,
        surface_key: str,
        default: bool,
    ) -> bool:
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        if top_key in state:
            return self._coerce_bool(state.get(top_key), default=default)
        if surface_key in surface:
            return self._coerce_bool(surface.get(surface_key), default=default)
        return bool(default)

    def register_schema(self, schema: ToolOptionSchema) -> None:
        """Register or replace one tool option schema."""
        tool_name = str(getattr(schema, "tool_name", "")).strip()
        if not tool_name:
            raise ValueError("schema.tool_name must not be empty")
        self._schemas[tool_name] = schema

    def _register_builtin_schemas(self) -> None:
        """Register built-in option schemas."""
        for tool_name, validator in (
            ("passive_config_audit", self._validate_passive_config_schema),
            ("dynamic_crawl", self._validate_dynamic_crawl_schema),
            ("active_web_crawler", self._validate_active_web_crawler_schema),
            ("dirsearch_scan", self._validate_dirsearch_schema),
            ("js_endpoint_extractor", self._validate_origin_only_http_schema),
            ("tech_stack_fingerprint", self._validate_origin_only_http_schema),
            ("login_form_detector", self._validate_origin_only_http_schema),
            ("sql_sanitization_audit", self._validate_input_audit_schema),
            ("xss_protection_audit", self._validate_input_audit_schema),
            ("param_fuzzer", self._validate_param_fuzzer_schema),
            ("nmap_scan", self._validate_nmap_schema),
            ("nuclei_exploit_check", self._validate_nuclei_schema),
            ("cors_misconfiguration", self._validate_origin_only_http_schema),
            ("http_security_headers", self._validate_origin_only_http_schema),
            ("ssl_expiry_check", self._validate_ssl_expiry_schema),
            ("subdomain_enum_passive", self._validate_subdomain_enum_schema),
            ("cve_lookup", self._validate_cve_lookup_schema),
            ("cve_verify", self._validate_cve_verify_schema),
        ):
            self.register_schema(_CallableToolOptionSchema(tool_name=tool_name, validator=validator))

    def validate_options_schema(
        self,
        action: Action,
        scope_model: _ScopeModel,
        tool: Any | None = None,
    ) -> str | None:
        """Validate per-tool option schema and safety bounds."""
        if tool is not None:
            reason = self._validate_tool_metadata_schema(action, scope_model, tool)
            if reason is not None or getattr(tool, "input_schema", {}):
                return reason
        schema = self._schemas.get(action.tool_name)
        if schema is None:
            return None
        return schema.validate(action, scope_model)

    def _validate_tool_metadata_schema(
        self,
        action: Action,
        scope_model: _ScopeModel,
        tool: Any,
    ) -> str | None:
        schema = getattr(tool, "input_schema", {})
        if not isinstance(schema, dict) or not schema:
            return None

        reason = self._validate_schema_target_mode(
            action=action,
            scope_model=scope_model,
            schema=schema,
        )
        if reason is not None:
            return reason

        return self._validate_schema_object(
            value=action.options,
            schema=schema,
            field_name="options",
            scope_model=scope_model,
            tool_name=action.tool_name,
        )

    def _validate_schema_target_mode(
        self,
        *,
        action: Action,
        scope_model: _ScopeModel,
        schema: dict[str, Any],
    ) -> str | None:
        target_mode = str(schema.get("target_mode", "")).strip().lower()
        if not target_mode:
            return None

        error_code = str(schema.get("target_error", "")).strip() or f"{action.tool_name}_target_invalid"
        parsed = urlparse(action.target)
        token = self._extract_host_or_token(action.target)

        if target_mode == "origin_http":
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return error_code
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                return error_code
            return None

        if target_mode == "http_url":
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return error_code
            return None

        if target_mode == "https_origin_or_host":
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                return None
            if token:
                return None
            return error_code

        if target_mode == "domain":
            if not token or "/" in token:
                return error_code
            try:
                ipaddress.ip_address(token)
                return error_code
            except ValueError:
                if scope_model.domains and not self._host_matches_scope_domain(token, scope_model.domains):
                    return error_code
                return None

        if target_mode == "host":
            if token:
                return None
            return error_code
        return None

    def _validate_schema_object(
        self,
        *,
        value: Any,
        schema: dict[str, Any],
        field_name: str,
        scope_model: _ScopeModel,
        tool_name: str,
    ) -> str | None:
        if not isinstance(value, dict):
            return str(schema.get("type_error", "")).strip() or f"{tool_name}_{field_name}_must_be_object"

        min_properties = schema.get("min_properties")
        max_properties = schema.get("max_properties")
        if min_properties is not None and len(value) < int(min_properties):
            return str(schema.get("error", "")).strip() or f"{tool_name}_{field_name}_object_invalid"
        if max_properties is not None and len(value) > int(max_properties):
            return str(schema.get("error", "")).strip() or f"{tool_name}_{field_name}_object_invalid"

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        required = schema.get("required", [])
        if isinstance(required, list):
            for item in required:
                key = str(item).strip()
                if key and key not in value:
                    return (
                        str(schema.get("required_error", "")).strip()
                        or f"{tool_name}_{field_name}_missing_required:{key}"
                    )

        additional_properties = bool(schema.get("additional_properties", True))
        unknown_keys = set(value.keys()) - set(properties.keys())
        if not additional_properties and unknown_keys:
            return str(schema.get("additional_properties_error", "")).strip() or f"{tool_name}_{field_name}_invalid_keys"

        for key, prop_schema in properties.items():
            if key not in value:
                continue
            reason = self._validate_schema_value(
                value=value[key],
                schema=prop_schema if isinstance(prop_schema, dict) else {},
                field_name=f"{field_name}.{key}",
                scope_model=scope_model,
                tool_name=tool_name,
            )
            if reason is not None:
                return reason

        key_schema = schema.get("key_schema", {})
        value_schema = schema.get("value_schema", {})
        for key, item_value in value.items():
            if key in properties:
                continue
            if isinstance(key_schema, dict) and key_schema:
                reason = self._validate_schema_value(
                    value=str(key),
                    schema=key_schema,
                    field_name=f"{field_name}.key",
                    scope_model=scope_model,
                    tool_name=tool_name,
                )
                if reason is not None:
                    return reason
            if isinstance(value_schema, dict) and value_schema:
                reason = self._validate_schema_value(
                    value=item_value,
                    schema=value_schema,
                    field_name=f"{field_name}.{key}",
                    scope_model=scope_model,
                    tool_name=tool_name,
                )
                if reason is not None:
                    return reason

        return None

    def _validate_schema_value(
        self,
        *,
        value: Any,
        schema: dict[str, Any],
        field_name: str,
        scope_model: _ScopeModel,
        tool_name: str,
    ) -> str | None:
        if not schema:
            return None

        error_code = str(schema.get("error", "")).strip()
        value_type = str(schema.get("type", "")).strip().lower()

        if value_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                return error_code or f"{tool_name}_{field_name}_must_be_integer"
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if minimum is not None and int(value) < int(minimum):
                return error_code or f"{tool_name}_{field_name}_out_of_bounds"
            if maximum is not None and int(value) > int(maximum):
                return error_code or f"{tool_name}_{field_name}_out_of_bounds"
            return None

        if value_type == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return error_code or f"{tool_name}_{field_name}_must_be_number"
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if minimum is not None and float(value) < float(minimum):
                return error_code or f"{tool_name}_{field_name}_out_of_bounds"
            if maximum is not None and float(value) > float(maximum):
                return error_code or f"{tool_name}_{field_name}_out_of_bounds"
            return None

        if value_type == "boolean":
            if not isinstance(value, bool):
                return error_code or f"{tool_name}_{field_name}_must_be_bool"
            return None

        if value_type == "string":
            if not isinstance(value, str):
                return error_code or f"{tool_name}_{field_name}_must_be_string"
            if not value.strip() and not bool(schema.get("allow_blank", False)):
                return error_code or f"{tool_name}_{field_name}_empty_string"
            min_length = schema.get("min_length")
            max_length = schema.get("max_length")
            if min_length is not None and len(value) < int(min_length):
                return error_code or f"{tool_name}_{field_name}_length_invalid"
            if max_length is not None and len(value) > int(max_length):
                return error_code or f"{tool_name}_{field_name}_length_invalid"
            pattern = schema.get("pattern")
            if pattern and not re.fullmatch(str(pattern), value):
                return error_code or f"{tool_name}_{field_name}_invalid_format"
            enum = schema.get("enum")
            if isinstance(enum, list) and value not in [str(item) for item in enum]:
                return error_code or f"{tool_name}_{field_name}_invalid"
            format_name = str(schema.get("format", "")).strip().lower()
            if format_name:
                reason = self._validate_schema_format(
                    value=value,
                    format_name=format_name,
                    field_name=field_name,
                    scope_model=scope_model,
                    tool_name=tool_name,
                    error_code=error_code,
                )
                if reason is not None:
                    return reason
            return None

        if value_type == "scalar":
            if isinstance(value, (dict, list, tuple)):
                return error_code or f"{tool_name}_{field_name}_must_be_scalar"
            text_value = str(value)
            min_length = schema.get("min_length")
            max_length = schema.get("max_length")
            if min_length is not None and len(text_value) < int(min_length):
                return error_code or f"{tool_name}_{field_name}_length_invalid"
            if max_length is not None and len(text_value) > int(max_length):
                return error_code or f"{tool_name}_{field_name}_length_invalid"
            pattern = schema.get("pattern")
            if pattern and not re.fullmatch(str(pattern), text_value):
                return error_code or f"{tool_name}_{field_name}_invalid_format"
            return None

        if value_type == "array":
            if not isinstance(value, list):
                return error_code or f"{tool_name}_{field_name}_must_be_list"
            min_items = schema.get("min_items")
            max_items = schema.get("max_items")
            if min_items is not None and len(value) < int(min_items):
                return error_code or f"{tool_name}_{field_name}_list_invalid"
            if max_items is not None and len(value) > int(max_items):
                return error_code or f"{tool_name}_{field_name}_list_invalid"
            item_schema = schema.get("items", {})
            for item in value:
                reason = self._validate_schema_value(
                    value=item,
                    schema=item_schema if isinstance(item_schema, dict) else {},
                    field_name=field_name,
                    scope_model=scope_model,
                    tool_name=tool_name,
                )
                if reason is not None:
                    return reason
            return None

        if value_type == "object":
            return self._validate_schema_object(
                value=value,
                schema=schema,
                field_name=field_name,
                scope_model=scope_model,
                tool_name=tool_name,
            )

        return None

    def _validate_schema_format(
        self,
        *,
        value: str,
        format_name: str,
        field_name: str,
        scope_model: _ScopeModel,
        tool_name: str,
        error_code: str,
    ) -> str | None:
        if format_name == "scope_domain":
            candidate = value.strip().lower().lstrip(".")
            if not candidate or not self._host_matches_scope_domain(candidate, scope_model.domains):
                return error_code or f"{tool_name}_{field_name}_out_of_scope"
            return None

        if format_name == "safe_shell_text":
            if self._contains_dangerous_shell_chars(value):
                return error_code or f"{tool_name}_{field_name}_contains_dangerous_chars"
            return None

        if format_name == "extension_token":
            if not re.fullmatch(r"[A-Za-z0-9]{1,10}", value.strip()):
                return error_code or f"{tool_name}_{field_name}_invalid_format"
            return None

        return None

    def _resolve_tool(self, tool_name: str, tool_getter: Callable[[str], Any] | None) -> Any | None:
        if tool_getter is None:
            return None
        try:
            return tool_getter(tool_name)
        except Exception:  # noqa: BLE001
            return None

    def _has_crawler_signal(self, target: str, state: dict[str, Any]) -> bool:
        normalized_target = self.normalize_target("dynamic_crawl", target)
        surface = state.get("surface", {})
        if isinstance(surface, dict):
            discovered = {
                self.normalize_target("dynamic_crawl", str(item))
                for item in surface.get("discovered_urls", [])
                if str(item).strip()
            }
            api_endpoints = {
                self.normalize_target("dynamic_crawl", str(item.get("url", "")))
                for item in surface.get("api_endpoints", [])
                if isinstance(item, dict) and str(item.get("url", "")).strip()
            }
            parameter_origins = {
                self.normalize_target("dynamic_crawl", str(origin))
                for origins in surface.get("parameter_origins", {}).values()
                if isinstance(origins, list)
                for origin in origins
                if str(origin).strip()
            }
            if normalized_target in discovered or normalized_target in api_endpoints or normalized_target in parameter_origins:
                return True

        for entry in state.get("breadcrumbs", []):
            if not isinstance(entry, dict):
                continue
            candidate = self.normalize_target("dynamic_crawl", str(entry.get("data", "")))
            if candidate and candidate == normalized_target:
                return True
        return False

    def _has_hints(self, surface: dict[str, Any], feedback: dict[str, Any], tool_name: str) -> bool:
        if any(
            surface.get(key)
            for key in (
                "tech_stack",
                "config_exposures",
                "discovered_urls",
                "api_endpoints",
                "http_security_headers",
                "tls_metadata",
            )
        ):
            return True
        follow_up_tools = {str(item).strip() for item in feedback.get("follow_up_tools", []) if str(item).strip()}
        return tool_name in follow_up_tools or bool(follow_up_tools)

    def _dependency_satisfied(self, dependency: str, action: Action, state: dict[str, Any]) -> bool:
        normalized_dependency = str(dependency).strip()
        if not normalized_dependency:
            return True

        if normalized_dependency in {"dynamic_crawl", "active_web_crawler", "js_endpoint_extractor", "api_schema_discovery"}:
            if self._has_crawler_signal(action.target, state):
                return True

        action_host = self._extract_host_or_token(action.target)
        action_origin = self._origin_if_url(action.target)
        for entry in state.get("history", []):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("status", "")).strip().lower() not in TERMINAL_HISTORY_STATUSES:
                continue
            if str(entry.get("tool", "")).strip() != normalized_dependency:
                continue
            candidate_target = str(entry.get("target", "")).strip()
            if not candidate_target:
                return True
            if candidate_target == action.target:
                return True
            if action_origin and self._origin_if_url(candidate_target) == action_origin:
                return True
            if action_host and self._extract_host_or_token(candidate_target) == action_host:
                return True
        return False

    def _validate_passive_config_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        parsed = urlparse(action.target)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return "passive_config_requires_base_origin_only"
        allowed_keys = {"request_timeout_seconds", "max_total_seconds", "max_paths"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "passive_config_options_invalid_keys"
        if "request_timeout_seconds" in action.options:
            value = action.options["request_timeout_seconds"]
            if not isinstance(value, (int, float)) or value < 1 or value > 8:
                return "passive_config_request_timeout_out_of_bounds"
        if "max_total_seconds" in action.options:
            value = action.options["max_total_seconds"]
            if not isinstance(value, (int, float)) or value < 3 or value > 60:
                return "passive_config_total_timeout_out_of_bounds"
        if "max_paths" in action.options:
            value = action.options["max_paths"]
            if not isinstance(value, int) or value < 1 or value > 15:
                return "passive_config_max_paths_out_of_bounds"
        return None

    def _validate_dynamic_crawl_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"max_depth", "allow_domain"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "dynamic_crawl_options_invalid_keys"
        max_depth = action.options.get("max_depth")
        if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 5:
            return "dynamic_crawl_max_depth_out_of_bounds"
        allow_domain = action.options.get("allow_domain")
        if not isinstance(allow_domain, list) or not allow_domain:
            return "dynamic_crawl_allow_domain_required"
        for item in allow_domain:
            if not isinstance(item, str) or not item.strip():
                return "dynamic_crawl_allow_domain_invalid"
            candidate = item.strip().lower().lstrip(".")
            if not self._host_matches_scope_domain(candidate, scope_model.domains):
                return "dynamic_crawl_allow_domain_out_of_scope"
        return None

    def _validate_active_web_crawler_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"max_depth", "allow_domain", "limit"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "active_web_crawler_options_invalid_keys"
        reason = self._validate_dynamic_crawl_schema(
            Action(
                action_id=action.action_id,
                tool_name=action.tool_name,
                target=action.target,
                options={
                    "max_depth": action.options.get("max_depth"),
                    "allow_domain": action.options.get("allow_domain"),
                },
                priority=action.priority,
                cost=action.cost,
                capabilities=action.capabilities,
                idempotency_key=action.idempotency_key,
                reason=action.reason,
                preconditions=action.preconditions,
                stop_conditions=action.stop_conditions,
            ),
            scope_model,
        )
        if reason is not None:
            return reason.replace("dynamic_crawl", "active_web_crawler")
        limit = action.options.get("limit")
        if not isinstance(limit, int) or limit < 1 or limit > 200:
            return "active_web_crawler_limit_out_of_bounds"
        return None

    def _validate_dirsearch_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        parsed = urlparse(action.target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "dirsearch_target_must_be_http_url"
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return "dirsearch_requires_base_origin_only"

        allowed_keys = {"wordlist", "extensions", "threads", "timeout_seconds", "max_results"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "dirsearch_options_invalid_keys"

        if "threads" in action.options:
            threads_value = action.options["threads"]
            if not isinstance(threads_value, int) or threads_value < 1 or threads_value > 10:
                return "dirsearch_threads_out_of_bounds"

        if "timeout_seconds" in action.options:
            timeout_value = action.options["timeout_seconds"]
            if not isinstance(timeout_value, (int, float)) or timeout_value < 1 or timeout_value > 900:
                return "dirsearch_timeout_out_of_bounds"

        if "max_results" in action.options:
            max_results = action.options["max_results"]
            if not isinstance(max_results, int) or max_results < 1 or max_results > 2000:
                return "dirsearch_max_results_out_of_bounds"

        for key in ("wordlist", "extensions"):
            if key not in action.options:
                continue
            value = action.options[key]
            if isinstance(value, list):
                if not value:
                    return "dirsearch_option_list_empty"
                for item in value:
                    if not isinstance(item, str) or not item.strip():
                        return "dirsearch_option_list_invalid_item"
                    if self._contains_dangerous_shell_chars(item):
                        return "dirsearch_option_contains_dangerous_chars"
            elif isinstance(value, str):
                if not value.strip():
                    return "dirsearch_option_empty_string"
                if self._contains_dangerous_shell_chars(value):
                    return "dirsearch_option_contains_dangerous_chars"
            else:
                return "dirsearch_option_invalid_type"

        if "extensions" in action.options:
            extensions_value = action.options["extensions"]
            values = (
                [item.strip() for item in extensions_value.split(",") if item.strip()]
                if isinstance(extensions_value, str)
                else [str(item).strip() for item in extensions_value]
            )
            if any(not re.fullmatch(r"[A-Za-z0-9]{1,10}", item) for item in values):
                return "dirsearch_extensions_invalid_format"

        return None

    def _validate_input_audit_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"method", "params"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return f"{action.tool_name}_options_invalid_keys"
        method = str(action.options.get("method", "GET")).strip().upper()
        if method != "GET":
            return f"{action.tool_name}_method_must_be_get"
        params = action.options.get("params", {})
        if not isinstance(params, dict):
            return f"{action.tool_name}_params_must_be_dict"
        if len(params) > 30:
            return f"{action.tool_name}_too_many_params"
        for key, value in params.items():
            if not isinstance(key, str) or not key.strip():
                return f"{action.tool_name}_invalid_param_key"
            if len(key) > 128:
                return f"{action.tool_name}_param_key_too_long"
            value_text = str(value)
            if len(value_text) > 2048:
                return f"{action.tool_name}_param_value_too_long"
        return None

    def _validate_param_fuzzer_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"method", "params", "mode", "max_probes"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "param_fuzzer_options_invalid_keys"
        method = str(action.options.get("method", "GET")).strip().upper()
        if method != "GET":
            return "param_fuzzer_method_must_be_get"
        mode = str(action.options.get("mode", "lightweight")).strip().lower()
        if mode != "lightweight":
            return "param_fuzzer_mode_invalid"
        max_probes = action.options.get("max_probes", 6)
        if not isinstance(max_probes, int) or max_probes < 1 or max_probes > 20:
            return "param_fuzzer_max_probes_out_of_bounds"
        params = action.options.get("params", {})
        if not isinstance(params, dict) or not params:
            return "param_fuzzer_params_must_be_non_empty_dict"
        if len(params) > 20:
            return "param_fuzzer_too_many_params"
        for key, value in params.items():
            if not isinstance(key, str) or not key.strip():
                return "param_fuzzer_invalid_param_key"
            if len(str(value)) > 1024:
                return "param_fuzzer_param_value_too_long"
        return None

    def _validate_nmap_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"ports", "scan_profile", "version_detection", "timeout_seconds"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "nmap_scan_options_invalid_keys"
        for key in action.options:
            lowered = key.lower()
            if any(token in lowered for token in ("script", "exploit", "brute", "dos")):
                return "nmap_scan_disallowed_option_key"
        for value in action.options.values():
            lowered_value = str(value).lower()
            if any(token in lowered_value for token in ("script", "exploit", "brute", "dos")):
                return "nmap_scan_disallowed_option_value"
        ports = action.options.get("ports", "top-1000")
        if not isinstance(ports, str):
            return "nmap_scan_ports_must_be_string"
        normalized_ports = ports.strip().lower()
        if normalized_ports not in {"top-100", "top-1000"} and not re.fullmatch(r"[0-9,\-]+", normalized_ports):
            return "nmap_scan_ports_invalid_format"
        if "scan_profile" in action.options:
            scan_profile = str(action.options["scan_profile"]).strip().lower()
            if scan_profile not in {"default", "conservative_service_discovery"}:
                return "nmap_scan_invalid_scan_profile"
        if "version_detection" in action.options and not isinstance(action.options["version_detection"], bool):
            return "nmap_scan_version_detection_must_be_bool"
        if "timeout_seconds" in action.options:
            timeout_value = action.options["timeout_seconds"]
            if not isinstance(timeout_value, (int, float)) or timeout_value < 1 or timeout_value > 600:
                return "nmap_scan_timeout_out_of_bounds"
        return None

    def _validate_nuclei_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"templates", "severity", "template_id", "timeout_seconds"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "nuclei_options_invalid_keys"

        blocked_tokens = ("cmd", "output", "config", "proxy")
        for key in action.options:
            lowered = str(key).lower()
            if lowered in {"o"} or any(token in lowered for token in blocked_tokens):
                return "nuclei_disallowed_option_key"

        if "timeout_seconds" in action.options:
            timeout_value = action.options["timeout_seconds"]
            if not isinstance(timeout_value, (int, float)) or timeout_value < 1 or timeout_value > 900:
                return "nuclei_timeout_out_of_bounds"

        for key in ("templates", "severity", "template_id"):
            if key not in action.options:
                continue
            value = action.options[key]
            if isinstance(value, list):
                if not value:
                    return "nuclei_option_list_empty"
                for item in value:
                    if not isinstance(item, str) or not item.strip():
                        return "nuclei_option_list_invalid_item"
                    if self._contains_dangerous_shell_chars(item):
                        return "nuclei_option_contains_dangerous_chars"
            elif isinstance(value, str):
                if not value.strip():
                    return "nuclei_option_empty_string"
                if self._contains_dangerous_shell_chars(value):
                    return "nuclei_option_contains_dangerous_chars"
            else:
                return "nuclei_option_invalid_type"

        if "severity" in action.options:
            raw_values = action.options["severity"]
            if isinstance(raw_values, str):
                severity_values = [raw_values.lower()]
            else:
                severity_values = [str(item).lower() for item in raw_values]
            allowed_severity = {"info", "low", "medium"}
            if any(item not in allowed_severity for item in severity_values):
                return "nuclei_invalid_severity"

        return None

    def _validate_origin_only_http_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        parsed = urlparse(action.target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return f"{action.tool_name}_target_must_be_http_url"
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return f"{action.tool_name}_requires_base_origin_only"
        if action.options:
            return f"{action.tool_name}_options_must_be_empty"
        return None

    def _validate_ssl_expiry_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        if action.options:
            return "ssl_expiry_check_options_must_be_empty"
        target = str(action.target).strip()
        parsed = urlparse(target)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return None
        token = self._extract_host_or_token(target)
        if not token:
            return "ssl_expiry_check_target_invalid"
        return None

    def _validate_subdomain_enum_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        if action.options:
            allowed_keys = {"max_results"}
            if not set(action.options.keys()).issubset(allowed_keys):
                return "subdomain_enum_passive_options_invalid_keys"
            if "max_results" in action.options:
                max_results = action.options["max_results"]
                if not isinstance(max_results, int) or max_results < 1 or max_results > 500:
                    return "subdomain_enum_passive_max_results_out_of_bounds"
        target = self._extract_host_or_token(action.target)
        if not target or "/" in target:
            return "subdomain_enum_passive_target_invalid"
        try:
            ipaddress.ip_address(target)
            return "subdomain_enum_passive_target_must_be_domain"
        except ValueError:
            return None

    def _validate_cve_lookup_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {"component", "version", "max_results", "severity"}
        if not set(action.options.keys()).issubset(allowed_keys):
            return "cve_lookup_options_invalid_keys"
        component = str(action.options.get("component", "")).strip()
        if not component:
            return "cve_lookup_component_missing"
        if len(component) > 128:
            return "cve_lookup_component_invalid"
        version = action.options.get("version")
        if version is not None and len(str(version).strip()) > 64:
            return "cve_lookup_version_invalid"
        max_results = action.options.get("max_results", 10)
        if not isinstance(max_results, int) or max_results < 1 or max_results > 50:
            return "cve_lookup_max_results_invalid"
        severity = str(action.options.get("severity", "medium")).strip().lower()
        if severity not in {"critical", "high", "medium", "low"}:
            return "cve_lookup_severity_invalid"
        return None

    def _validate_cve_verify_schema(self, action: Action, scope_model: _ScopeModel) -> str | None:
        allowed_keys = {
            "cve_ids",
            "safe_only",
            "authorization_confirmed",
            "allow_high_risk",
            "timeout_seconds",
            "safety_grade",
        }
        if not set(action.options.keys()).issubset(allowed_keys):
            return "cve_verify_options_invalid_keys"
        cve_ids = action.options.get("cve_ids")
        if not isinstance(cve_ids, list) or not cve_ids:
            return "cve_verify_invalid_cve_id"
        seen: set[str] = set()
        for item in cve_ids:
            token = str(item).strip().upper()
            if not token or token in seen:
                continue
            seen.add(token)
            if not re.fullmatch(r"CVE-\d{4}-\d{4,8}", token):
                return "cve_verify_invalid_cve_id"
        if not seen:
            return "cve_verify_invalid_cve_id"
        if "safe_only" in action.options and not isinstance(action.options.get("safe_only"), bool):
            return "cve_verify_safe_only_must_be_bool"
        if "authorization_confirmed" in action.options and not isinstance(
            action.options.get("authorization_confirmed"),
            bool,
        ):
            return "cve_verify_authorization_confirmed_must_be_bool"
        if "allow_high_risk" in action.options and not isinstance(action.options.get("allow_high_risk"), bool):
            return "cve_verify_allow_high_risk_must_be_bool"
        if "timeout_seconds" in action.options:
            timeout_seconds = action.options.get("timeout_seconds")
            if not isinstance(timeout_seconds, (int, float)) or timeout_seconds < 1 or timeout_seconds > 900:
                return "cve_verify_timeout_out_of_bounds"
        if "safety_grade" in action.options:
            grade = normalize_safety_grade(action.options.get("safety_grade"))
            if grade not in {"conservative", "balanced", "aggressive"}:
                return "cve_verify_safety_grade_invalid"
        return None

    @staticmethod
    def _contains_dangerous_shell_chars(value: Any) -> bool:
        text = str(value)
        return any(token in text for token in (";", "\n", "\r", "&&", "||", "|", "`", "$("))

    def normalize_target(self, tool_name: str, target: str) -> str:
        """Normalize targets for deterministic policy and idempotency checks."""
        raw = str(target).strip()
        if not raw:
            return ""
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

        token = self._extract_host_or_token(raw)
        return token.lower()

    def canonical_options_json(self, options: dict[str, Any]) -> str:
        """Render canonical JSON for deterministic idempotency calculation."""
        canonical = self._canonicalize_object(options)
        return json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def compute_idempotency_key(self, tool_name: str, target: str, options: dict[str, Any]) -> str:
        """Compute sha256 idempotency key."""
        canonical_target = self.normalize_target(tool_name, target)
        canonical_options = self.canonical_options_json(options)
        raw = f"{tool_name}{canonical_target}{canonical_options}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _extract_actions(self, plan: Any) -> list[Any]:
        """Extract raw action entries from ActionPlan-like object."""
        if isinstance(plan, dict):
            raw_actions = plan.get("actions", [])
            if isinstance(raw_actions, list):
                return raw_actions
            return []

        raw_actions = getattr(plan, "actions", [])
        if isinstance(raw_actions, list):
            return raw_actions
        return []

    def _coerce_action(self, raw: Any, index: int) -> Action:
        """Convert raw action object into normalized Action dataclass."""
        if isinstance(raw, Action):
            return Action(**raw.to_dict())

        if isinstance(raw, dict):
            payload = raw
        else:
            payload = {
                "action_id": getattr(raw, "action_id", f"A{index}"),
                "tool_name": getattr(raw, "tool_name", ""),
                "target": getattr(raw, "target", ""),
                "options": getattr(raw, "options", {}),
                "priority": getattr(raw, "priority", 50),
                "cost": getattr(raw, "cost", 0),
                "capabilities": getattr(raw, "capabilities", ["network_read"]),
                "idempotency_key": getattr(raw, "idempotency_key", ""),
                "reason": getattr(raw, "reason", ""),
                "preconditions": getattr(raw, "preconditions", []),
                "stop_conditions": getattr(raw, "stop_conditions", []),
            }

        return Action(
            action_id=str(payload.get("action_id", f"A{index}")),
            tool_name=str(payload.get("tool_name", "")).strip(),
            target=str(payload.get("target", "")).strip(),
            options=payload.get("options", {}) if isinstance(payload.get("options", {}), dict) else {},
            priority=int(payload.get("priority", 50)),
            cost=max(0, int(payload.get("cost", 0))),
            capabilities=list(payload.get("capabilities", ["network_read"])),
            idempotency_key=str(payload.get("idempotency_key", "")).strip(),
            reason=str(payload.get("reason", "")).strip(),
            preconditions=[str(item) for item in payload.get("preconditions", []) if str(item).strip()],
            stop_conditions=[str(item) for item in payload.get("stop_conditions", []) if str(item).strip()],
        )

    def _collect_provenance_tokens(self, state: dict[str, Any]) -> set[str]:
        """Collect normalized provenance tokens from scope, breadcrumbs, and surface."""
        tokens: set[str] = set()

        for raw in state.get("scope", []):
            token = self._extract_host_or_token(str(raw))
            if token:
                tokens.add(token.lower())
            normalized = self.normalize_target("nmap_scan", str(raw))
            if normalized:
                tokens.add(normalized)
            origin = self._origin_if_url(str(raw))
            if origin:
                tokens.add(origin)

        for entry in state.get("breadcrumbs", []):
            if not isinstance(entry, dict):
                continue
            data = str(entry.get("data", "")).strip()
            if not data:
                continue
            tokens.update(self._target_to_tokens(data))

        surface = state.get("surface", {})
        if isinstance(surface, dict):
            for url in surface.get("discovered_urls", []):
                tokens.update(self._target_to_tokens(str(url)))
            for item in surface.get("api_endpoints", []):
                if isinstance(item, dict):
                    tokens.update(self._target_to_tokens(str(item.get("url", ""))))
                else:
                    tokens.update(self._target_to_tokens(str(item)))

        return {item for item in tokens if item}

    def _target_to_tokens(self, raw_target: str) -> set[str]:
        """Convert target text into equivalent normalized tokens."""
        tokens: set[str] = set()
        raw = raw_target.strip()
        if not raw:
            return tokens

        normalized_url = self.normalize_target("dynamic_crawl", raw)
        if normalized_url:
            tokens.add(normalized_url)
            origin = self._origin_if_url(normalized_url)
            if origin:
                tokens.add(origin)
            host = self._extract_host_or_token(normalized_url)
            if host:
                tokens.add(host)
            return tokens

        token = self._extract_host_or_token(raw)
        if token:
            tokens.add(token.lower())
        return tokens

    def _parse_scope(self, scope_items: list[str]) -> _ScopeModel:
        """Parse scope list into domain/IP/network sets."""
        domains: set[str] = set()
        ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

        for raw in scope_items:
            token = self._extract_host_or_token(raw)
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

    def _resolve_domain_ips(self, domain: str) -> list[str]:
        """Resolve domain to IP list for scope fail-closed checks."""
        if self._dns_resolver is not None:
            try:
                resolved = [str(item).strip() for item in self._dns_resolver(domain)]
                return sorted({item for item in resolved if item})
            except Exception:
                return []

        try:
            records = socket.getaddrinfo(domain, None)
        except OSError:
            return []
        ips = {
            entry[4][0]
            for entry in records
            if isinstance(entry, tuple) and len(entry) > 4 and entry[4]
        }
        return sorted(ips)

    def _canonical_netloc(self, parsed: Any) -> str:
        """Canonicalize URL netloc with explicit default port."""
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

    def _origin_if_url(self, value: str) -> str:
        """Return origin string if input is URL; else empty."""
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        return urlunparse((parsed.scheme.lower(), self._canonical_netloc(parsed), "", "", "", ""))

    def _extract_host_or_token(self, raw: str) -> str:
        """Extract host or token from URL/string input."""
        candidate = raw.strip()
        if not candidate:
            return ""
        if "://" in candidate:
            parsed = urlparse(candidate)
            return (parsed.hostname or "").strip().lower()

        try:
            ipaddress.ip_address(candidate)
            return candidate.lower()
        except ValueError:
            pass

        if ":" in candidate and candidate.count(":") == 1:
            host, _port = candidate.split(":", maxsplit=1)
            return host.strip().lower()
        return candidate.lower()

    def _host_matches_scope_domain(self, host: str, domains: set[str]) -> bool:
        """Check whether host matches any scope domain (exact or subdomain)."""
        normalized_host = host.lower().strip(".")
        if not normalized_host:
            return False
        return any(
            normalized_host == domain or normalized_host.endswith(f".{domain}")
            for domain in domains
        )

    def _target_in_scope(self, target: str, scope_model: _ScopeModel) -> bool:
        """Return whether target is in scope using the same fail-closed logic."""
        probe = Action(
            action_id="scope-probe",
            tool_name="scope_probe",
            target=target,
            options={},
            priority=0,
            cost=0,
            capabilities=[],
            idempotency_key="scope-probe",
            reason="scope probe",
            preconditions=[],
            stop_conditions=[],
        )
        return self.validate_scope_fail_closed(probe, scope_model) is None

    def _token_in_ip_scope(self, token: str, scope_model: _ScopeModel) -> bool:
        """Check whether token is scoped IP."""
        if not token:
            return False
        try:
            ip_value = ipaddress.ip_address(token)
        except ValueError:
            return False
        if ip_value in scope_model.ips:
            return True
        return any(ip_value in network for network in scope_model.networks)

    def _canonicalize_object(self, value: Any) -> Any:
        """Recursively canonicalize objects for deterministic JSON rendering."""
        if isinstance(value, dict):
            return {
                str(key): self._canonicalize_object(value[key])
                for key in sorted(value.keys(), key=lambda item: str(item))
            }
        if isinstance(value, list):
            return [self._canonicalize_object(item) for item in value]
        if isinstance(value, tuple):
            return [self._canonicalize_object(item) for item in value]
        return value
