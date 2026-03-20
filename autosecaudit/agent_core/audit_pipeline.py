"""Phase-based audit workflow orchestration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlparse


@dataclass(frozen=True)
class AuditPhase:
    """One audit phase with tool constraints and budget cap."""

    name: str
    allowed_tools: list[str]
    entry_conditions: list[str]
    exit_conditions: list[str]
    max_budget_pct: float
    min_findings_to_advance: int = 0
    advance_when: Callable[[dict[str, Any]], bool] | None = None


@dataclass(frozen=True)
class PhaseTransition:
    """Computed phase transition result."""

    phase: AuditPhase
    changed: bool
    reason: str


# Passive recon tools that should run before advancing to active_discovery.
# The pipeline requires at least _MIN_CRITICAL_PASSIVE_RAN of these.
_CRITICAL_PASSIVE_TOOLS: tuple[str, ...] = (
    "tech_stack_fingerprint",
    "http_security_headers",
    "passive_config_audit",
    "nmap_scan",
    "git_exposure_check",
    "security_txt_check",
)
_MIN_CRITICAL_PASSIVE_RAN: int = 3

# Phase budget floor to avoid dead starts on host/IP-only targets where
# passive_recon mainly relies on nmap_scan (cost=15).
_PHASE_MIN_BUDGET: dict[str, int] = {
    "passive_recon": 15,
}


class AuditPipeline:
    """Stateful multi-phase audit pipeline."""

    PHASES: tuple[AuditPhase, ...] = (
        AuditPhase(
            name="passive_recon",
            allowed_tools=[
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
                "tech_stack_fingerprint",
                "login_form_detector",
                "js_endpoint_extractor",
                "passive_config_audit",
                "http_security_headers",
                "ssl_expiry_check",
                "subdomain_enum_passive",
                "git_exposure_check",
                "source_map_detector",
                "error_page_analyzer",
                "waf_detector",
                "security_txt_check",
            ],
            entry_conditions=["initial_state"],
            exit_conditions=["http_origin_identified", "passive_recon_sufficient"],
            max_budget_pct=0.20,
        ),
        AuditPhase(
            name="active_discovery",
            allowed_tools=[
                "service_banner_probe",
                "dynamic_crawl",
                "active_web_crawler",
                "dirsearch_scan",
                "api_schema_discovery",
                "page_vision_analyzer",
            ],
            entry_conditions=["http_origin_identified"],
            exit_conditions=["surface_enriched", "parameterized_endpoint_discovered"],
            max_budget_pct=0.30,
        ),
        AuditPhase(
            name="deep_testing",
            allowed_tools=[
                "cors_misconfiguration",
                "sql_sanitization_audit",
                "xss_protection_audit",
                "param_fuzzer",
                "cookie_security_audit",
                "csp_evaluator",
                "rag_intel_lookup",
            ],
            entry_conditions=["parameterized_endpoint_discovered", "follow_up_testing_requested"],
            exit_conditions=["testing_completed", "high_value_signal_found"],
            max_budget_pct=0.30,
        ),
        AuditPhase(
            name="verification",
            allowed_tools=[
                "nuclei_exploit_check",
                "tls_service_probe",
                "dns_zone_audit",
                "reverse_dns_probe",
                "ssh_auth_audit",
                "smtp_security_check",
                "mysql_handshake_probe",
                "postgres_handshake_probe",
                "redis_exposure_check",
                "memcached_exposure_check",
                "sql_sanitization_audit",
                "xss_protection_audit",
                "cookie_security_audit",
                "csp_evaluator",
                "http_security_headers",
                "cors_misconfiguration",
                "passive_config_audit",
                "cve_lookup",
                "cve_verify",
                "rag_intel_lookup",
                "page_vision_analyzer",
                "poc_sandbox_exec",
            ],
            entry_conditions=["high_value_signal_found", "verification_requested"],
            exit_conditions=["verification_completed"],
            max_budget_pct=0.20,
            min_findings_to_advance=1,
        ),
    )

    def __init__(self) -> None:
        self._phase_lookup = {phase.name: phase for phase in self.PHASES}

    def bootstrap_state(self, state: dict[str, Any]) -> dict[str, Any]:
        """Ensure phase-tracking fields exist in the mutable state."""
        total_budget = max(
            int(state.get("total_budget", 0) or 0),
            int(state.get("budget_remaining", 0) or 0),
        )
        state.setdefault("total_budget", total_budget)
        state.setdefault("phase_budget_spent", {})
        state.setdefault("phase_history", [])
        initial_phase = str(state.get("current_phase", "")).strip() or self.PHASES[0].name
        if initial_phase not in self._phase_lookup:
            initial_phase = self.PHASES[0].name
        state["current_phase"] = initial_phase
        return state

    def current_phase(self, state: dict[str, Any]) -> AuditPhase:
        """Return the current phase, defaulting to the first phase."""
        self.bootstrap_state(state)
        phase_name = str(state.get("current_phase", self.PHASES[0].name)).strip()
        return self._phase_lookup.get(phase_name, self.PHASES[0])

    def allowed_tools(
        self,
        state: dict[str, Any],
        available_tools: Iterable[str] | None = None,
    ) -> list[str]:
        """Return tools allowed for the current phase."""
        phase = self.current_phase(state)
        available = {str(item).strip() for item in (available_tools or phase.allowed_tools) if str(item).strip()}
        return [tool for tool in phase.allowed_tools if tool in available]

    def phase_budget_remaining(self, state: dict[str, Any], phase_name: str | None = None) -> int:
        """Return remaining budget allocated to a phase."""
        self.bootstrap_state(state)
        phase = self.current_phase(state) if phase_name is None else self._phase_lookup.get(phase_name, self.PHASES[0])
        total_budget = max(0, int(state.get("total_budget", state.get("budget_remaining", 0)) or 0))
        if total_budget <= 0:
            return 0
        phase_index = self._phase_index(phase.name)
        cumulative_cap = min(
            total_budget,
            sum(self._phase_budget_cap(total_budget, item) for item in self.PHASES[: phase_index + 1]),
        )
        spent_map = dict(state.get("phase_budget_spent", {}))
        cumulative_spent = sum(max(0, int(spent_map.get(item.name, 0) or 0)) for item in self.PHASES[: phase_index + 1])
        return max(0, cumulative_cap - cumulative_spent)

    def record_spend(self, state: dict[str, Any], phase_name: str, amount: int) -> None:
        """Update per-phase budget accounting."""
        self.bootstrap_state(state)
        spent = dict(state.get("phase_budget_spent", {}))
        spent[phase_name] = max(0, int(spent.get(phase_name, 0))) + max(0, int(amount))
        state["phase_budget_spent"] = spent

    def _phase_budget_cap(self, total_budget: int, phase: AuditPhase) -> int:
        budget_cap = max(1, int(total_budget * phase.max_budget_pct)) if total_budget > 0 else 0
        min_floor = max(0, int(_PHASE_MIN_BUDGET.get(phase.name, 0)))
        if total_budget > 0 and min_floor > 0:
            budget_cap = min(total_budget, max(budget_cap, min_floor))
        return budget_cap

    def evaluate_transition(
        self,
        state: dict[str, Any],
        *,
        available_tools: Iterable[str] | None = None,
    ) -> PhaseTransition:
        """Advance or roll back one phase based on observed state."""
        self.bootstrap_state(state)
        current_index = self._phase_index(str(state.get("current_phase", self.PHASES[0].name)))
        current_phase = self.PHASES[current_index]

        if current_phase.name in {"deep_testing", "verification"} and not self._has_testing_surface(state):
            fallback = self._phase_lookup["active_discovery"]
            state["current_phase"] = fallback.name
            self._append_phase_history(state, fallback.name, "fallback:testing_surface_missing")
            return PhaseTransition(fallback, True, "fallback:testing_surface_missing")

        if self._should_advance(current_phase, state):
            if current_index + 1 < len(self.PHASES):
                next_phase = self.PHASES[current_index + 1]
                state["current_phase"] = next_phase.name
                self._append_phase_history(state, next_phase.name, f"advance:{current_phase.name}")
                return PhaseTransition(next_phase, True, f"advance:{current_phase.name}")

        if self.phase_budget_remaining(state, current_phase.name) <= 0:
            if current_index + 1 < len(self.PHASES):
                next_phase = self.PHASES[current_index + 1]
                state["current_phase"] = next_phase.name
                self._append_phase_history(state, next_phase.name, f"budget_exhausted:{current_phase.name}")
                return PhaseTransition(next_phase, True, f"budget_exhausted:{current_phase.name}")

        if available_tools is not None:
            phase_tools = set(self.allowed_tools(state, available_tools))
            if not phase_tools and current_index + 1 < len(self.PHASES):
                next_phase = self.PHASES[current_index + 1]
                state["current_phase"] = next_phase.name
                self._append_phase_history(state, next_phase.name, f"no_available_tools:{current_phase.name}")
                return PhaseTransition(next_phase, True, f"no_available_tools:{current_phase.name}")

        return PhaseTransition(self.current_phase(state), False, "stay")

    def _should_advance(self, phase: AuditPhase, state: dict[str, Any]) -> bool:
        if callable(phase.advance_when):
            return bool(phase.advance_when(state))
        finding_count = int(state.get("findings_count", 0) or 0)
        if phase.name == "passive_recon":
            # Require HTTP origins AND a minimum number of critical passive
            # tools to have completed.  This prevents the pipeline from
            # skipping important passive checks like tech_stack, headers,
            # git_exposure etc. just because nmap found an HTTP port.
            if not self._has_http_origins(state):
                return False
            ran = self._ran_tools(state)
            critical_ran = sum(1 for t in _CRITICAL_PASSIVE_TOOLS if t in ran)
            return critical_ran >= _MIN_CRITICAL_PASSIVE_RAN
        if phase.name == "active_discovery":
            return self._has_testing_surface(state) or self._has_follow_up_tool(state, "sql_sanitization_audit")
        if phase.name == "deep_testing":
            return self._ran_any(state, phase.allowed_tools) and (
                finding_count >= phase.min_findings_to_advance or self._has_high_value_signal(state)
            )
        if phase.name == "verification":
            return self._ran_any(state, phase.allowed_tools)
        return False

    def _has_http_origins(self, state: dict[str, Any]) -> bool:
        for url in self._iter_urls(state):
            parsed = urlparse(url)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                return True
        return False

    def _has_testing_surface(self, state: dict[str, Any]) -> bool:
        surface = state.get("surface", {})
        if isinstance(surface, dict):
            if surface.get("url_parameters") or surface.get("parameter_origins") or surface.get("api_endpoints"):
                return True
        for url in self._iter_urls(state):
            if parse_qsl(urlparse(url).query, keep_blank_values=True):
                return True
        return False

    def _has_follow_up_tool(self, state: dict[str, Any], tool_name: str) -> bool:
        feedback = state.get("feedback", {})
        if not isinstance(feedback, dict):
            return False
        follow_up_tools = {str(item).strip() for item in feedback.get("follow_up_tools", []) if str(item).strip()}
        return str(tool_name).strip() in follow_up_tools

    def _has_high_value_signal(self, state: dict[str, Any]) -> bool:
        feedback = state.get("feedback", {})
        if isinstance(feedback, dict) and str(feedback.get("risk_signal", "")).strip().lower() in {"tighten", "pause"}:
            return True
        findings_count = int(state.get("findings_count", 0) or 0)
        return findings_count > 0

    def _ran_tools(self, state: dict[str, Any]) -> set[str]:
        """Return set of tool names that appear in execution history."""
        return {
            str(entry.get("tool", "")).strip()
            for entry in state.get("history", [])
            if isinstance(entry, dict) and str(entry.get("tool", "")).strip()
        }

    def _ran_any(self, state: dict[str, Any], tool_names: list[str]) -> bool:
        observed = self._ran_tools(state)
        return any(tool in observed for tool in tool_names)

    def _iter_urls(self, state: dict[str, Any]) -> list[str]:
        urls: list[str] = []
        for entry in state.get("breadcrumbs", []):
            if isinstance(entry, dict):
                candidate = str(entry.get("data", "")).strip()
                if candidate:
                    urls.append(candidate)
        surface = state.get("surface", {})
        if isinstance(surface, dict):
            for item in surface.get("discovered_urls", []):
                candidate = str(item).strip()
                if candidate:
                    urls.append(candidate)
            for item in surface.get("api_endpoints", []):
                if isinstance(item, dict):
                    candidate = str(item.get("url", "")).strip()
                else:
                    candidate = str(item).strip()
                if candidate:
                    urls.append(candidate)
            for item in self._iter_nmap_surface_urls(surface):
                candidate = str(item).strip()
                if candidate:
                    urls.append(candidate)
        return urls

    def _iter_nmap_surface_urls(self, surface: dict[str, Any]) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for field in ("nmap_service_origins", "nmap_http_origins", "nmap_https_origins"):
            values = surface.get(field, [])
            if not isinstance(values, list):
                continue
            for item in values:
                candidate = str(item).strip()
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    urls.append(candidate)
        for item in surface.get("nmap_services", []):
            if not isinstance(item, dict):
                continue
            candidate = str(item.get("origin", "")).strip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                urls.append(candidate)
        if urls:
            return urls
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
                    if isinstance(first, dict):
                        host_token = str(first.get("addr", "")).strip()
            if not host_token:
                continue
            for port_entry in host.get("open_ports", []):
                if not isinstance(port_entry, dict):
                    continue
                port = int(port_entry.get("port", 0) or 0)
                service = str(port_entry.get("service", "")).lower()
                if "https" in service or port in {443, 8443}:
                    candidate = f"https://{host_token}:{port}"
                elif "http" in service or port in {80, 8080, 8000, 8008, 8888}:
                    candidate = f"http://{host_token}:{port}"
                else:
                    continue
                if candidate not in seen:
                    seen.add(candidate)
                    urls.append(candidate)
        return urls

    def _append_phase_history(self, state: dict[str, Any], phase_name: str, reason: str) -> None:
        history = list(state.get("phase_history", []))
        history.append({"phase": phase_name, "reason": reason})
        state["phase_history"] = history[-20:]

    def _phase_index(self, phase_name: str) -> int:
        for index, phase in enumerate(self.PHASES):
            if phase.name == phase_name:
                return index
        return 0
