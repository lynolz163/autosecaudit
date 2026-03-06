"""Natural-language mission intake and multi-turn mission dialogue."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import re
import secrets
from typing import Any, Callable
from urllib.parse import urlsplit

from autosecaudit.agent_core.autonomy import (
    PLAYWRIGHT_TOOL_NAMES,
    autonomy_allowed_risk_levels,
    default_autonomy_mode,
    normalize_autonomy_mode,
)
from autosecaudit.agent_core.builtin_tools import load_builtin_agent_tools
from autosecaudit.agent_core.skill_loader import SkillDefinition, load_builtin_skill_registry
from autosecaudit.agent_core.tool_registry import get_tool, list_tools


_LOGGER = logging.getLogger("autosecaudit")


_URL_RE = re.compile(r"(?P<value>https?://[^\s,，。；;]+)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
_CHINESE_RE = re.compile(r"[\u4e00-\u9fff]")
_PORT_RE = re.compile(r"(?<!\d)(\d{2,5})(?!\d)")

_INTENT_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("retest", ("复测", "retest", "verify fix", "fix verification", "修复验证")),
    ("verify", ("验证", "核验", "verify", "cve", "漏洞复现", "漏洞验证")),
    ("recon", ("信息收集", "侦察", "侦查", "资产摸排", "资产发现", "recon", "asset discovery")),
    ("pentest", ("渗透测试", "渗透", "攻防测试", "pentest", "penetration test", "security test")),
]
_DEEP_MARKERS = ("深度", "深测", "激进", "高强度", "aggressive", "deep", "full", "全面")
_LIGHT_MARKERS = ("低风险", "保守", "只读", "safe-only", "light", "read-only")
_PLAN_MARKERS = ("只生成计划", "生成计划", "plan only", "dry run", "规划")
_AUTH_MARKERS = ("已授权", "授权", "authorized", "my site", "my website", "我的网站", "我自己的网站", "本人网站")
_APPROVAL_GRANTED_MARKERS = ("批准高风险", "允许高风险", "approval granted", "allow high risk")
_APPROVAL_DENIED_MARKERS = ("禁止高风险", "不要高风险", "deny high risk", "no high risk")
_DISABLE_MARKERS = ("disable", "skip", "without", "don't", "do not", "不要", "禁用", "不用", "别跑")
_ENABLE_MARKERS = ("enable", "use", "allow", "恢复", "启用", "使用")
_PLAYWRIGHT_MARKERS = ("playwright", "browser", "screenshot", "headless")
_AUTONOMY_CONSTRAINED_MARKERS = ("低风险", "只读", "保守", "constrained", "read-only")
_AUTONOMY_SUPERVISED_MARKERS = ("深测", "高强度", "激进", "supervised", "aggressive")
_AUTONOMY_ADAPTIVE_MARKERS = ("adaptive", "自动", "自适应")
_PORT_HINT_MARKERS = ("port", "ports", "端口", ":", "/", "443", "8443", "8080", "8000", "8008", "8888")

_INTENT_CATEGORY_FILTERS: dict[str, set[str] | None] = {
    "recon": {"recon", "discovery"},
    "pentest": None,
    "verify": {"testing", "validation"},
    "retest": {"testing", "validation"},
}
_INTENT_EXTRA_SKILLS: dict[str, tuple[str, ...]] = {
    "verify": ("rag_intel_lookup", "cve_lookup", "nuclei_exploit_check"),
    "retest": ("rag_intel_lookup", "cve_lookup", "nuclei_exploit_check"),
}

_MISSION_DEFAULTS: dict[tuple[str, str], dict[str, Any]] = {
    ("recon", "light"): {"budget": 80, "max_iterations": 3, "global_timeout": 600.0, "safety_grade": "balanced"},
    ("recon", "standard"): {"budget": 140, "max_iterations": 5, "global_timeout": 1200.0, "safety_grade": "balanced"},
    ("recon", "deep"): {"budget": 220, "max_iterations": 7, "global_timeout": 1800.0, "safety_grade": "aggressive"},
    ("pentest", "light"): {"budget": 120, "max_iterations": 4, "global_timeout": 1200.0, "safety_grade": "balanced"},
    ("pentest", "standard"): {"budget": 220, "max_iterations": 7, "global_timeout": 2400.0, "safety_grade": "balanced"},
    ("pentest", "deep"): {"budget": 360, "max_iterations": 10, "global_timeout": 3600.0, "safety_grade": "aggressive"},
    ("verify", "light"): {"budget": 100, "max_iterations": 3, "global_timeout": 900.0, "safety_grade": "balanced"},
    ("verify", "standard"): {"budget": 160, "max_iterations": 5, "global_timeout": 1800.0, "safety_grade": "balanced"},
    ("verify", "deep"): {"budget": 240, "max_iterations": 7, "global_timeout": 2400.0, "safety_grade": "aggressive"},
    ("retest", "light"): {"budget": 90, "max_iterations": 3, "global_timeout": 900.0, "safety_grade": "balanced"},
    ("retest", "standard"): {"budget": 140, "max_iterations": 4, "global_timeout": 1500.0, "safety_grade": "balanced"},
    ("retest", "deep"): {"budget": 200, "max_iterations": 6, "global_timeout": 2400.0, "safety_grade": "aggressive"},
}

_OVERRIDE_KEYS = {
    "target",
    "intent",
    "depth",
    "mode",
    "scope",
    "plugins",
    "report_lang",
    "budget",
    "max_iterations",
    "global_timeout",
    "safety_grade",
    "autonomy_mode",
    "tools",
    "skills",
    "multi_agent",
    "multi_agent_rounds",
    "approval_granted",
    "authorization_confirmed",
    "surface",
    "surface_file",
    "llm_config",
    "llm_source",
    "llm_model",
    "llm_provider",
    "llm_provider_type",
    "llm_base_url",
    "llm_api_key_env",
    "llm_fallback",
    "llm_timeout",
    "llm_temperature",
    "llm_max_output_tokens",
    "no_llm_hints",
    "resume",
    "plan_filename",
}


@dataclass(frozen=True)
class MissionDraft:
    """Compiled mission description and derived job payload."""

    raw_message: str
    target: str | None
    scope: str | None
    intent: str
    depth: str
    mode: str
    report_lang: str
    safety_grade: str
    autonomy_mode: str
    multi_agent: bool
    multi_agent_rounds: int
    authorization_confirmed: bool
    approval_granted: bool | None
    payload: dict[str, Any]
    selected_tools: list[str] = field(default_factory=list)
    selected_skills: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MissionTurn:
    """One mission dialogue turn."""

    role: str
    message: str
    summary: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MissionConversation:
    """One multi-turn mission session."""

    session_id: str
    draft: MissionDraft
    messages: list[MissionTurn] = field(default_factory=list)


class MissionSessionManager:
    """Small in-memory dialogue session manager."""

    def __init__(self) -> None:
        self._sessions: dict[str, MissionConversation] = {}

    def compile_turn(
        self,
        message: str,
        *,
        overrides: dict[str, Any] | None = None,
        session_id: str | None = None,
        llm_completion: Callable[[str], str] | None = None,
    ) -> MissionConversation:
        normalized_session_id = str(session_id or "").strip()
        previous = self._sessions.get(normalized_session_id)
        if previous is None and normalized_session_id:
            raise KeyError(f"mission_session_not_found:{normalized_session_id}")

        if previous is None:
            draft = build_mission_draft(message, overrides=overrides, llm_completion=llm_completion)
            next_session_id = normalized_session_id or secrets.token_hex(8)
            messages = [
                MissionTurn(role="user", message=str(message or "").strip()),
                MissionTurn(role="system", message=_conversation_message_for_draft(draft), summary=list(draft.summary)),
            ]
        else:
            draft = continue_mission_draft(
                previous.draft,
                message,
                overrides=overrides,
                llm_completion=llm_completion,
            )
            next_session_id = previous.session_id
            messages = [
                *previous.messages,
                MissionTurn(role="user", message=str(message or "").strip()),
                MissionTurn(role="system", message=_conversation_message_for_draft(draft), summary=list(draft.summary)),
            ]

        conversation = MissionConversation(session_id=next_session_id, draft=draft, messages=messages)
        self._sessions[next_session_id] = conversation
        return conversation


def build_mission_draft(
    message: str,
    *,
    overrides: dict[str, Any] | None = None,
    llm_completion: Callable[[str], str] | None = None,
) -> MissionDraft:
    """Parse one natural-language mission into a job payload draft."""
    return _compile_mission_draft(
        message,
        overrides=overrides,
        base_draft=None,
        llm_completion=llm_completion,
    )


def continue_mission_draft(
    previous: MissionDraft,
    message: str,
    *,
    overrides: dict[str, Any] | None = None,
    llm_completion: Callable[[str], str] | None = None,
) -> MissionDraft:
    """Apply one follow-up utterance on top of an existing draft."""
    return _compile_mission_draft(
        message,
        overrides=overrides,
        base_draft=previous,
        llm_completion=llm_completion,
    )


def _compile_mission_draft(
    message: str,
    *,
    overrides: dict[str, Any] | None,
    base_draft: MissionDraft | None,
    llm_completion: Callable[[str], str] | None,
) -> MissionDraft:
    raw_message = str(message or "").strip()
    normalized = raw_message.lower()
    explicit_overrides = _normalize_overrides(overrides)
    llm_overrides = _llm_overrides_from_message(
        raw_message,
        base_draft=base_draft,
        llm_completion=llm_completion,
    )
    override_payload = _merge_normalized_overrides(llm_overrides, explicit_overrides)
    parser_source = "llm" if llm_overrides else "heuristic"
    parser_values = _mission_parser_values(llm_overrides)

    base_payload = dict(base_draft.payload) if base_draft is not None else {}
    base_surface = dict(base_payload.get("surface", {})) if isinstance(base_payload.get("surface", {}), dict) else {}
    override_surface = dict(override_payload.get("surface", {})) if isinstance(override_payload.get("surface", {}), dict) else {}

    explicit_target = _clean_text(override_payload.get("target")) or _extract_target(raw_message)
    target = explicit_target or (base_draft.target if base_draft is not None else "")
    scope = (
        _clean_text(override_payload.get("scope"))
        or _target_to_scope(target)
        or (base_draft.scope if base_draft is not None else "")
    )

    explicit_intent = _clean_text(override_payload.get("intent")) or _infer_explicit_intent(normalized)
    intent = explicit_intent or (base_draft.intent if base_draft is not None else _infer_intent(normalized))

    explicit_depth = _clean_text(override_payload.get("depth")) or _infer_explicit_depth(normalized)
    depth = explicit_depth or (base_draft.depth if base_draft is not None else _infer_depth(normalized))

    mode = _clean_text(override_payload.get("mode")) or (
        "plan"
        if _contains_any(normalized, _PLAN_MARKERS)
        else (base_draft.mode if base_draft is not None else "agent")
    )
    report_lang = _clean_text(override_payload.get("report_lang")) or (
        _infer_language(raw_message) if raw_message else (base_draft.report_lang if base_draft is not None else "en")
    )

    authorization_confirmed = _coerce_bool(override_payload.get("authorization_confirmed"))
    if authorization_confirmed is None:
        if _contains_any(normalized, _AUTH_MARKERS):
            authorization_confirmed = True
        else:
            authorization_confirmed = base_draft.authorization_confirmed if base_draft is not None else False

    approval_granted = _coerce_bool(override_payload.get("approval_granted"))
    if approval_granted is None:
        if _contains_any(normalized, _APPROVAL_GRANTED_MARKERS):
            approval_granted = True
        elif _contains_any(normalized, _APPROVAL_DENIED_MARKERS):
            approval_granted = False
        elif base_draft is not None:
            approval_granted = base_draft.approval_granted

    defaults = dict(_MISSION_DEFAULTS.get((intent, depth), _MISSION_DEFAULTS[("pentest", "standard")]))
    profile_changed = explicit_intent is not None or explicit_depth is not None

    safety_grade = _clean_text(override_payload.get("safety_grade")) or _infer_safety_grade(
        normalized,
        previous=(base_draft.safety_grade if base_draft is not None else None),
        default=str(defaults["safety_grade"]),
    )

    multi_agent = bool(override_payload.get("multi_agent", base_draft.multi_agent if base_draft is not None else False))
    if not multi_agent and ("multi-agent" in normalized or "多智能体" in raw_message):
        multi_agent = True
    multi_agent_rounds = _to_int(
        override_payload.get("multi_agent_rounds"),
        base_draft.multi_agent_rounds if base_draft is not None else (2 if multi_agent else 1),
        minimum=1,
        maximum=8,
    )

    explicit_autonomy = _clean_text(override_payload.get("autonomy_mode")).lower() or _infer_autonomy_mode(normalized)
    if explicit_autonomy:
        autonomy_mode = normalize_autonomy_mode(explicit_autonomy, safety_grade=safety_grade)
    elif base_draft is not None:
        autonomy_mode = normalize_autonomy_mode(base_draft.autonomy_mode, safety_grade=safety_grade)
    else:
        autonomy_mode = default_autonomy_mode(safety_grade=safety_grade)

    directives = _extract_follow_up_directives(raw_message, normalized)
    disabled_tools = set(_coerce_text_list(base_surface.get("disabled_tools", [])))
    disabled_tools.update(_coerce_text_list(override_surface.get("disabled_tools", [])))
    if directives["disable_playwright"]:
        disabled_tools.update(PLAYWRIGHT_TOOL_NAMES)
    if directives["enable_playwright"]:
        disabled_tools.difference_update(PLAYWRIGHT_TOOL_NAMES)

    selected_skills, selected_tools, warnings = _select_capabilities(
        intent=intent,
        depth=depth,
        authorization_confirmed=bool(authorization_confirmed),
        approval_granted=approval_granted,
        autonomy_mode=autonomy_mode,
        disabled_tools=disabled_tools,
    )

    explicit_tools_requested = "tools" in override_payload
    payload_tools = list(override_payload.get("tools") or selected_tools)
    payload_skills = list(override_payload.get("skills") or selected_skills)
    payload_tools, payload_skills = _sanitize_capability_selection(
        payload_tools,
        payload_skills,
        preserve_explicit_tools=explicit_tools_requested,
    )
    if disabled_tools:
        registry = load_builtin_skill_registry()
        payload_tools = [item for item in payload_tools if item not in disabled_tools]
        payload_skills = [
            item
            for item in payload_skills
            if (skill := registry.get(item)) is None or skill.tool not in disabled_tools
        ]

    focus_ports = (
        directives["focus_ports"]
        or _coerce_port_list(override_surface.get("focus_ports", []))
        or _coerce_port_list(base_surface.get("focus_ports", []))
    )
    preferred_origins = _coerce_text_list(override_surface.get("preferred_origins", [])) or _build_preferred_origins(
        target=target,
        focus_ports=focus_ports,
    )
    surface = _merge_surface(base_surface, override_surface)
    surface["mission_intent"] = intent
    surface["mission_depth"] = depth
    surface["mission_message"] = raw_message
    surface["autonomy_mode"] = autonomy_mode
    surface["authorization_confirmed"] = bool(authorization_confirmed)
    surface["mission_parser_source"] = parser_source
    surface["mission_parser_values"] = parser_values
    surface["disabled_tools"] = sorted(disabled_tools)
    surface["focus_ports"] = focus_ports
    if preferred_origins:
        surface["preferred_origins"] = preferred_origins
    elif "preferred_origins" not in surface:
        surface["preferred_origins"] = []

    if approval_granted is not None:
        surface["approval_granted"] = bool(approval_granted)

    payload: dict[str, Any] = {
        "target": target or "",
        "mode": mode,
        "scope": scope,
        "report_lang": report_lang,
        "budget": _to_int(
            override_payload.get("budget"),
            _payload_default(base_payload, "budget", defaults["budget"], use_defaults=profile_changed),
            minimum=1,
            maximum=100000,
        ),
        "max_iterations": _to_int(
            override_payload.get("max_iterations"),
            _payload_default(base_payload, "max_iterations", defaults["max_iterations"], use_defaults=profile_changed),
            minimum=1,
            maximum=100,
        ),
        "global_timeout": _to_float(
            override_payload.get("global_timeout"),
            _payload_default(base_payload, "global_timeout", defaults["global_timeout"], use_defaults=profile_changed),
            minimum=10.0,
            maximum=86400.0,
        ),
        "safety_grade": safety_grade,
        "autonomy_mode": autonomy_mode,
        "tools": payload_tools,
        "skills": payload_skills,
        "multi_agent": bool(multi_agent),
        "multi_agent_rounds": int(multi_agent_rounds),
        "surface": surface,
    }
    plugins = _clean_text(override_payload.get("plugins")) or _clean_text(base_payload.get("plugins"))
    if plugins:
        payload["plugins"] = plugins

    for key in ("surface_file", "llm_config", "llm_source", "plan_filename", "resume"):
        value = override_payload.get(key)
        if value not in (None, ""):
            payload[key] = value
        elif base_draft is not None and key in base_payload and base_payload.get(key) not in (None, ""):
            payload[key] = base_payload.get(key)

    if approval_granted is not None:
        payload["approval_granted"] = bool(approval_granted)

    no_llm_hints = override_payload.get("no_llm_hints")
    if bool(no_llm_hints):
        payload["no_llm_hints"] = True
    elif base_draft is not None and bool(base_payload.get("no_llm_hints", False)):
        payload["no_llm_hints"] = True

    missing_fields = ["target"] if not target else []
    warnings = _append_directive_warnings(warnings, directives=directives, disabled_tools=disabled_tools)
    summary = _build_summary(
        target=target,
        intent=intent,
        depth=depth,
        mode=mode,
        safety_grade=safety_grade,
        autonomy_mode=autonomy_mode,
        tool_count=len(payload_tools),
        skill_count=len(payload_skills),
        report_lang=report_lang,
        multi_agent=multi_agent,
        warnings=warnings,
        focus_ports=focus_ports,
        parser_source=parser_source,
    )
    return MissionDraft(
        raw_message=raw_message,
        target=target or None,
        scope=scope or None,
        intent=intent,
        depth=depth,
        mode=mode,
        report_lang=report_lang,
        safety_grade=safety_grade,
        autonomy_mode=autonomy_mode,
        multi_agent=bool(multi_agent),
        multi_agent_rounds=int(multi_agent_rounds),
        authorization_confirmed=bool(authorization_confirmed),
        approval_granted=approval_granted,
        payload=payload,
        selected_tools=list(payload_tools),
        selected_skills=list(payload_skills),
        warnings=warnings,
        missing_fields=missing_fields,
        summary=summary,
    )


def _normalize_overrides(value: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if key not in _OVERRIDE_KEYS:
            continue
        if item is None:
            continue
        normalized[key] = item
    if "tools" in normalized:
        normalized["tools"] = _coerce_text_list(normalized["tools"])
    if "skills" in normalized:
        normalized["skills"] = _coerce_text_list(normalized["skills"])
    return normalized


def _merge_normalized_overrides(base: dict[str, Any], explicit: dict[str, Any]) -> dict[str, Any]:
    output = dict(base)
    if isinstance(output.get("surface"), dict):
        output["surface"] = dict(output["surface"])
    for key, value in explicit.items():
        if key == "surface" and isinstance(value, dict):
            merged_surface = dict(output.get("surface", {}))
            merged_surface.update(value)
            output["surface"] = merged_surface
            continue
        output[key] = value
    return output


def _extract_target(message: str) -> str:
    text = str(message or "").strip()
    for pattern in (_URL_RE, _IP_RE, _DOMAIN_RE):
        match = pattern.search(text)
        if match:
            value = match.group("value") if "value" in match.groupdict() else match.group(0)
            return value.rstrip(".,);，。；")
    return ""


def _target_to_scope(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        parsed = urlsplit(text)
        return parsed.hostname or text
    return text


def _infer_language(message: str) -> str:
    return "zh-CN" if _CHINESE_RE.search(str(message or "")) else "en"


def _infer_intent(normalized_message: str) -> str:
    return _infer_explicit_intent(normalized_message) or "pentest"


def _infer_explicit_intent(normalized_message: str) -> str | None:
    for intent, markers in _INTENT_RULES:
        if _contains_any(normalized_message, markers):
            return intent
    return None


def _infer_depth(normalized_message: str) -> str:
    return _infer_explicit_depth(normalized_message) or "standard"


def _infer_explicit_depth(normalized_message: str) -> str | None:
    if _contains_any(normalized_message, _LIGHT_MARKERS):
        return "light"
    if _contains_any(normalized_message, _DEEP_MARKERS):
        return "deep"
    return None


def _infer_safety_grade(normalized_message: str, *, previous: str | None, default: str) -> str:
    if _contains_any(normalized_message, _LIGHT_MARKERS):
        return "conservative"
    if _contains_any(normalized_message, _DEEP_MARKERS):
        return "aggressive"
    if previous:
        return previous
    return default


def _infer_autonomy_mode(normalized_message: str) -> str | None:
    if _contains_any(normalized_message, _AUTONOMY_CONSTRAINED_MARKERS):
        return "constrained"
    if _contains_any(normalized_message, _AUTONOMY_SUPERVISED_MARKERS):
        return "supervised"
    if _contains_any(normalized_message, _AUTONOMY_ADAPTIVE_MARKERS):
        return "adaptive"
    return None


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _extract_follow_up_directives(raw_message: str, normalized_message: str) -> dict[str, Any]:
    mentions_playwright = _contains_any(normalized_message, _PLAYWRIGHT_MARKERS)
    disable_playwright = mentions_playwright and _contains_any(normalized_message, _DISABLE_MARKERS)
    enable_playwright = mentions_playwright and not disable_playwright and _contains_any(normalized_message, _ENABLE_MARKERS)
    focus_ports: list[int] = []
    if any(marker in raw_message or marker in normalized_message for marker in _PORT_HINT_MARKERS):
        focus_ports = _coerce_port_list(_PORT_RE.findall(raw_message))
    return {
        "disable_playwright": disable_playwright,
        "enable_playwright": enable_playwright,
        "focus_ports": focus_ports,
    }


def _select_capabilities(
    *,
    intent: str,
    depth: str,
    authorization_confirmed: bool,
    approval_granted: bool | None,
    autonomy_mode: str,
    disabled_tools: set[str],
) -> tuple[list[str], list[str], list[str]]:
    load_builtin_agent_tools()
    registry = load_builtin_skill_registry()
    category_filter = _INTENT_CATEGORY_FILTERS.get(intent)
    allowed_risks = autonomy_allowed_risk_levels(autonomy_mode)
    selected: list[SkillDefinition] = []
    warnings: list[str] = []

    for skill in registry.list():
        if category_filter is not None and skill.category not in category_filter:
            continue
        if skill.tool in disabled_tools:
            continue
        if skill.name == "cve_verify" and not authorization_confirmed:
            continue
        if skill.name == "poc_sandbox_exec" and not (authorization_confirmed and approval_granted):
            continue
        if depth == "light" and skill.category in {"validation", "testing"} and intent == "recon":
            continue

        tool = get_tool(skill.tool)
        risk_level = str(getattr(tool, "risk_level", "safe")).strip().lower() or "safe"
        if risk_level not in allowed_risks:
            continue

        available, reason = tool.check_availability()
        if not available:
            if reason:
                warnings.append(f"{skill.tool}: {reason}")
            continue
        selected.append(skill)

    extra_skills = _INTENT_EXTRA_SKILLS.get(intent, ())
    existing_names = {skill.name for skill in selected}
    for extra_name in extra_skills:
        if extra_name in existing_names:
            continue
        skill = registry.get(extra_name)
        if skill is None or skill.tool in disabled_tools:
            continue
        if skill.name == "cve_verify" and not authorization_confirmed:
            continue
        if skill.name == "poc_sandbox_exec" and not (authorization_confirmed and approval_granted):
            continue

        tool = get_tool(skill.tool)
        risk_level = str(getattr(tool, "risk_level", "safe")).strip().lower() or "safe"
        if risk_level not in allowed_risks:
            continue

        available, reason = tool.check_availability()
        if not available:
            if reason:
                warnings.append(f"{skill.tool}: {reason}")
            continue
        selected.append(skill)
        existing_names.add(skill.name)

    tools = [skill.tool for skill in selected]
    skills = [skill.name for skill in selected]
    return skills, tools, _dedupe_strings(warnings)


def _build_summary(
    *,
    target: str,
    intent: str,
    depth: str,
    mode: str,
    safety_grade: str,
    autonomy_mode: str,
    tool_count: int,
    skill_count: int,
    report_lang: str,
    multi_agent: bool,
    warnings: list[str],
    focus_ports: list[int],
    parser_source: str,
) -> list[str]:
    summary = [
        f"Target: {target or 'missing'}",
        f"Intent: {intent}",
        f"Depth: {depth}",
        f"Mode: {mode}",
        f"Safety grade: {safety_grade}",
        f"Autonomy mode: {autonomy_mode}",
        f"Report language: {report_lang}",
        f"Skills selected: {skill_count}",
        f"Tools selected: {tool_count}",
        f"Multi-agent: {'enabled' if multi_agent else 'disabled'}",
        f"Mission parser: {parser_source}",
    ]
    if focus_ports:
        summary.append(f"Focused ports: {', '.join(str(item) for item in focus_ports)}")
    if warnings:
        summary.append(f"Warnings: {len(warnings)} capability checks skipped unavailable tools")
    return summary


def _conversation_message_for_draft(draft: MissionDraft) -> str:
    details = [f"{draft.intent}/{draft.depth}", draft.safety_grade, draft.autonomy_mode]
    return f"Prepared mission for {draft.target or 'missing target'} ({', '.join(details)})."


def _append_directive_warnings(
    warnings: list[str],
    *,
    directives: dict[str, Any],
    disabled_tools: set[str],
) -> list[str]:
    output = list(warnings)
    if directives.get("disable_playwright"):
        output.append("Playwright tools disabled for this mission dialogue.")
    if directives.get("enable_playwright"):
        output.append("Playwright tools re-enabled for this mission dialogue.")
    if directives.get("focus_ports"):
        output.append(
            "Focused deep testing on ports: "
            + ", ".join(str(item) for item in directives.get("focus_ports", []))
        )
    if disabled_tools:
        output.append("Disabled tools: " + ", ".join(sorted(disabled_tools)))
    return _dedupe_strings(output)


def _llm_overrides_from_message(
    raw_message: str,
    *,
    base_draft: MissionDraft | None,
    llm_completion: Callable[[str], str] | None,
) -> dict[str, Any]:
    if llm_completion is None or not raw_message:
        return {}
    prompt = _build_mission_llm_prompt(raw_message=raw_message, base_draft=base_draft)
    try:
        response = str(llm_completion(prompt) or "").strip()
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("Mission LLM parser failed; using heuristic fallback: %s", exc)
        return {}
    payload = _extract_json_object(response)
    if not isinstance(payload, dict):
        return {}
    return _normalize_overrides(_normalize_llm_payload(payload))


def _build_mission_llm_prompt(*, raw_message: str, base_draft: MissionDraft | None) -> str:
    load_builtin_agent_tools()
    skill_registry = load_builtin_skill_registry()
    previous_draft = {
        "target": base_draft.target if base_draft is not None else None,
        "scope": base_draft.scope if base_draft is not None else None,
        "intent": base_draft.intent if base_draft is not None else None,
        "depth": base_draft.depth if base_draft is not None else None,
        "mode": base_draft.mode if base_draft is not None else None,
        "report_lang": base_draft.report_lang if base_draft is not None else None,
        "safety_grade": base_draft.safety_grade if base_draft is not None else None,
        "autonomy_mode": base_draft.autonomy_mode if base_draft is not None else None,
        "authorization_confirmed": base_draft.authorization_confirmed if base_draft is not None else None,
        "approval_granted": base_draft.approval_granted if base_draft is not None else None,
        "multi_agent": base_draft.multi_agent if base_draft is not None else None,
        "multi_agent_rounds": base_draft.multi_agent_rounds if base_draft is not None else None,
        "selected_tools": list(base_draft.selected_tools) if base_draft is not None else [],
        "selected_skills": list(base_draft.selected_skills) if base_draft is not None else [],
        "surface": dict(base_draft.payload.get("surface", {})) if base_draft is not None else {},
    }
    schema = {
        "target": "string|null",
        "scope": "string|null",
        "intent": "recon|pentest|verify|retest|null",
        "depth": "light|standard|deep|null",
        "mode": "agent|plan|plugins|null",
        "report_lang": "zh-CN|en|null",
        "safety_grade": "conservative|balanced|aggressive|null",
        "autonomy_mode": "constrained|adaptive|supervised|null",
        "authorization_confirmed": "boolean|null",
        "approval_granted": "boolean|null",
        "multi_agent": "boolean|null",
        "multi_agent_rounds": "integer|null",
        "budget": "integer|null",
        "max_iterations": "integer|null",
        "global_timeout": "number|null",
        "plugins": "string|null",
        "tools": "string[]",
        "skills": "string[]",
        "surface": {
            "disabled_tools": "string[]",
            "focus_ports": "integer[]",
            "preferred_origins": "string[]",
        },
    }
    return (
        "You are a mission compiler for AutoSecAudit.\n"
        "Convert the user's chat request into exactly one JSON object for backend execution.\n"
        "Do not explain. Do not use markdown. JSON only.\n"
        "Follow-up turns must update the previous mission instead of resetting it.\n"
        "If a field is not specified in the current user message, return null for scalars or [] for arrays.\n"
        "Never invent targets, tools, or skills.\n"
        "Allowed enums:\n"
        "- intent: recon, pentest, verify, retest\n"
        "- depth: light, standard, deep\n"
        "- mode: agent, plan, plugins\n"
        "- report_lang: zh-CN, en\n"
        "- safety_grade: conservative, balanced, aggressive\n"
        "- autonomy_mode: constrained, adaptive, supervised\n"
        f"Available tools: {json.dumps(list_tools(), ensure_ascii=True)}\n"
        f"Available skills: {json.dumps([skill.name for skill in skill_registry.list()], ensure_ascii=True)}\n"
        f"Schema guide: {json.dumps(schema, ensure_ascii=True)}\n"
        f"Previous draft: {json.dumps(previous_draft, ensure_ascii=True)}\n"
        f"User message: {json.dumps(raw_message, ensure_ascii=True)}\n"
    )


def _extract_json_object(text: str) -> dict[str, Any] | None:
    raw_text = str(text or "").strip()
    if not raw_text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw_text, re.DOTALL | re.IGNORECASE)
    if fenced:
        raw_text = fenced.group(1).strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(raw_text):
        if char != "{":
            continue
        try:
            payload, _end = decoder.raw_decode(raw_text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _normalize_llm_payload(payload: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "target",
        "scope",
        "intent",
        "depth",
        "mode",
        "report_lang",
        "safety_grade",
        "autonomy_mode",
        "authorization_confirmed",
        "approval_granted",
        "multi_agent",
        "multi_agent_rounds",
        "budget",
        "max_iterations",
        "global_timeout",
        "plugins",
        "tools",
        "skills",
    ):
        if key in payload:
            output[key] = payload.get(key)

    raw_surface = payload.get("surface", {})
    surface = dict(raw_surface) if isinstance(raw_surface, dict) else {}
    for key in ("disabled_tools", "focus_ports", "preferred_origins"):
        if key in payload and key not in surface:
            surface[key] = payload.get(key)
    if surface:
        output["surface"] = surface
    return output


def _mission_parser_values(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, Any] = {}
    for key, item in value.items():
        if key == "surface" and isinstance(item, dict):
            nested: dict[str, Any] = {}
            for nested_key, nested_value in item.items():
                if nested_value in (None, "", [], {}):
                    continue
                nested[nested_key] = nested_value
            if nested:
                output[key] = nested
            continue
        if item in (None, "", [], {}):
            continue
        output[key] = item
    return output


def _merge_surface(base: dict[str, Any], override: Any) -> dict[str, Any]:
    output = dict(base)
    if isinstance(override, dict):
        for key, value in override.items():
            output[key] = value
    return output


def _sanitize_capability_selection(
    tools: list[str],
    skills: list[str],
    *,
    preserve_explicit_tools: bool = False,
) -> tuple[list[str], list[str]]:
    load_builtin_agent_tools()
    skill_registry = load_builtin_skill_registry()
    valid_tools = set(list_tools())

    sanitized_tools: list[str] = []
    seen_tools: set[str] = set()
    for item in tools:
        normalized = str(item).strip()
        if not normalized or normalized not in valid_tools or normalized in seen_tools:
            continue
        seen_tools.add(normalized)
        sanitized_tools.append(normalized)

    sanitized_skills: list[str] = []
    for item in skills:
        resolved = skill_registry.get(item)
        if resolved is None or resolved.name in sanitized_skills:
            continue
        sanitized_skills.append(resolved.name)
        if preserve_explicit_tools:
            continue
        if resolved.tool not in seen_tools:
            seen_tools.add(resolved.tool)
            sanitized_tools.append(resolved.tool)
    return sanitized_tools, sanitized_skills


def _payload_default(payload: dict[str, Any], key: str, fallback: Any, *, use_defaults: bool) -> Any:
    if use_defaults:
        return fallback
    if key in payload and payload.get(key) not in (None, ""):
        return payload.get(key)
    return fallback


def _build_preferred_origins(*, target: str, focus_ports: list[int]) -> list[str]:
    if not target or not focus_ports:
        return []
    parsed = urlsplit(target if target.startswith(("http://", "https://")) else f"https://{target}")
    host = str(parsed.hostname or parsed.path or target).strip()
    if not host:
        return []
    discovered: list[str] = []
    for port in focus_ports:
        scheme = _scheme_for_port(port)
        if not scheme:
            continue
        discovered.append(f"{scheme}://{host}:{port}/")
    return _dedupe_strings(discovered)


def _scheme_for_port(port: int) -> str:
    if port in {443, 8443}:
        return "https"
    if port in {80, 8080, 8000, 8008, 8888, 3128, 5800}:
        return "http"
    return ""


def _clean_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value).strip()


def _coerce_text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        items = [item.strip() for item in str(value).split(",") if item.strip()]
    return _dedupe_strings(items)


def _coerce_port_list(value: Any) -> list[int]:
    raw_items: list[str] = []
    if isinstance(value, list):
        raw_items = [str(item).strip() for item in value if str(item).strip()]
    elif isinstance(value, str):
        raw_items = [item.strip() for item in re.split(r"[,/ ]+", value) if item.strip()]
    else:
        raw_items = [str(item).strip() for item in list(value or []) if str(item).strip()] if value else []
    ports: list[int] = []
    seen: set[int] = set()
    for item in raw_items:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if port < 1 or port > 65535 or port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        key = str(value).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(str(value).strip())
    return output


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


def _to_int(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _to_float(value: Any, default: float, *, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))
