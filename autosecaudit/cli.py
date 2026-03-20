"""CLI entry point for AutoSecAudit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from autosecaudit.agent_core import AgentOrchestrator
from autosecaudit.agent_core.skill_loader import load_builtin_skill_registry
from autosecaudit.agent_safety import AGENT_SAFETY_GRADES, DEFAULT_AGENT_SAFETY_GRADE
from autosecaudit.core.command import SafeCommandRunner
from autosecaudit.core.logging_utils import OperationRecorder, configure_logging
from autosecaudit.core.models import AuditContext, RuntimeConfig
from autosecaudit.core.plugin_loader import PluginHotLoader
from autosecaudit.core.registry import registry
from autosecaudit.core.report import ReportWriter, normalize_report_lang
from autosecaudit.core.runner import AuditRunner
from autosecaudit.core.safety import SafetyPolicy
from autosecaudit.decision import AuditDecisionMaker, MultiAgentDecisionMaker
from autosecaudit.integrations import LLMRouter, LLMRouterError, build_notifier_from_config
import autosecaudit.plugins  # noqa: F401  # Force plugin module import and registration.


def build_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="autosecaudit",
        description=(
            "AutoSecAudit: safe, read-only security discovery and configuration validation framework."
        ),
    )
    parser.add_argument("--target", required=True, help="Target host or URL, e.g. https://example.com")
    parser.add_argument(
        "--mode",
        choices=("plugins", "plan", "agent"),
        default="plugins",
        help="Execution mode. plugins=legacy plugin runner, plan=generate ActionPlan only, agent=run orchestrator loop.",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Output directory for audit artifacts (reports). Default: ./output",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help="Directory for logs. Default: <output>/logs",
    )
    parser.add_argument(
        "--plugins",
        default=None,
        help=(
            "Comma-separated plugin IDs to run. "
            "If omitted, all built-in plugins are executed."
        ),
    )
    parser.add_argument(
        "--tools",
        default=None,
        help="Comma-separated agent tool names to enable for plan/agent mode.",
    )
    parser.add_argument(
        "--skills",
        default=None,
        help="Comma-separated agent skill names to enable for plan/agent mode. Resolved to their bound tools.",
    )
    parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        help="Additional directory containing hot-loadable plugin .py files (repeatable).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-plugin timeout in seconds. Default: 15",
    )
    parser.add_argument(
        "--allow-command",
        action="append",
        default=[],
        help="Add extra allowlisted read-only command executable name.",
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="Comma-separated scope entries (domain/IP/CIDR). Default derives from --target.",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=50,
        help="Agent planning/execution budget. Default: 50",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Max constrained autonomous loop iterations in agent mode. Default: 3",
    )
    parser.add_argument(
        "--global-timeout",
        type=float,
        default=300.0,
        help="Global timeout (seconds) for plan/agent mode. Default: 300",
    )
    parser.add_argument(
        "--no-llm-hints",
        action="store_true",
        help="Disable optional LLM hints when building ActionPlan.",
    )
    parser.add_argument(
        "--multi-agent",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable layered multi-agent planning (Recon/Exploiter/Reviewer).",
    )
    parser.add_argument(
        "--multi-agent-rounds",
        type=int,
        default=1,
        help="Planning rounds in multi-agent mode. Default: 1",
    )
    parser.add_argument(
        "--agent-safety-grade",
        choices=AGENT_SAFETY_GRADES,
        default=DEFAULT_AGENT_SAFETY_GRADE,
        help="Agent safety posture. Conservative blocks active tools; aggressive allows the widest safe set.",
    )
    parser.add_argument(
        "--authorization-confirmed",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Explicitly confirm target authorization for high-risk validation flows "
            "(for example cve_verify)."
        ),
    )
    parser.add_argument(
        "--cve-safe-only",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Default CVE verification mode. true=non-destructive template subset, false=broader checks.",
    )
    parser.add_argument(
        "--cve-allow-high-risk",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Allow high-risk CVE verification behavior (effective only in aggressive safety grade).",
    )
    parser.add_argument(
        "--approval-granted",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Explicit approval gate for high-risk sandbox PoC execution flows.",
    )
    parser.add_argument(
        "--plan-filename",
        default="ActionPlan.json",
        help="Action plan output filename in --mode plan. Default: ActionPlan.json",
    )
    parser.add_argument(
        "--history-file",
        default=None,
        help="Optional JSON file for initial history list.",
    )
    parser.add_argument(
        "--breadcrumbs-file",
        default=None,
        help="Optional JSON file for initial breadcrumbs list.",
    )
    parser.add_argument(
        "--surface-file",
        default=None,
        help="Optional JSON file for initial surface object.",
    )
    parser.add_argument(
        "--resume",
        default=None,
        help="Resume from previous agent state file or session directory.",
    )
    parser.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Path to LLM router JSON config "
            "(provider/model routing, providers, fallbacks)."
        ),
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        help=(
            "Primary LLM model. Supports 'provider/model' or plain model name "
            "(used with --llm-provider)."
        ),
    )
    parser.add_argument(
        "--llm-fallback",
        action="append",
        default=[],
        help="Fallback model reference (repeatable). Supports 'provider/model'.",
    )
    parser.add_argument(
        "--llm-provider",
        default="openai",
        help="Default provider alias for plain --llm-model values. Default: openai",
    )
    parser.add_argument(
        "--llm-provider-type",
        choices=("openai_sdk", "openai_compatible", "codex_oauth"),
        default="openai_sdk",
        help=(
            "Provider implementation type. "
            "openai_sdk=official OpenAI SDK, "
            "openai_compatible=HTTP /chat/completions, "
            "codex_oauth=OpenAI-compatible endpoint + OAuth bearer token."
        ),
    )
    parser.add_argument(
        "--llm-base-url",
        default=None,
        help=(
            "Optional provider base URL (useful for OpenAI-compatible gateways/local models). "
            "Example: http://localhost:11434/v1"
        ),
    )
    parser.add_argument(
        "--llm-api-key-env",
        default="OPENAI_API_KEY",
        help="Environment variable name storing provider API key. Default: OPENAI_API_KEY",
    )
    parser.add_argument(
        "--llm-oauth-token-env",
        default=None,
        help=(
            "OAuth access token environment variable name for --llm-provider-type codex_oauth "
            "(e.g. OPENAI_ACCESS_TOKEN)."
        ),
    )
    parser.add_argument(
        "--llm-oauth-token-file",
        default=None,
        help=(
            "Path to OAuth token file (JSON or raw token text) for --llm-provider-type codex_oauth."
        ),
    )
    parser.add_argument(
        "--llm-oauth-command-json",
        default=None,
        help=(
            "JSON array command used to fetch OAuth token for --llm-provider-type codex_oauth. "
            "Executed with shell=False. Example: [\"python\",\"get_token.py\"]"
        ),
    )
    parser.add_argument(
        "--llm-oauth-browser-login",
        action="store_true",
        help=(
            "Enable interactive browser OAuth login (PKCE) for --llm-provider-type codex_oauth "
            "when no token is found in env/file/command."
        ),
    )
    parser.add_argument(
        "--llm-oauth-authorize-url",
        default=None,
        help="OAuth authorization endpoint URL (required for browser login mode).",
    )
    parser.add_argument(
        "--llm-oauth-token-url",
        default=None,
        help="OAuth token endpoint URL (required for browser login mode).",
    )
    parser.add_argument(
        "--llm-oauth-client-id",
        default=None,
        help="OAuth client_id for browser login mode.",
    )
    parser.add_argument(
        "--llm-oauth-scope",
        action="append",
        default=[],
        help="OAuth scope for browser login mode (repeatable).",
    )
    parser.add_argument(
        "--llm-oauth-redirect-host",
        default="127.0.0.1",
        help="Local callback host for browser login. Default: 127.0.0.1",
    )
    parser.add_argument(
        "--llm-oauth-redirect-port",
        type=int,
        default=8765,
        help="Local callback port for browser login. Default: 8765",
    )
    parser.add_argument(
        "--llm-oauth-redirect-path",
        default="/callback",
        help="Local callback path for browser login. Default: /callback",
    )
    parser.add_argument(
        "--llm-oauth-cache-file",
        default=None,
        help=(
            "Token cache file for browser OAuth login (JSON). "
            "If omitted, defaults to ~/.autosecaudit/<provider>_oauth_token.json"
        ),
    )
    parser.add_argument(
        "--llm-oauth-profile-id",
        default="default",
        help="Auth profile ID for codex_oauth provider token store. Default: default",
    )
    parser.add_argument(
        "--llm-oauth-profiles-file",
        default=None,
        help=(
            "Auth profiles store file path (JSON). "
            "If omitted, defaults to ~/.autosecaudit/auth-profiles.json"
        ),
    )
    parser.add_argument(
        "--llm-oauth-no-auto-refresh",
        action="store_true",
        help="Disable OAuth access-token auto refresh from refresh_token in auth profile store.",
    )
    parser.add_argument(
        "--llm-oauth-login-timeout",
        type=float,
        default=180.0,
        help="Browser OAuth login timeout seconds. Default: 180",
    )
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=300.0,
        help="LLM request timeout seconds. Default: 300",
    )
    parser.add_argument(
        "--llm-temperature",
        type=float,
        default=0.0,
        help="LLM temperature. Default: 0.0 (deterministic planning)",
    )
    parser.add_argument(
        "--llm-max-output-tokens",
        type=int,
        default=1200,
        help="LLM max output tokens. Default: 1200",
    )
    parser.add_argument(
        "--report-lang",
        default=None,
        help="Report language for agent markdown/html metadata. Supported: en, zh-CN",
    )
    return parser


def parse_plugin_ids(raw_value: str | None) -> list[str] | None:
    """Parse comma-separated plugin IDs."""
    if raw_value is None:
        return None
    plugin_ids = [item.strip() for item in raw_value.split(",") if item.strip()]
    return plugin_ids or None


def parse_tool_ids(raw_value: str | None) -> list[str] | None:
    """Parse comma-separated tool names with stable deduplication."""
    if raw_value is None:
        return None
    tool_ids: list[str] = []
    seen: set[str] = set()
    for item in raw_value.split(","):
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        tool_ids.append(normalized)
    return tool_ids or None


def parse_skill_ids(raw_value: str | None) -> list[str] | None:
    """Parse comma-separated skill names with stable deduplication."""
    if raw_value is None:
        return None
    skill_ids: list[str] = []
    seen: set[str] = set()
    for item in raw_value.split(","):
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        skill_ids.append(normalized)
    return skill_ids or None


def resolve_selected_tools(
    *,
    tool_ids: Sequence[str] | None = None,
    skill_ids: Sequence[str] | None = None,
) -> list[str] | None:
    """Resolve one effective tool filter from explicit tools and selected skills."""
    resolved: list[str] = []
    seen: set[str] = set()
    for item in tool_ids or []:
        normalized = str(item).strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            resolved.append(normalized)
    if skill_ids:
        registry = load_builtin_skill_registry()
        for skill_id in skill_ids:
            skill = registry.get(str(skill_id).strip())
            if skill is None:
                continue
            if skill.tool not in seen:
                seen.add(skill.tool)
                resolved.append(skill.tool)
    return resolved or None


def parse_scope(raw_scope: str | None, target: str) -> list[str]:
    """Parse scope CSV or derive scope seed from target."""
    if raw_scope:
        parsed = [item.strip() for item in raw_scope.split(",") if item.strip()]
        if parsed:
            return parsed

    candidate = target.strip()
    parsed_target = urlparse(candidate)
    if parsed_target.scheme in {"http", "https"} and parsed_target.hostname:
        return [parsed_target.hostname.lower()]

    if ":" in candidate and candidate.count(":") == 1 and "/" not in candidate:
        return [candidate.split(":", maxsplit=1)[0].strip().lower()]
    return [candidate]


def _read_json_file(path_text: str | None, expected_type: type[list] | type[dict]) -> Any:
    """Read optional JSON file and fall back to empty container on mismatch/error."""
    if not path_text:
        return [] if expected_type is list else {}

    path = Path(path_text)
    if not path.exists() or not path.is_file():
        return [] if expected_type is list else {}

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [] if expected_type is list else {}

    if expected_type is list and isinstance(payload, list):
        return payload
    if expected_type is dict and isinstance(payload, dict):
        return payload
    return [] if expected_type is list else {}


def _read_json_object(path_text: str | None) -> dict[str, Any]:
    """Read JSON object from file path for optional extended config sections."""
    if not path_text:
        return {}
    path = Path(path_text)
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _apply_agent_cve_runtime_flags(state: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Apply CLI CVE runtime flags into agent state/surface without clobbering absent options."""
    if not isinstance(state, dict):
        return state
    surface = state.get("surface", {})
    if not isinstance(surface, dict):
        surface = {}
    if args.authorization_confirmed is not None:
        state["authorization_confirmed"] = bool(args.authorization_confirmed)
        surface["authorization_confirmed"] = bool(args.authorization_confirmed)
    if args.cve_safe_only is not None:
        state["cve_safe_only"] = bool(args.cve_safe_only)
        surface["safe_only"] = bool(args.cve_safe_only)
    if args.cve_allow_high_risk is not None:
        state["cve_allow_high_risk"] = bool(args.cve_allow_high_risk)
        surface["allow_high_risk"] = bool(args.cve_allow_high_risk)
    if args.approval_granted is not None:
        state["approval_granted"] = bool(args.approval_granted)
        surface["approval_granted"] = bool(args.approval_granted)
    if getattr(args, "report_lang", None):
        state["report_lang"] = normalize_report_lang(str(args.report_lang))
        surface["report_lang"] = normalize_report_lang(str(args.report_lang))
    state["surface"] = surface
    return state


def _build_decision_maker_from_llm_args(
    args: argparse.Namespace,
    logger: Any,
    *,
    available_tools: Sequence[str] | None = None,
    output_dir: Path | None = None,
) -> AuditDecisionMaker | MultiAgentDecisionMaker | None:
    """
    Build decision maker with provider/model LLM routing when configured.

    Returns:
        One configured decision maker instance, or `None` when default single-agent
        planner behavior should be used.
    """
    llm_router: LLMRouter | None = None

    if args.llm_config:
        llm_router = LLMRouter.from_json_file(Path(args.llm_config).resolve(), logger=logger)
    elif args.llm_model:
        llm_router = LLMRouter.from_cli_args(
            llm_model=str(args.llm_model),
            llm_provider=str(args.llm_provider),
            llm_provider_type=str(args.llm_provider_type),
            llm_fallbacks=list(args.llm_fallback or []),
            llm_base_url=(str(args.llm_base_url) if args.llm_base_url else None),
            llm_api_key_env=str(args.llm_api_key_env),
            llm_oauth_token_env=(str(args.llm_oauth_token_env) if args.llm_oauth_token_env else None),
            llm_oauth_token_file=(str(args.llm_oauth_token_file) if args.llm_oauth_token_file else None),
            llm_oauth_command_json=(
                str(args.llm_oauth_command_json) if args.llm_oauth_command_json else None
            ),
            llm_oauth_browser_login=bool(args.llm_oauth_browser_login),
            llm_oauth_authorize_url=(
                str(args.llm_oauth_authorize_url) if args.llm_oauth_authorize_url else None
            ),
            llm_oauth_token_url=(
                str(args.llm_oauth_token_url) if args.llm_oauth_token_url else None
            ),
            llm_oauth_client_id=(
                str(args.llm_oauth_client_id) if args.llm_oauth_client_id else None
            ),
            llm_oauth_scopes=list(args.llm_oauth_scope or []),
            llm_oauth_redirect_host=str(args.llm_oauth_redirect_host),
            llm_oauth_redirect_port=int(args.llm_oauth_redirect_port),
            llm_oauth_redirect_path=str(args.llm_oauth_redirect_path),
            llm_oauth_cache_file=(
                str(args.llm_oauth_cache_file) if args.llm_oauth_cache_file else None
            ),
            llm_oauth_login_timeout=float(args.llm_oauth_login_timeout),
            llm_oauth_profile_id=(
                str(args.llm_oauth_profile_id) if args.llm_oauth_profile_id else None
            ),
            llm_oauth_profiles_file=(
                str(args.llm_oauth_profiles_file) if args.llm_oauth_profiles_file else None
            ),
            llm_oauth_auto_refresh=not bool(args.llm_oauth_no_auto_refresh),
            llm_timeout=float(args.llm_timeout),
            llm_temperature=float(args.llm_temperature),
            llm_max_output_tokens=int(args.llm_max_output_tokens),
            logger=logger,
        )
    else:
        llm_router = None

    if llm_router is not None:
        logger.info(
            "LLM router enabled: primary=%s, fallbacks=%s, default_provider=%s",
            llm_router.config.primary_model,
            llm_router.config.fallback_models,
            llm_router.config.default_provider,
        )

    llm_callable = llm_router.as_callable() if llm_router is not None else None
    if bool(args.multi_agent):
        session_tree_path = None
        if output_dir is not None:
            session_tree_path = Path(output_dir).resolve() / "agent" / "multi_agent_session_tree.json"
        return MultiAgentDecisionMaker(
            llm_callable=llm_callable,
            safety_grade=args.agent_safety_grade,
            available_tools=available_tools,
            session_tree_path=session_tree_path,
            max_rounds=max(1, int(args.multi_agent_rounds or 1)),
        )
    if llm_callable is None:
        return None
    return AuditDecisionMaker(
        llm_callable=llm_callable,
        safety_grade=args.agent_safety_grade,
        available_tools=available_tools,
    )


def _extract_slow_action_threshold_ms(config: dict[str, Any]) -> int | None:
    """Extract notifier slow-action threshold from config template if present."""
    if not isinstance(config, dict):
        return None
    notifiers = config.get("notifiers")
    if not isinstance(notifiers, dict):
        return None
    for item in notifiers.values():
        if not isinstance(item, dict):
            continue
        event_rules = item.get("event_rules")
        if not isinstance(event_rules, dict):
            continue
        value = event_rules.get("slow_action_threshold_ms")
        try:
            threshold = int(value)
        except (TypeError, ValueError):
            continue
        if threshold > 0:
            return threshold
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Run AutoSecAudit CLI flow."""
    args = build_parser().parse_args(argv)

    output_dir = Path(args.output).resolve()
    log_dir = Path(args.log_dir).resolve() if args.log_dir else (output_dir / "logs").resolve()

    logger = configure_logging(log_dir)
    recorder = OperationRecorder(log_dir / "operations.jsonl", logger)

    builtin_allowlist = ("python", "nslookup", "dig", "ping", "tracert", "host")
    merged_allowlist = tuple(sorted(set(builtin_allowlist + tuple(args.allow_command))))

    if args.mode == "plugins":
        plugin_loader = PluginHotLoader(registry)
        try:
            plugin_loader.load_from_directories(args.plugin_dir or [])
        except Exception as exc:  # noqa: BLE001
            logger.error("Plugin hot-load failed: %s", exc)
            return 2

        config = RuntimeConfig(
            target=args.target,
            output_dir=output_dir,
            log_dir=log_dir,
            enabled_plugins=parse_plugin_ids(args.plugins),
            plugin_timeout_seconds=args.timeout,
            strict_safe_mode=True,
            command_allowlist=merged_allowlist,
        )

        context = AuditContext(
            config=config,
            logger=logger,
            recorder=recorder,
            command_runner=SafeCommandRunner(config.command_allowlist),
        )

        runner = AuditRunner(registry=registry, safety_policy=SafetyPolicy(strict_read_only=True))
        report_writer = ReportWriter()

        try:
            session = runner.run(context)
            artifacts = report_writer.write(session, output_dir)
        except KeyError as exc:
            logger.error(str(exc))
            logger.info("Available plugin IDs: %s", ", ".join(registry.available_ids()))
            return 2
        except Exception as exc:  # noqa: BLE001
            logger.exception("Audit execution failed: %s", exc)
            return 1

        logger.info("Audit report generated: %s", artifacts.json_report)
        logger.info("Audit report generated: %s", artifacts.markdown_report)
        return 0

    try:
        selected_skills = parse_skill_ids(args.skills)
        selected_tools = resolve_selected_tools(
            tool_ids=parse_tool_ids(args.tools),
            skill_ids=selected_skills,
        )
        decision_maker = _build_decision_maker_from_llm_args(
            args,
            logger,
            available_tools=selected_tools,
            output_dir=output_dir,
        )
        llm_config_payload = _read_json_object(args.llm_config)
        notifier = build_notifier_from_config(llm_config_payload, logger=logger) if llm_config_payload else None
        slow_action_threshold_ms = _extract_slow_action_threshold_ms(llm_config_payload) or 15000
        orchestrator = AgentOrchestrator(
            output_dir=output_dir,
            logger=logger,
            recorder=recorder,
            decision_maker=decision_maker,
            safety_grade=args.agent_safety_grade,
            max_iterations=args.max_iterations,
            global_timeout_seconds=args.global_timeout,
            use_llm_hints=not args.no_llm_hints,
            notifier=notifier,
            slow_action_threshold_ms=slow_action_threshold_ms,
            available_tools=selected_tools,
        )
        resume_path = Path(args.resume).resolve() if args.resume else None

        if args.mode == "plan":
            if resume_path is not None:
                state = orchestrator.load_state_from_file(resume_path)
                state = _apply_agent_cve_runtime_flags(state, args)
                result = orchestrator.plan_only(
                    state,
                    plan_filename=args.plan_filename,
                    resumed_from=str(resume_path),
                )
            else:
                state = orchestrator.build_state(
                    target=args.target,
                    scope=parse_scope(args.scope, args.target),
                    budget_remaining=max(0, int(args.budget)),
                    safety_grade=args.agent_safety_grade,
                    report_lang=normalize_report_lang(args.report_lang),
                    breadcrumbs=_read_json_file(args.breadcrumbs_file, list),
                    history=_read_json_file(args.history_file, list),
                    surface=_read_json_file(args.surface_file, dict),
                )
                state = _apply_agent_cve_runtime_flags(state, args)
                result = orchestrator.plan_only(state, plan_filename=args.plan_filename)
        else:
            if resume_path is not None:
                loaded_state = orchestrator.load_state_from_file(resume_path)
                loaded_state = _apply_agent_cve_runtime_flags(loaded_state, args)
                result = orchestrator.run(loaded_state)
            else:
                state = orchestrator.build_state(
                    target=args.target,
                    scope=parse_scope(args.scope, args.target),
                    budget_remaining=max(0, int(args.budget)),
                    safety_grade=args.agent_safety_grade,
                    report_lang=normalize_report_lang(args.report_lang),
                    breadcrumbs=_read_json_file(args.breadcrumbs_file, list),
                    history=_read_json_file(args.history_file, list),
                    surface=_read_json_file(args.surface_file, dict),
                )
                state = _apply_agent_cve_runtime_flags(state, args)
                result = orchestrator.run(state)
    except LLMRouterError as exc:
        logger.error("LLM configuration error: %s", exc)
        return 2
    except Exception as exc:  # noqa: BLE001
        logger.exception("Agent execution failed: %s", exc)
        return 1

    logger.info("Agent decision summary: %s", result.decision_summary)
    logger.info("Action plan: %s", result.action_plan_path)
    logger.info("History: %s", result.history_path)
    logger.info("State: %s", result.state_path)
    logger.info("Blocked actions: %s", result.blocked_actions_path)
    logger.info("Artifact index: %s", result.artifact_index_path)
    logger.info("Markdown report: %s", result.markdown_report_path)
    if result.html_report_path is not None:
        logger.info("HTML visual report: %s", result.html_report_path)
    logger.info("Findings: %s, Budget remaining: %s", result.findings_count, result.budget_remaining)
    logger.info("Resumed: %s, Resumed from: %s", result.resumed, result.resumed_from)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
