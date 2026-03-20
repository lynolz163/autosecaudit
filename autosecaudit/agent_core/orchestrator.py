"""Agent-mode orchestrator composing decision, policy, scheduler, and tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import json
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from autosecaudit.core.logging_utils import OperationRecorder
from autosecaudit.core.models import OperationEvent, utc_now_iso
from autosecaudit.core.report import (
    create_report_snapshot,
    generate_agent_json_report,
    generate_agent_visual_html_report,
    generate_markdown_report,
    normalize_report_lang,
)
from autosecaudit.agent_safety import DEFAULT_AGENT_SAFETY_GRADE, normalize_safety_grade
from autosecaudit.decision import ActionPlan, AuditDecisionMaker, PlannedAction
from autosecaudit.integrations.notifier import BaseNotifier, NoopNotifier, NotificationEvent
from autosecaudit.tools.base_tool import ToolExecutionResult

from .autonomy import apply_autonomy_option_caps, normalize_autonomy_mode
from .builtin_tools import load_builtin_agent_tools
from .agent_memory import AgentMemoryStore
from .audit_pipeline import AuditPipeline
from .circuit_breaker import ToolCircuitBreaker
from .cve_validation_pipeline import CveValidationPipeline
from .evidence_graph import EvidenceGraphBuilder
from .feedback_engine import FeedbackEngine
from .policy import PolicyBlock, PolicyEngine
from .scheduler import Action, ActionScheduler
from .skill_loader import SkillRegistry, load_builtin_skill_registry
from .skill_planner import SkillDrivenPlanner
from .tool_registry import get_tool, list_tools
from .tools import BaseAgentTool


@dataclass(frozen=True)
class AgentRunResult:
    """Summary of one agent-mode execution."""

    decision_summary: str
    action_plan_path: Path
    history_path: Path
    state_path: Path
    blocked_actions_path: Path
    artifact_index_path: Path
    markdown_report_path: Path
    findings_count: int
    history_count: int
    budget_remaining: int
    html_report_path: Path | None = None
    resumed: bool = False
    resumed_from: str | None = None


class AgentOrchestrator:
    """Constrained autonomous agent loop for safe security auditing."""

    def __init__(
        self,
        *,
        output_dir: Path,
        logger: Any,
        recorder: OperationRecorder,
        decision_maker: AuditDecisionMaker | None = None,
        policy_engine: PolicyEngine | None = None,
        safety_grade: str = DEFAULT_AGENT_SAFETY_GRADE,
        max_iterations: int = 3,
        global_timeout_seconds: float = 300.0,
        use_llm_hints: bool = True,
        tool_getter: Callable[[str], BaseAgentTool] | None = None,
        notifier: BaseNotifier | None = None,
        slow_action_threshold_ms: int = 15000,
        pipeline: AuditPipeline | None = None,
        feedback_engine: FeedbackEngine | None = None,
        circuit_breaker: ToolCircuitBreaker | None = None,
        skill_registry: SkillRegistry | None = None,
        skill_planner: SkillDrivenPlanner | None = None,
        memory_store: AgentMemoryStore | None = None,
        available_tools: Sequence[str] | None = None,
    ) -> None:
        self._output_dir = output_dir
        self._logger = logger
        self._recorder = recorder
        self._safety_grade = normalize_safety_grade(safety_grade)
        self._skill_registry = skill_registry if skill_registry is not None else load_builtin_skill_registry()
        self._skill_planner = skill_planner or SkillDrivenPlanner()
        self._decision_maker = decision_maker or AuditDecisionMaker(
            safety_grade=self._safety_grade,
            skill_registry=self._skill_registry,
            skill_planner=self._skill_planner,
            available_tools=available_tools,
        )
        self._policy_engine = policy_engine or PolicyEngine(safety_grade=self._safety_grade)
        self._max_iterations = max(1, int(max_iterations))
        self._global_timeout_seconds = max(10.0, float(global_timeout_seconds))
        self._use_llm_hints = bool(use_llm_hints)
        self._notifier = notifier or NoopNotifier()
        self._slow_action_threshold_ms = max(100, int(slow_action_threshold_ms))
        self._pipeline = pipeline or AuditPipeline()
        self._feedback_engine = feedback_engine or FeedbackEngine(
            skill_registry=self._skill_registry,
            skill_planner=self._skill_planner,
        )
        self._circuit_breaker = circuit_breaker or ToolCircuitBreaker()
        self._memory_store = memory_store or AgentMemoryStore()
        self._evidence_graph_builder = EvidenceGraphBuilder()
        self._cve_validation_pipeline = CveValidationPipeline()

        # Load all builtin tools once; registrations are import side-effects.
        load_builtin_agent_tools()
        self._tool_getter = tool_getter or get_tool

        self._agent_dir = self._output_dir / "agent"
        self._plan_dir = self._agent_dir / "plans"
        self._artifact_dir = self._agent_dir / "artifacts"
        self._memory_context_path = self._agent_dir / "memory_context.json"
        self._target_memory_path = self._agent_dir / "target_memory.json"
        self._agent_dir.mkdir(parents=True, exist_ok=True)
        self._plan_dir.mkdir(parents=True, exist_ok=True)
        self._artifact_dir.mkdir(parents=True, exist_ok=True)

    def build_state(
        self,
        *,
        target: str,
        scope: list[str],
        budget_remaining: int,
        safety_grade: str = DEFAULT_AGENT_SAFETY_GRADE,
        autonomy_mode: str | None = None,
        report_lang: str = "en",
        breadcrumbs: list[dict[str, Any]] | None = None,
        history: list[dict[str, Any]] | None = None,
        surface: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build normalized mutable agent state."""
        normalized_scope = [item.strip() for item in scope if item and item.strip()]
        if not normalized_scope:
            host_seed = self._extract_host_or_token(target)
            if host_seed:
                normalized_scope = [host_seed]

        merged_breadcrumbs = list(breadcrumbs or [])
        normalized_target = self._normalize_url(target)
        if normalized_target:
            merged_breadcrumbs.append({"type": "service", "data": self._origin_of(normalized_target)})
            merged_breadcrumbs.append({"type": "endpoint", "data": normalized_target})
        else:
            merged_breadcrumbs.append({"type": "service", "data": target.strip()})

        state = {
            "scope": normalized_scope,
            "breadcrumbs": self._dedupe_breadcrumbs(merged_breadcrumbs),
            "assets": [],
            "history": list(history or []),
            "surface": surface or {},
            "budget_remaining": max(0, int(budget_remaining)),
            "total_budget": max(0, int(budget_remaining)),
            "target": target,
            "safety_grade": normalize_safety_grade(safety_grade or self._safety_grade),
            "autonomy_mode": normalize_autonomy_mode(
                autonomy_mode,
                safety_grade=safety_grade or self._safety_grade,
            ),
            "report_lang": normalize_report_lang(report_lang),
            "iteration_count": 0,
            "resumed": False,
            "resumed_from": None,
            "current_phase": "passive_recon",
            "phase_budget_spent": {},
            "phase_history": [],
            "feedback": {},
            "findings_count": 0,
            "circuit_breaker": {},
            "findings_preview": [],
            "session_status": "idle",
            "pending_approval": {},
            "loop_guard": {
                "stalled_iterations": 0,
                "last_signature": "",
                "last_reason": "",
                "environment_block_count": 0,
            },
            "thought_stream": [],
            "evidence_graph": {},
            "cve_validation": {},
        }
        normalized = self._pipeline.bootstrap_state(self._normalize_runtime_state(state))
        self._attach_memory_context(normalized)
        return self._refresh_derived_analysis(normalized)

    def load_state_from_file(self, path: Path) -> dict[str, Any]:
        """
        Load and validate persisted agent state.

        Accepts either:
        - direct state file path, or
        - session directory containing `agent_state.json`, or
        - output root containing `agent/agent_state.json`.
        """
        state_path = self._resolve_state_path(path)
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ValueError(f"resume state file not found: {state_path}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"resume state file is not valid JSON: {state_path}") from exc
        except OSError as exc:
            raise ValueError(f"failed to read resume state file: {state_path}: {exc}") from exc

        if not isinstance(payload, dict):
            raise ValueError(f"resume state must be a JSON object: {state_path}")

        required = ("history", "breadcrumbs", "budget_remaining", "scope")
        missing = [key for key in required if key not in payload]
        if missing:
            raise ValueError(f"resume state missing required field(s): {', '.join(missing)}")

        if not isinstance(payload.get("history"), list):
            raise ValueError("resume state field `history` must be a list")
        if not isinstance(payload.get("breadcrumbs"), list):
            raise ValueError("resume state field `breadcrumbs` must be a list")
        if not isinstance(payload.get("scope"), list):
            raise ValueError("resume state field `scope` must be a list")
        if not isinstance(payload.get("surface", {}), dict):
            raise ValueError("resume state field `surface` must be an object when present")

        try:
            payload["budget_remaining"] = max(0, int(float(payload.get("budget_remaining", 0))))
        except (TypeError, ValueError) as exc:
            raise ValueError("resume state field `budget_remaining` must be numeric") from exc

        iteration_value = payload.get("iteration_count", len(payload.get("history", [])))
        try:
            payload["iteration_count"] = max(0, int(iteration_value))
        except (TypeError, ValueError) as exc:
            raise ValueError("resume state field `iteration_count` must be numeric") from exc

        payload.setdefault("surface", {})
        payload.setdefault("target", "")
        payload["safety_grade"] = normalize_safety_grade(payload.get("safety_grade", self._safety_grade))
        payload["report_lang"] = normalize_report_lang(payload.get("report_lang", "en"))
        payload["resumed"] = True
        payload["resumed_from"] = str(state_path)
        payload.setdefault("feedback", {})
        payload.setdefault("findings_count", 0)
        payload.setdefault("circuit_breaker", {})
        payload.setdefault("findings_preview", [])
        payload.setdefault("session_status", "idle")
        payload.setdefault("pending_approval", {})
        payload.setdefault(
            "loop_guard",
            {
                "stalled_iterations": 0,
                "last_signature": "",
                "last_reason": "",
                "environment_block_count": 0,
            },
        )
        payload.setdefault("thought_stream", [])
        payload.setdefault("evidence_graph", {})
        payload.setdefault("cve_validation", {})
        normalized = self._pipeline.bootstrap_state(self._normalize_runtime_state(payload))
        self._attach_memory_context(normalized)
        return self._refresh_derived_analysis(normalized)

    def plan_only(
        self,
        state: dict[str, Any],
        plan_filename: str = "ActionPlan.json",
        resumed_from: str | None = None,
    ) -> AgentRunResult:
        """Generate policy-filtered action plan JSON and exit without execution."""
        if resumed_from:
            state["resumed"] = True
            state["resumed_from"] = resumed_from
        self._normalize_runtime_state(state)
        self._pipeline.bootstrap_state(state)
        self._attach_memory_context(state)
        self._refresh_derived_analysis(state)

        raw_plan, allowed_actions, blocked = self._request_and_filter_plan(state)

        scheduler = ActionScheduler(budget_remaining=int(state.get("budget_remaining", 0)))
        for action in allowed_actions:
            scheduler.enqueue(action)

        selected: list[PlannedAction] = []
        while scheduler.has_next():
            action = scheduler.pop_next()
            if action is None:
                break
            selected.append(self._to_planned_action(action))

        final_summary = raw_plan.decision_summary
        if blocked:
            final_summary += f" Blocked actions: {len(blocked)}."
        if len(selected) != len(getattr(raw_plan, "actions", [])):
            final_summary += f" Executable actions after environment checks: {len(selected)}."

        final_plan = ActionPlan(decision_summary=final_summary, actions=selected)
        plan_path = self._agent_dir / plan_filename
        self._write_json(plan_path, self._plan_to_dict(final_plan))

        blocked_path = self._agent_dir / "blocked_actions.json"
        blocked_payload = [self._blocked_to_dict(item) for item in blocked]
        self._write_json(blocked_path, blocked_payload)

        history_path = self._agent_dir / "agent_history.json"
        state_path = self._agent_dir / "agent_state.json"
        artifact_index_path = self._agent_dir / "artifact_index.json"
        markdown_report_path = self._agent_dir / "agent_report.md"
        self._write_json(history_path, state.get("history", []))
        self._write_json(self._memory_context_path, state.get("memory_context", {}))
        self._write_json(state_path, state)
        self._write_json(artifact_index_path, [])
        generate_markdown_report(
            [],
            str(markdown_report_path),
            evidence_graph=state.get("evidence_graph", {}),
            report_lang=str(state.get("report_lang", "en")),
            history_data=state.get("history", []),
            blocked_actions=blocked_payload,
            state_data=state,
            decision_summary=final_plan.decision_summary,
        )
        html_report_path = self._agent_dir / "agent_report.html"
        audit_report_json_path = self._agent_dir / "audit_report.json"
        json_payload = generate_agent_json_report(
            findings=[],
            state=state,
            output_path=audit_report_json_path,
            decision_summary=final_plan.decision_summary,
            report_lang=str(state.get("report_lang", "en")),
            blocked_actions=blocked_payload,
        )
        generate_agent_visual_html_report(
            audit_report_json_path=audit_report_json_path,
            agent_state_json_path=state_path,
            output_html_path=html_report_path,
        )
        self._append_run_metadata_to_report(
            markdown_report_path=markdown_report_path,
            resumed=bool(state.get("resumed", False)),
            resumed_from=state.get("resumed_from"),
            start_iteration=int(state.get("iteration_count", 0)) + 1,
            start_budget=int(state.get("budget_remaining", 0)),
        )
        snapshot_markdown_path, snapshot_html_path = self._capture_report_snapshots(
            target=str(state.get("target", "")),
            markdown_report_path=markdown_report_path,
            html_report_path=html_report_path,
            audit_report_json_path=audit_report_json_path,
        )

        self._record_operation(
            plugin_id="agent",
            action="plan_only",
            status="success",
            detail="Plan generated without execution.",
        )
        self._safe_flush_notifier()

        return AgentRunResult(
            decision_summary=final_plan.decision_summary,
            action_plan_path=plan_path,
            history_path=history_path,
            state_path=state_path,
            blocked_actions_path=blocked_path,
            artifact_index_path=artifact_index_path,
            markdown_report_path=snapshot_markdown_path,
            html_report_path=snapshot_html_path,
            findings_count=0,
            history_count=len(state.get("history", [])),
            budget_remaining=int(state.get("budget_remaining", 0)),
            resumed=bool(state.get("resumed", False)),
            resumed_from=state.get("resumed_from"),
        )

    def run(
        self,
        state: dict[str, Any] | None = None,
        *,
        resume_path: Path | None = None,
    ) -> AgentRunResult:
        """Execute constrained decision loop and produce final artifacts."""
        if resume_path is not None:
            state = self.load_state_from_file(resume_path)
        if state is None:
            raise ValueError("state is required when resume_path is not provided")
        self._normalize_runtime_state(state)
        self._pipeline.bootstrap_state(state)

        started = time.perf_counter()
        artifact_index: list[dict[str, Any]] = []
        blocked_actions: list[PolicyBlock] = []
        blocked_signatures: set[tuple[str, str]] = set()
        all_findings: list[dict[str, Any]] = []
        final_plan = ActionPlan(decision_summary="No actions planned.", actions=[])

        resumed = bool(state.get("resumed", False))
        resumed_from = str(state.get("resumed_from") or "") or None
        start_iteration = int(state.get("iteration_count", len(state.get("history", [])))) + 1
        start_budget = int(state.get("budget_remaining", 0))
        final_stop_reason = ""
        state["session_status"] = "running"
        state["pending_approval"] = {}
        state.setdefault("thought_stream", [])

        self._record_operation(
            plugin_id="agent",
            action="run_start",
            status="start",
            detail=(
                f"budget={state.get('budget_remaining', 0)}, "
                f"max_iterations={self._max_iterations}, timeout={self._global_timeout_seconds}s, "
                f"resumed={resumed}"
            ),
        )

        if resumed and resumed_from:
            self._record_operation(
                plugin_id="agent",
                action="run_resume",
                status="info",
                detail=(
                    f"Resuming from {resumed_from}; "
                    f"start_iteration={start_iteration}, budget={start_budget}"
                ),
            )

        for iteration in range(start_iteration, self._max_iterations + 1):
            self._attach_memory_context(state, findings=all_findings)
            self._refresh_derived_analysis(state, findings=all_findings)
            if self._is_timed_out(started):
                final_stop_reason = "timeout"
                self._record_operation(
                    plugin_id="agent",
                    action="run_stop",
                    status="warning",
                    detail="Global timeout reached.",
                )
                break

            if int(state.get("budget_remaining", 0)) <= 0:
                final_stop_reason = "budget_exhausted"
                self._record_operation(
                    plugin_id="agent",
                    action="run_stop",
                    status="warning",
                    detail="Budget exhausted.",
                )
                break

            available_tools = self._discover_available_tool_names()
            transition = self._pipeline.evaluate_transition(state, available_tools=available_tools)
            current_phase = transition.phase
            phase_budget_remaining = self._pipeline.phase_budget_remaining(state, current_phase.name)
            effective_iteration_budget = min(int(state.get("budget_remaining", 0)), phase_budget_remaining)
            if transition.changed:
                self._record_operation(
                    plugin_id="agent",
                    action="phase_transition",
                    status="info",
                    detail=f"phase={current_phase.name} reason={transition.reason}",
                )
                self._emit_reasoning_event(
                    state,
                    kind="strategy_shift",
                    summary=f"Shifted into phase `{current_phase.name}`.",
                    phase_name=current_phase.name,
                    status="info",
                    context={"reason": transition.reason},
                )
            if effective_iteration_budget <= 0:
                final_stop_reason = "phase_budget_exhausted"
                self._record_operation(
                    plugin_id="agent",
                    action="iteration_stop",
                    status="warning",
                    detail=f"Iteration {iteration}: phase budget exhausted for {current_phase.name}.",
                )
                if transition.changed:
                    continue
                break

            plan_state = dict(state)
            plan_state["budget_remaining"] = effective_iteration_budget
            raw_plan, allowed_actions, blocked = self._request_and_filter_plan(
                plan_state,
                available_tools=self._pipeline.allowed_tools(state, available_tools),
            )
            new_blocked: list[PolicyBlock] = []
            for item in blocked:
                signature = (item.action.idempotency_key, str(item.reason))
                if signature in blocked_signatures:
                    continue
                blocked_signatures.add(signature)
                blocked_actions.append(item)
                new_blocked.append(item)
            self._notify_blocked_actions(new_blocked, state=state, phase="policy")

            scheduler = ActionScheduler(budget_remaining=int(state.get("budget_remaining", 0)))
            for action in allowed_actions:
                scheduler.enqueue(action)

            scheduled_actions: list[PlannedAction] = []
            execution_order: list[Action] = []
            while scheduler.has_next():
                action = scheduler.pop_next()
                if action is None:
                    break
                execution_order.append(action)
                scheduled_actions.append(self._to_planned_action(action))
            self._notify_scheduler_budget_skips(scheduler.skipped_by_budget, state=state)

            final_plan = ActionPlan(
                decision_summary=self._compose_iteration_summary(
                    raw_summary=raw_plan.decision_summary,
                    planned_count=len(getattr(raw_plan, "actions", [])),
                    executable_count=len(scheduled_actions),
                    blocked_count=len(blocked),
                    phase_name=current_phase.name,
                ),
                actions=scheduled_actions,
            )
            plan_path = self._plan_dir / f"iteration_{iteration:02d}_plan.json"
            self._write_json(plan_path, self._plan_to_dict(final_plan))
            self._emit_reasoning_event(
                state,
                kind="thought",
                summary=(
                    f"Iteration {iteration} planned {len(getattr(raw_plan, 'actions', []))} action(s); "
                    f"{len(scheduled_actions)} executable, {len(new_blocked)} blocked."
                ),
                phase_name=current_phase.name,
                status="info",
                context={
                    "decision_summary": final_plan.decision_summary,
                    "blocked_count": len(new_blocked),
                    "executable_count": len(scheduled_actions),
                    "planned_count": len(getattr(raw_plan, "actions", [])),
                },
            )

            pending_approval = self._build_pending_approval(state, blocked=new_blocked, phase_name=current_phase.name)
            if pending_approval and not execution_order:
                state["session_status"] = "waiting_approval"
                state["pending_approval"] = pending_approval
                final_stop_reason = "approval_pending"
                self._emit_reasoning_event(
                    state,
                    kind="approval_pending",
                    summary="High-risk follow-up actions are ready and require operator approval.",
                    phase_name=current_phase.name,
                    status="warning",
                    context=pending_approval,
                )

            if not execution_order:
                if state.get("session_status") != "waiting_approval" and self._blocked_actions_are_environmental(new_blocked):
                    state["session_status"] = "environment_blocked"
                    final_stop_reason = "environment_blocked"
                    self._emit_reasoning_event(
                        state,
                        kind="loop_break",
                        summary="No executable actions remain because the environment is blocking all next steps.",
                        phase_name=current_phase.name,
                        status="warning",
                        context={"blocked_reasons": [str(item.reason) for item in new_blocked]},
                    )
                state["iteration_count"] = iteration
                self._flush_iteration_state(state, artifact_index, blocked_actions, final_plan)
                self._record_operation(
                    plugin_id="agent",
                    action="iteration_stop",
                    status="warning",
                    detail=f"Iteration {iteration}: no executable actions after policy/scheduler.",
                )
                break

            executed_count = 0
            pause_requested = False
            iteration_findings = 0
            iteration_breadcrumb_delta = 0
            iteration_asset_delta = 0
            iteration_surface_delta = 0
            iteration_errors: list[str] = []
            for action in execution_order:
                if self._is_timed_out(started):
                    final_stop_reason = "timeout"
                    self._record_operation(
                        plugin_id="agent",
                        action="run_stop",
                        status="warning",
                        detail="Global timeout reached during execution.",
                    )
                    break

                self._emit_reasoning_event(
                    state,
                    kind="thought",
                    summary=f"Select `{action.tool_name}` for `{action.target}`.",
                    phase_name=current_phase.name,
                    action=action,
                    status="info",
                    context={
                        "reason": action.reason,
                        "priority": action.priority,
                        "cost": action.cost,
                        "preconditions": list(action.preconditions),
                    },
                )
                prior_budget = int(state.get("budget_remaining", 0))
                result = self._execute_action(action, phase_name=current_phase.name, state=state)
                executed_count += 1

                result["history_record"]["action_cost"] = int(action.cost)
                result["history_record"]["budget_before"] = prior_budget
                state["budget_remaining"] = scheduler.budget_remaining
                self._pipeline.record_spend(state, current_phase.name, int(action.cost))
                result["history_record"]["budget_after"] = int(state["budget_remaining"])
                state["history"].append(result["history_record"])
                artifact_index.extend(result["artifacts"])
                all_findings.extend(result["findings"])
                state["findings_preview"] = list(all_findings[-8:])
                iteration_findings += len(result["findings"])
                iteration_breadcrumb_delta += len(result["breadcrumbs_delta"])
                iteration_asset_delta += len(result.get("assets_delta", []))
                iteration_surface_delta += len(result["surface_delta"])
                if result["history_record"].get("error"):
                    iteration_errors.append(str(result["history_record"]["error"]))

                state["breadcrumbs"] = self._merge_breadcrumbs(
                    state.get("breadcrumbs", []),
                    result["breadcrumbs_delta"],
                )
                state["assets"] = self._merge_assets(
                    state.get("assets", []),
                    result.get("assets_delta", []),
                )
                state["surface"] = self._merge_surface(
                    state.get("surface", {}),
                    result["surface_delta"],
                )
                self._normalize_runtime_state(state)
                state["findings_count"] = len(all_findings)
                self._refresh_derived_analysis(state, findings=all_findings)
                feedback_update = self._feedback_engine.build_feedback(
                    history=state.get("history", []),
                    surface=state.get("surface", {}),
                    findings=result["findings"],
                    tool_follow_up_hints=result.get("follow_up_hints", []),
                )
                state["feedback"] = self._feedback_engine.merge_feedback(
                    state.get("feedback", {}),
                    feedback_update,
                )
                state["circuit_breaker"] = self._circuit_breaker.snapshot()
                self._emit_reasoning_event(
                    state,
                    kind="observation",
                    summary=(
                        f"`{action.tool_name}` finished with status `{result['history_record'].get('status', 'unknown')}` "
                        f"and produced {len(result['findings'])} finding(s)."
                    ),
                    phase_name=current_phase.name,
                    action=action,
                    status=str(result["history_record"].get("status", "info")),
                    context={
                        "error": result["history_record"].get("error"),
                        "finding_count": len(result["findings"]),
                        "breadcrumb_delta": len(result["breadcrumbs_delta"]),
                        "asset_delta": len(result.get("assets_delta", [])),
                        "surface_delta_keys": sorted(result["surface_delta"].keys()),
                    },
                )
                risk_signal = str(state.get("feedback", {}).get("risk_signal", "none")).strip().lower()
                pause_from_risk, stop_reason = self._apply_risk_signal_controls(
                    state,
                    risk_signal=risk_signal,
                    phase_name=current_phase.name,
                    action=action,
                )
                if pause_from_risk:
                    pause_requested = True
                    final_stop_reason = stop_reason or final_stop_reason
                    break

            should_break, loop_reason = self._evaluate_loop_guard(
                state,
                phase_name=current_phase.name,
                executed_count=executed_count,
                blocked=new_blocked,
                error_messages=iteration_errors,
                finding_count=iteration_findings,
                breadcrumb_delta=iteration_breadcrumb_delta,
                asset_delta=iteration_asset_delta,
                surface_delta=iteration_surface_delta,
            )
            if should_break:
                final_stop_reason = "environment_blocked"
            state["iteration_count"] = iteration
            self._flush_iteration_state(state, artifact_index, blocked_actions, final_plan)

            if should_break or executed_count == 0 or pause_requested:
                break

        history_path = self._agent_dir / "agent_history.json"
        state_path = self._agent_dir / "agent_state.json"
        artifact_index_path = self._agent_dir / "artifact_index.json"
        blocked_actions_path = self._agent_dir / "blocked_actions.json"
        action_plan_path = self._agent_dir / "ActionPlan.json"
        markdown_report_path = self._agent_dir / "agent_report.md"
        html_report_path = self._agent_dir / "agent_report.html"
        audit_report_json_path = self._agent_dir / "audit_report.json"

        if state.get("session_status") == "running":
            state["session_status"] = self._finalize_session_status(
                state,
                final_stop_reason=final_stop_reason,
            )

        persisted_memory = self._persist_target_memory(state, findings=all_findings)
        self._write_json(history_path, state.get("history", []))
        self._write_json(self._memory_context_path, state.get("memory_context", {}))
        self._write_json(self._target_memory_path, persisted_memory)
        self._write_json(state_path, state)
        self._write_json(artifact_index_path, artifact_index)
        blocked_payload = [self._blocked_to_dict(item) for item in blocked_actions]
        self._write_json(blocked_actions_path, blocked_payload)
        self._write_json(action_plan_path, self._plan_to_dict(final_plan))
        json_payload = generate_agent_json_report(
            findings=all_findings,
            state=state,
            output_path=audit_report_json_path,
            decision_summary=final_plan.decision_summary,
            report_lang=str(state.get("report_lang", "en")),
            blocked_actions=blocked_payload,
        )
        generate_markdown_report(
            all_findings,
            str(markdown_report_path),
            recon_data=json_payload.get("recon"),
            evidence_graph=json_payload.get("evidence_graph"),
            report_lang=str(state.get("report_lang", "en")),
            coverage_data=json_payload.get("coverage"),
            history_data=json_payload.get("history"),
            blocked_actions=blocked_payload,
            state_data=state,
            decision_summary=final_plan.decision_summary,
        )
        generate_agent_visual_html_report(
            audit_report_json_path=audit_report_json_path,
            agent_state_json_path=state_path,
            output_html_path=html_report_path,
        )
        self._append_run_metadata_to_report(
            markdown_report_path=markdown_report_path,
            resumed=resumed,
            resumed_from=resumed_from,
            start_iteration=start_iteration,
            start_budget=start_budget,
        )
        snapshot_markdown_path, snapshot_html_path = self._capture_report_snapshots(
            target=str(state.get("target", "")),
            markdown_report_path=markdown_report_path,
            html_report_path=html_report_path,
            audit_report_json_path=audit_report_json_path,
        )

        self._record_operation(
            plugin_id="agent",
            action="run_end",
            status="success",
            detail=(
                f"history={len(state.get('history', []))}, findings={len(all_findings)}, "
                f"session_status={state.get('session_status', 'completed')}"
            ),
        )
        self._safe_flush_notifier()

        return AgentRunResult(
            decision_summary=final_plan.decision_summary,
            action_plan_path=action_plan_path,
            history_path=history_path,
            state_path=state_path,
            blocked_actions_path=blocked_actions_path,
            artifact_index_path=artifact_index_path,
            markdown_report_path=snapshot_markdown_path,
            html_report_path=snapshot_html_path,
            findings_count=len(all_findings),
            history_count=len(state.get("history", [])),
            budget_remaining=int(state.get("budget_remaining", 0)),
            resumed=resumed,
            resumed_from=resumed_from,
        )

    def _attach_memory_context(
        self,
        state: dict[str, Any],
        *,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Attach compact local memory context for planning and reporting."""
        if not isinstance(state, dict):
            return {}
        target = str(state.get("target", "")).strip()
        persisted_memory = self._memory_store.load(target=target) if target else {}
        state["memory_context"] = self._memory_store.build_memory_context(
            state=state,
            persisted_memory=persisted_memory,
            findings=findings,
        )
        return state

    def _refresh_evidence_graph(
        self,
        state: dict[str, Any],
        *,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Rebuild evidence correlation graph from current runtime state."""
        if not isinstance(state, dict):
            return {}
        safe_findings = findings if isinstance(findings, list) else state.get("findings_preview", [])
        if not isinstance(safe_findings, list):
            safe_findings = []
        state["evidence_graph"] = self._evidence_graph_builder.build(
            state=state,
            findings=safe_findings,
        )
        return state

    def _refresh_derived_analysis(
        self,
        state: dict[str, Any],
        *,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Refresh corroboration and staged-validation views used across the platform."""
        safe_findings = findings if isinstance(findings, list) else state.get("findings_preview", [])
        if not isinstance(safe_findings, list):
            safe_findings = []
        try:
            self._refresh_evidence_graph(state, findings=safe_findings)
            state["cve_validation"] = self._cve_validation_pipeline.build(
                state=state,
                findings=safe_findings,
            )
            if isinstance(state.get("analysis_errors"), list):
                state["analysis_errors"] = []
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            analysis_errors = state.get("analysis_errors", [])
            if not isinstance(analysis_errors, list):
                analysis_errors = []
            analysis_errors.append(error_text)
            state["analysis_errors"] = analysis_errors[-5:]
            state.setdefault("evidence_graph", {})
            state.setdefault("cve_validation", {})
            self._record_operation(
                plugin_id="agent",
                action="analysis_refresh_error",
                status="warning",
                detail=error_text,
            )
        return state

    def _persist_target_memory(
        self,
        state: dict[str, Any],
        *,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Persist long-term target memory and refresh in-state memory context."""
        target = str(state.get("target", "")).strip()
        if not target:
            return {}
        persisted = self._memory_store.persist(
            target=target,
            state=state,
            findings=findings,
        )
        state["memory_context"] = self._memory_store.build_memory_context(
            state=state,
            persisted_memory=persisted,
            findings=findings,
        )
        return persisted

    def _request_and_filter_plan(
        self,
        state: dict[str, Any],
        *,
        available_tools: list[str] | None = None,
    ) -> tuple[ActionPlan, list[Action], list[PolicyBlock]]:
        """Request action plan from decision maker and filter via policy engine."""
        active_tools = list(available_tools or self._discover_available_tool_names())
        raw_plan = self._decision_maker.plan_from_state(
            state,
            use_llm_hints=self._use_llm_hints,
            available_tools=active_tools,
        )
        allowed, blocked = self._policy_engine.validate_plan(raw_plan, state, tool_getter=self._tool_getter)
        available_allowed, availability_blocked = self._filter_unavailable_actions(allowed)
        if availability_blocked:
            blocked = [*blocked, *availability_blocked]
        circuit_allowed, circuit_blocked = self._filter_open_circuit_actions(available_allowed)
        if circuit_blocked:
            blocked = [*blocked, *circuit_blocked]
        return raw_plan, circuit_allowed, blocked

    def _discover_available_tool_names(self) -> list[str]:
        """List tools that are currently runnable in this environment."""
        available: list[str] = []
        for tool_name in list_tools():
            try:
                tool = self._tool_getter(tool_name)
                is_available, _reason = tool.check_availability()
            except Exception:  # noqa: BLE001
                continue
            if is_available:
                available.append(tool_name)
        return available

    def _filter_unavailable_actions(
        self,
        actions: list[Action],
    ) -> tuple[list[Action], list[PolicyBlock]]:
        """
        Remove actions whose tools are not runnable in the current environment.

        This prevents avoidable runtime failures (missing local dependencies like
        Playwright/dirsearch/nmap) from consuming execution slots and budget.
        """
        allowed: list[Action] = []
        blocked: list[PolicyBlock] = []
        for action in actions:
            try:
                tool = self._tool_getter(action.tool_name)
                is_available, reason = tool.check_availability()
            except KeyError:
                blocked.append(PolicyBlock(action=action, reason="tool_not_registered"))
                continue
            except Exception as exc:  # noqa: BLE001
                blocked.append(
                    PolicyBlock(
                        action=action,
                        reason=f"tool_availability_check_failed:{type(exc).__name__}:{exc}",
                    )
                )
                continue

            if not is_available:
                blocked.append(
                    PolicyBlock(
                        action=action,
                        reason=f"tool_unavailable:{reason or 'unknown'}",
                    )
                )
                continue
            allowed.append(action)
        return allowed, blocked

    def _compose_iteration_summary(
        self,
        *,
        raw_summary: str,
        planned_count: int,
        executable_count: int,
        blocked_count: int,
        phase_name: str,
    ) -> str:
        """Append execution-context counts to planner summary for clearer operator feedback."""
        summary = f"[phase:{phase_name}] {raw_summary}"
        if blocked_count > 0 and "Blocked actions:" not in summary:
            summary += f" Blocked actions: {blocked_count}."
        if executable_count != planned_count:
            summary += f" Executable actions after environment checks: {executable_count}."
        return summary

    def _filter_open_circuit_actions(
        self,
        actions: list[Action],
    ) -> tuple[list[Action], list[PolicyBlock]]:
        """Block actions whose tool circuit is currently open."""
        allowed: list[Action] = []
        blocked: list[PolicyBlock] = []
        for action in actions:
            can_execute, reason = self._circuit_breaker.can_execute(action.tool_name)
            if not can_execute:
                blocked.append(PolicyBlock(action=action, reason=reason or "circuit_open"))
                continue
            allowed.append(action)
        return allowed, blocked

    def _execute_action(
        self,
        action: Action,
        phase_name: str | None = None,
        state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute one action via tool registry and collect history + artifacts."""
        started_at = utc_now_iso()
        started_clock = time.perf_counter()
        status = "error"
        error: str | None = None
        payload: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        breadcrumbs_delta: list[dict[str, str]] = []
        assets_delta: list[dict[str, Any]] = []
        surface_delta: dict[str, Any] = {}
        follow_up_hints: list[str] = []
        metadata: dict[str, Any] = {}
        tool_result: ToolExecutionResult | None = None
        attempts = 0
        autonomy_adjustments: list[str] = []
        retry_policy: dict[str, Any] = {"max_retries": 0, "backoff_seconds": 0.0, "retryable_errors": set()}
        last_retryable_error = False

        self._record_operation(
            plugin_id=action.tool_name,
            action="action_start",
            status="start",
            detail=f"{action.action_id} target={action.target}",
        )

        try:
            tool = self._tool_getter(action.tool_name)
            effective_options, autonomy_adjustments = self._apply_autonomy_execution_caps(
                action=action,
                state=state,
            )
            if autonomy_adjustments:
                action.options = effective_options
                action.idempotency_key = self._policy_engine.compute_idempotency_key(
                    action.tool_name,
                    action.target,
                    action.options,
                )
            can_execute, circuit_reason = self._circuit_breaker.can_execute(action.tool_name)
            if not can_execute:
                raise RuntimeError(circuit_reason or f"circuit open for {action.tool_name}")

            retry_policy = self._retry_policy_for_tool(tool)
            max_attempts = max(1, int(retry_policy.get("max_retries", 0)) + 1)
            backoff_seconds = float(retry_policy.get("backoff_seconds", 0.0) or 0.0)
            for attempts in range(1, max_attempts + 1):
                try:
                    tool_result = tool.run(target=action.target, options=action.options or {})
                    normalized = self._normalize_tool_result(tool_result)
                    skill = self._skill_registry.for_tool(action.tool_name) if self._skill_registry else None
                    if skill is not None:
                        normalized = self._skill_planner.interpret_result(skill, normalized)
                    status = normalized["status"]
                    error = normalized["error"]
                    payload = normalized["payload"]
                    findings = normalized["findings"]
                    breadcrumbs_delta = normalized["breadcrumbs_delta"]
                    assets_delta = normalized["assets_delta"]
                    surface_delta = normalized["surface_delta"]
                    follow_up_hints = normalized["follow_up_hints"]
                    metadata = normalized["metadata"]
                    last_retryable_error = self._is_retryable_error(error, retry_policy)
                    if status == "error" and last_retryable_error and attempts < max_attempts:
                        time.sleep(backoff_seconds * attempts)
                        continue
                    break
                except Exception as exc:  # noqa: BLE001
                    error = str(exc)
                    payload = {"error": error}
                    status = "error"
                    last_retryable_error = self._is_retryable_error(error, retry_policy)
                    if last_retryable_error and attempts < max_attempts:
                        time.sleep(backoff_seconds * attempts)
                        continue
                    break
            if status == "completed":
                self._circuit_breaker.record_success(action.tool_name)
            else:
                self._circuit_breaker.record_failure(action.tool_name, error)
        except KeyError:
            error = f"tool not registered: {action.tool_name}"
            payload = {"error": error}
            status = "error"
            self._circuit_breaker.record_failure(action.tool_name, error)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            payload = {"error": str(exc)}
            status = "error"
            self._circuit_breaker.record_failure(action.tool_name, error)

        ended_at = utc_now_iso()
        measured_duration_ms = int((time.perf_counter() - started_clock) * 1000)
        duration_ms = tool_result.duration_ms if tool_result and tool_result.duration_ms > 0 else measured_duration_ms
        ranking_explanation = self._build_ranking_explanation(
            tool_name=action.tool_name,
            target=action.target,
            options=action.options,
            metadata=metadata,
            action_reason=action.reason,
            preconditions=action.preconditions,
            phase_name=phase_name,
        )
        action_payload = action.to_dict()
        if ranking_explanation:
            action_payload["ranking_explanation"] = ranking_explanation
        if autonomy_adjustments:
            action_payload["autonomy_adjustments"] = list(autonomy_adjustments)
        retry_metadata = {
            "max_retries": int(retry_policy.get("max_retries", 0) or 0),
            "attempts": attempts,
            "retryable_error": bool(last_retryable_error),
            "final_attempt": attempts >= max(1, int(retry_policy.get("max_retries", 0) or 0) + 1),
            "backoff_seconds": float(retry_policy.get("backoff_seconds", 0.0) or 0.0),
        }
        artifact_payload = {
            "action": action_payload,
            "status": status,
            "error": error,
            "duration_ms": duration_ms,
            "attempts": attempts,
            "retry": retry_metadata,
            "result": payload,
            "metadata": metadata,
            "tool_result": asdict(tool_result) if tool_result is not None else None,
        }
        if ranking_explanation:
            artifact_payload["ranking_explanation"] = ranking_explanation
        if autonomy_adjustments:
            artifact_payload["autonomy_adjustments"] = list(autonomy_adjustments)
        artifact_path = self._write_action_artifact(action, artifact_payload)

        history_record = {
            "tool": action.tool_name,
            "target": action.target,
            "options": action.options,
            "idempotency_key": action.idempotency_key,
            "reason": action.reason,
            "preconditions": list(action.preconditions),
            "status": status,
            "started_at": started_at,
            "ended_at": ended_at,
            "retry_attempts": attempts,
            "retry": retry_metadata,
            "artifacts": [str(artifact_path)],
        }
        if phase_name:
            history_record["phase"] = str(phase_name).strip()
        if ranking_explanation:
            history_record["ranking_explanation"] = ranking_explanation
        compact_metadata = self._compact_history_metadata(metadata)
        if compact_metadata:
            history_record["metadata_summary"] = compact_metadata
        if autonomy_adjustments:
            history_record["autonomy_adjustments"] = list(autonomy_adjustments)
        if error:
            history_record["error"] = error

        op_status = "success" if status == "completed" else ("warning" if status == "failed" else "error")
        self._record_operation(
            plugin_id=action.tool_name,
            action="action_end",
            status=op_status,
            detail=f"{action.action_id} status={status} duration_ms={duration_ms}",
        )
        self._notify_action_result(
            action=action,
            status=status,
            error=error,
            findings=findings,
            duration_ms=duration_ms,
        )

        return {
            "history_record": history_record,
            "artifacts": [{"action_id": action.action_id, "path": str(artifact_path)}],
            "findings": findings,
            "breadcrumbs_delta": breadcrumbs_delta,
            "assets_delta": assets_delta,
            "surface_delta": surface_delta,
            "follow_up_hints": follow_up_hints,
            "metadata": metadata,
            "duration_ms": duration_ms,
        }

    def _apply_autonomy_execution_caps(
        self,
        *,
        action: Action,
        state: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], list[str]]:
        runtime_state = state if isinstance(state, dict) else {}
        surface = runtime_state.get("surface", {}) if isinstance(runtime_state.get("surface", {}), dict) else {}
        autonomy_mode = normalize_autonomy_mode(
            runtime_state.get("autonomy_mode", surface.get("autonomy_mode", None)),
            safety_grade=runtime_state.get("safety_grade", self._safety_grade),
        )
        return apply_autonomy_option_caps(
            tool_name=action.tool_name,
            options=action.options,
            autonomy_mode=autonomy_mode,
        )

    def _normalize_tool_result(self, result: ToolExecutionResult) -> dict[str, Any]:
        data: Any = result.data
        if hasattr(data, "to_data") and callable(data.to_data):
            data = data.to_data()
        elif is_dataclass(data):
            data = asdict(data)
        elif not isinstance(data, dict):
            data = {}

        status = str(data.get("status", "completed" if result.ok else "failed")).strip().lower()
        if status not in {"completed", "failed", "error"}:
            status = "completed" if result.ok else "failed"
        if result.error and status == "completed":
            status = "error"

        payload = data.get("payload", data)
        findings = data.get("findings", [])
        breadcrumbs_delta = data.get("breadcrumbs_delta", [])
        assets_delta = data.get("assets_delta", [])
        surface_delta = data.get("surface_delta", {})
        follow_up_hints = data.get("follow_up_hints", [])
        metadata = data.get("metadata", {})

        if not isinstance(payload, dict):
            payload = {"value": payload}
        if not isinstance(findings, list):
            findings = []
        if not isinstance(breadcrumbs_delta, list):
            breadcrumbs_delta = []
        if not isinstance(assets_delta, list):
            assets_delta = []
        if not isinstance(surface_delta, dict):
            surface_delta = {}
        if not isinstance(follow_up_hints, list):
            follow_up_hints = []
        if not isinstance(metadata, dict):
            metadata = {}

        return {
            "status": status,
            "error": result.error,
            "payload": payload,
            "findings": findings,
            "breadcrumbs_delta": breadcrumbs_delta,
            "assets_delta": assets_delta,
            "surface_delta": surface_delta,
            "follow_up_hints": [str(item).strip() for item in follow_up_hints if str(item).strip()],
            "metadata": metadata,
        }

    @staticmethod
    def _compact_history_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
        """Keep only ranking/execution hints that are useful in report history."""
        if not isinstance(metadata, dict):
            return {}
        keys = (
            "component",
            "version",
            "service",
            "port",
            "candidate_order",
            "verification_order",
            "selected_templates",
            "template",
            "rag_recommended_tools",
            "requested_cve_ids",
            "safe_only",
            "allow_high_risk",
            "safety_grade",
        )
        compact: dict[str, Any] = {}
        for key in keys:
            value = metadata.get(key)
            if value in (None, "", [], {}):
                continue
            compact[key] = value
        return compact

    def _apply_risk_signal_controls(
        self,
        state: dict[str, Any],
        *,
        risk_signal: str,
        phase_name: str,
        action: Action,
    ) -> tuple[bool, str | None]:
        """Apply post-observation risk controls without mutating requested safety grade."""
        normalized_signal = str(risk_signal).strip().lower()
        if normalized_signal == "tighten":
            self._tighten_autonomy_mode(state)
            self._emit_reasoning_event(
                state,
                kind="strategy_shift",
                summary="Recent findings increased risk; tightening autonomy for the next planning cycle.",
                phase_name=phase_name,
                status="warning",
                context={
                    "risk_signal": normalized_signal,
                    "autonomy_mode": state.get("autonomy_mode"),
                    "safety_grade": state.get("safety_grade"),
                },
            )
            return False, None
        if normalized_signal == "pause":
            state["session_status"] = "waiting_approval"
            state["pending_approval"] = self._pending_approval_from_risk_signal(
                state,
                action=action,
                phase_name=phase_name,
            )
            self._record_operation(
                plugin_id="agent",
                action="risk_pause",
                status="warning",
                detail="Critical finding triggered pause signal.",
            )
            self._emit_reasoning_event(
                state,
                kind="approval_pending",
                summary="Critical evidence was found. Further validation is paused pending operator approval.",
                phase_name=phase_name,
                action=action,
                status="warning",
                context=state.get("pending_approval", {}),
            )
            return True, "approval_pending"
        return False, None

    def _tighten_autonomy_mode(self, state: dict[str, Any]) -> None:
        """Tighten autonomy one step without overwriting the configured safety grade."""
        surface = state.get("surface", {})
        if not isinstance(surface, dict):
            surface = {}
            state["surface"] = surface
        current = normalize_autonomy_mode(
            state.get("autonomy_mode", surface.get("autonomy_mode", None)),
            safety_grade=state.get("safety_grade", self._safety_grade),
        )
        next_mode = "adaptive" if current == "supervised" else current
        state["autonomy_mode"] = next_mode
        surface["autonomy_mode"] = next_mode

    @staticmethod
    def _normalize_candidate_list(value: Any) -> list[str]:
        if isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    def _build_ranking_explanation(
        self,
        *,
        tool_name: str,
        target: str,
        options: dict[str, Any] | None,
        metadata: dict[str, Any] | None = None,
        action_reason: str | None = None,
        preconditions: list[str] | None = None,
        phase_name: str | None = None,
    ) -> dict[str, Any]:
        safe_options = options if isinstance(options, dict) else {}
        safe_metadata = metadata if isinstance(metadata, dict) else {}
        normalized_reason = str(action_reason or "").strip()
        normalized_phase = str(phase_name or "").strip()
        normalized_preconditions = [str(item).strip() for item in (preconditions or []) if str(item).strip()]

        component = str(safe_metadata.get("component") or safe_options.get("component") or "").strip() or None
        service = str(safe_metadata.get("service") or safe_options.get("service") or "").strip() or None
        version = str(safe_metadata.get("version") or safe_options.get("version") or "").strip() or None

        candidate_order = (
            self._normalize_candidate_list(safe_metadata.get("verification_order"))
            or self._normalize_candidate_list(safe_metadata.get("candidate_order"))
            or self._normalize_candidate_list(safe_metadata.get("requested_cve_ids"))
            or self._normalize_candidate_list(safe_options.get("cve_ids"))
            or self._normalize_candidate_list(safe_options.get("template_id"))
        )
        selected_candidate = str(safe_options.get("cve_id") or "").strip() or (candidate_order[0] if candidate_order else "")

        selected_templates = (
            self._normalize_candidate_list(safe_metadata.get("selected_templates"))
            or self._normalize_candidate_list(safe_options.get("templates"))
        )
        template_name = str(safe_metadata.get("template") or safe_options.get("template") or "").strip()
        if template_name and template_name not in selected_templates:
            selected_templates = [template_name, *selected_templates]

        template_index = safe_metadata.get("template_capability_index")
        if not isinstance(template_index, dict):
            template_index = safe_options.get("template_capability_index")
        if not isinstance(template_index, dict):
            template_index = {}
        selected_capability = template_index.get(str(selected_candidate).strip().upper(), {})
        if not isinstance(selected_capability, dict):
            selected_capability = {}
        protocol_tags = self._normalize_candidate_list(selected_capability.get("protocol_tags"))
        rag_recommended_tools = self._normalize_candidate_list(
            safe_metadata.get("rag_recommended_tools") or safe_options.get("rag_recommended_tools")
        )

        reasons: list[str] = []

        def _append_reason(message: str) -> None:
            normalized = str(message).strip()
            if normalized and normalized not in reasons:
                reasons.append(normalized)

        if normalized_reason:
            _append_reason(normalized_reason)
        if normalized_phase:
            _append_reason(f"Scheduled in phase: {normalized_phase}")
        if normalized_preconditions:
            _append_reason(f"Preconditions satisfied: {', '.join(normalized_preconditions[:4])}")
        if component:
            _append_reason(f"Component match: {component}")
        if service:
            _append_reason(f"Service match: {service}")
        if version:
            _append_reason(f"Version hint: {version}")
        if selected_templates:
            _append_reason(f"Matched {len(selected_templates)} template(s)")
        elif candidate_order:
            _append_reason(f"Candidate set narrowed to {len(candidate_order)} item(s)")
        if protocol_tags:
            _append_reason(f"Protocol tags: {', '.join(protocol_tags[:4])}")
        if rag_recommended_tools and str(tool_name).strip().lower() in {item.lower() for item in rag_recommended_tools}:
            _append_reason(f"RAG recommended {tool_name}")
        if safe_options.get("safe_only") is True:
            _append_reason("Safe-only validation mode")
        if safe_options.get("allow_high_risk") is True:
            _append_reason("High-risk validation enabled")
        safety_grade = str(safe_options.get("safety_grade") or safe_metadata.get("safety_grade") or "").strip().lower()
        if safety_grade:
            _append_reason(f"Safety grade: {safety_grade}")

        if not any([component, service, version, selected_candidate, selected_templates, protocol_tags, reasons]):
            return {}

        return {
            "tool": str(tool_name).strip(),
            "target": str(target).strip() or None,
            "component": component,
            "service": service,
            "version": version,
            "selected_candidate": selected_candidate or None,
            "candidate_order": candidate_order[:12],
            "selected_templates": selected_templates[:12],
            "protocol_tags": protocol_tags[:8],
            "rag_recommended_tools": rag_recommended_tools[:8],
            "reasons": reasons[:8],
        }

    def _retry_policy_for_tool(self, tool: BaseAgentTool) -> dict[str, Any]:
        policy = getattr(tool, "retry_policy", {}) if tool is not None else {}
        if not isinstance(policy, dict):
            policy = {}
        retryable_errors = policy.get(
            "retryable_errors",
            ["timeout", "connection_reset", "dns_resolution", "temporarily unavailable"],
        )
        return {
            "max_retries": max(0, int(policy.get("max_retries", 0) or 0)),
            "backoff_seconds": max(0.0, float(policy.get("backoff_seconds", 0.0) or 0.0)),
            "retryable_errors": {str(item).strip().lower() for item in retryable_errors if str(item).strip()},
        }

    def _is_retryable_error(self, error: str | None, retry_policy: dict[str, Any]) -> bool:
        if not error:
            return False
        lowered = str(error).strip().lower()
        return any(token in lowered for token in retry_policy.get("retryable_errors", set()))

    def _flush_iteration_state(
        self,
        state: dict[str, Any],
        artifact_index: list[dict[str, Any]],
        blocked_actions: list[PolicyBlock],
        final_plan: ActionPlan,
    ) -> None:
        """Persist key runtime artifacts at the end of each iteration."""
        self._write_json(self._agent_dir / "agent_history.json", state.get("history", []))
        self._write_json(self._agent_dir / "agent_state.json", state)
        self._write_json(self._agent_dir / "artifact_index.json", artifact_index)
        self._write_json(
            self._agent_dir / "blocked_actions.json",
            [self._blocked_to_dict(item) for item in blocked_actions],
        )
        self._write_json(self._agent_dir / "ActionPlan.json", self._plan_to_dict(final_plan))

    def _resolve_state_path(self, path: Path) -> Path:
        candidate = path.expanduser().resolve()
        if candidate.is_file():
            return candidate
        if candidate.is_dir():
            direct = candidate / "agent_state.json"
            if direct.exists():
                return direct
            nested = candidate / "agent" / "agent_state.json"
            if nested.exists():
                return nested
        raise ValueError(
            "resume path must point to an agent_state.json file or a directory containing it"
        )

    def _append_run_metadata_to_report(
        self,
        *,
        markdown_report_path: Path,
        resumed: bool,
        resumed_from: str | None,
        start_iteration: int,
        start_budget: int,
    ) -> None:
        """Append resume metadata section into final markdown report."""
        try:
            existing = markdown_report_path.read_text(encoding="utf-8").rstrip()
        except OSError:
            return

        lines = [
            "",
            "## Run Metadata",
            "",
            f"- resumed: `{str(resumed).lower()}`",
            f"- resumed_from: `{resumed_from or ''}`",
            f"- resume_start_iteration: `{start_iteration}`",
            f"- resume_start_budget: `{start_budget}`",
            "",
        ]
        try:
            markdown_report_path.write_text(existing + "\n" + "\n".join(lines), encoding="utf-8")
        except OSError:
            return

    def _write_action_artifact(self, action: Action, payload: dict[str, Any]) -> Path:
        """Persist one action artifact JSON."""
        filename = f"{action.action_id}_{action.tool_name}.json"
        output_path = self._artifact_dir / filename
        self._write_json(output_path, payload)
        return output_path

    def _plan_to_dict(self, plan: ActionPlan) -> dict[str, Any]:
        """Serialize ActionPlan dataclass for JSON output."""
        actions: list[dict[str, Any]] = []
        ranking_overview: list[dict[str, Any]] = []
        for action in plan.actions:
            action_payload = asdict(action)
            ranking_explanation = self._build_ranking_explanation(
                tool_name=action.tool_name,
                target=action.target,
                options=action.options,
                action_reason=action.reason,
                preconditions=action.preconditions,
            )
            if ranking_explanation:
                action_payload["ranking_explanation"] = ranking_explanation
                ranking_overview.append(ranking_explanation)
            actions.append(action_payload)
        return {
            "decision_summary": plan.decision_summary,
            "actions": actions,
            "ranking_overview": ranking_overview,
        }

    def _blocked_to_dict(self, block: PolicyBlock) -> dict[str, Any]:
        """Serialize blocked action record."""
        return {
            "action": block.action.to_dict(),
            "reason": block.reason,
        }

    def _to_planned_action(self, action: Action) -> PlannedAction:
        """Convert scheduler action into DecisionMaker schema dataclass."""
        return PlannedAction(
            action_id=action.action_id,
            tool_name=action.tool_name,
            target=action.target,
            options=action.options,
            priority=action.priority,
            cost=action.cost,
            capabilities=action.capabilities,
            idempotency_key=action.idempotency_key,
            reason=action.reason,
            preconditions=action.preconditions,
            stop_conditions=action.stop_conditions,
        )

    def _record_operation(self, plugin_id: str, action: str, status: str, detail: str) -> None:
        """Record operation using shared JSONL recorder."""
        self._recorder.record(
            OperationEvent(
                timestamp=utc_now_iso(),
                plugin_id=plugin_id,
                action=action,
                status=status,
                detail=detail,
            )
        )

    def _emit_reasoning_event(
        self,
        state: dict[str, Any],
        *,
        kind: str,
        summary: str,
        phase_name: str | None = None,
        action: Action | None = None,
        status: str = "info",
        context: dict[str, Any] | None = None,
    ) -> None:
        """Append operator-facing reasoning events to state and structured logs."""
        payload: dict[str, Any] = {
            "kind": kind,
            "summary": summary,
            "phase": phase_name,
            "status": status,
            "timestamp": utc_now_iso(),
        }
        if action is not None:
            payload.update(
                {
                    "action_id": action.action_id,
                    "tool_name": action.tool_name,
                    "target": action.target,
                }
            )
        if context:
            payload["context"] = context
        stream = state.get("thought_stream", [])
        if not isinstance(stream, list):
            stream = []
        stream.append(payload)
        state["thought_stream"] = stream[-80:]
        self._record_operation(
            plugin_id="agent",
            action=kind,
            status=status,
            detail=json.dumps(payload, ensure_ascii=False, sort_keys=True),
        )

    def _build_pending_approval(
        self,
        state: dict[str, Any],
        *,
        blocked: list[PolicyBlock],
        phase_name: str,
    ) -> dict[str, Any] | None:
        """Build approval request context from blocked high-risk actions."""
        pending_actions: list[dict[str, Any]] = []
        for block in blocked:
            reason = str(block.reason).strip().lower()
            if reason not in {"precondition_failed:approval_granted", "precondition_failed:authorization_confirmed"}:
                continue
            try:
                tool = self._tool_getter(block.action.tool_name)
                risk_level = str(getattr(tool, "risk_level", "safe")).strip().lower()
            except Exception:  # noqa: BLE001
                risk_level = "unknown"
            if risk_level not in {"high", "critical"}:
                continue
            pending_actions.append(
                {
                    "action_id": block.action.action_id,
                    "tool_name": block.action.tool_name,
                    "target": block.action.target,
                    "reason": block.reason,
                    "risk_level": risk_level,
                    "rationale": block.action.reason,
                }
            )
        if not pending_actions:
            return None
        return {
            "requested_at": utc_now_iso(),
            "phase": phase_name,
            "summary": "High-risk validation is ready but requires explicit operator approval.",
            "actions": pending_actions,
            "evidence_summary": self._summarize_recent_findings(state),
        }

    def _pending_approval_from_risk_signal(
        self,
        state: dict[str, Any],
        *,
        action: Action,
        phase_name: str,
    ) -> dict[str, Any]:
        """Build approval payload when feedback engine triggers a pause."""
        return {
            "requested_at": utc_now_iso(),
            "phase": phase_name,
            "summary": "Critical findings triggered a manual approval checkpoint before deeper validation.",
            "actions": [
                {
                    "action_id": action.action_id,
                    "tool_name": action.tool_name,
                    "target": action.target,
                    "reason": "feedback_pause",
                    "risk_level": "high",
                    "rationale": action.reason,
                }
            ],
            "evidence_summary": self._summarize_recent_findings(state),
        }

    def _summarize_recent_findings(self, state: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
        """Summarize recent findings for approval dialogs and reports."""
        findings = state.get("findings_preview", [])
        if not isinstance(findings, list):
            findings = []
        output: list[dict[str, Any]] = []
        for item in findings[-limit:]:
            if not isinstance(item, dict):
                continue
            output.append(
                {
                    "name": str(item.get("name", "")).strip(),
                    "severity": str(item.get("severity", "")).strip().lower() or "info",
                    "evidence": str(item.get("evidence", ""))[:280],
                }
            )
        return output

    def _evaluate_loop_guard(
        self,
        state: dict[str, Any],
        *,
        phase_name: str,
        executed_count: int,
        blocked: list[PolicyBlock],
        error_messages: list[str],
        finding_count: int,
        breadcrumb_delta: int,
        asset_delta: int,
        surface_delta: int,
    ) -> tuple[bool, str | None]:
        """Detect repeated non-progress environment loops and stop early."""
        if str(state.get("session_status", "")).strip().lower() == "waiting_approval":
            return False, None

        loop_guard = state.get("loop_guard", {})
        if not isinstance(loop_guard, dict):
            loop_guard = {}

        made_progress = any(
            value > 0
            for value in (finding_count, breadcrumb_delta, asset_delta, surface_delta)
        )
        if executed_count > 0 and not error_messages:
            made_progress = True

        reasons: list[str] = []
        env_like = False
        for block in blocked:
            reason = str(block.reason).strip()
            if not reason:
                continue
            reasons.append(reason)
            lowered = reason.lower()
            if lowered.startswith("tool_unavailable:") or lowered.startswith("circuit_open"):
                env_like = True
        for message in error_messages:
            lowered = str(message).strip().lower()
            if not lowered:
                continue
            reasons.append(lowered[:180])
            if any(token in lowered for token in ("timed out", "timeout", "connection", "refused", "unreachable", "waf", "forbidden", "network", "dns", "ssl")):
                env_like = True

        if made_progress or not reasons or not env_like:
            state["loop_guard"] = {
                "stalled_iterations": 0,
                "last_signature": "",
                "last_reason": "",
                "environment_block_count": 0,
            }
            return False, None

        signature = json.dumps(
            {
                "phase": phase_name,
                "reasons": sorted(set(reasons)),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        stalled_iterations = 1
        environment_block_count = 1
        if signature == str(loop_guard.get("last_signature", "")):
            stalled_iterations = int(loop_guard.get("stalled_iterations", 0) or 0) + 1
            environment_block_count = int(loop_guard.get("environment_block_count", 0) or 0) + 1
        state["loop_guard"] = {
            "stalled_iterations": stalled_iterations,
            "last_signature": signature,
            "last_reason": reasons[0],
            "environment_block_count": environment_block_count,
        }
        if stalled_iterations < 2:
            return False, None

        state["session_status"] = "environment_blocked"
        self._emit_reasoning_event(
            state,
            kind="loop_break",
            summary="Repeated environment blocking signals detected. Pausing the session to avoid budget burn.",
            phase_name=phase_name,
            status="warning",
            context={"reasons": sorted(set(reasons)), "stalled_iterations": stalled_iterations},
        )
        return True, reasons[0]

    def _finalize_session_status(
        self,
        state: dict[str, Any],
        *,
        final_stop_reason: str,
    ) -> str:
        """Map stop reason into stable session status."""
        if final_stop_reason == "budget_exhausted":
            history = state.get("history", [])
            has_failures = any(
                isinstance(entry, dict)
                and (
                    str(entry.get("status", "")).strip().lower() in {"failed", "error"}
                    or (
                        entry.get("error") is not None
                        and str(entry.get("error", "")).strip() != ""
                    )
                )
                for entry in history
            )
            return "partial_complete" if has_failures else "completed"
        if final_stop_reason in {"timeout", "phase_budget_exhausted"}:
            return "partial_complete" if state.get("history") else "completed"
        return "completed"

    def _blocked_actions_are_environmental(self, blocked: list[PolicyBlock]) -> bool:
        """Return whether blocked actions indicate an environment-level stop."""
        reasons = [str(item.reason).strip().lower() for item in blocked if str(item.reason).strip()]
        if not reasons:
            return False
        allowed_prefixes = (
            "tool_unavailable:",
            "circuit_open",
            "tool_availability_check_failed:",
        )
        return all(reason.startswith(allowed_prefixes) for reason in reasons)

    def _write_json(self, path: Path, payload: Any) -> None:
        """Write JSON file with UTF-8 encoding."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _capture_report_snapshots(
        self,
        *,
        target: str,
        markdown_report_path: Path,
        html_report_path: Path | None,
        audit_report_json_path: Path | None,
    ) -> tuple[Path, Path | None]:
        """
        Save uniquely named report snapshots while preserving stable canonical names.

        Canonical report files remain:
        - agent_report.md / agent_report.html / audit_report.json
        Additional snapshots avoid operator confusion when collecting many reports.
        """
        details: list[str] = []
        markdown_snapshot = create_report_snapshot(markdown_report_path, target=target)
        if markdown_snapshot is not None:
            details.append(f"markdown={markdown_snapshot.name}")
        html_snapshot: Path | None = None
        if html_report_path is not None:
            html_snapshot = create_report_snapshot(html_report_path, target=target)
            if html_snapshot is not None:
                details.append(f"html={html_snapshot.name}")
        if audit_report_json_path is not None:
            json_snapshot = create_report_snapshot(audit_report_json_path, target=target)
            if json_snapshot is not None:
                details.append(f"json={json_snapshot.name}")
        if details:
            self._record_operation(
                plugin_id="agent",
                action="report_snapshot",
                status="info",
                detail=", ".join(details),
            )
        return markdown_snapshot or markdown_report_path, html_snapshot or html_report_path

    def _is_timed_out(self, started: float) -> bool:
        """Check global timeout condition."""
        return (time.perf_counter() - started) >= self._global_timeout_seconds

    def _merge_breadcrumbs(
        self,
        original: list[dict[str, Any]],
        delta: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Merge breadcrumbs with deduplication."""
        return self._dedupe_breadcrumbs([*original, *delta])

    def _dedupe_breadcrumbs(self, breadcrumbs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate breadcrumbs by (type, data)."""
        output: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in breadcrumbs:
            if not isinstance(item, dict):
                continue
            breadcrumb_type = str(item.get("type", "")).strip().lower()
            data = str(item.get("data", "")).strip()
            if not breadcrumb_type or not data:
                continue
            signature = (breadcrumb_type, data)
            if signature in seen:
                continue
            seen.add(signature)
            output.append({"type": breadcrumb_type, "data": data})
        return output

    def _merge_surface(self, original: dict[str, Any], delta: dict[str, Any]) -> dict[str, Any]:
        """Merge surface objects while preserving deterministic structure."""
        merged = dict(original)
        for key, value in delta.items():
            if key not in merged:
                merged[key] = value
                continue

            if isinstance(merged[key], list) and isinstance(value, list):
                combined = [*merged[key], *value]
                merged[key] = self._dedupe_list(combined)
                continue

            if isinstance(merged[key], dict) and isinstance(value, dict):
                combined_dict = dict(merged[key])
                for sub_key, sub_value in value.items():
                    if sub_key not in combined_dict:
                        combined_dict[sub_key] = sub_value
                        continue
                    if isinstance(combined_dict[sub_key], list) and isinstance(sub_value, list):
                        combined_dict[sub_key] = self._dedupe_list([*combined_dict[sub_key], *sub_value])
                    else:
                        combined_dict[sub_key] = sub_value
                merged[key] = combined_dict
                continue

            merged[key] = value
        return merged

    def _merge_assets(self, original: list[dict[str, Any]], delta: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Merge normalized asset rows by stable id and accumulate attributes."""
        merged: dict[str, dict[str, Any]] = {}
        for item in [*(original or []), *(delta or [])]:
            if not isinstance(item, dict):
                continue
            marker = str(item.get("id", "")).strip() or json.dumps(item, ensure_ascii=False, sort_keys=True)
            current = merged.get(marker)
            if current is None:
                merged[marker] = dict(item)
                continue
            current_attributes = current.get("attributes", {}) if isinstance(current.get("attributes", {}), dict) else {}
            incoming_attributes = item.get("attributes", {}) if isinstance(item.get("attributes", {}), dict) else {}
            current_evidence = current.get("evidence", {}) if isinstance(current.get("evidence", {}), dict) else {}
            incoming_evidence = item.get("evidence", {}) if isinstance(item.get("evidence", {}), dict) else {}
            for key, value in item.items():
                if key in {"attributes", "evidence"}:
                    continue
                if value is not None and value != "":
                    current[key] = value
            current["attributes"] = {**current_attributes, **incoming_attributes}
            current["evidence"] = {**current_evidence, **incoming_evidence}
        return list(merged.values())

    def _normalize_runtime_state(self, state: dict[str, Any]) -> dict[str, Any]:
        """
        Keep CVE runtime controls synchronized between top-level state and surface.

        This avoids planner/policy drift when callers provide flags only in one place
        (for example web jobs passing `surface_file` only).
        """
        if not isinstance(state, dict):
            return {}

        surface = state.get("surface", {})
        if not isinstance(surface, dict):
            surface = {}
        assets = state.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        surface_assets = surface.get("assets", [])
        if not isinstance(surface_assets, list):
            surface_assets = []
        normalized_assets = self._merge_assets(assets, surface_assets)
        state["assets"] = normalized_assets
        surface["assets"] = self._merge_assets(surface.get("assets", []), normalized_assets)

        top_candidates = state.get("cve_candidates", [])
        surface_candidates = surface.get("cve_candidates", [])
        raw_candidates = surface_candidates if isinstance(surface_candidates, list) else top_candidates
        if isinstance(raw_candidates, list):
            normalized_candidates = self._normalize_cve_candidates(raw_candidates)
            state["cve_candidates"] = normalized_candidates
            surface["cve_candidates"] = list(normalized_candidates)

        authorization_confirmed = self._coerce_bool(
            state.get("authorization_confirmed", surface.get("authorization_confirmed", None)),
            default=False,
        )
        cve_safe_only = self._coerce_bool(
            state.get("cve_safe_only", surface.get("safe_only", None)),
            default=True,
        )
        cve_allow_high_risk = self._coerce_bool(
            state.get("cve_allow_high_risk", surface.get("allow_high_risk", None)),
            default=False,
        )
        autonomy_mode = normalize_autonomy_mode(
            surface.get("autonomy_mode", state.get("autonomy_mode", None)),
            safety_grade=state.get("safety_grade", self._safety_grade),
        )
        approval_granted = self._coerce_bool(
            state.get("approval_granted", surface.get("approval_granted", None)),
            default=False,
        )
        disabled_tools = self._normalize_runtime_text_list(
            state.get("disabled_tools", surface.get("disabled_tools", [])),
        )
        focus_ports = self._normalize_runtime_port_list(
            state.get("focus_ports", surface.get("focus_ports", [])),
        )
        preferred_origins = self._normalize_runtime_origins(
            state.get("preferred_origins", surface.get("preferred_origins", [])),
        )
        state["authorization_confirmed"] = authorization_confirmed
        state["cve_safe_only"] = cve_safe_only
        state["cve_allow_high_risk"] = cve_allow_high_risk
        state["autonomy_mode"] = autonomy_mode
        state["approval_granted"] = approval_granted
        state["disabled_tools"] = disabled_tools
        state["focus_ports"] = focus_ports
        state["preferred_origins"] = preferred_origins
        evidence_graph = state.get("evidence_graph", {})
        if not isinstance(evidence_graph, dict):
            evidence_graph = {}
        state["evidence_graph"] = evidence_graph
        surface["authorization_confirmed"] = authorization_confirmed
        surface["safe_only"] = cve_safe_only
        surface["allow_high_risk"] = cve_allow_high_risk
        surface["autonomy_mode"] = autonomy_mode
        surface["approval_granted"] = approval_granted
        surface["disabled_tools"] = list(disabled_tools)
        surface["focus_ports"] = list(focus_ports)
        surface["preferred_origins"] = list(preferred_origins)
        state["surface"] = surface
        return state

    def _normalize_cve_candidates(self, candidates: list[Any]) -> list[dict[str, Any]]:
        """Normalize/dedupe CVE candidate rows while preserving unknown fields."""
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in candidates:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            if "cve_id" in row:
                row["cve_id"] = str(row.get("cve_id", "")).strip().upper()
            if "target" in row:
                row["target"] = str(row.get("target", "")).strip()
            if "safe_only" in row:
                row["safe_only"] = self._coerce_bool(row.get("safe_only"), default=True)
            if "allow_high_risk" in row:
                row["allow_high_risk"] = self._coerce_bool(row.get("allow_high_risk"), default=False)
            if "authorization_confirmed" in row:
                row["authorization_confirmed"] = self._coerce_bool(
                    row.get("authorization_confirmed"),
                    default=False,
                )
            marker = json.dumps(row, ensure_ascii=False, sort_keys=True)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(row)
        return output

    def _dedupe_list(self, items: list[Any]) -> list[Any]:
        """Deduplicate list values while preserving order."""
        output: list[Any] = []
        seen: set[str] = set()
        for item in items:
            marker = json.dumps(item, ensure_ascii=False, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(item)
        return output

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
    def _normalize_runtime_text_list(value: Any) -> list[str]:
        if isinstance(value, list):
            items = [str(item).strip() for item in value if str(item).strip()]
        elif isinstance(value, str):
            items = [item.strip() for item in value.split(",") if item.strip()]
        else:
            items = []
        seen: set[str] = set()
        output: list[str] = []
        for item in items:
            lowered = item.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            output.append(item)
        return output

    @staticmethod
    def _normalize_runtime_port_list(value: Any) -> list[int]:
        raw_items: list[str] = []
        if isinstance(value, list):
            raw_items = [str(item).strip() for item in value if str(item).strip()]
        elif isinstance(value, str):
            raw_items = [item.strip() for item in value.replace("/", ",").split(",") if item.strip()]
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

    def _normalize_runtime_origins(self, value: Any) -> list[str]:
        values = self._normalize_runtime_text_list(value)
        output: list[str] = []
        for item in values:
            normalized = self._normalize_url(item)
            if normalized:
                output.append(normalized)
        return self._dedupe_list(output)

    def _normalize_url(self, value: str) -> str:
        """Normalize URL string."""
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        path = parsed.path or "/"
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))

    def _origin_of(self, url: str) -> str:
        """Return canonical URL origin."""
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), "", "", "", ""))

    def _extract_host_or_token(self, raw: str) -> str:
        """Extract host token from URL or plain target."""
        from urllib.parse import urlparse

        candidate = raw.strip()
        if not candidate:
            return ""
        parsed = urlparse(candidate)
        if parsed.scheme and parsed.netloc:
            return (parsed.hostname or "").lower()
        if ":" in candidate and candidate.count(":") == 1:
            host, _ = candidate.split(":", maxsplit=1)
            return host.lower()
        return candidate.lower()

    def _notify_action_result(
        self,
        *,
        action: Action,
        status: str,
        error: str | None,
        findings: list[dict[str, Any]],
        duration_ms: int,
    ) -> None:
        """Emit notifications for high-severity findings and slow actions."""
        if duration_ms >= self._slow_action_threshold_ms:
            self._safe_notify(
                NotificationEvent(
                    event_type="slow_action",
                    severity="warning",
                    title="Agent action execution slow",
                    message=(
                        f"Action {action.action_id} ({action.tool_name}) exceeded slow-action threshold "
                        f"with duration {duration_ms}ms."
                    ),
                    context={
                        "action_id": action.action_id,
                        "tool_name": action.tool_name,
                        "target": action.target,
                        "duration_ms": duration_ms,
                        "threshold_ms": self._slow_action_threshold_ms,
                        "status": status,
                    },
                )
            )

        high_findings = [
            item for item in findings
            if str(item.get("severity", "")).strip().lower() in {"high", "critical"}
        ]
        for item in high_findings:
            recommendation = None
            model = item.get("model")
            if isinstance(model, dict):
                recommendation = model.get("recommendation")
            recommendation = recommendation or item.get("recommendation")
            self._safe_notify(
                NotificationEvent(
                    event_type="high_severity_finding",
                    severity=str(item.get("severity", "high")).strip().lower() or "high",
                    title=f"High severity finding: {str(item.get('name', 'Unnamed Finding'))}",
                    message=(
                        f"{action.tool_name} discovered a high-severity finding on {action.target}. "
                        "Review evidence and remediation guidance."
                    ),
                    context={
                        "action_id": action.action_id,
                        "tool_name": action.tool_name,
                        "target": action.target,
                        "finding_name": item.get("name"),
                        "severity": item.get("severity"),
                        "evidence": str(item.get("evidence", ""))[:600],
                        "recommendation": str(recommendation)[:400] if recommendation else None,
                    },
                )
            )

        if status == "error" and error:
            # Keep error notification lightweight to avoid noisy channels.
            return

    def _notify_blocked_actions(
        self,
        blocked: list[PolicyBlock],
        *,
        state: dict[str, Any],
        phase: str,
    ) -> None:
        """Emit notifications for blocked actions on budget/scope fail-closed reasons."""
        for block in blocked:
            reason = str(block.reason)
            severity = None
            title = ""
            if "scope_fail_closed" in reason or "out_of_scope" in reason:
                severity = "high"
                title = "Action blocked by scope fail-closed policy"
            elif reason in {"insufficient_budget", "low_budget_priority_restriction"}:
                severity = "warning"
                title = "Action blocked by budget policy"
            if severity is None:
                continue
            self._safe_notify(
                NotificationEvent(
                    event_type="policy_block",
                    severity=severity,
                    title=title,
                    message=(
                        f"{phase} blocked action {block.action.action_id} ({block.action.tool_name}) "
                        f"for target {block.action.target}: {reason}"
                    ),
                    context={
                        "reason": reason,
                        "phase": phase,
                        "action": block.action.to_dict(),
                        "budget_remaining": int(state.get("budget_remaining", 0)),
                    },
                )
            )

    def _notify_scheduler_budget_skips(
        self,
        skipped: list[dict[str, Any]],
        *,
        state: dict[str, Any],
    ) -> None:
        """Emit notifications for scheduler-level budget skips."""
        for item in skipped:
            reason = str(item.get("reason", "")).strip()
            if reason not in {"insufficient_budget", "low_budget_priority_restriction"}:
                continue
            self._safe_notify(
                NotificationEvent(
                    event_type="scheduler_budget_skip",
                    severity="warning",
                    title="Action skipped by scheduler budget control",
                    message=(
                        f"Scheduler skipped {item.get('action_id')} ({item.get('tool_name')}) "
                        f"due to {reason}."
                    ),
                    context={
                        **item,
                        "agent_budget_remaining": int(state.get("budget_remaining", 0)),
                    },
                )
            )

    def _safe_notify(self, event: NotificationEvent) -> None:
        """Send notifier event without impacting main agent flow."""
        try:
            self._notifier.notify(event)
        except Exception:  # noqa: BLE001
            return

    def _safe_flush_notifier(self) -> None:
        """Flush notifier queue without impacting flow."""
        try:
            self._notifier.flush(timeout_seconds=2.0)
        except Exception:  # noqa: BLE001
            return
