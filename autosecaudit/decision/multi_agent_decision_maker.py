"""Multi-agent layered decision maker (Recon / Exploiter / Reviewer)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from autosecaudit.agent_core.message_router import AgentMessage, MultiAgentMessageRouter
from autosecaudit.agent_core.session_tree import SessionTreeLogger
from autosecaudit.agent_core.skill_loader import SkillRegistry, load_builtin_skill_registry
from autosecaudit.agent_core.skill_planner import SkillDrivenPlanner
from autosecaudit.agent_core.builtin_tools import load_builtin_agent_tools
from autosecaudit.agent_core.tool_registry import get_tool
from autosecaudit.agent_safety import (
    DEFAULT_AGENT_SAFETY_GRADE,
    SAFETY_GRADE_ACTION_LIMITS,
    SAFETY_GRADE_DENIED_TOOLS,
    normalize_safety_grade,
)

from .audit_decision_maker import AuditDecisionMaker
from .models import ActionPlan, PlannedAction


class MultiAgentDecisionMaker:
    """Layered planner delegating to role-specific decision makers."""

    def __init__(
        self,
        *,
        llm_callable: Any | None = None,
        available_tools: Sequence[str] | None = None,
        safety_grade: str = DEFAULT_AGENT_SAFETY_GRADE,
        session_tree_path: Path | None = None,
        max_rounds: int = 1,
        skill_registry: SkillRegistry | None = None,
        skill_planner: SkillDrivenPlanner | None = None,
    ) -> None:
        self._llm_callable = llm_callable
        load_builtin_agent_tools()
        self._safety_grade = normalize_safety_grade(safety_grade)
        self._available_tools = [str(item).strip() for item in (available_tools or []) if str(item).strip()]
        self._max_rounds = max(1, int(max_rounds or 1))
        self._skill_registry = skill_registry if skill_registry is not None else load_builtin_skill_registry()
        self._skill_planner = skill_planner or SkillDrivenPlanner()
        self._router = MultiAgentMessageRouter()
        self._session_logger = SessionTreeLogger(session_tree_path)

    def plan_from_state(
        self,
        audit_state: dict[str, Any],
        use_llm_hints: bool = True,
        available_tools: Sequence[str] | None = None,
    ) -> ActionPlan:
        """Generate one reviewed plan via recon -> exploiter -> reviewer flow."""
        active_tools = [str(item).strip() for item in (available_tools or self._available_tools) if str(item).strip()]
        if not active_tools:
            # fall back to default core planner behavior
            maker = self._build_role_maker(role="recon", tools=active_tools)
            return maker.plan_from_state(
                audit_state,
                use_llm_hints=use_llm_hints,
                available_tools=active_tools if active_tools else None,
            )

        recon_tools, exploiter_tools = self._split_tools(active_tools)
        recon_maker = self._build_role_maker(role="recon", tools=recon_tools)
        exploiter_maker = self._build_role_maker(role="exploiter", tools=exploiter_tools)

        root_id = self._session_logger.append(
            role="orchestrator",
            event_type="multi_agent_start",
            content="Multi-agent planning started.",
            metadata={
                "active_tools": active_tools,
                "recon_tools": recon_tools,
                "exploiter_tools": exploiter_tools,
                "max_rounds": self._max_rounds,
            },
        )

        recon_plan = ActionPlan(decision_summary="No recon actions.", actions=[])
        exploiter_plan = ActionPlan(decision_summary="No exploiter actions.", actions=[])
        for round_index in range(1, self._max_rounds + 1):
            request_msg = AgentMessage(
                sender="orchestrator",
                receiver="recon",
                topic="plan_request",
                payload={"round": round_index, "state_summary": self._state_summary(audit_state)},
            )
            self._router.route(request_msg)
            recon_request_id = self._session_logger.append(
                role="orchestrator",
                event_type="route_to_recon",
                content=f"Round {round_index}: request recon plan.",
                parent_id=root_id,
                metadata=request_msg.payload,
            )
            recon_plan = recon_maker.plan_from_state(
                audit_state,
                use_llm_hints=use_llm_hints,
                available_tools=recon_tools,
            )
            self._session_logger.append(
                role="recon",
                event_type="plan_generated",
                content=recon_plan.decision_summary,
                parent_id=recon_request_id,
                metadata={"action_count": len(recon_plan.actions)},
            )

            exploit_msg = AgentMessage(
                sender="recon",
                receiver="exploiter",
                topic="plan_context",
                payload={
                    "round": round_index,
                    "recon_action_count": len(recon_plan.actions),
                    "recon_tools": [item.tool_name for item in recon_plan.actions],
                },
            )
            self._router.route(exploit_msg)
            exploiter_request_id = self._session_logger.append(
                role="router",
                event_type="route_to_exploiter",
                content=f"Round {round_index}: dispatch exploiter planning.",
                parent_id=root_id,
                metadata=exploit_msg.payload,
            )
            exploiter_plan = exploiter_maker.plan_from_state(
                audit_state,
                use_llm_hints=use_llm_hints,
                available_tools=exploiter_tools,
            )
            self._session_logger.append(
                role="exploiter",
                event_type="plan_generated",
                content=exploiter_plan.decision_summary,
                parent_id=exploiter_request_id,
                metadata={"action_count": len(exploiter_plan.actions)},
            )

            if round_index >= self._max_rounds:
                break

        reviewed, blocked = self._review_and_merge(
            recon_actions=recon_plan.actions,
            exploiter_actions=exploiter_plan.actions,
            audit_state=audit_state,
        )
        self._session_logger.append(
            role="reviewer",
            event_type="review_complete",
            content=f"Reviewer approved {len(reviewed)} actions and blocked {len(blocked)} actions.",
            parent_id=root_id,
            metadata={"blocked": blocked},
        )
        self._session_logger.append(
            role="orchestrator",
            event_type="multi_agent_end",
            content="Multi-agent planning finished.",
            parent_id=root_id,
            metadata={"approved_actions": len(reviewed)},
        )

        summary = (
            f"[multi-agent] recon={len(recon_plan.actions)} exploiter={len(exploiter_plan.actions)} "
            f"reviewed={len(reviewed)} blocked={len(blocked)}"
        )
        return ActionPlan(decision_summary=summary, actions=reviewed)

    def _build_role_maker(self, *, role: str, tools: list[str]) -> AuditDecisionMaker:
        del role
        return AuditDecisionMaker(
            llm_callable=self._llm_callable,
            available_tools=tools or None,
            safety_grade=self._safety_grade,
            skill_registry=self._skill_registry,
            skill_planner=self._skill_planner,
        )

    def _split_tools(self, tools: list[str]) -> tuple[list[str], list[str]]:
        recon: list[str] = []
        exploiter: list[str] = []
        for tool_name in tools:
            category = self._tool_category(tool_name)
            if category in {"recon", "discovery"}:
                recon.append(tool_name)
            elif category in {"testing", "validation"}:
                exploiter.append(tool_name)
            else:
                recon.append(tool_name)
        if not recon:
            recon = list(tools)
        if not exploiter:
            exploiter = list(tools)
        return recon, exploiter

    @staticmethod
    def _tool_category(tool_name: str) -> str:
        try:
            tool = get_tool(tool_name)
        except Exception:  # noqa: BLE001
            return "generic"
        return str(getattr(tool, "category", "generic")).strip().lower()

    def _review_and_merge(
        self,
        *,
        recon_actions: list[PlannedAction],
        exploiter_actions: list[PlannedAction],
        audit_state: dict[str, Any],
    ) -> tuple[list[PlannedAction], list[dict[str, Any]]]:
        grade = normalize_safety_grade(audit_state.get("safety_grade", self._safety_grade))
        denied = SAFETY_GRADE_DENIED_TOOLS.get(grade, frozenset())
        limit = int(SAFETY_GRADE_ACTION_LIMITS.get(grade, 8))

        surface = audit_state.get("surface", {}) if isinstance(audit_state.get("surface", {}), dict) else {}
        authorization_confirmed = self._coerce_bool(
            audit_state.get("authorization_confirmed", surface.get("authorization_confirmed", None)),
            default=False,
        )
        approval_granted = self._coerce_bool(
            audit_state.get("approval_granted", surface.get("approval_granted", None)),
            default=False,
        )

        merged: dict[str, PlannedAction] = {}
        blocked: list[dict[str, Any]] = []
        for action in [*recon_actions, *exploiter_actions]:
            reason = self._review_action(
                action,
                denied_tools=denied,
                grade=grade,
                authorization_confirmed=authorization_confirmed,
                approval_granted=approval_granted,
            )
            if reason is not None:
                blocked.append({"tool_name": action.tool_name, "target": action.target, "reason": reason})
                continue
            existing = merged.get(action.idempotency_key)
            if existing is None or int(action.priority) < int(existing.priority):
                merged[action.idempotency_key] = action

        ranked = sorted(
            merged.values(),
            key=lambda item: (int(item.priority), int(item.cost), item.tool_name, item.target),
        )
        return ranked[:limit], blocked

    def _review_action(
        self,
        action: PlannedAction,
        *,
        denied_tools: set[str] | frozenset[str],
        grade: str,
        authorization_confirmed: bool,
        approval_granted: bool,
    ) -> str | None:
        if action.tool_name in denied_tools:
            return f"denied_by_safety_grade:{grade}"
        if action.tool_name == "cve_verify" and not authorization_confirmed:
            return "authorization_required_for_cve_verify"
        if action.tool_name == "poc_sandbox_exec":
            if grade != "aggressive":
                return "poc_requires_aggressive_grade"
            if not authorization_confirmed:
                return "authorization_required_for_poc"
            if not approval_granted:
                return "approval_required_for_poc"
        return None

    @staticmethod
    def _state_summary(audit_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "scope_size": len(audit_state.get("scope", []) if isinstance(audit_state.get("scope", []), list) else []),
            "breadcrumbs": len(
                audit_state.get("breadcrumbs", []) if isinstance(audit_state.get("breadcrumbs", []), list) else []
            ),
            "history": len(audit_state.get("history", []) if isinstance(audit_state.get("history", []), list) else []),
            "budget_remaining": int(audit_state.get("budget_remaining", 0) or 0),
            "current_phase": str(audit_state.get("current_phase", "")),
        }

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
