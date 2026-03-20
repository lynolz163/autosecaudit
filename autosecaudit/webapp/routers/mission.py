"""Natural-language mission intake routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from autosecaudit.agent_core.mission_intake import MissionConversation, MissionDraft, MissionTurn

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..schemas import (
    MissionChatResponse,
    MissionDraftResponse,
    MissionDraftView,
    MissionExecutionResponse,
    MissionRequest,
    MissionTurnView,
)


router = APIRouter(tags=["mission"])
require_viewer = require_role("viewer")
require_operator = require_role("operator")
HIGH_RISK_CAPABILITY_HINTS = {"cve_verify", "poc_sandbox_exec"}


@router.post("/mission/chat", response_model=MissionChatResponse)
async def chat_mission(
    payload: MissionRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> MissionChatResponse:
    conversation = _compile_conversation(payload, request)
    draft = conversation.draft
    action = _chat_action_for_draft(draft, principal=principal)
    workflow_state = _workflow_state_for_chat_action(action)
    job = None
    assistant_message = _chat_message_for_action(action=action, draft=draft, principal=principal)

    if action == "executed":
        try:
            job = request.app.state.manager.submit(draft.payload, actor=principal.actor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"mission_submit_failed:{exc}") from exc
        assistant_message = _chat_message_for_action(
            action=action,
            draft=draft,
            principal=principal,
            job=job,
        )

    conversation = request.app.state.mission_sessions.append_system_turn(
        conversation.session_id,
        assistant_message,
        summary=_chat_summary(action=action, draft=draft, job=job),
    )
    audit_event(
        request,
        actor=principal.actor,
        event_type=f"mission_chat_{action}",
        resource_type="job" if job else "mission",
        resource_id=str(job.get("job_id", "")) if job else str(draft.target or ""),
        detail={
            "target": draft.target,
            "intent": draft.intent,
            "depth": draft.depth,
            "mode": draft.mode,
            "safety_grade": draft.safety_grade,
            "autonomy_mode": draft.autonomy_mode,
            "session_id": conversation.session_id,
            "action": action,
            "workflow_state": workflow_state,
        },
    )
    return MissionChatResponse(
        session_id=conversation.session_id,
        action=action,
        workflow_state=workflow_state,
        assistant_message=assistant_message,
        messages=_to_chat_turn_views(conversation.messages),
        draft=_to_view(draft),
        job=job,
    )


@router.post("/mission/parse", response_model=MissionDraftResponse)
async def parse_mission(
    payload: MissionRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> MissionDraftResponse:
    conversation = _compile_conversation(payload, request)
    draft = conversation.draft
    audit_event(
        request,
        actor=principal.actor,
        event_type="mission_parsed",
        resource_type="mission",
        resource_id=draft.target,
        detail={
            "intent": draft.intent,
            "depth": draft.depth,
            "mode": draft.mode,
            "session_id": conversation.session_id,
        },
    )
    return MissionDraftResponse(
        session_id=conversation.session_id,
        messages=[_to_turn_view(item) for item in conversation.messages],
        draft=_to_view(draft),
    )


@router.post("/mission/execute", response_model=MissionExecutionResponse, status_code=201)
async def execute_mission(
    payload: MissionRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_operator),
) -> MissionExecutionResponse:
    conversation = _compile_conversation(payload, request)
    draft = conversation.draft
    if draft.missing_fields:
        raise HTTPException(status_code=400, detail=f"mission_missing_required_fields:{','.join(draft.missing_fields)}")
    try:
        job = request.app.state.manager.submit(draft.payload, actor=principal.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"mission_submit_failed:{exc}") from exc
    audit_event(
        request,
        actor=principal.actor,
        event_type="mission_executed",
        resource_type="job",
        resource_id=str(job.get("job_id", "")),
        detail={
            "target": draft.target,
            "intent": draft.intent,
            "depth": draft.depth,
            "mode": draft.mode,
            "safety_grade": draft.safety_grade,
            "autonomy_mode": draft.autonomy_mode,
            "session_id": conversation.session_id,
        },
    )
    return MissionExecutionResponse(
        session_id=conversation.session_id,
        messages=[_to_turn_view(item) for item in conversation.messages],
        draft=_to_view(draft),
        job=job,
    )


def _to_view(draft: MissionDraft) -> MissionDraftView:
    return MissionDraftView(
        raw_message=draft.raw_message,
        target=draft.target,
        scope=draft.scope,
        intent=draft.intent,
        depth=draft.depth,
        mode=draft.mode,
        report_lang=draft.report_lang,
        safety_grade=draft.safety_grade,
        autonomy_mode=draft.autonomy_mode,
        multi_agent=draft.multi_agent,
        multi_agent_rounds=draft.multi_agent_rounds,
        authorization_confirmed=draft.authorization_confirmed,
        approval_granted=draft.approval_granted,
        selected_tools=list(draft.selected_tools),
        selected_skills=list(draft.selected_skills),
        warnings=list(draft.warnings),
        missing_fields=list(draft.missing_fields),
        summary=list(draft.summary),
        payload=dict(draft.payload),
    )


def _to_turn_view(turn: MissionTurn) -> MissionTurnView:
    return MissionTurnView(role=turn.role, message=turn.message, summary=list(turn.summary))


def _to_chat_turn_views(turns: list[MissionTurn]) -> list[MissionTurnView]:
    views: list[MissionTurnView] = []
    for turn in turns:
        if _is_internal_draft_turn(turn):
            continue
        views.append(_to_turn_view(turn))
    return views


def _is_internal_draft_turn(turn: MissionTurn) -> bool:
    return turn.role == "system" and str(turn.message or "").startswith("Prepared mission for ")


def _compile_conversation(payload: MissionRequest, request: Request) -> MissionConversation:
    try:
        llm_completion = request.app.state.manager.get_mission_llm_completion()
        return request.app.state.mission_sessions.compile_turn(
            payload.message,
            overrides=payload.overrides,
            session_id=payload.session_id,
            llm_completion=llm_completion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _chat_action_for_draft(draft: MissionDraft, *, principal: AuthPrincipal) -> str:
    if draft.missing_fields:
        return "ask"
    if not principal.allows("operator"):
        return "preview"
    if _draft_requires_confirmation(draft):
        return "confirm"
    return "executed"


def _draft_requires_confirmation(draft: MissionDraft) -> bool:
    if draft.safety_grade == "aggressive" and draft.approval_granted is not True:
        return True
    selected = {str(item or "").strip().lower() for item in [*draft.selected_tools, *draft.selected_skills]}
    return bool(selected & HIGH_RISK_CAPABILITY_HINTS) and draft.approval_granted is not True


def _workflow_state_for_chat_action(action: str) -> str:
    normalized = str(action or "").strip().lower()
    if normalized == "ask":
        return "needs_input"
    if normalized == "preview":
        return "launch_preview"
    if normalized == "confirm":
        return "launch_confirm"
    return "launch_executed"


def _chat_message_for_action(
    *,
    action: str,
    draft: MissionDraft,
    principal: AuthPrincipal,
    job: dict[str, Any] | None = None,
) -> str:
    zh = str(draft.report_lang or "").lower().startswith("zh")
    target = str(draft.target or "").strip() or ("该任务" if zh else "this mission")
    if action == "ask":
        missing = ", ".join(_missing_field_labels(draft.missing_fields, zh=zh))
        return (
            f"我已经理解了任务方向，但还缺少这些信息：{missing}。补充后我就继续。"
            if zh
            else f"I understand the mission, but I still need: {missing}. Reply with that information and I will continue."
        )
    if action == "confirm":
        return (
            f"我已经整理好针对 {target} 的任务草案，但它会进入更高风险的验证路径。回复“批准高风险”或“approval granted”后我再继续执行。"
            if zh
            else f"I prepared the mission for {target}, but it enters a higher-risk validation path. Reply with 'approval granted' to continue."
        )
    if action == "preview":
        return (
            f"我已经整理好针对 {target} 的任务草案，但当前账号只有查看权限，不能直接发起任务。"
            if zh
            else f"I prepared the mission for {target}, but this account does not have permission to launch jobs."
        )
    job_id = str((job or {}).get("job_id", "")).strip() or "-"
    mode = str(draft.mode or "agent").strip() or "agent"
    return (
        f"已开始执行 {target}，任务号 {job_id}，模式 {mode}。"
        if zh
        else f"Started {target} as job {job_id} in {mode} mode."
    )


def _chat_summary(*, action: str, draft: MissionDraft, job: dict[str, Any] | None = None) -> list[str]:
    summary = [f"Action: {action}", f"Target: {draft.target or 'missing'}"]
    if job and job.get("job_id"):
        summary.append(f"Job: {job['job_id']}")
    return summary


def _missing_field_labels(fields: list[str], *, zh: bool) -> list[str]:
    mapping = {
        "target": "目标" if zh else "target",
        "scope": "范围" if zh else "scope",
    }
    return [mapping.get(str(item), str(item)) for item in fields]
