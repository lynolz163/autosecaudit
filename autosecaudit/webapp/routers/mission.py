"""Natural-language mission intake routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from autosecaudit.agent_core.mission_intake import MissionConversation, MissionDraft, MissionTurn

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..schemas import (
    MissionDraftResponse,
    MissionDraftView,
    MissionExecutionResponse,
    MissionRequest,
    MissionTurnView,
)


router = APIRouter(tags=["mission"])
require_viewer = require_role("viewer")
require_operator = require_role("operator")


@router.post("/mission/parse", response_model=MissionDraftResponse)
async def parse_mission(
    payload: MissionRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> MissionDraftResponse:
    try:
        llm_completion = request.app.state.manager.get_mission_llm_completion()
        conversation = request.app.state.mission_sessions.compile_turn(
            payload.message,
            overrides=payload.overrides,
            session_id=payload.session_id,
            llm_completion=llm_completion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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
    try:
        llm_completion = request.app.state.manager.get_mission_llm_completion()
        conversation = request.app.state.mission_sessions.compile_turn(
            payload.message,
            overrides=payload.overrides,
            session_id=payload.session_id,
            llm_completion=llm_completion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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
