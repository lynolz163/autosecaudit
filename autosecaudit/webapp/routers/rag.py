"""RAG corpus management and retrieval routes for the web console API."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from autosecaudit.agent_core.rag_service import (
    DEFAULT_RAG_CORPUS_ENV,
    DEFAULT_RAG_CORPUS_PATH,
    RagIntelService,
)

from ..api_support import audit_event, require_role
from ..auth import AuthPrincipal
from ..schemas import (
    RagCorpusResponse,
    RagCorpusSaveRequest,
    RagSearchResponse,
    RagSearchRequest,
)


router = APIRouter(tags=["rag"])
require_viewer = require_role("viewer")
require_admin = require_role("admin")

_DOC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{1,95}$")
_SEVERITY_HINTS = {"info", "low", "medium", "high", "critical"}


@router.get("/rag/corpus", response_model=RagCorpusResponse)
async def get_rag_corpus(
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> RagCorpusResponse:
    del request
    del principal
    return _build_corpus_response(_resolve_corpus_path())


@router.put("/rag/corpus", response_model=RagCorpusResponse)
async def save_rag_corpus(
    payload: RagCorpusSaveRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_admin),
) -> RagCorpusResponse:
    path = _resolve_corpus_path()
    try:
        documents = _normalize_documents(payload.documents)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"rag_corpus_invalid:{exc}") from exc

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"documents": documents}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"rag_corpus_write_failed:{exc}") from exc

    audit_event(
        request,
        actor=principal.actor,
        event_type="rag_corpus_updated",
        resource_type="rag",
        resource_id=str(path),
        detail={"document_count": len(documents)},
    )
    return _build_corpus_response(path)


@router.post("/rag/search", response_model=RagSearchResponse)
async def rag_search(
    payload: RagSearchRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_viewer),
) -> RagSearchResponse:
    del request
    del principal
    path = _resolve_corpus_path()
    service = RagIntelService(corpus_path=path)
    items = service.search(
        query=payload.query or "",
        component=payload.component,
        version=payload.version,
        tech_stack=list(payload.tech_stack),
        max_results=int(payload.max_results),
        min_score=float(payload.min_score),
    )
    return RagSearchResponse(corpus_path=str(path), items=[item for item in items if isinstance(item, dict)])


def _build_corpus_response(path: Path) -> RagCorpusResponse:
    documents = _read_external_documents(path)
    service = RagIntelService(corpus_path=path)
    effective_count = len(getattr(service, "_documents", []) or [])

    writable = False
    try:
        writable = os.access(path.parent if path.parent != Path("") else Path.cwd(), os.W_OK)
    except OSError:
        writable = False

    return RagCorpusResponse(
        corpus_path=str(path),
        exists=path.exists() and path.is_file(),
        writable=bool(writable),
        external_document_count=len(documents),
        effective_document_count=int(effective_count),
        documents=documents,
    )


def _resolve_corpus_path() -> Path:
    raw = os.getenv(DEFAULT_RAG_CORPUS_ENV, "").strip()
    candidate = Path(raw).expanduser() if raw else Path(DEFAULT_RAG_CORPUS_PATH).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (Path.cwd() / candidate).resolve()


def _read_external_documents(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []

    raw_docs: list[Any]
    if isinstance(payload, dict):
        candidate = payload.get("documents", [])
        raw_docs = candidate if isinstance(candidate, list) else []
    elif isinstance(payload, list):
        raw_docs = payload
    else:
        raw_docs = []

    output: list[dict[str, Any]] = []
    for item in raw_docs:
        if not isinstance(item, dict):
            continue
        doc_id = _normalize_doc_id(item.get("id"))
        title = str(item.get("title", "")).strip()
        if not doc_id or not title:
            continue
        output.append(
            {
                "id": doc_id,
                "title": title,
                "summary": str(item.get("summary", "")).strip(),
                "content": str(item.get("content", "")).strip(),
                "tags": _normalize_string_list(item.get("tags"), lower=True),
                "recommended_tools": _normalize_string_list(item.get("recommended_tools"), lower=False),
                "severity_hint": _normalize_severity_hint(item.get("severity_hint")),
                "references": _normalize_string_list(item.get("references"), lower=False),
                "source": str(item.get("source", "file")).strip() or "file",
            }
        )
    return output


def _normalize_documents(raw_documents: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, raw in enumerate(raw_documents):
        if hasattr(raw, "model_dump") and callable(raw.model_dump):
            raw = raw.model_dump()
        if not isinstance(raw, dict):
            raise ValueError(f"document[{idx}] must be object")
        doc_id = _normalize_doc_id(raw.get("id"))
        if not doc_id:
            raise ValueError(f"document[{idx}].id invalid")
        if doc_id in seen:
            raise ValueError(f"duplicate document id: {doc_id}")
        title = str(raw.get("title", "")).strip()
        if not title:
            raise ValueError(f"document[{idx}].title required")
        seen.add(doc_id)
        normalized.append(
            {
                "id": doc_id,
                "title": title,
                "summary": str(raw.get("summary", "")).strip(),
                "content": str(raw.get("content", "")).strip(),
                "tags": _normalize_string_list(raw.get("tags"), lower=True),
                "recommended_tools": _normalize_string_list(raw.get("recommended_tools"), lower=False),
                "severity_hint": _normalize_severity_hint(raw.get("severity_hint")),
                "references": _normalize_string_list(raw.get("references"), lower=False),
            }
        )
    return normalized


def _normalize_doc_id(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"[^a-z0-9._:-]+", "-", text)
    text = text.strip("-._:")
    if not _DOC_ID_RE.match(text):
        return ""
    return text


def _normalize_severity_hint(value: Any) -> str:
    hint = str(value or "").strip().lower()
    if hint not in _SEVERITY_HINTS:
        return "info"
    return hint


def _normalize_string_list(value: Any, *, lower: bool) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item or "").strip()
        if not text:
            continue
        normalized = text.lower() if lower else text
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out
