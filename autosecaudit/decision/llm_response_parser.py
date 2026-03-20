"""Helpers for parsing noisy LLM planner responses."""

from __future__ import annotations

import json
from typing import Any


def parse_json_payload(llm_response: str) -> dict[str, Any]:
    """Parse a JSON object from possibly noisy LLM text."""
    raw = llm_response.strip()
    if not raw:
        raise ValueError("LLM response is empty")

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = extract_fenced_json(raw)
    if fenced:
        try:
            parsed = json.loads(fenced)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    for idx, char in enumerate(raw):
        if char != "{":
            continue
        try:
            parsed_obj, _end = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed_obj, dict):
            return parsed_obj

    raise ValueError("Unable to parse JSON object from LLM response")


def extract_fenced_json(text: str) -> str | None:
    """Extract the first markdown fenced block as JSON text."""
    marker = "```"
    first = text.find(marker)
    if first < 0:
        return None
    second = text.find(marker, first + len(marker))
    if second < 0:
        return None

    block = text[first + len(marker) : second].strip()
    if block.lower().startswith("json"):
        block = block[4:].strip()
    return block or None


def extract_tool_candidates(payload: dict[str, Any]) -> list[str]:
    """Extract tool names from common planner JSON shapes."""
    raw_tools: list[str] = []

    if isinstance(payload.get("tool"), str):
        raw_tools.append(payload["tool"].strip())

    tools_field = payload.get("tools")
    if isinstance(tools_field, list):
        for item in tools_field:
            if isinstance(item, str):
                raw_tools.append(item.strip())
            elif isinstance(item, dict) and isinstance(item.get("tool"), str):
                raw_tools.append(item["tool"].strip())

    rec_field = payload.get("recommendations")
    if isinstance(rec_field, list):
        for item in rec_field:
            if isinstance(item, str):
                raw_tools.append(item.strip())
            elif isinstance(item, dict) and isinstance(item.get("tool"), str):
                raw_tools.append(item["tool"].strip())

    return [item for item in raw_tools if item]


def extract_reason(payload: dict[str, Any]) -> str | None:
    """Extract an optional planner reason string."""
    reason = payload.get("reason")
    if isinstance(reason, str):
        reason_text = reason.strip()
        return reason_text or None
    return None


__all__ = [
    "extract_fenced_json",
    "extract_reason",
    "extract_tool_candidates",
    "parse_json_payload",
]
