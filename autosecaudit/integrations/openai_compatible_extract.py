"""OpenAI-compatible response text extraction helpers."""

from __future__ import annotations

from typing import Any


def _content_length(value: Any) -> int:
    """Estimate text length for heterogeneous content payloads."""
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value)
    if isinstance(value, list):
        return sum(_content_length(item) for item in value)
    if isinstance(value, dict):
        return sum(_content_length(item) for item in value.values())
    return len(str(value))


def _prefix_extract_source(prefix: str, source: str) -> str:
    """Prefix nested extract source paths."""
    if not source:
        return prefix
    if source.startswith("["):
        return f"{prefix}{source}"
    return f"{prefix}.{source}"


def _extract_text_field_from_payload(payload: dict[str, Any], source: str) -> tuple[str, str]:
    """Extract one text value from common gateway field shapes."""
    for key in ("text", "content", "value", "output_text", "reasoning_content", "reasoning"):
        value = payload.get(key)
        field_source = f"{source}.{key}"
        if isinstance(value, str):
            return value, field_source
        if isinstance(value, dict):
            nested_value = value.get("value")
            if isinstance(nested_value, str):
                return nested_value, f"{field_source}.value"
            nested_text = value.get("text")
            if isinstance(nested_text, str):
                return nested_text, f"{field_source}.text"
        if isinstance(value, list):
            nested = _collect_text_fragments_from_items(value, field_source)
            if nested:
                return "\n".join(nested), field_source
    return "", ""


def _collect_text_fragments_from_items(items: list[Any], source: str) -> list[str]:
    """Collect text-like fragments from heterogeneous content arrays."""
    fragments: list[str] = []
    for item in items:
        if isinstance(item, str):
            fragments.append(item)
            continue
        if not isinstance(item, dict):
            continue
        text, _source = _extract_text_field_from_payload(item, source)
        if text:
            fragments.append(text)
            continue
        if isinstance(item.get("parts"), list):
            fragments.extend(_collect_text_fragments_from_items(item["parts"], f"{source}.parts"))
    return [item for item in fragments if item.strip()]


def _normalize_openai_compatible_content(content: Any, source: str) -> tuple[str, str]:
    """Normalize chat/message content into plain text."""
    if isinstance(content, str):
        return content, source
    if isinstance(content, dict):
        return _extract_text_field_from_payload(content, source)
    if isinstance(content, list):
        fragments = _collect_text_fragments_from_items(content, source)
        if fragments:
            return "\n".join(fragments), source
    return "", ""


def _extract_message_text_from_payload(message: dict[str, Any], base_source: str) -> tuple[str, str]:
    """Extract text from chat-completion message or delta payload."""
    for field_name in ("content", "reasoning_content", "reasoning", "output_text", "text", "content_text"):
        if field_name not in message:
            continue
        text, source = _normalize_openai_compatible_content(
            message.get(field_name),
            f"{base_source}.{field_name}",
        )
        if text.strip():
            return text, source
    return "", ""


def _extract_responses_output_chunks(output: list[Any], source: str) -> tuple[list[str], str]:
    """Extract textual chunks from OpenAI Responses-style output array."""
    chunks: list[str] = []
    first_source = ""
    for index, item in enumerate(output):
        if not isinstance(item, dict):
            continue
        item_source = f"{source}[{index}]"
        content_items = item.get("content")
        if isinstance(content_items, list):
            fragments = _collect_text_fragments_from_items(content_items, f"{item_source}.content")
            if fragments:
                chunks.extend(fragments)
                first_source = first_source or f"{item_source}.content"
                continue
        if isinstance(content_items, dict):
            text, text_source = _extract_text_field_from_payload(content_items, f"{item_source}.content")
            if text.strip():
                chunks.append(text)
                first_source = first_source or text_source
                continue
        text, text_source = _extract_text_field_from_payload(item, item_source)
        if text.strip():
            chunks.append(text)
            first_source = first_source or text_source
    return chunks, first_source or source


def extract_text_from_openai_compatible_response(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract completion text from mixed OpenAI-compatible payload variants."""
    if not isinstance(payload, dict):
        payload = {}

    def _finalize(text: str, source: str) -> tuple[str, dict[str, Any]]:
        stripped = text.strip()
        return stripped, {
            "source": source,
            "length": len(stripped),
            "is_empty": not bool(stripped),
        }

    choices = payload.get("choices")
    if isinstance(choices, list):
        for index, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            choice_source = f"choices[{index}]"
            message = choice.get("message")
            if isinstance(message, dict):
                text, source = _extract_message_text_from_payload(message, f"{choice_source}.message")
                if text.strip():
                    return _finalize(text, source)
            delta = choice.get("delta")
            if isinstance(delta, dict):
                text, source = _extract_message_text_from_payload(delta, f"{choice_source}.delta")
                if text.strip():
                    return _finalize(text, source)
            choice_text = choice.get("text")
            if isinstance(choice_text, str) and choice_text.strip():
                return _finalize(choice_text, f"{choice_source}.text")

    response_obj = payload.get("response")
    if isinstance(response_obj, dict):
        for field_name in ("output_text", "text"):
            field_value = response_obj.get(field_name)
            if isinstance(field_value, str) and field_value.strip():
                return _finalize(field_value, f"response.{field_name}")

    output = payload.get("output")
    if isinstance(output, list):
        chunks, source = _extract_responses_output_chunks(output, "output")
        if chunks:
            return _finalize("\n".join(chunks), source)

    candidates = payload.get("candidates")
    if isinstance(candidates, list):
        for index, candidate in enumerate(candidates):
            if not isinstance(candidate, dict):
                continue
            content = candidate.get("content")
            if isinstance(content, dict):
                parts = content.get("parts")
                if isinstance(parts, list):
                    fragments = _collect_text_fragments_from_items(parts, f"candidates[{index}].content.parts")
                    if fragments:
                        return _finalize("\n".join(fragments), f"candidates[{index}].content.parts")

    for field_name in ("output_text", "text"):
        field_value = payload.get(field_name)
        if isinstance(field_value, str) and field_value.strip():
            return _finalize(field_value, field_name)

    for key in ("data", "result", "response"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            nested_text, nested_meta = extract_text_from_openai_compatible_response(nested)
            if nested_text.strip():
                return _finalize(nested_text, _prefix_extract_source(key, str(nested_meta.get("source", ""))))

    return _finalize("", "none")


__all__ = [
    "_collect_text_fragments_from_items",
    "_content_length",
    "_extract_responses_output_chunks",
    "extract_text_from_openai_compatible_response",
]
