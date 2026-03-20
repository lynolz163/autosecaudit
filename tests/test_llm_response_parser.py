from __future__ import annotations

from autosecaudit.decision.llm_response_parser import (
    extract_reason,
    extract_tool_candidates,
    parse_json_payload,
)


def test_parse_json_payload_accepts_fenced_and_prefixed_output() -> None:
    payload = parse_json_payload(
        """
        Planner notes:
        ```json
        {"tools": ["nmap_scan"], "reason": "Start with port discovery."}
        ```
        """
    )

    assert payload["tools"] == ["nmap_scan"]
    assert payload["reason"] == "Start with port discovery."


def test_extract_tool_candidates_and_reason_support_multiple_shapes() -> None:
    payload = {
        "tool": "http_security_headers",
        "tools": ["ssl_expiry_check", {"tool": "cors_misconfiguration"}],
        "recommendations": [{"tool": "nuclei_exploit_check"}],
        "reason": "Expand passive validation before active checks.",
    }

    assert extract_tool_candidates(payload) == [
        "http_security_headers",
        "ssl_expiry_check",
        "cors_misconfiguration",
        "nuclei_exploit_check",
    ]
    assert extract_reason(payload) == "Expand passive validation before active checks."
