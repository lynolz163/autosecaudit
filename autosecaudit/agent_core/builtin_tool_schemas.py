"""Schema helper builders reused by builtin agent tools."""

from __future__ import annotations

from typing import Any


def origin_no_options_schema(*, target_mode: str = "origin_http") -> dict[str, Any]:
    """Return metadata schema for origin-only tools with no options."""
    return {
        "target_mode": target_mode,
        "properties": {},
        "additional_properties": False,
    }


def parameter_probe_schema(tool_name: str, *, max_params: int, max_value_length: int) -> dict[str, Any]:
    """Return metadata schema for GET-only parameterized endpoint tools."""
    return {
        "target_mode": "http_url",
        "required": ["method", "params"],
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET"],
                "error": f"{tool_name}_method_must_be_get",
            },
            "params": {
                "type": "object",
                "min_properties": 1,
                "max_properties": max_params,
                "key_schema": {
                    "type": "string",
                    "min_length": 1,
                    "max_length": 128,
                    "error": f"{tool_name}_invalid_param_key",
                },
                "value_schema": {
                    "type": "scalar",
                    "max_length": max_value_length,
                    "error": f"{tool_name}_param_value_too_long",
                },
                "error": f"{tool_name}_params_must_be_dict",
            },
        },
        "additional_properties": False,
        "additional_properties_error": f"{tool_name}_options_invalid_keys",
    }

