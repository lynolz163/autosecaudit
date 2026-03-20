"""Tests for AgentPassiveConfigAuditTool (builtin_tools.py)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from autosecaudit.agent_core.builtin_tools import AgentPassiveConfigAuditTool


TARGET = "http://example.invalid"


def _make_response(body: bytes, status: int = 200):
    """Build a normalized HTTP helper response."""
    return SimpleNamespace(
        status_code=status,
        text=body.decode("utf-8", errors="replace"),
        url=TARGET,
        headers={},
        header_lists={},
        content=body,
    )


class TestPassiveConfigAuditTool:
    """Test suite for the passive config audit tool."""

    def setup_method(self):
        self.tool = AgentPassiveConfigAuditTool()

    # ------------------------------------------------------------------
    # Path coverage
    # ------------------------------------------------------------------

    def test_required_paths_count(self):
        """Tool must probe at least 14 sensitive paths."""
        # Count visible paths from tool internals by running with no matches
        with patch("autosecaudit.agent_core.builtin_tools.request_text") as mock_request:
            from autosecaudit.agent_core.http_client import HttpClientError
            mock_request.side_effect = HttpClientError("connection refused")
            result = self.tool.run(TARGET, {})
        assert result.ok
        # The payload includes checked_paths
        checked = result.data.get("payload", {}).get("checked_paths", [])
        assert len(checked) >= 14, f"Expected >=14 paths, got {len(checked)}: {checked}"

    def test_includes_key_paths(self):
        """Must probe .git/config, .env, actuator/env, swagger.json."""
        with patch("autosecaudit.agent_core.builtin_tools.request_text") as mock_request:
            from autosecaudit.agent_core.http_client import HttpClientError
            mock_request.side_effect = HttpClientError("connection refused")
            result = self.tool.run(TARGET, {})
        checked = result.data.get("payload", {}).get("checked_paths", [])
        for required in [".git/config", ".env", "actuator/env", "swagger.json"]:
            assert required in checked, f"Missing required path: {required}"

    # ------------------------------------------------------------------
    # Keyword detection
    # ------------------------------------------------------------------

    def test_detects_git_config_exposure(self):
        """.git/config with [core] content should be flagged."""
        hit_content = b"[core]\n\trepositoryformatversion = 0\n"

        def side_effect(url, **_kwargs):
            if ".git/config" in url:
                return _make_response(hit_content, 200)
            from autosecaudit.agent_core.http_client import HttpClientError
            raise HttpClientError("not found")

        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=side_effect):
            result = self.tool.run(TARGET, {})

        assert result.ok
        exposures = result.data.get("payload", {}).get("exposures", [])
        paths = [e["path"] for e in exposures]
        assert ".git/config" in paths

    def test_detects_env_secret_key(self):
        """.env with SECRET_KEY value should be flagged."""
        env_content = b"SECRET_KEY=super_secret_value\nDB_HOST=localhost\n"

        def side_effect(url, **_kwargs):
            if url.endswith("/.env"):
                return _make_response(env_content, 200)
            from autosecaudit.agent_core.http_client import HttpClientError
            raise HttpClientError("not found")

        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=side_effect):
            result = self.tool.run(TARGET, {})

        exposures = result.data.get("payload", {}).get("exposures", [])
        paths = [e["path"] for e in exposures]
        assert ".env" in paths

    def test_no_exposure_when_404(self):
        """404 responses should not be flagged as exposures."""
        def side_effect(_url, **_kwargs):
            return _make_response(b"", 404)

        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=side_effect):
            result = self.tool.run(TARGET, {})

        assert result.ok
        exposures = result.data.get("payload", {}).get("exposures", [])
        assert len(exposures) == 0

    def test_no_exposure_when_body_lacks_keywords(self):
        """200 response without matching keywords should NOT be flagged."""

        def side_effect(url, **_kwargs):
            if ".env" in url:
                return _make_response(b"SOME_SAFE_VAR=hello", 200)
            from autosecaudit.agent_core.http_client import HttpClientError
            raise HttpClientError("not found")

        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=side_effect):
            result = self.tool.run(TARGET, {})

        exposures = result.data.get("payload", {}).get("exposures", [])
        assert ".env" not in [e["path"] for e in exposures]

    # ------------------------------------------------------------------
    # Error resilience
    # ------------------------------------------------------------------

    def test_all_requests_timeout(self):
        """Tool must complete without raising even if all requests timeout."""
        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=TimeoutError):
            result = self.tool.run(TARGET, {})
        assert result.ok

    def test_mixed_success_and_errors(self):
        """Handle mix of successes and errors per path."""
        call_count = [0]

        def side_effect(_url, **_kwargs):
            call_count[0] += 1
            if call_count[0] % 3 == 0:
                return _make_response(b"[core]\nrepositoryformatversion = 0", 200)
            from autosecaudit.agent_core.http_client import HttpClientError
            raise HttpClientError("some error")

        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=side_effect):
            result = self.tool.run(TARGET, {})
        assert result.ok

    # ------------------------------------------------------------------
    # Output structure
    # ------------------------------------------------------------------

    def test_result_structure(self):
        """Result data must have required keys."""
        with patch("autosecaudit.agent_core.builtin_tools.request_text") as mock_request:
            from autosecaudit.agent_core.http_client import HttpClientError
            mock_request.side_effect = HttpClientError("none")
            result = self.tool.run(TARGET, {})
        assert result.ok
        assert "payload" in result.data
        assert "findings" in result.data
        assert "surface_delta" in result.data
        payload = result.data["payload"]
        assert "checked_paths" in payload
        assert "exposures" in payload

    def test_findings_format(self):
        """Findings for exposures must include required fields."""
        env_content = b"API_KEY=very_secret_key_value"

        def side_effect(url, **_kwargs):
            if url.endswith("/.env"):
                return _make_response(env_content, 200)
            from autosecaudit.agent_core.http_client import HttpClientError
            raise HttpClientError("not found")

        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=side_effect):
            result = self.tool.run(TARGET, {})

        findings = result.data.get("findings", [])
        assert findings, "Expected at least one finding for .env exposure"
        for finding in findings:
            assert "type" in finding
            assert "name" in finding
            assert "severity" in finding

    def test_bounded_options_are_reflected_in_payload(self):
        """Custom lightweight bounds should be honored and exposed in payload."""
        with patch("autosecaudit.agent_core.builtin_tools.request_text", side_effect=TimeoutError):
            result = self.tool.run(
                TARGET,
                {
                    "request_timeout_seconds": 3,
                    "max_total_seconds": 18,
                    "max_paths": 10,
                },
            )

        payload = result.data.get("payload", {})
        assert payload.get("request_timeout_seconds") == 3.0
        assert payload.get("max_total_seconds") == 18.0
        assert len(payload.get("checked_paths", [])) == 10
