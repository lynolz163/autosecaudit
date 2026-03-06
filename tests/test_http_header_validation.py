"""Tests for HTTPHeaderValidationPlugin (plugins/http_header_validation.py)."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autosecaudit.core.models import AuditContext, RuntimeConfig
from autosecaudit.plugins.http_header_validation import HTTPHeaderValidationPlugin


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_context(target: str = "https://example.com") -> AuditContext:
    config = RuntimeConfig(
        target=target,
        output_dir=Path("/tmp/test_headers"),
        log_dir=Path("/tmp/test_headers/logs"),
        enabled_plugins=["http_headers_validation"],
    )
    ctx = MagicMock(spec=AuditContext)
    ctx.config = config
    ctx.log_operation = MagicMock()
    return ctx



def _make_urlopen_response(headers: dict[str, str], status: int = 200):
    """Build a mock urllib response with specific headers."""
    resp = MagicMock()
    resp.status = status
    resp.headers = MagicMock()
    resp.headers.items.return_value = list(headers.items())
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


# ---------------------------------------------------------------------------
# REQUIRED_HEADERS coverage
# ---------------------------------------------------------------------------

class TestRequiredHeaders:
    def test_has_six_required_headers(self):
        """Plugin must check exactly 6 security headers after our update."""
        headers = HTTPHeaderValidationPlugin.REQUIRED_HEADERS
        assert len(headers) == 6

    def test_includes_referrer_policy(self):
        assert "referrer-policy" in HTTPHeaderValidationPlugin.REQUIRED_HEADERS

    def test_includes_permissions_policy(self):
        assert "permissions-policy" in HTTPHeaderValidationPlugin.REQUIRED_HEADERS

    def test_includes_original_four(self):
        required = HTTPHeaderValidationPlugin.REQUIRED_HEADERS
        for header in ["strict-transport-security", "content-security-policy",
                       "x-content-type-options", "x-frame-options"]:
            assert header in required


# ---------------------------------------------------------------------------
# Plugin run – security header outcomes
# ---------------------------------------------------------------------------

class TestHTTPHeaderPlugin:
    def setup_method(self):
        self.plugin = HTTPHeaderValidationPlugin()

    def test_all_headers_present_passes(self):
        """Response with all 6 headers → plugin should pass."""
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen") as mock_open:
            mock_open.return_value = _make_urlopen_response(SECURE_HEADERS)
            result = self.plugin.run(ctx)
        assert result.status == "passed"
        assert all(f.severity == "info" for f in result.findings)

    def test_missing_hsts_produces_high_finding(self):
        """Missing HSTS → finding with 'high' severity."""
        headers = dict(SECURE_HEADERS)
        del headers["Strict-Transport-Security"]
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen") as mock_open:
            mock_open.return_value = _make_urlopen_response(headers)
            result = self.plugin.run(ctx)
        assert result.status == "failed"
        high_findings = [f for f in result.findings if f.severity == "high"]
        assert high_findings, "Expected a high severity finding for missing HSTS"

    def test_missing_referrer_policy_produces_low_finding(self):
        """Missing Referrer-Policy → finding with 'low' severity."""
        headers = dict(SECURE_HEADERS)
        del headers["Referrer-Policy"]
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen") as mock_open:
            mock_open.return_value = _make_urlopen_response(headers)
            result = self.plugin.run(ctx)
        assert result.status == "failed"
        low_findings = [f for f in result.findings if f.severity == "low"]
        assert any("referrer" in f.title.lower() for f in low_findings)

    def test_missing_permissions_policy_produces_low_finding(self):
        """Missing Permissions-Policy → finding with 'low' severity."""
        headers = dict(SECURE_HEADERS)
        del headers["Permissions-Policy"]
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen") as mock_open:
            mock_open.return_value = _make_urlopen_response(headers)
            result = self.plugin.run(ctx)
        assert result.status == "failed"
        low_findings = [f for f in result.findings if f.severity == "low"]
        assert any("permissions" in f.title.lower() for f in low_findings)

    def test_all_headers_missing_produces_failed_status(self):
        """Response with zero security headers → status failed."""
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen") as mock_open:
            mock_open.return_value = _make_urlopen_response({"Server": "nginx"})
            result = self.plugin.run(ctx)
        assert result.status == "failed"
        assert len(result.findings) == 6, f"Expected 6 findings, got {len(result.findings)}"

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def test_network_error_returns_error_status(self):
        from urllib.error import URLError
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen", side_effect=URLError("timeout")):
            result = self.plugin.run(ctx)
        assert result.status == "error"
        assert result.error is not None

    def test_http_error_returns_error_status(self):
        from urllib.error import HTTPError
        ctx = _make_context()
        exc = HTTPError("https://example.com", 500, "Server Error", MagicMock(), io.BytesIO(b""))
        with patch("autosecaudit.plugins.http_header_validation.urlopen", side_effect=exc):
            result = self.plugin.run(ctx)
        assert result.status == "error"

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def test_metadata_includes_missing_headers(self):
        headers = dict(SECURE_HEADERS)
        del headers["Referrer-Policy"]
        del headers["Permissions-Policy"]
        ctx = _make_context()
        with patch("autosecaudit.plugins.http_header_validation.urlopen") as mock_open:
            mock_open.return_value = _make_urlopen_response(headers)
            result = self.plugin.run(ctx)
        missing = result.metadata.get("missing_headers", [])
        assert "referrer-policy" in missing
        assert "permissions-policy" in missing
