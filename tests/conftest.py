from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def security_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOSECAUDIT_WEB_JWT_SECRET", "test-jwt-secret-0123456789abcdef")
    monkeypatch.delenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_DISPLAY_NAME", raising=False)
    monkeypatch.delenv("AUTOSECAUDIT_WEB_BOOTSTRAP_TOKEN_TTL_SECONDS", raising=False)
