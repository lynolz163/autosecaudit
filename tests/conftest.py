from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def security_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTOSECAUDIT_CODEX_OAUTH_BUILTIN_PRESET", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_ACCESS_TOKEN", raising=False)
