"""Codex OAuth service helpers for AutoSecAudit web UI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from autosecaudit.integrations.llm_router import (
    CodexOAuthProvider,
    LLMProviderConfig,
    LLMRequestConfig,
    LLMRouterError,
)


def _utc_now() -> str:
    """Return UTC timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class CodexWebAuthManager:
    """
    Browser-redirect Codex OAuth helper for Web UI.

    Design:
    - Frontend opens returned official authorize URL in the user's browser.
    - Callback comes back to this web service (`/oauth/codex/callback`).
    - Tokens are persisted to the existing auth profile store.
    - Model list is fetched from the configured OpenAI-compatible `/models` endpoint.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, dict[str, Any]] = {}

    def is_configured(self) -> bool:
        """Return whether required Codex OAuth settings are present."""
        return bool(self._authorize_url() and self._token_url() and self._client_id())

    def config_summary(self) -> dict[str, Any]:
        """Return safe configuration summary for frontend display."""
        builtin_enabled = self._builtin_preset_enabled()
        explicit_auth = bool(os.getenv("AUTOSECAUDIT_CODEX_OAUTH_AUTHORIZE_URL", "").strip())
        explicit_token = bool(os.getenv("AUTOSECAUDIT_CODEX_OAUTH_TOKEN_URL", "").strip())
        explicit_client = bool(os.getenv("AUTOSECAUDIT_CODEX_OAUTH_CLIENT_ID", "").strip())
        return {
            "configured": self.is_configured(),
            "provider_alias": self._provider_alias(),
            "provider_type": "codex_oauth",
            "base_url": self._base_url(),
            "profile_id": self._profile_id(),
            "profiles_file": self._profiles_file(),
            "authorize_url": self._authorize_url(),
            "token_url": self._token_url(),
            "client_id_configured": bool(self._client_id()),
            "scopes": self._scopes(),
            "builtin_preset_enabled": builtin_enabled,
            "preset_source": (
                "env"
                if (explicit_auth or explicit_token or explicit_client)
                else ("builtin_openai_codex" if builtin_enabled else "none")
            ),
            "login_backend": "direct_oauth",
            "agent_provider_alias": self._provider_alias(),
            "agent_provider_type": "codex_oauth",
            "agent_base_url": self._base_url(),
            "agent_api_key_env": "OPENAI_API_KEY",
        }

    def start_login(self, *, request_headers: Any, host_fallback: str) -> dict[str, Any]:
        """Create OAuth login session and return official authorize URL."""
        authorize_url = self._authorize_url()
        token_url = self._token_url()
        client_id = self._client_id()
        if not authorize_url or not token_url or not client_id:
            raise ValueError(
                "Codex OAuth is not configured on the server. Set AUTOSECAUDIT_CODEX_OAUTH_AUTHORIZE_URL, "
                "AUTOSECAUDIT_CODEX_OAUTH_TOKEN_URL and AUTOSECAUDIT_CODEX_OAUTH_CLIENT_ID."
            )

        session_id = secrets.token_urlsafe(18)
        redirect_uri_base = self._redirect_uri_from_request(request_headers=request_headers, host_fallback=host_fallback)
        redirect_uri = self._append_query_param(redirect_uri_base, "session_id", session_id)
        state_token = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = CodexOAuthProvider._pkce_s256_challenge(code_verifier)

        auth_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state_token,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        scopes = self._scopes()
        if scopes:
            auth_params["scope"] = " ".join(scopes)
        if self._builtin_preset_enabled() and not os.getenv("AUTOSECAUDIT_CODEX_OAUTH_DISABLE_HINT_PARAMS", "").strip():
            auth_params.setdefault("codex_cli_simplified_flow", "true")
            auth_params.setdefault("id_token_add_organizations", "true")
            auth_params.setdefault("originator", "autosecaudit_web")
        auth_url = f"{authorize_url}?{urllib_parse.urlencode(auth_params)}"

        with self._lock:
            self._sessions[session_id] = {
                "session_id": session_id,
                "state": state_token,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "status": "pending",
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
                "error": None,
                "provider_alias": self._provider_alias(),
                "profile_id": self._profile_id(),
            }

        return {
            "session_id": session_id,
            "authorize_url": auth_url,
            "redirect_uri": redirect_uri,
            "provider_alias": self._provider_alias(),
            "profile_id": self._profile_id(),
            "base_url": self._base_url(),
        }

    def get_status(self, session_id: str) -> dict[str, Any]:
        """Return OAuth login session status."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(session_id)
        return {
            "session_id": session["session_id"],
            "status": session["status"],
            "created_at": session["created_at"],
            "updated_at": session["updated_at"],
            "error": session.get("error"),
            "provider_alias": session.get("provider_alias"),
            "profile_id": session.get("profile_id"),
            "model_count": session.get("model_count"),
            "login_backend": session.get("login_backend") or "direct_oauth",
        }

    def handle_callback(self, query: dict[str, list[str]]) -> tuple[int, str]:
        """Handle OAuth redirect callback and persist token."""
        session_id = str((query.get("session_id") or [""])[0]).strip()
        state = str((query.get("state") or [""])[0]).strip()
        code = str((query.get("code") or [""])[0]).strip()
        oauth_error = str((query.get("error") or [""])[0]).strip()
        oauth_error_description = str((query.get("error_description") or [""])[0]).strip()

        if not session_id:
            return 400, self._callback_html("Missing session_id", ok=False)

        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            return 404, self._callback_html("Invalid or expired OAuth session.", ok=False)

        if oauth_error:
            self._update_session(
                session_id,
                status="error",
                error=f"{oauth_error}: {oauth_error_description}".strip(": "),
            )
            return 400, self._callback_html("Login failed. Return to AutoSecAudit Web Console.", ok=False)

        if not code:
            self._update_session(session_id, status="error", error="callback_missing_authorization_code")
            return 400, self._callback_html("Authorization code missing.", ok=False)

        if state != str(session.get("state", "")):
            self._update_session(session_id, status="error", error="oauth_state_mismatch")
            return 400, self._callback_html("State mismatch. Please retry login.", ok=False)

        provider = self._build_provider_config()
        helper = CodexOAuthProvider(provider, LLMRequestConfig())
        try:
            token_payload = helper._exchange_oauth_code_for_token(  # noqa: SLF001
                token_url=self._token_url(),
                client_id=self._client_id(),
                code=code,
                redirect_uri=str(session["redirect_uri"]),
                code_verifier=str(session["code_verifier"]),
            )
            helper._write_oauth_cache_file(token_payload)  # noqa: SLF001
            helper._persist_profile_token_payload(token_payload, source="web_browser_login")  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self._update_session(session_id, status="error", error=str(exc))
            return 500, self._callback_html(f"Token exchange failed: {exc}", ok=False)

        try:
            models = self.list_models()
            model_count = len(models.get("models", []))
        except Exception:
            model_count = None

        self._update_session(session_id, status="completed", error=None, model_count=model_count)
        return 200, self._callback_html("Login successful. You can close this tab and return to AutoSecAudit.", ok=True)

    def list_models(self) -> dict[str, Any]:
        """Fetch model list using stored Codex OAuth token."""
        provider = self._build_provider_config()
        helper = CodexOAuthProvider(provider, LLMRequestConfig())
        try:
            bearer = helper._resolve_bearer_token()  # noqa: SLF001
        except LLMRouterError as exc:
            raise ValueError(str(exc)) from exc

        base_url = self._base_url().rstrip("/")
        endpoint = f"{base_url}/models"
        request = urllib_request.Request(
            url=endpoint,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer}",
            },
            method="GET",
        )
        try:
            with urllib_request.urlopen(request, timeout=20.0) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"models endpoint HTTP {exc.code}: {body[:300]}") from exc
        except urllib_error.URLError as exc:
            raise ValueError(f"models endpoint network error: {exc}") from exc
        except OSError as exc:
            raise ValueError(f"models endpoint request failed: {exc}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("models endpoint returned invalid JSON") from exc

        items = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(items, list):
            items = []
        models: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            model_id = str(item.get("id", "")).strip()
            if not model_id:
                continue
            models.append(
                {
                    "id": model_id,
                    "label": model_id,
                    "owned_by": str(item.get("owned_by", "")).strip() or None,
                    "created": item.get("created"),
                }
            )
        models.sort(key=lambda x: x["id"])
        return {
            "provider_alias": self._provider_alias(),
            "provider_type": "codex_oauth",
            "base_url": self._base_url(),
            "profile_id": self._profile_id(),
            "models": models,
            "login_backend": "direct_oauth",
            "agent_provider_alias": self._provider_alias(),
            "agent_provider_type": "codex_oauth",
            "agent_base_url": self._base_url(),
            "agent_api_key_env": "OPENAI_API_KEY",
        }

    def _build_provider_config(self) -> LLMProviderConfig:
        """Build Codex provider config from server-side environment."""
        return LLMProviderConfig(
            name=self._provider_alias(),
            provider_type="codex_oauth",
            base_url=self._base_url(),
            api_key_env="OPENAI_API_KEY",
            timeout_seconds=300.0,
            oauth_browser_login=False,
            oauth_authorize_url=self._authorize_url(),
            oauth_token_url=self._token_url(),
            oauth_client_id=self._client_id(),
            oauth_scopes=self._scopes(),
            oauth_profile_id=self._profile_id(),
            oauth_profiles_file=self._profiles_file(),
            oauth_token_env=self._token_env(),
            oauth_auto_refresh=self._oauth_auto_refresh(),
        )

    def _update_session(self, session_id: str, *, status: str, error: str | None, model_count: int | None = None) -> None:
        """Update one OAuth session record."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return
            session["status"] = status
            session["error"] = error
            session["updated_at"] = _utc_now()
            if model_count is not None:
                session["model_count"] = int(model_count)

    def _redirect_uri_from_request(self, *, request_headers: Any, host_fallback: str) -> str:
        """Build callback URL using public base URL override or incoming request host."""
        public_base = os.getenv("AUTOSECAUDIT_WEB_PUBLIC_BASE_URL", "").strip().rstrip("/")
        if public_base:
            return f"{public_base}/oauth/codex/callback"

        proto = str(request_headers.get("X-Forwarded-Proto", "") or "").strip().lower()
        if proto not in {"http", "https"}:
            proto = "http"
        host = str(request_headers.get("X-Forwarded-Host", "") or request_headers.get("Host", "") or host_fallback).strip()
        if not host:
            host = host_fallback
        return f"{proto}://{host}/oauth/codex/callback"

    @staticmethod
    def _append_query_param(url: str, key: str, value: str) -> str:
        """Append one query param to URL."""
        parsed = urllib_parse.urlparse(url)
        query_items = urllib_parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_items.append((str(key), str(value)))
        new_query = urllib_parse.urlencode(query_items)
        return urllib_parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
        )

    def _callback_html(self, message: str, *, ok: bool) -> str:
        """Render minimal callback page."""
        title = "Codex Login Success" if ok else "Codex Login Failed"
        tone = "#065f46" if ok else "#991b1b"
        bg = "#ecfdf5" if ok else "#fef2f2"
        border = "#a7f3d0" if ok else "#fecaca"
        safe_message = (
            str(message)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return (
            "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{title}</title></head><body style='font-family:system-ui;background:#f8fafc;padding:24px;'>"
            f"<div style='max-width:560px;margin:40px auto;background:{bg};border:1px solid {border};border-radius:16px;padding:20px;color:{tone};'>"
            f"<h2 style='margin:0 0 8px 0'>{title}</h2><p style='margin:0 0 12px 0'>{safe_message}</p>"
            "<p style='margin:0;font-size:12px;color:#475569'>Return to the AutoSecAudit Web Console and refresh model list if needed.</p>"
            "</div></body></html>"
        )

    @staticmethod
    def _builtin_openai_codex_preset() -> dict[str, Any]:
        """
        Built-in zero-config preset for official Codex OAuth.

        Values are intentionally overridable via environment variables.
        If OpenAI changes these, set AUTOSECAUDIT_CODEX_OAUTH_* env vars.
        """
        return {
            "authorize_url": "https://auth.openai.com/oauth/authorize",
            "token_url": "https://auth.openai.com/oauth/token",
            "base_url": "https://api.openai.com/v1",
            # Observed in Codex-generated OAuth authorize URLs (OpenAI Codex ecosystem).
            "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
            "scopes": ["openid", "profile", "email", "offline_access"],
        }

    @classmethod
    def _builtin_preset_enabled(cls) -> bool:
        raw = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_BUILTIN_PRESET", "1").strip().lower()
        return raw not in {"0", "false", "no", "off"}

    @staticmethod
    def _provider_alias() -> str:
        return os.getenv("AUTOSECAUDIT_CODEX_PROVIDER_ALIAS", "codex").strip() or "codex"

    @staticmethod
    def _base_url() -> str:
        explicit = os.getenv("AUTOSECAUDIT_CODEX_BASE_URL", "").strip()
        if explicit:
            return explicit
        if CodexWebAuthManager._builtin_preset_enabled():
            return str(CodexWebAuthManager._builtin_openai_codex_preset()["base_url"])
        return "https://api.openai.com/v1"

    @staticmethod
    def _authorize_url() -> str:
        explicit = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_AUTHORIZE_URL", "").strip()
        if explicit:
            return explicit
        if CodexWebAuthManager._builtin_preset_enabled():
            return str(CodexWebAuthManager._builtin_openai_codex_preset()["authorize_url"])
        return ""

    @staticmethod
    def _token_url() -> str:
        explicit = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_TOKEN_URL", "").strip()
        if explicit:
            return explicit
        if CodexWebAuthManager._builtin_preset_enabled():
            return str(CodexWebAuthManager._builtin_openai_codex_preset()["token_url"])
        return ""

    @staticmethod
    def _client_id() -> str:
        explicit = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_CLIENT_ID", "").strip()
        if explicit:
            return explicit
        if CodexWebAuthManager._builtin_preset_enabled():
            return str(CodexWebAuthManager._builtin_openai_codex_preset()["client_id"])
        return ""

    @staticmethod
    def _scopes() -> list[str]:
        raw = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_SCOPES", "").strip()
        if raw:
            return [item.strip() for item in raw.split(",") if item.strip()]
        if CodexWebAuthManager._builtin_preset_enabled():
            return [str(item) for item in CodexWebAuthManager._builtin_openai_codex_preset()["scopes"]]
        return ["openid", "profile", "offline_access"]

    @staticmethod
    def _profile_id() -> str:
        return os.getenv("AUTOSECAUDIT_CODEX_OAUTH_PROFILE_ID", "web").strip() or "web"

    @staticmethod
    def _profiles_file() -> str | None:
        value = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_PROFILES_FILE", "").strip()
        return value or None

    @staticmethod
    def _token_env() -> str | None:
        value = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_TOKEN_ENV", "OPENAI_ACCESS_TOKEN").strip()
        return value or None

    @staticmethod
    def _oauth_auto_refresh() -> bool:
        raw = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_AUTO_REFRESH", "1").strip().lower()
        return raw not in {"0", "false", "no", "off"}



