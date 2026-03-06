"""OpenClaw-style LLM routing with provider/model references and fallbacks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import base64
import hashlib
from http import server as http_server
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
import webbrowser

from . import openai_compatible_extract
from .auth_profiles import AuthProfileStore, token_expired


class LLMRouterError(RuntimeError):
    """Raised when LLM routing/provider invocation fails."""


@dataclass(frozen=True)
class LLMRequestConfig:
    """Request-level generation controls."""

    temperature: float = 0.0
    max_output_tokens: int = 1200


@dataclass(frozen=True)
class LLMProviderConfig:
    """Provider configuration."""

    name: str
    provider_type: str
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str | None = None
    timeout_seconds: float = 300.0
    headers: dict[str, str] = field(default_factory=dict)
    oauth_token_env: str | None = None
    oauth_token_file: str | None = None
    oauth_command: list[str] = field(default_factory=list)
    oauth_browser_login: bool = False
    oauth_authorize_url: str | None = None
    oauth_token_url: str | None = None
    oauth_client_id: str | None = None
    oauth_scopes: list[str] = field(default_factory=list)
    oauth_redirect_host: str = "127.0.0.1"
    oauth_redirect_port: int = 8765
    oauth_redirect_path: str = "/callback"
    oauth_cache_file: str | None = None
    oauth_login_timeout_seconds: float = 180.0
    oauth_profile_id: str | None = None
    oauth_profiles_file: str | None = None
    oauth_auto_refresh: bool = True


@dataclass(frozen=True)
class LLMRouterConfig:
    """Model routing configuration (primary + fallbacks)."""

    primary_model: str
    fallback_models: list[str] = field(default_factory=list)
    default_provider: str = "openai"
    providers: dict[str, LLMProviderConfig] = field(default_factory=dict)
    request: LLMRequestConfig = field(default_factory=LLMRequestConfig)


class BaseLLMProvider(ABC):
    """Provider interface for prompt -> text completion."""

    def __init__(
        self,
        config: LLMProviderConfig,
        request_config: LLMRequestConfig,
        logger: Any | None = None,
    ) -> None:
        self._config = config
        self._request_config = request_config
        self._logger = logger

    @abstractmethod
    def generate_text(self, model: str, prompt: str) -> str:
        """Generate text for the given model and prompt."""
        raise NotImplementedError

    def _resolve_api_key(self) -> str:
        """Resolve API key from environment (empty allowed for some local gateways)."""
        api_key = os.getenv(self._config.api_key_env, "")
        return api_key.strip()


def _content_length(value: Any) -> int:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._content_length(value)


def _prefix_extract_source(prefix: str, source: str) -> str:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._prefix_extract_source(prefix, source)


def _extract_text_field_from_payload(payload: dict[str, Any], source: str) -> tuple[str, str]:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._extract_text_field_from_payload(payload, source)


def _collect_text_fragments_from_items(items: list[Any], source: str) -> list[str]:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._collect_text_fragments_from_items(items, source)


def _normalize_openai_compatible_content(content: Any, source: str) -> tuple[str, str]:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._normalize_openai_compatible_content(content, source)


def _extract_message_text_from_payload(message: dict[str, Any], base_source: str) -> tuple[str, str]:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._extract_message_text_from_payload(message, base_source)


def _extract_responses_output_chunks(output: list[Any], source: str) -> tuple[list[str], str]:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract._extract_responses_output_chunks(output, source)


def extract_text_from_openai_compatible_response(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Backward-compatible wrapper around extracted helper implementation."""
    return openai_compatible_extract.extract_text_from_openai_compatible_response(payload)


class OpenAICompatibleProvider(BaseLLMProvider):
    """
    OpenAI-compatible HTTP provider.

    Uses `/chat/completions`, which is widely supported by gateways and local runtimes.
    """

    def generate_text(self, model: str, prompt: str) -> str:
        """POST one OpenAI-compatible chat completion request and return text."""
        if not self._config.base_url:
            raise LLMRouterError(
                f"provider '{self._config.name}' requires base_url for openai_compatible mode"
            )

        base_url = self._config.base_url.rstrip("/")
        endpoint = f"{base_url}/chat/completions"
        bearer_token = self._resolve_bearer_token()

        headers = {
            "Content-Type": "application/json",
        }
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        headers.update(self._config.headers)

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": float(self._request_config.temperature),
            "max_tokens": int(self._request_config.max_output_tokens),
        }
        request = urllib_request.Request(
            url=endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib_request.urlopen(
                request,
                timeout=float(self._config.timeout_seconds),
            ) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise LLMRouterError(
                f"{self._config.name} HTTP {exc.code}: {body[:500]}"
            ) from exc
        except urllib_error.URLError as exc:
            raise LLMRouterError(f"{self._config.name} network error: {exc}") from exc
        except OSError as exc:
            raise LLMRouterError(f"{self._config.name} request failed: {exc}") from exc

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMRouterError(f"{self._config.name} returned non-JSON response") from exc

        text, extract_meta = self._extract_text_and_meta_from_openai_compatible_response(parsed)
        if not text.strip():
            response_summary = self._summarize_response_payload(parsed, extract_meta=extract_meta)
            self._log_empty_text_debug(
                model=model,
                base_url=base_url,
                response_summary=response_summary,
            )
            raise LLMRouterError(
                f"{self._config.name} returned empty completion text; "
                f"response_summary={response_summary}"
            )
        return text

    def _resolve_bearer_token(self) -> str:
        """Resolve bearer token for OpenAI-compatible auth (defaults to API key env)."""
        return self._resolve_api_key()

    def _extract_text_and_meta_from_openai_compatible_response(
        self,
        payload: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        """Extract text plus extraction metadata from OpenAI-compatible payloads."""
        return extract_text_from_openai_compatible_response(payload)

    def _extract_text_from_openai_compatible_response(self, payload: dict[str, Any]) -> str:
        """Extract text from common OpenAI-compatible response shapes."""
        text, _meta = self._extract_text_and_meta_from_openai_compatible_response(payload)
        return text

    def _log_empty_text_debug(self, *, model: str, base_url: str, response_summary: str) -> None:
        """Log one safe debug line for empty-text OpenAI-compatible responses."""
        if self._logger is None:
            return
        try:
            self._logger.warning(
                "LLM empty completion text provider=%s model=%s base_url=%s response_summary=%s",
                self._config.name,
                model,
                base_url,
                response_summary,
            )
        except Exception:  # noqa: BLE001
            pass

    def _summarize_response_payload(
        self,
        payload: Any,
        extract_meta: dict[str, Any] | None = None,
    ) -> str:
        """Build one compact response summary for provider failure logs."""
        if not isinstance(payload, dict):
            return f"type={type(payload).__name__}"

        summary: dict[str, Any] = {
            "keys": sorted(str(key) for key in payload.keys())[:12],
        }
        if extract_meta:
            summary["extract_source"] = str(extract_meta.get("source", "") or "")
            summary["extract_length"] = int(extract_meta.get("length", 0) or 0)
            summary["extract_empty"] = bool(extract_meta.get("is_empty", True))

        choices = payload.get("choices")
        if isinstance(choices, list):
            summary["choices_count"] = len(choices)
            choice_summaries: list[dict[str, Any]] = []
            for index, choice in enumerate(choices[:4]):
                if not isinstance(choice, dict):
                    continue
                choice_summary: dict[str, Any] = {
                    "index": index,
                    "keys": sorted(str(key) for key in choice.keys())[:12],
                }
                finish_reason = choice.get("finish_reason")
                if finish_reason is not None:
                    choice_summary["finish_reason"] = str(finish_reason)
                    if index == 0:
                        summary["finish_reason"] = str(finish_reason)
                for key in ("message", "delta"):
                    node = choice.get(key)
                    if not isinstance(node, dict):
                        continue
                    choice_summary[f"{key}_keys"] = sorted(str(item) for item in node.keys())[:12]
                    field_lengths = {
                        field: _content_length(node.get(field))
                        for field in ("content", "reasoning_content", "reasoning", "output_text", "text")
                        if field in node
                    }
                    if field_lengths:
                        choice_summary[f"{key}_lengths"] = field_lengths
                if isinstance(choice.get("text"), str):
                    choice_summary["text_length"] = len(str(choice.get("text", "")))
                choice_summaries.append(choice_summary)
            if choice_summaries:
                summary["choices"] = choice_summaries

        output_text = payload.get("output_text")
        if isinstance(output_text, str):
            summary["output_text_len"] = len(output_text)
            if output_text.strip():
                summary["output_text_preview"] = output_text.strip()[:160]

        output = payload.get("output")
        if isinstance(output, list):
            summary["output_count"] = len(output)
            chunks, _source = _extract_responses_output_chunks(output, "output")
            if chunks:
                summary["output_preview"] = "\n".join(chunks)[:160]

        candidates = payload.get("candidates")
        if isinstance(candidates, list):
            summary["candidates_count"] = len(candidates)
            if candidates and isinstance(candidates[0], dict):
                content = candidates[0].get("content")
                if isinstance(content, dict):
                    parts = content.get("parts")
                    if isinstance(parts, list):
                        fragments = _collect_text_fragments_from_items(parts, "candidates[0].content.parts")
                        if fragments:
                            summary["candidate_preview"] = "\n".join(fragments)[:160]

        usage = payload.get("usage")
        if isinstance(usage, dict):
            summary["usage_keys"] = sorted(str(key) for key in usage.keys())[:12]

        return json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class OpenAISDKProvider(BaseLLMProvider):
    """Official OpenAI SDK provider (Responses API)."""

    def __init__(
        self,
        config: LLMProviderConfig,
        request_config: LLMRequestConfig,
        logger: Any | None = None,
    ) -> None:
        super().__init__(config, request_config, logger=logger)
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:
            raise LLMRouterError(
                "openai package is not installed; install it or use openai_compatible provider"
            ) from exc

        client_kwargs: dict[str, Any] = {
            "api_key": self._resolve_api_key() or None,
            "timeout": float(config.timeout_seconds),
        }
        if config.base_url:
            client_kwargs["base_url"] = config.base_url
        self._client = OpenAI(**client_kwargs)

    def generate_text(self, model: str, prompt: str) -> str:
        """Call OpenAI Responses API and return output_text."""
        try:
            response = self._client.responses.create(
                model=model,
                input=prompt,
                temperature=float(self._request_config.temperature),
                max_output_tokens=int(self._request_config.max_output_tokens),
            )
        except Exception as exc:  # noqa: BLE001
            raise LLMRouterError(f"{self._config.name} SDK call failed: {exc}") from exc

        text = str(getattr(response, "output_text", "") or "").strip()
        if text:
            return text

        # Fallback parsing across SDK response object shapes.
        try:
            response_dict = response.model_dump()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            response_dict = {}
        compat = OpenAICompatibleProvider(self._config, self._request_config, logger=self._logger)
        if isinstance(response_dict, dict):
            text, extract_meta = compat._extract_text_and_meta_from_openai_compatible_response(response_dict)
            if text.strip():
                return text
            response_summary = compat._summarize_response_payload(response_dict, extract_meta=extract_meta)
        else:
            response_summary = compat._summarize_response_payload(response_dict)
        compat._log_empty_text_debug(
            model=model,
            base_url=str(self._config.base_url or ""),
            response_summary=response_summary,
        )
        raise LLMRouterError(
            f"{self._config.name} returned empty completion text; "
            f"response_summary={response_summary}"
        )


class CodexOAuthProvider(OpenAICompatibleProvider):
    """
    OpenAI-compatible provider using OAuth subscription bearer tokens.

    This is intentionally "OpenClaw-like": it does not implement the browser/device
    OAuth login flow itself. Instead, it consumes an existing OAuth access token from:
    1) configured env var
    2) configured token file (JSON/text)
    3) configured command output (JSON/text), executed safely with shell=False
    4) common fallback env vars / token file locations
    """

    _DEFAULT_TOKEN_ENV_CANDIDATES: tuple[str, ...] = (
        "OPENAI_ACCESS_TOKEN",
        "CODEX_ACCESS_TOKEN",
    )
    _DEFAULT_TOKEN_FILE_CANDIDATES: tuple[str, ...] = (
        "~/.codex/auth.json",
        "~/.codex/oauth.json",
        "~/.config/codex/auth.json",
        "~/.config/openclaw/auth.json",
        "~/.openclaw/auth.json",
        r"%USERPROFILE%\.codex\auth.json",
        r"%USERPROFILE%\.openclaw\auth.json",
    )
    _TOKEN_JSON_KEY_CANDIDATES: tuple[str, ...] = (
        "access_token",
        "accessToken",
        "token",
        "oauth_token",
        "id_token",
    )
    _TOKEN_JSON_NESTED_PATHS: tuple[tuple[str, ...], ...] = (
        ("auth", "access_token"),
        ("oauth", "access_token"),
        ("credentials", "access_token"),
        ("tokens", "access_token"),
    )

    def _profile_store(self) -> AuthProfileStore | None:
        """Return auth profile store if profile mode is configured."""
        profile_id = (self._config.oauth_profile_id or "").strip()
        if not profile_id:
            return None
        store_path = self._config.oauth_profiles_file
        return AuthProfileStore(path=store_path) if store_path else AuthProfileStore()

    def _profile_id(self) -> str:
        """Return configured profile id or provider default."""
        return (self._config.oauth_profile_id or "default").strip()

    def _load_profile_access_token(self) -> str:
        """Load access token from auth profile store, refreshing if configured and possible."""
        try:
            store = self._profile_store()
        except Exception:  # noqa: BLE001
            return ""
        if store is None:
            return ""
        try:
            profile = store.get_profile(provider=self._config.name, profile_id=self._profile_id())
        except Exception:  # noqa: BLE001
            return ""
        if profile is None:
            return ""
        token_payload = profile.data if isinstance(profile.data, dict) else {}
        if not token_payload:
            return ""

        access_token = self._extract_token_from_json(token_payload)
        if access_token and not token_expired(token_payload):
            return access_token

        if not self._config.oauth_auto_refresh:
            return ""

        try:
            refreshed = self._refresh_profile_token(store=store, token_payload=token_payload)
        except Exception:  # noqa: BLE001
            return ""
        if refreshed:
            return self._extract_token_from_json(refreshed)
        return ""

    def _persist_profile_token_payload(self, token_payload: dict[str, Any], source: str) -> None:
        """Persist token payload to auth profile store when profile mode is enabled."""
        store = self._profile_store()
        if store is None:
            return
        store.upsert_oauth_profile(
            provider=self._config.name,
            profile_id=self._profile_id(),
            token_payload=token_payload,
            metadata={
                "source": source,
                "base_url": self._config.base_url or "",
            },
        )

    def _refresh_profile_token(
        self,
        *,
        store: AuthProfileStore,
        token_payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Refresh profile token using refresh_token if available."""
        refresh_token = str(token_payload.get("refresh_token", "")).strip()
        token_url = (self._config.oauth_token_url or "").strip()
        client_id = (self._config.oauth_client_id or "").strip()
        if not refresh_token or not token_url or not client_id:
            return None

        refreshed = self._refresh_oauth_token(
            token_url=token_url,
            client_id=client_id,
            refresh_token=refresh_token,
        )
        if not refreshed:
            return None

        merged = dict(token_payload)
        merged.update(refreshed)
        if "refresh_token" not in refreshed:
            merged["refresh_token"] = refresh_token
        store.upsert_oauth_profile(
            provider=self._config.name,
            profile_id=self._profile_id(),
            token_payload=merged,
            metadata={"source": "refresh", "base_url": self._config.base_url or ""},
        )
        return merged

    def _resolve_bearer_token(self) -> str:
        """Resolve OAuth bearer token from configured or common sources."""
        # 0) Auth profile store (OpenClaw-style token sink).
        token = self._load_profile_access_token()
        if token:
            return token

        # 1) Explicit env var.
        if self._config.oauth_token_env:
            token = os.getenv(self._config.oauth_token_env, "").strip()
            if token:
                return token

        # 2) Explicit token file.
        if self._config.oauth_token_file:
            token = self._read_token_file(self._config.oauth_token_file)
            if token:
                return token

        # 3) Explicit command.
        if self._config.oauth_command:
            token = self._run_token_command(self._config.oauth_command)
            if token:
                return token

        # 4) Common envs.
        for env_name in self._DEFAULT_TOKEN_ENV_CANDIDATES:
            token = os.getenv(env_name, "").strip()
            if token:
                return token

        # 5) Common local files.
        for raw_path in self._DEFAULT_TOKEN_FILE_CANDIDATES:
            token = self._read_token_file(raw_path, raise_on_error=False)
            if token:
                return token

        # 6) Interactive browser OAuth login (PKCE) if enabled and configured.
        if self._config.oauth_browser_login:
            return self._browser_oauth_login()

        raise LLMRouterError(
            f"{self._config.name} could not resolve Codex OAuth token "
            "(set oauth_token_env/oauth_token_file/oauth_command in provider config)"
        )

    def _run_token_command(self, argv: list[str]) -> str:
        """Run external token helper safely and parse token from stdout."""
        if not argv:
            return ""
        if any(not str(item).strip() for item in argv):
            raise LLMRouterError(f"{self._config.name} oauth_command contains empty argument")

        try:
            completed = subprocess.run(
                [str(item) for item in argv],
                capture_output=True,
                text=True,
                timeout=min(float(self._config.timeout_seconds), 30.0),
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise LLMRouterError(
                f"{self._config.name} oauth_command executable not found: {argv[0]}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise LLMRouterError(f"{self._config.name} oauth_command timed out") from exc
        except OSError as exc:
            raise LLMRouterError(f"{self._config.name} oauth_command failed: {exc}") from exc

        if completed.returncode != 0:
            stderr_snippet = (completed.stderr or "").strip()[:300]
            raise LLMRouterError(
                f"{self._config.name} oauth_command exit={completed.returncode}: {stderr_snippet}"
            )

        token = self._extract_token_from_text(completed.stdout or "")
        if not token:
            raise LLMRouterError(f"{self._config.name} oauth_command returned no token")
        return token

    def _read_token_file(self, path_text: str, raise_on_error: bool = True) -> str:
        """Read OAuth token from JSON or raw-text file."""
        expanded = os.path.expandvars(os.path.expanduser(str(path_text)))
        path = Path(expanded)
        try:
            raw = path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            if raise_on_error:
                raise LLMRouterError(f"{self._config.name} oauth_token_file not found: {path}")
            return ""
        except OSError as exc:
            if raise_on_error:
                raise LLMRouterError(f"{self._config.name} failed reading oauth_token_file: {exc}") from exc
            return ""

        token = self._extract_token_from_text(raw)
        if token and self._token_is_expired_json(raw):
            if raise_on_error:
                raise LLMRouterError(f"{self._config.name} oauth_token_file token is expired: {path}")
            return ""
        if token:
            return token
        if raise_on_error:
            raise LLMRouterError(
                f"{self._config.name} oauth_token_file does not contain a readable access token: {path}"
            )
        return ""

    def _extract_token_from_text(self, raw: str) -> str:
        """Extract token from JSON object/string or plain text."""
        text = (raw or "").strip()
        if not text:
            return ""

        # Raw token on first line.
        first_line = text.splitlines()[0].strip()
        if first_line and not first_line.startswith("{") and " " not in first_line:
            return first_line

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return first_line if first_line else ""

        return self._extract_token_from_json(payload)

    def _extract_token_from_json(self, payload: Any) -> str:
        """Extract access token from flexible JSON payloads."""
        if isinstance(payload, str):
            return payload.strip()
        if not isinstance(payload, dict):
            return ""

        for key in self._TOKEN_JSON_KEY_CANDIDATES:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        for path in self._TOKEN_JSON_NESTED_PATHS:
            current: Any = payload
            for part in path:
                if not isinstance(current, dict):
                    current = None
                    break
                current = current.get(part)
            if isinstance(current, str) and current.strip():
                return current.strip()

        # Some tools may return {"data": {"token": "..."}}
        for value in payload.values():
            if isinstance(value, dict):
                nested = self._extract_token_from_json(value)
                if nested:
                    return nested
        return ""

    def _token_is_expired_json(self, raw: str) -> bool:
        """Best-effort expiration check for cached OAuth token JSON payload."""
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return False
        if not isinstance(payload, dict):
            return False
        expires_at = payload.get("expires_at") or payload.get("expiresAt")
        if isinstance(expires_at, (int, float)):
            # 30s clock skew buffer
            return float(expires_at) <= (time.time() + 30)
        return False

    def _browser_oauth_login(self) -> str:
        """Run authorization-code PKCE flow via local browser and cache access token."""
        authorize_url = (self._config.oauth_authorize_url or "").strip()
        token_url = (self._config.oauth_token_url or "").strip()
        client_id = (self._config.oauth_client_id or "").strip()
        if not authorize_url or not token_url or not client_id:
            raise LLMRouterError(
                f"{self._config.name} oauth_browser_login requires oauth_authorize_url, "
                "oauth_token_url and oauth_client_id"
            )

        redirect_path = self._normalize_redirect_path(self._config.oauth_redirect_path)
        redirect_uri = (
            f"http://{self._config.oauth_redirect_host}:{int(self._config.oauth_redirect_port)}"
            f"{redirect_path}"
        )
        state = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(64)
        challenge = self._pkce_s256_challenge(verifier)

        callback_payload = self._wait_for_oauth_callback(
            authorize_url=authorize_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=self._config.oauth_scopes,
            state=state,
            code_challenge=challenge,
            redirect_host=self._config.oauth_redirect_host,
            redirect_port=int(self._config.oauth_redirect_port),
            redirect_path=redirect_path,
            timeout_seconds=float(self._config.oauth_login_timeout_seconds),
        )

        if callback_payload.get("state") != state:
            raise LLMRouterError(f"{self._config.name} OAuth state mismatch")
        if callback_payload.get("error"):
            raise LLMRouterError(
                f"{self._config.name} OAuth authorization error: {callback_payload.get('error')}"
            )
        code = str(callback_payload.get("code", "")).strip()
        if not code:
            raise LLMRouterError(f"{self._config.name} OAuth callback missing authorization code")

        token_payload = self._exchange_oauth_code_for_token(
            token_url=token_url,
            client_id=client_id,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=verifier,
        )
        token = self._extract_token_from_json(token_payload)
        if not token:
            raise LLMRouterError(f"{self._config.name} OAuth token endpoint returned no access token")

        self._write_oauth_cache_file(token_payload)
        self._persist_profile_token_payload(token_payload, source="browser_login")
        return token

    def _wait_for_oauth_callback(
        self,
        *,
        authorize_url: str,
        client_id: str,
        redirect_uri: str,
        scopes: list[str],
        state: str,
        code_challenge: str,
        redirect_host: str,
        redirect_port: int,
        redirect_path: str,
        timeout_seconds: float,
    ) -> dict[str, str]:
        """Start local callback server, open browser, and wait for one OAuth redirect."""
        result: dict[str, str] = {}
        ready_event = threading.Event()
        done_event = threading.Event()
        server_error: dict[str, str] = {}

        class _OAuthHandler(http_server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib_parse.urlparse(self.path)
                if parsed.path != redirect_path:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"Not Found")
                    return

                query = urllib_parse.parse_qs(parsed.query, keep_blank_values=True)
                result["code"] = str(query.get("code", [""])[0])
                result["state"] = str(query.get("state", [""])[0])
                result["error"] = str(query.get("error", [""])[0])
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    (
                        "<html><body><h3>Login completed</h3>"
                        "<p>You can close this window and return to AutoSecAudit.</p>"
                        "</body></html>"
                    ).encode("utf-8")
                )
                done_event.set()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                # Silence callback server logging.
                return

        try:
            httpd = http_server.ThreadingHTTPServer((redirect_host, redirect_port), _OAuthHandler)
        except OSError as exc:
            raise LLMRouterError(
                f"{self._config.name} failed to bind OAuth callback server on "
                f"{redirect_host}:{redirect_port}: {exc}"
            ) from exc

        def _serve() -> None:
            try:
                ready_event.set()
                httpd.handle_request()
            except Exception as exc:  # noqa: BLE001
                server_error["error"] = str(exc)
                done_event.set()

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        ready_event.wait(timeout=1.0)

        auth_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if scopes:
            auth_params["scope"] = " ".join(scopes)
        launch_url = f"{authorize_url}?{urllib_parse.urlencode(auth_params)}"
        opened = webbrowser.open(launch_url, new=1, autoraise=True)
        if not opened:
            # Still wait; some systems return False even when a handler exists.
            pass

        if not done_event.wait(timeout=max(5.0, timeout_seconds)):
            try:
                httpd.server_close()
            except Exception:  # noqa: BLE001
                pass
            raise LLMRouterError(
                f"{self._config.name} OAuth login timed out after {timeout_seconds:.0f}s "
                f"(callback not received)"
            )

        try:
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

        if server_error.get("error"):
            raise LLMRouterError(f"{self._config.name} OAuth callback server error: {server_error['error']}")
        return result

    def _exchange_oauth_code_for_token(
        self,
        *,
        token_url: str,
        client_id: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for access token using PKCE."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        headers.update(self._config.headers)
        form = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        request = urllib_request.Request(
            url=token_url,
            data=urllib_parse.urlencode(form).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=float(self._config.timeout_seconds)) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise LLMRouterError(f"{self._config.name} token endpoint HTTP {exc.code}: {body[:500]}") from exc
        except urllib_error.URLError as exc:
            raise LLMRouterError(f"{self._config.name} token endpoint network error: {exc}") from exc
        except OSError as exc:
            raise LLMRouterError(f"{self._config.name} token exchange failed: {exc}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMRouterError(f"{self._config.name} token endpoint returned non-JSON response") from exc
        if not isinstance(payload, dict):
            raise LLMRouterError(f"{self._config.name} token endpoint returned invalid payload")
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)):
            payload["expires_at"] = time.time() + float(expires_in)
        return payload

    def _refresh_oauth_token(
        self,
        *,
        token_url: str,
        client_id: str,
        refresh_token: str,
    ) -> dict[str, Any] | None:
        """Refresh OAuth access token using refresh_token."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        headers.update(self._config.headers)
        form = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        }
        request = urllib_request.Request(
            url=token_url,
            data=urllib_parse.urlencode(form).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=float(self._config.timeout_seconds)) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except (urllib_error.HTTPError, urllib_error.URLError, OSError):
            return None

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)):
            payload["expires_at"] = time.time() + float(expires_in)
        return payload

    def _write_oauth_cache_file(self, token_payload: dict[str, Any]) -> None:
        """Write token payload to cache file if configured."""
        cache_path_text = (
            self._config.oauth_cache_file
            or self._config.oauth_token_file
            or str(Path.home() / ".autosecaudit" / f"{self._config.name}_oauth_token.json")
        )
        path = Path(os.path.expandvars(os.path.expanduser(cache_path_text)))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(token_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            raise LLMRouterError(f"{self._config.name} failed writing oauth cache file: {exc}") from exc

    @staticmethod
    def _normalize_redirect_path(path: str) -> str:
        """Normalize callback path to `/foo` shape."""
        raw = (path or "/callback").strip()
        if not raw.startswith("/"):
            raw = "/" + raw
        return raw

    @staticmethod
    def _pkce_s256_challenge(verifier: str) -> str:
        """Compute RFC7636 S256 code challenge."""
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class LLMRouter:
    """Provider/model router with deterministic fallback behavior."""

    _PROVIDER_TYPES: dict[str, type[BaseLLMProvider]] = {
        "openai_compatible": OpenAICompatibleProvider,
        "openai_sdk": OpenAISDKProvider,
        "codex_oauth": CodexOAuthProvider,
    }

    def __init__(self, config: LLMRouterConfig, logger: Any | None = None) -> None:
        self._config = config
        self._logger = logger
        self._providers: dict[str, BaseLLMProvider] = {}

    @classmethod
    def from_json_file(cls, path: Path, logger: Any | None = None) -> "LLMRouter":
        """Load router config from JSON file."""
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError as exc:
            raise LLMRouterError(f"LLM config file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise LLMRouterError(f"LLM config file is not valid JSON: {path}") from exc
        except OSError as exc:
            raise LLMRouterError(f"Failed to read LLM config file {path}: {exc}") from exc
        return cls.from_dict(payload, logger=logger)

    @classmethod
    def from_dict(cls, payload: dict[str, Any], logger: Any | None = None) -> "LLMRouter":
        """Build router from dict config."""
        if not isinstance(payload, dict):
            raise LLMRouterError("LLM config must be a JSON object")

        primary_model = str(payload.get("primary_model", "")).strip()
        if not primary_model:
            raise LLMRouterError("LLM config missing 'primary_model'")

        default_provider = str(payload.get("default_provider", "openai")).strip() or "openai"
        fallback_models_raw = payload.get("fallback_models", payload.get("fallbacks", []))
        fallback_models = cls._normalize_fallback_models(
            primary_model=primary_model,
            default_provider=default_provider,
            raw_fallbacks=fallback_models_raw,
        )

        request_payload = payload.get("request", {})
        request_config = LLMRequestConfig(
            temperature=float(request_payload.get("temperature", 0.0))
            if isinstance(request_payload, dict)
            else 0.0,
            max_output_tokens=int(request_payload.get("max_output_tokens", 1200))
            if isinstance(request_payload, dict)
            else 1200,
        )

        providers_payload = payload.get("providers", {})
        if not isinstance(providers_payload, dict):
            raise LLMRouterError("LLM config field 'providers' must be an object")
        providers: dict[str, LLMProviderConfig] = {}
        for provider_name, provider_item in providers_payload.items():
            if not isinstance(provider_item, dict):
                raise LLMRouterError(f"provider '{provider_name}' config must be an object")
            provider_type = str(provider_item.get("type", "")).strip()
            if provider_type not in cls._PROVIDER_TYPES:
                raise LLMRouterError(
                    f"provider '{provider_name}' has unsupported type '{provider_type}'"
                )
            headers = provider_item.get("headers", {})
            resolved_base_url = (
                str(provider_item["base_url"]).strip()
                if provider_item.get("base_url") is not None
                else None
            )
            if provider_type == "codex_oauth" and not resolved_base_url:
                resolved_base_url = "https://api.openai.com/v1"
            providers[str(provider_name)] = LLMProviderConfig(
                name=str(provider_name),
                provider_type=provider_type,
                api_key_env=str(provider_item.get("api_key_env", "OPENAI_API_KEY")),
                base_url=resolved_base_url,
                timeout_seconds=float(provider_item.get("timeout_seconds", 300.0)),
                headers=dict(headers) if isinstance(headers, dict) else {},
                oauth_token_env=(
                    str(provider_item["oauth_token_env"]).strip()
                    if provider_item.get("oauth_token_env") is not None
                    else None
                ),
                oauth_token_file=(
                    str(provider_item["oauth_token_file"]).strip()
                    if provider_item.get("oauth_token_file") is not None
                    else None
                ),
                oauth_command=cls._parse_oauth_command_config(
                    provider_item.get("oauth_command"),
                    provider_name=str(provider_name),
                ),
                oauth_browser_login=bool(provider_item.get("oauth_browser_login", False)),
                oauth_authorize_url=(
                    str(provider_item["oauth_authorize_url"]).strip()
                    if provider_item.get("oauth_authorize_url") is not None
                    else None
                ),
                oauth_token_url=(
                    str(provider_item["oauth_token_url"]).strip()
                    if provider_item.get("oauth_token_url") is not None
                    else None
                ),
                oauth_client_id=(
                    str(provider_item["oauth_client_id"]).strip()
                    if provider_item.get("oauth_client_id") is not None
                    else None
                ),
                oauth_scopes=cls._parse_oauth_scopes_config(
                    provider_item.get("oauth_scopes"),
                    provider_name=str(provider_name),
                ),
                oauth_redirect_host=str(provider_item.get("oauth_redirect_host", "127.0.0.1")),
                oauth_redirect_port=int(provider_item.get("oauth_redirect_port", 8765)),
                oauth_redirect_path=str(provider_item.get("oauth_redirect_path", "/callback")),
                oauth_cache_file=(
                    str(provider_item["oauth_cache_file"]).strip()
                    if provider_item.get("oauth_cache_file") is not None
                    else None
                ),
                oauth_login_timeout_seconds=float(provider_item.get("oauth_login_timeout_seconds", 180.0)),
                oauth_profile_id=(
                    str(provider_item["oauth_profile_id"]).strip()
                    if provider_item.get("oauth_profile_id") is not None
                    else None
                ),
                oauth_profiles_file=(
                    str(provider_item["oauth_profiles_file"]).strip()
                    if provider_item.get("oauth_profiles_file") is not None
                    else None
                ),
                oauth_auto_refresh=bool(provider_item.get("oauth_auto_refresh", True)),
            )

        config = LLMRouterConfig(
            primary_model=primary_model,
            fallback_models=fallback_models,
            default_provider=default_provider,
            providers=providers,
            request=request_config,
        )
        return cls(config=config, logger=logger)

    @classmethod
    def from_cli_args(
        cls,
        *,
        llm_model: str,
        llm_provider: str,
        llm_provider_type: str,
        llm_fallbacks: list[str] | None,
        llm_base_url: str | None,
        llm_api_key_env: str,
        llm_oauth_token_env: str | None,
        llm_oauth_token_file: str | None,
        llm_oauth_command_json: str | None,
        llm_oauth_browser_login: bool,
        llm_oauth_authorize_url: str | None,
        llm_oauth_token_url: str | None,
        llm_oauth_client_id: str | None,
        llm_oauth_scopes: list[str] | None,
        llm_oauth_redirect_host: str,
        llm_oauth_redirect_port: int,
        llm_oauth_redirect_path: str,
        llm_oauth_cache_file: str | None,
        llm_oauth_login_timeout: float,
        llm_oauth_profile_id: str | None,
        llm_oauth_profiles_file: str | None,
        llm_oauth_auto_refresh: bool,
        llm_timeout: float,
        llm_temperature: float,
        llm_max_output_tokens: int,
        logger: Any | None = None,
    ) -> "LLMRouter":
        """Build a router from CLI flags (single provider + optional fallback models)."""
        provider_name = llm_provider.strip() or "openai"
        if llm_provider_type not in cls._PROVIDER_TYPES:
            raise LLMRouterError(f"Unsupported llm provider type: {llm_provider_type}")

        resolved_base_url = llm_base_url.strip() if llm_base_url else None
        if llm_provider_type == "codex_oauth" and not resolved_base_url:
            resolved_base_url = "https://api.openai.com/v1"
        normalized_primary_model = llm_model.strip()
        normalized_fallback_models = cls._normalize_fallback_models(
            primary_model=normalized_primary_model,
            default_provider=provider_name,
            raw_fallbacks=llm_fallbacks or [],
        )

        config = LLMRouterConfig(
            primary_model=normalized_primary_model,
            fallback_models=normalized_fallback_models,
            default_provider=provider_name,
            providers={
                provider_name: LLMProviderConfig(
                    name=provider_name,
                    provider_type=llm_provider_type,
                    api_key_env=llm_api_key_env.strip() or "OPENAI_API_KEY",
                    base_url=resolved_base_url,
                    timeout_seconds=max(1.0, float(llm_timeout)),
                    oauth_token_env=(llm_oauth_token_env.strip() if llm_oauth_token_env else None),
                    oauth_token_file=(llm_oauth_token_file.strip() if llm_oauth_token_file else None),
                    oauth_command=cls._parse_oauth_command_json_cli(llm_oauth_command_json),
                    oauth_browser_login=bool(llm_oauth_browser_login),
                    oauth_authorize_url=(
                        llm_oauth_authorize_url.strip() if llm_oauth_authorize_url else None
                    ),
                    oauth_token_url=(llm_oauth_token_url.strip() if llm_oauth_token_url else None),
                    oauth_client_id=(llm_oauth_client_id.strip() if llm_oauth_client_id else None),
                    oauth_scopes=[item.strip() for item in (llm_oauth_scopes or []) if item.strip()],
                    oauth_redirect_host=(llm_oauth_redirect_host.strip() or "127.0.0.1"),
                    oauth_redirect_port=max(1, int(llm_oauth_redirect_port)),
                    oauth_redirect_path=(llm_oauth_redirect_path.strip() or "/callback"),
                    oauth_cache_file=(llm_oauth_cache_file.strip() if llm_oauth_cache_file else None),
                    oauth_login_timeout_seconds=max(10.0, float(llm_oauth_login_timeout)),
                    oauth_profile_id=(llm_oauth_profile_id.strip() if llm_oauth_profile_id else None),
                    oauth_profiles_file=(
                        llm_oauth_profiles_file.strip() if llm_oauth_profiles_file else None
                    ),
                    oauth_auto_refresh=bool(llm_oauth_auto_refresh),
                )
            },
            request=LLMRequestConfig(
                temperature=float(llm_temperature),
                max_output_tokens=max(1, int(llm_max_output_tokens)),
            ),
        )
        return cls(config=config, logger=logger)

    @classmethod
    def _normalize_fallback_models(
        cls,
        *,
        primary_model: str,
        default_provider: str,
        raw_fallbacks: Any,
    ) -> list[str]:
        """Normalize fallback model refs and inject safe reasoner defaults when needed."""
        fallback_models = (
            [str(item).strip() for item in raw_fallbacks if str(item).strip()]
            if isinstance(raw_fallbacks, list)
            else []
        )
        normalized: list[str] = []
        seen: set[str] = set()
        auto_fallback = cls._auto_reasoner_fallback_model(
            primary_model=primary_model,
            default_provider=default_provider,
        )
        for model_ref in ([auto_fallback] if auto_fallback else []) + fallback_models:
            if not model_ref:
                continue
            explicit_ref = cls._normalize_model_ref(model_ref, default_provider=default_provider)
            primary_ref = cls._normalize_model_ref(primary_model, default_provider=default_provider)
            if explicit_ref == primary_ref or explicit_ref in seen:
                continue
            seen.add(explicit_ref)
            normalized.append(explicit_ref)
        return normalized

    @staticmethod
    def _normalize_model_ref(model_ref: str, *, default_provider: str) -> str:
        """Normalize model refs to explicit `provider/model` form for comparison."""
        raw = str(model_ref).strip()
        if not raw:
            return ""
        if "/" in raw:
            provider_name, model_name = raw.split("/", maxsplit=1)
            provider_name = provider_name.strip() or default_provider
            model_name = model_name.strip()
            return f"{provider_name}/{model_name}" if model_name else ""
        return f"{default_provider}/{raw}"

    @classmethod
    def _auto_reasoner_fallback_model(cls, *, primary_model: str, default_provider: str) -> str:
        """Inject deepseek-chat as the first fallback for deepseek-reasoner."""
        explicit_primary = cls._normalize_model_ref(primary_model, default_provider=default_provider)
        if not explicit_primary.endswith("/deepseek-reasoner"):
            return ""
        provider_name, _model_name = explicit_primary.split("/", maxsplit=1)
        return f"{provider_name}/deepseek-chat"

    @staticmethod
    def _parse_oauth_command_json_cli(raw_json: str | None) -> list[str]:
        """Parse CLI oauth command JSON array."""
        if raw_json is None or not str(raw_json).strip():
            return []
        try:
            payload = json.loads(str(raw_json))
        except json.JSONDecodeError as exc:
            raise LLMRouterError("--llm-oauth-command-json must be a JSON array of strings") from exc
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise LLMRouterError("--llm-oauth-command-json must be a JSON array of strings")
        command = [item.strip() for item in payload if item.strip()]
        if not command:
            raise LLMRouterError("--llm-oauth-command-json must not be empty")
        return command

    @staticmethod
    def _parse_oauth_command_config(raw_value: Any, provider_name: str) -> list[str]:
        """Parse provider config oauth_command (must be list[str])."""
        if raw_value is None:
            return []
        if not isinstance(raw_value, list) or not all(isinstance(item, str) for item in raw_value):
            raise LLMRouterError(
                f"provider '{provider_name}' field 'oauth_command' must be an array of strings"
            )
        command = [item.strip() for item in raw_value if item.strip()]
        if not command:
            raise LLMRouterError(
                f"provider '{provider_name}' field 'oauth_command' must not be empty"
            )
        return command

    @staticmethod
    def _parse_oauth_scopes_config(raw_value: Any, provider_name: str) -> list[str]:
        """Parse provider config oauth_scopes (list[str] or space-delimited str)."""
        if raw_value is None:
            return []
        if isinstance(raw_value, str):
            return [item for item in raw_value.split(" ") if item.strip()]
        if isinstance(raw_value, list) and all(isinstance(item, str) for item in raw_value):
            return [item.strip() for item in raw_value if item.strip()]
        raise LLMRouterError(
            f"provider '{provider_name}' field 'oauth_scopes' must be a string or array of strings"
        )

    @property
    def config(self) -> LLMRouterConfig:
        """Expose immutable router config."""
        return self._config

    def as_callable(self, fail_safe_response: str = '{"tools":[]}') -> Callable[[str], str]:
        """
        Return fail-safe prompt->text callable for AuditDecisionMaker.

        If all providers fail, returns `fail_safe_response` instead of raising.
        """

        def _call(prompt: str) -> str:
            try:
                return self.complete(prompt)
            except Exception as exc:  # noqa: BLE001
                if self._logger is not None:
                    try:
                        self._logger.warning("LLM router failed; using fallback empty suggestion: %s", exc)
                    except Exception:  # noqa: BLE001
                        pass
                return fail_safe_response

        return _call

    def complete(self, prompt: str) -> str:
        """Route prompt to primary model then fallback chain."""
        if not str(prompt).strip():
            raise LLMRouterError("prompt must not be empty")

        model_refs = [self._config.primary_model, *self._config.fallback_models]
        errors: list[str] = []
        for index, model_ref in enumerate(model_refs):
            provider_name, model_name = self._parse_model_ref(model_ref)
            try:
                provider = self._get_provider(provider_name)
                if self._logger is not None:
                    try:
                        self._logger.info("LLM request via provider=%s model=%s", provider_name, model_name)
                    except Exception:  # noqa: BLE001
                        pass
                result = provider.generate_text(model=model_name, prompt=prompt)
                if str(result).strip():
                    return str(result)
                raise LLMRouterError("empty response")
            except Exception as exc:  # noqa: BLE001
                message = f"{provider_name}/{model_name}: {exc}"
                errors.append(message)
                if self._logger is not None:
                    try:
                        if index + 1 < len(model_refs):
                            next_provider, next_model = self._parse_model_ref(model_refs[index + 1])
                            self._logger.warning(
                                "LLM attempt failed (%s); trying fallback %s/%s",
                                message,
                                next_provider,
                                next_model,
                            )
                        else:
                            self._logger.warning("LLM attempt failed (%s)", message)
                    except Exception:  # noqa: BLE001
                        pass
                continue
        raise LLMRouterError("all LLM providers/models failed: " + " | ".join(errors))

    def _get_provider(self, provider_name: str) -> BaseLLMProvider:
        """Create/cache provider instance."""
        if provider_name in self._providers:
            return self._providers[provider_name]
        if provider_name not in self._config.providers:
            raise LLMRouterError(f"provider '{provider_name}' is not configured")
        provider_config = self._config.providers[provider_name]
        provider_cls = self._PROVIDER_TYPES.get(provider_config.provider_type)
        if provider_cls is None:
            raise LLMRouterError(
                f"provider '{provider_name}' has unsupported type '{provider_config.provider_type}'"
            )
        provider = provider_cls(provider_config, self._config.request, logger=self._logger)
        self._providers[provider_name] = provider
        return provider

    def _parse_model_ref(self, model_ref: str) -> tuple[str, str]:
        """
        Parse `provider/model` reference.

        If provider prefix is omitted, use configured default provider.
        """
        raw = str(model_ref).strip()
        if not raw:
            raise LLMRouterError("empty model reference")
        if "/" in raw:
            provider_name, model_name = raw.split("/", maxsplit=1)
            provider_name = provider_name.strip()
            model_name = model_name.strip()
            if provider_name and model_name:
                return provider_name, model_name
        return self._config.default_provider, raw


def router_config_from_openclaw_style_file(path: str | Path, logger: Any | None = None) -> LLMRouter:
    """
    Convenience helper to load an OpenClaw-style LLM router config JSON file.

    The supported schema is intentionally small and stable for AutoSecAudit.
    """
    return LLMRouter.from_json_file(Path(path), logger=logger)
