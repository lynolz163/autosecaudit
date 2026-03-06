"""JWT and RBAC helpers for the web console."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import os
import secrets
import time
from typing import Any

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext

from .job_index import JobIndexStore


ROLE_ORDER = {"viewer": 10, "operator": 20, "admin": 30}
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
PASSWORD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class AuthPrincipal:
    """Authenticated console principal."""

    username: str
    role: str
    auth_type: str
    user_id: int | None = None
    display_name: str | None = None

    @property
    def actor(self) -> str:
        return f"{self.auth_type}:{self.username}"

    def allows(self, required_role: str) -> bool:
        return ROLE_ORDER.get(str(self.role), 0) >= ROLE_ORDER.get(str(required_role), 0)


@dataclass(frozen=True)
class PasswordPolicy:
    """Console password policy."""

    min_length: int
    require_mixed_case: bool
    require_digit: bool
    require_special: bool

    @classmethod
    def from_env(cls) -> PasswordPolicy:
        min_length_raw = os.getenv("AUTOSECAUDIT_WEB_PASSWORD_MIN_LENGTH", "").strip()
        min_length = int(min_length_raw) if min_length_raw.isdigit() else 10
        return cls(
            min_length=max(8, min(128, min_length)),
            require_mixed_case=_env_flag("AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_MIXED_CASE", True),
            require_digit=_env_flag("AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_DIGIT", True),
            require_special=_env_flag("AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_SPECIAL", False),
        )

    def validate(self, password: str) -> None:
        text = str(password or "")
        if len(text) < self.min_length:
            raise ValueError("password_too_short")
        if self.require_mixed_case and (text.lower() == text or text.upper() == text):
            raise ValueError("password_requires_mixed_case")
        if self.require_digit and not any(char.isdigit() for char in text):
            raise ValueError("password_requires_digit")
        if self.require_special and not any(not char.isalnum() for char in text):
            raise ValueError("password_requires_special")


class AuthService:
    """Persisted user auth with JWT access tokens and bootstrap fallback."""

    def __init__(
        self,
        store: JobIndexStore,
        *,
        bootstrap_token: str | None,
        issuer: str = "autosecaudit-web",
    ) -> None:
        self._store = store
        self._issuer = issuer
        self._bootstrap_token = bootstrap_token.strip() if isinstance(bootstrap_token, str) and bootstrap_token.strip() else None
        self._password_policy = PasswordPolicy.from_env()
        self._runtime = self._ensure_runtime_settings()
        self._ensure_env_default_admin()

    @property
    def bootstrap_enabled(self) -> bool:
        return bool(self._bootstrap_token)

    @property
    def token_ttl_seconds(self) -> int:
        return int(self._runtime.get("token_ttl_seconds", 28800) or 28800)

    @property
    def refresh_token_ttl_seconds(self) -> int:
        return int(self._runtime.get("refresh_token_ttl_seconds", 1209600) or 1209600)

    def status(self) -> dict[str, Any]:
        return {
            "has_users": self._store.count_users() > 0,
            "bootstrap_enabled": self.bootstrap_enabled,
            "default_admin_env_configured": bool(
                os.getenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_USERNAME", "").strip()
                and os.getenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_PASSWORD", "")
            ),
            "roles": ["admin", "operator", "viewer"],
            "token_ttl_seconds": self.token_ttl_seconds,
            "refresh_token_ttl_seconds": self.refresh_token_ttl_seconds,
            "password_policy": {
                "min_length": self._password_policy.min_length,
                "require_mixed_case": self._password_policy.require_mixed_case,
                "require_digit": self._password_policy.require_digit,
                "require_special": self._password_policy.require_special,
            },
        }

    def login(self, *, username: str, password: str) -> dict[str, Any]:
        try:
            record = self._store.get_user_auth_record(username)
        except KeyError as exc:
            raise ValueError("invalid_credentials") from exc
        if not bool(record.get("enabled", False)):
            raise ValueError("user_disabled")
        current_hash = str(record.get("password_hash", ""))
        if not self.verify_password(password, current_hash):
            raise ValueError("invalid_credentials")
        if self._needs_password_rehash(current_hash):
            self._store.update_user(
                int(record["user_id"]),
                {
                    "password_hash": self.hash_password(password),
                    "updated_at": _utc_now(),
                },
            )
        now = _utc_now()
        self._store.touch_user_login(int(record["user_id"]), last_login_at=now, updated_at=now)
        user = self._store.get_user(int(record["user_id"]))
        return self._issue_login_response(user)

    def bootstrap_admin(self, *, username: str, password: str, display_name: str | None = None) -> dict[str, Any]:
        if self._store.count_users() > 0:
            raise ValueError("bootstrap_locked")
        user = self.create_user(
            username=username,
            password=password,
            role="admin",
            display_name=display_name,
            enabled=True,
        )
        return self._issue_login_response(user)

    def create_user(
        self,
        *,
        username: str,
        password: str,
        role: str,
        display_name: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        now = _utc_now()
        return self._store.create_user(
            {
                "username": username,
                "password_hash": self.hash_password(password),
                "role": role,
                "display_name": display_name,
                "enabled": enabled,
                "created_at": now,
                "updated_at": now,
                "last_login_at": None,
            }
        )

    def update_user(
        self,
        user_id: int,
        *,
        username: str | None = None,
        password: str | None = None,
        role: str | None = None,
        display_name: str | None = None,
        enabled: bool | None = None,
        actor_user_id: int | None = None,
    ) -> dict[str, Any]:
        existing = self._store.get_user_auth_record_by_id(int(user_id))
        next_role = str(role).strip().lower() if role is not None else str(existing.get("role", "viewer")).strip().lower()
        next_enabled = bool(enabled) if enabled is not None else bool(existing.get("enabled", False))
        self._validate_user_management_change(
            existing_user=existing,
            actor_user_id=actor_user_id,
            next_role=next_role,
            next_enabled=next_enabled,
            deleting=False,
        )
        payload: dict[str, Any] = {"updated_at": _utc_now()}
        if username is not None:
            payload["username"] = username
        if password is not None:
            payload["password_hash"] = self.hash_password(password)
        if role is not None:
            payload["role"] = role
        if display_name is not None:
            payload["display_name"] = display_name
        if enabled is not None:
            payload["enabled"] = enabled
        return self._store.update_user(int(user_id), payload)

    def delete_user(self, user_id: int, *, actor_user_id: int | None = None) -> None:
        existing = self._store.get_user_auth_record_by_id(int(user_id))
        self._validate_user_management_change(
            existing_user=existing,
            actor_user_id=actor_user_id,
            next_role=str(existing.get("role", "viewer")).strip().lower(),
            next_enabled=False,
            deleting=True,
        )
        self._store.delete_user(int(user_id))

    def list_users(self) -> list[dict[str, Any]]:
        return self._store.list_users()

    def get_user(self, user_id: int) -> dict[str, Any]:
        return self._store.get_user(int(user_id))

    def ensure_admin_user(
        self,
        *,
        username: str,
        password: str,
        display_name: str | None = None,
        enabled: bool = True,
        only_if_missing: bool = False,
    ) -> dict[str, Any]:
        normalized_username = str(username or "").strip()
        if not normalized_username:
            raise ValueError("username is required")
        try:
            existing = self._store.get_user_auth_record(normalized_username)
        except KeyError:
            return self.create_user(
                username=normalized_username,
                password=password,
                role="admin",
                display_name=display_name,
                enabled=enabled,
            )

        if only_if_missing:
            return self._store.get_user(int(existing["user_id"]))

        payload = {
            "updated_at": _utc_now(),
            "password_hash": self.hash_password(password),
            "role": "admin",
            "enabled": enabled,
        }
        if display_name is not None:
            payload["display_name"] = display_name
        return self._store.update_user(int(existing["user_id"]), payload)

    def get_principal_from_bearer(self, bearer: str) -> AuthPrincipal:
        token = str(bearer or "").strip()
        if not token:
            raise ValueError("missing_credentials")
        if self._bootstrap_token and hmac.compare_digest(token, self._bootstrap_token):
            return AuthPrincipal(
                username="bootstrap-admin",
                role="admin",
                auth_type="bootstrap",
                user_id=None,
                display_name="Bootstrap Admin",
            )
        payload = self._decode_token(token, expected_token_type="access")
        user_id = int(payload.get("uid", 0) or 0)
        if user_id <= 0:
            raise ValueError("invalid_token")
        try:
            user = self._store.get_user_auth_record_by_id(user_id)
        except KeyError as exc:
            raise ValueError("user_not_found") from exc
        if not bool(user.get("enabled", False)):
            raise ValueError("user_disabled")
        return AuthPrincipal(
            username=str(user["username"]),
            role=str(user["role"]),
            auth_type="jwt",
            user_id=int(user["user_id"]),
            display_name=user.get("display_name"),
        )

    def issue_access_token(self, user: dict[str, Any]) -> str:
        return self._issue_signed_token(user=user, token_type="access", ttl_seconds=self.token_ttl_seconds)

    def issue_refresh_token(self, user: dict[str, Any]) -> str:
        return self._issue_signed_token(user=user, token_type="refresh", ttl_seconds=self.refresh_token_ttl_seconds)

    def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        payload = self._decode_token(str(refresh_token or "").strip(), expected_token_type="refresh")
        user_id = int(payload.get("uid", 0) or 0)
        if user_id <= 0:
            raise ValueError("invalid_refresh_token")
        try:
            user = self._store.get_user_auth_record_by_id(user_id)
        except KeyError as exc:
            raise ValueError("user_not_found") from exc
        if not bool(user.get("enabled", False)):
            raise ValueError("user_disabled")
        return self._issue_login_response(self._store.get_user(user_id))

    def _issue_login_response(self, user: dict[str, Any]) -> dict[str, Any]:
        access_token = self.issue_access_token(user)
        refresh_token = self.issue_refresh_token(user)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.token_ttl_seconds,
            "refresh_expires_in": self.refresh_token_ttl_seconds,
            "user": user,
        }

    def _issue_signed_token(self, *, user: dict[str, Any], token_type: str, ttl_seconds: int) -> str:
        now = int(time.time())
        payload = {
            "iss": self._issuer,
            "sub": str(user["username"]),
            "uid": int(user["user_id"]),
            "role": str(user["role"]),
            "display_name": user.get("display_name"),
            "token_type": token_type,
            "jti": secrets.token_urlsafe(12),
            "iat": now,
            "exp": now + max(60, int(ttl_seconds)),
        }
        token = jwt.encode(payload, self._signing_key(), algorithm="HS256")
        return str(token)

    def hash_password(self, password: str) -> str:
        text = str(password or "")
        self._password_policy.validate(text)
        return str(PASSWORD_CONTEXT.hash(text))

    @staticmethod
    def verify_password(password: str, encoded: str) -> bool:
        normalized = str(encoded or "")
        if normalized.startswith("$2a$") or normalized.startswith("$2b$") or normalized.startswith("$2y$"):
            try:
                return bool(PASSWORD_CONTEXT.verify(str(password or ""), normalized))
            except Exception:
                return False
        if normalized.startswith("pbkdf2_sha256$"):
            return AuthService._verify_legacy_pbkdf2(password=password, encoded=normalized)
        return False

    @staticmethod
    def _verify_legacy_pbkdf2(*, password: str, encoded: str) -> bool:
        try:
            scheme, iterations_text, salt_text, digest_text = str(encoded or "").split("$", 3)
        except ValueError:
            return False
        if scheme != "pbkdf2_sha256":
            return False
        try:
            iterations = int(iterations_text)
            salt = _b64url_decode(salt_text)
            expected = _b64url_decode(digest_text)
        except Exception:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def _needs_password_rehash(encoded: str) -> bool:
        value = str(encoded or "")
        if value.startswith("pbkdf2_sha256$"):
            return True
        if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
            return bool(PASSWORD_CONTEXT.needs_update(value))
        return True

    def _ensure_runtime_settings(self) -> dict[str, Any]:
        existing = self._store.get_setting("auth_runtime", default={}).get("value") or {}
        if not isinstance(existing, dict):
            existing = {}
        env_secret = os.getenv("AUTOSECAUDIT_WEB_JWT_SECRET", "").strip()
        ttl_raw = os.getenv("AUTOSECAUDIT_WEB_JWT_TTL_SECONDS", "").strip()
        refresh_ttl_raw = os.getenv("AUTOSECAUDIT_WEB_REFRESH_TTL_SECONDS", "").strip()
        ttl = int(ttl_raw) if ttl_raw.isdigit() else int(existing.get("token_ttl_seconds", 28800) or 28800)
        ttl = max(900, min(604800, ttl))
        refresh_ttl = (
            int(refresh_ttl_raw)
            if refresh_ttl_raw.isdigit()
            else int(existing.get("refresh_token_ttl_seconds", 1209600) or 1209600)
        )
        refresh_ttl = max(ttl, min(2592000, refresh_ttl))
        secret = env_secret or str(existing.get("jwt_secret", "")).strip() or secrets.token_urlsafe(48)
        normalized = {
            "jwt_secret": secret,
            "token_ttl_seconds": ttl,
            "refresh_token_ttl_seconds": refresh_ttl,
        }
        if normalized != existing:
            self._store.set_setting("auth_runtime", normalized, updated_at=_utc_now())
        return normalized

    def _ensure_env_default_admin(self) -> None:
        username = os.getenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_USERNAME", "").strip()
        password = os.getenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_PASSWORD", "")
        display_name = os.getenv("AUTOSECAUDIT_WEB_DEFAULT_ADMIN_DISPLAY_NAME", "").strip() or None
        if not username and not password:
            return
        if not username or not password:
            raise ValueError(
                "AUTOSECAUDIT_WEB_DEFAULT_ADMIN_USERNAME and "
                "AUTOSECAUDIT_WEB_DEFAULT_ADMIN_PASSWORD must be provided together"
            )
        if self._store.count_users() > 0:
            return
        self.ensure_admin_user(
            username=username,
            password=password,
            display_name=display_name,
            enabled=True,
            only_if_missing=True,
        )

    def _validate_user_management_change(
        self,
        *,
        existing_user: dict[str, Any],
        actor_user_id: int | None,
        next_role: str,
        next_enabled: bool,
        deleting: bool,
    ) -> None:
        user_id = int(existing_user["user_id"])
        current_role = str(existing_user.get("role", "viewer")).strip().lower()
        current_enabled = bool(existing_user.get("enabled", False))
        is_current_admin = current_role == "admin" and current_enabled
        is_future_admin = next_role == "admin" and next_enabled and not deleting

        if actor_user_id is not None and int(actor_user_id) == user_id:
            if deleting:
                raise ValueError("cannot_delete_self")
            if not next_enabled and current_enabled:
                raise ValueError("cannot_freeze_self")
            if next_role != current_role:
                raise ValueError("cannot_change_own_role")

        if is_current_admin and not is_future_admin and self._store.count_enabled_admins() <= 1:
            raise ValueError("last_enabled_admin")

    def _signing_key(self) -> bytes:
        return str(self._runtime.get("jwt_secret", "")).encode("utf-8")

    def _decode_token(self, token: str, *, expected_token_type: str) -> dict[str, Any]:
        parts = str(token).split(".")
        if len(parts) != 3:
            raise ValueError("invalid_token")
        signature_part = str(parts[2]).strip()
        try:
            signature_bytes = _b64url_decode(signature_part)
        except Exception as exc:
            raise ValueError("invalid_token") from exc
        # Reject non-canonical base64url token encodings to avoid accepting
        # alternate serialized signatures that decode to the same bytes.
        if _b64url_encode(signature_bytes) != signature_part:
            raise ValueError("invalid_token")

        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise ValueError("invalid_token") from exc
        if str(header.get("alg", "")).upper() != "HS256":
            raise ValueError("invalid_token")

        try:
            payload = jwt.decode(
                token,
                self._signing_key(),
                algorithms=["HS256"],
                issuer=self._issuer,
                options={"require": ["iss", "iat", "exp"]},
            )
        except ExpiredSignatureError as exc:
            raise ValueError("token_expired" if expected_token_type == "access" else "refresh_token_expired") from exc
        except InvalidTokenError as exc:
            raise ValueError("invalid_token") from exc

        if not isinstance(payload, dict):
            raise ValueError("invalid_token")
        if str(payload.get("token_type", "")).strip() != expected_token_type:
            raise ValueError("invalid_token")
        return payload


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    return default
