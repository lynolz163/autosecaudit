"""Tests for JWT authentication and RBAC logic in webapp/auth.py."""

from __future__ import annotations

import sqlite3
import tempfile
import time
from pathlib import Path
import base64
import hashlib
import hmac
import secrets

import pytest

from autosecaudit.webapp.job_index import JobIndexStore
from autosecaudit.webapp.auth import AuthConfigurationError, AuthService, AuthPrincipal, ROLE_ORDER


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_store(tmp_path: Path) -> JobIndexStore:
    """Return a fresh in-memory-like SQLite store backed by a temp file."""
    return JobIndexStore(tmp_path / "test.db")


@pytest.fixture()
def auth_service(tmp_store: JobIndexStore) -> AuthService:
    return AuthService(tmp_store, bootstrap_token="test-bootstrap-token")


@pytest.fixture()
def admin_user(auth_service: AuthService):
    """Create and return an admin user dict."""
    return auth_service.create_user(
        username="admin",
        password="AdminPass1234",
        role="admin",
    )


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_and_verify_success(self, auth_service: AuthService):
        hashed = auth_service.hash_password("MyStr0ngPassw0rd!")
        assert auth_service.verify_password("MyStr0ngPassw0rd!", hashed)

    def test_wrong_password_fails(self, auth_service: AuthService):
        hashed = auth_service.hash_password("CorrectPassword1")
        assert not auth_service.verify_password("WrongPassword1", hashed)

    def test_short_password_raises(self, auth_service: AuthService):
        with pytest.raises(ValueError, match="password_too_short"):
            auth_service.hash_password("short")

    def test_hash_is_not_plaintext(self, auth_service: AuthService):
        pw = "SecretPassword1"
        hashed = auth_service.hash_password(pw)
        assert pw not in hashed

    def test_two_hashes_differ(self, auth_service: AuthService):
        """Same password should produce different hashes (random salt)."""
        h1 = auth_service.hash_password("SamePassword123")
        h2 = auth_service.hash_password("SamePassword123")
        assert h1 != h2

    def test_verify_legacy_pbkdf2_hash(self, auth_service: AuthService):
        def _enc(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        password = "LegacyPassword123"
        salt = secrets.token_bytes(16)
        iterations = 310_000
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        legacy = f"pbkdf2_sha256${iterations}${_enc(salt)}${_enc(digest)}"
        assert auth_service.verify_password(password, legacy)

    def test_password_requires_mixed_case_by_default(self, tmp_store: JobIndexStore):
        auth = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        with pytest.raises(ValueError, match="password_requires_mixed_case"):
            auth.hash_password("lowercase123")

    def test_password_requires_digit_by_default(self, tmp_store: JobIndexStore):
        auth = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        with pytest.raises(ValueError, match="password_requires_digit"):
            auth.hash_password("NoDigitsHere")

    def test_password_special_requirement_can_be_enabled(self, tmp_store: JobIndexStore, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_SPECIAL", "1")
        auth = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        with pytest.raises(ValueError, match="password_requires_special"):
            auth.hash_password("StrongPass123")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_success(self, auth_service: AuthService, admin_user):
        result = auth_service.login(username="admin", password="AdminPass1234")
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user"]["username"] == "admin"

    def test_login_wrong_password(self, auth_service: AuthService, admin_user):
        with pytest.raises(ValueError, match="invalid_credentials"):
            auth_service.login(username="admin", password="WrongPassword!")

    def test_login_unknown_user(self, auth_service: AuthService):
        with pytest.raises(ValueError, match="invalid_credentials"):
            auth_service.login(username="nobody", password="SomePass123")

    def test_login_disabled_user(self, auth_service: AuthService, admin_user, tmp_store: JobIndexStore):
        auth_service.create_user(username="backup-admin", password="BackupAdmin123", role="admin")
        auth_service.update_user(admin_user["user_id"], enabled=False)
        with pytest.raises(ValueError, match="user_disabled"):
            auth_service.login(username="admin", password="AdminPass1234")

    def test_login_rehashes_legacy_password_hash(self, auth_service: AuthService):
        def _enc(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        password = "LegacyPassword123"
        salt = secrets.token_bytes(16)
        iterations = 310_000
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        legacy_hash = f"pbkdf2_sha256${iterations}${_enc(salt)}${_enc(digest)}"

        user = auth_service.create_user(username="legacy-admin", password="TmpPass1234", role="admin")
        auth_service.update_user(user["user_id"], password=password)
        auth_service._store.update_user(  # noqa: SLF001
            user["user_id"],
            {"password_hash": legacy_hash, "updated_at": "2026-01-01T00:00:00Z"},
        )

        auth_service.login(username="legacy-admin", password=password)
        refreshed = auth_service._store.get_user_auth_record("legacy-admin")  # noqa: SLF001
        assert str(refreshed["password_hash"]).startswith("$2")


# ---------------------------------------------------------------------------
# JWT token issue and verification
# ---------------------------------------------------------------------------

class TestAccessToken:
    def test_access_token_valid(self, auth_service: AuthService, admin_user):
        token = auth_service.issue_access_token(admin_user)
        principal = auth_service.get_principal_from_bearer(token)
        assert principal.username == "admin"
        assert principal.role == "admin"
        assert principal.auth_type == "jwt"

    def test_tampered_token_rejected(self, auth_service: AuthService, admin_user):
        token = auth_service.issue_access_token(admin_user)
        # Flip the last character of the signature
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with pytest.raises(ValueError, match="invalid_token"):
            auth_service.get_principal_from_bearer(tampered)

    def test_empty_token_rejected(self, auth_service: AuthService):
        with pytest.raises(ValueError, match="missing_credentials"):
            auth_service.get_principal_from_bearer("")

    def test_refresh_token_rejected_as_access(self, auth_service: AuthService, admin_user):
        """A refresh token must not be accepted as an access token."""
        refresh = auth_service.issue_refresh_token(admin_user)
        with pytest.raises(ValueError, match="invalid_token"):
            auth_service.get_principal_from_bearer(refresh)

    def test_jwt_secret_from_env_survives_service_restart(self, tmp_store: JobIndexStore):
        first = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        user = first.create_user(username="persist-admin", password="PersistPass123", role="admin")
        token = first.issue_access_token(user)

        second = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        principal = second.get_principal_from_bearer(token)

        assert principal.username == "persist-admin"
        assert first.status()["token_ttl_seconds"] == second.status()["token_ttl_seconds"]

    def test_missing_jwt_secret_raises(self, tmp_store: JobIndexStore, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AUTOSECAUDIT_WEB_JWT_SECRET", raising=False)
        with pytest.raises(AuthConfigurationError, match="AUTOSECAUDIT_WEB_JWT_SECRET is required"):
            AuthService(tmp_store, bootstrap_token="test-bootstrap-token")


# ---------------------------------------------------------------------------
# Refresh token
# ---------------------------------------------------------------------------

class TestRefreshToken:
    def test_refresh_issues_new_access_token(self, auth_service: AuthService, admin_user):
        login = auth_service.login(username="admin", password="AdminPass1234")
        refreshed = auth_service.refresh_token(login["refresh_token"])
        assert "access_token" in refreshed
        assert "refresh_token" in refreshed
        assert refreshed["user"]["username"] == "admin"

    def test_access_token_rejected_as_refresh(self, auth_service: AuthService, admin_user):
        access = auth_service.issue_access_token(admin_user)
        with pytest.raises(ValueError, match="invalid_token"):
            auth_service.refresh_token(access)

    def test_refresh_for_disabled_user_rejected(self, auth_service: AuthService, admin_user):
        login = auth_service.login(username="admin", password="AdminPass1234")
        auth_service.create_user(username="backup-admin", password="BackupAdmin123", role="admin")
        auth_service.update_user(admin_user["user_id"], enabled=False)
        with pytest.raises(ValueError, match="user_disabled"):
            auth_service.refresh_token(login["refresh_token"])


# ---------------------------------------------------------------------------
# Bootstrap token
# ---------------------------------------------------------------------------

class TestBootstrapToken:
    def test_bootstrap_token_grants_admin(self, auth_service: AuthService):
        principal = auth_service.get_principal_from_bearer("test-bootstrap-token")
        assert principal.role == "admin"
        assert principal.auth_type == "bootstrap"

    def test_wrong_bootstrap_token_rejected(self, auth_service: AuthService):
        with pytest.raises(ValueError):
            auth_service.get_principal_from_bearer("wrong-token")

    def test_bootstrap_token_is_disabled_after_first_user_creation(self, tmp_store: JobIndexStore):
        auth = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        assert auth.bootstrap_enabled

        auth.create_user(username="admin", password="AdminPass1234", role="admin")

        assert not auth.bootstrap_enabled
        with pytest.raises(ValueError, match="bootstrap_unavailable"):
            auth.get_principal_from_bearer("test-bootstrap-token")

    def test_bootstrap_token_expires_after_ttl(self, tmp_store: JobIndexStore, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUTOSECAUDIT_WEB_BOOTSTRAP_TOKEN_TTL_SECONDS", "300")
        monkeypatch.setattr("autosecaudit.webapp.auth.time.time", lambda: 1_700_000_000)
        auth = AuthService(tmp_store, bootstrap_token="test-bootstrap-token")
        assert auth.bootstrap_enabled

        monkeypatch.setattr("autosecaudit.webapp.auth.time.time", lambda: 1_700_000_301)
        assert not auth.bootstrap_enabled
        with pytest.raises(ValueError, match="bootstrap_unavailable"):
            auth.get_principal_from_bearer("test-bootstrap-token")


# ---------------------------------------------------------------------------
# RBAC role ordering
# ---------------------------------------------------------------------------

class TestRBAC:
    def test_admin_allows_all(self):
        p = AuthPrincipal(username="u", role="admin", auth_type="jwt")
        assert p.allows("admin")
        assert p.allows("operator")
        assert p.allows("viewer")

    def test_operator_allows_operator_and_viewer(self):
        p = AuthPrincipal(username="u", role="operator", auth_type="jwt")
        assert not p.allows("admin")
        assert p.allows("operator")
        assert p.allows("viewer")

    def test_viewer_allows_only_viewer(self):
        p = AuthPrincipal(username="u", role="viewer", auth_type="jwt")
        assert not p.allows("admin")
        assert not p.allows("operator")
        assert p.allows("viewer")

    def test_role_order_values(self):
        assert ROLE_ORDER["admin"] > ROLE_ORDER["operator"] > ROLE_ORDER["viewer"]
