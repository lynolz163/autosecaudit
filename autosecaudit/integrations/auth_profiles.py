"""JSON auth profile store for API keys and OAuth tokens."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import time
from typing import Any


class AuthProfileError(RuntimeError):
    """Raised when auth profile operations fail."""


@dataclass
class AuthProfile:
    """Stored auth profile entry."""

    profile_id: str
    provider: str
    kind: str  # e.g. "oauth", "api_key"
    created_at: float
    updated_at: float
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize profile to JSON object."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuthProfile":
        """Load one profile from dict."""
        if not isinstance(payload, dict):
            raise AuthProfileError("auth profile entry must be a JSON object")
        profile_id = str(payload.get("profile_id", "")).strip()
        provider = str(payload.get("provider", "")).strip()
        kind = str(payload.get("kind", "")).strip()
        if not profile_id or not provider or not kind:
            raise AuthProfileError("auth profile missing profile_id/provider/kind")
        created_at = float(payload.get("created_at", time.time()))
        updated_at = float(payload.get("updated_at", created_at))
        data = payload.get("data", {})
        metadata = payload.get("metadata", {})
        return cls(
            profile_id=profile_id,
            provider=provider,
            kind=kind,
            created_at=created_at,
            updated_at=updated_at,
            data=dict(data) if isinstance(data, dict) else {},
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )


class FileLock:
    """Simple lock-file based mutual exclusion for profile store writes."""

    def __init__(self, path: Path, timeout_seconds: float = 10.0, poll_interval: float = 0.1) -> None:
        self._path = path
        self._timeout_seconds = max(0.5, float(timeout_seconds))
        self._poll_interval = max(0.05, float(poll_interval))
        self._fd: int | None = None

    def __enter__(self) -> "FileLock":
        deadline = time.time() + self._timeout_seconds
        while True:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._fd = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.write(self._fd, str(os.getpid()).encode("ascii", errors="ignore"))
                return self
            except FileExistsError:
                if time.time() >= deadline:
                    raise AuthProfileError(f"timed out waiting for lock: {self._path}")
                time.sleep(self._poll_interval)

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass


class AuthProfileStore:
    """JSON file-based auth profile store with basic locking."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else (Path.home() / ".autosecaudit" / "auth-profiles.json")
        self._lock_path = self._path.with_suffix(self._path.suffix + ".lock")

    @property
    def path(self) -> Path:
        """Return backing store path."""
        return self._path

    def list_profiles(self) -> list[AuthProfile]:
        """List all profiles."""
        return list(self._load_store().values())

    def get_profile(self, provider: str, profile_id: str) -> AuthProfile | None:
        """Get profile by provider + profile_id."""
        key = self._make_key(provider, profile_id)
        return self._load_store().get(key)

    def upsert_profile(self, profile: AuthProfile) -> AuthProfile:
        """Insert or update profile."""
        with FileLock(self._lock_path):
            profiles = self._load_store()
            key = self._make_key(profile.provider, profile.profile_id)
            now = time.time()
            existing = profiles.get(key)
            if existing is not None:
                profile.created_at = existing.created_at
            profile.updated_at = now
            profiles[key] = profile
            self._write_store(profiles)
        return profile

    def upsert_oauth_profile(
        self,
        *,
        provider: str,
        profile_id: str,
        token_payload: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> AuthProfile:
        """Upsert OAuth token payload under profile."""
        now = time.time()
        profile = self.get_profile(provider, profile_id)
        if profile is None:
            profile = AuthProfile(
                profile_id=profile_id,
                provider=provider,
                kind="oauth",
                created_at=now,
                updated_at=now,
                data={},
                metadata={},
            )
        profile.kind = "oauth"
        profile.data = dict(token_payload)
        if metadata:
            merged_metadata = dict(profile.metadata)
            merged_metadata.update(metadata)
            profile.metadata = merged_metadata
        return self.upsert_profile(profile)

    def delete_profile(self, provider: str, profile_id: str) -> bool:
        """Delete a profile if it exists."""
        with FileLock(self._lock_path):
            profiles = self._load_store()
            key = self._make_key(provider, profile_id)
            if key not in profiles:
                return False
            del profiles[key]
            self._write_store(profiles)
        return True

    def _load_store(self) -> dict[str, AuthProfile]:
        """Load store content."""
        try:
            raw = self._path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise AuthProfileError(f"failed reading auth profile store {self._path}: {exc}") from exc

        if not raw.strip():
            return {}

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthProfileError(f"auth profile store is invalid JSON: {self._path}") from exc

        if not isinstance(payload, dict):
            raise AuthProfileError(f"auth profile store must be a JSON object: {self._path}")

        items = payload.get("profiles", [])
        if not isinstance(items, list):
            raise AuthProfileError("auth profile store field 'profiles' must be a list")

        profiles: dict[str, AuthProfile] = {}
        for item in items:
            profile = AuthProfile.from_dict(item)
            profiles[self._make_key(profile.provider, profile.profile_id)] = profile
        return profiles

    def _write_store(self, profiles: dict[str, AuthProfile]) -> None:
        """Persist store content atomically."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": time.time(),
            "profiles": [profile.to_dict() for profile in sorted(profiles.values(), key=lambda p: (p.provider, p.profile_id))],
        }
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp_path.replace(self._path)
        except OSError as exc:
            raise AuthProfileError(f"failed writing auth profile store {self._path}: {exc}") from exc
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _make_key(provider: str, profile_id: str) -> str:
        """Build deterministic provider/profile composite key."""
        return f"{provider.strip().lower()}::{profile_id.strip()}"


def token_expired(token_payload: dict[str, Any], skew_seconds: float = 30.0) -> bool:
    """Best-effort expiration check for OAuth token payload dict."""
    expires_at = token_payload.get("expires_at") or token_payload.get("expiresAt")
    if isinstance(expires_at, (int, float)):
        return float(expires_at) <= (time.time() + float(skew_seconds))
    return False
