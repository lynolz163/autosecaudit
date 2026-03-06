"""Safe external command execution helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import time
from typing import Iterable, Sequence


class CommandPolicyError(ValueError):
    """Raised when a command violates execution policy."""


@dataclass(frozen=True)
class CommandExecution:
    """Result container for an external command execution."""

    args: list[str]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0
    error: str | None = None


class SafeCommandRunner:
    """
    Run external commands safely.

    Security guarantees:
    - Requires list-form arguments.
    - Uses `shell=False`.
    - Enforces executable allowlist.
    """

    def __init__(self, allowlist: Iterable[str]) -> None:
        normalized = {self._normalize_executable(item) for item in allowlist}
        if not normalized:
            raise ValueError("allowlist must contain at least one executable")
        self._allowlist = normalized

    def run(
        self,
        args: Sequence[str],
        timeout_seconds: float = 10.0,
        cwd: Path | None = None,
    ) -> CommandExecution:
        """Execute a command with timeout and defensive error handling."""
        if not args:
            raise CommandPolicyError("args must not be empty")

        executable = self._normalize_executable(args[0])
        if executable not in self._allowlist:
            raise CommandPolicyError(f"Executable {executable!r} is not in allowlist")

        start = time.perf_counter()
        try:
            completed = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
                cwd=str(cwd) if cwd is not None else None,
            )
            return CommandExecution(
                args=list(args),
                return_code=completed.returncode,
                stdout=(completed.stdout or "").strip(),
                stderr=(completed.stderr or "").strip(),
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            return CommandExecution(
                args=list(args),
                return_code=-1,
                stdout=(exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "").strip() if isinstance(exc.stderr, str) else "",
                timed_out=True,
                duration_ms=int((time.perf_counter() - start) * 1000),
                error=f"Command timed out after {timeout_seconds:.1f}s",
            )
        except OSError as exc:
            return CommandExecution(
                args=list(args),
                return_code=-1,
                stdout="",
                stderr="",
                duration_ms=int((time.perf_counter() - start) * 1000),
                error=f"Command execution failed: {exc}",
            )

    @staticmethod
    def _normalize_executable(executable: str) -> str:
        """Normalize executable names for policy checks."""
        return Path(executable).name.lower()
