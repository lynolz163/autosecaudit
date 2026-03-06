"""Constrained subprocess sandbox runner for generated PoC code."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any


@dataclass(frozen=True)
class SandboxExecutionResult:
    """Result of one sandbox execution."""

    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    working_dir: str
    command: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "working_dir": self.working_dir,
            "command": list(self.command),
        }


class SandboxRunner:
    """Run Python snippets inside an isolated temporary working directory."""

    def run_python(
        self,
        *,
        code: str,
        timeout_seconds: float = 20.0,
        max_output_bytes: int = 120_000,
    ) -> SandboxExecutionResult:
        timeout_seconds = max(1.0, float(timeout_seconds))
        max_output_bytes = max(1024, int(max_output_bytes))
        started = time.perf_counter()

        with tempfile.TemporaryDirectory(prefix="autosecaudit-poc-") as tmp:
            workdir = Path(tmp)
            script_path = workdir / "poc_exec.py"
            script_path.write_text(str(code), encoding="utf-8")

            command = [sys.executable, "-I", str(script_path)]
            env = {
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": os.getenv("PATH", ""),
            }

            try:
                completed = subprocess.run(
                    command,
                    cwd=str(workdir),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    check=False,
                    shell=False,
                )
                stdout = (completed.stdout or "")[:max_output_bytes]
                stderr = (completed.stderr or "")[:max_output_bytes]
                duration_ms = int((time.perf_counter() - started) * 1000)
                return SandboxExecutionResult(
                    ok=(completed.returncode == 0),
                    exit_code=int(completed.returncode),
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=False,
                    duration_ms=duration_ms,
                    working_dir=str(workdir),
                    command=command,
                )
            except subprocess.TimeoutExpired as exc:
                stdout = (str(exc.stdout or ""))[:max_output_bytes]
                stderr = (str(exc.stderr or ""))[:max_output_bytes]
                duration_ms = int((time.perf_counter() - started) * 1000)
                return SandboxExecutionResult(
                    ok=False,
                    exit_code=-1,
                    stdout=stdout,
                    stderr=stderr or "sandbox_timeout",
                    timed_out=True,
                    duration_ms=duration_ms,
                    working_dir=str(workdir),
                    command=command,
                )

