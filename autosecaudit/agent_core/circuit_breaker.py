"""Simple per-tool circuit breaker for agent tool execution."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any


@dataclass
class _CircuitState:
    failures: int = 0
    opened_at: float | None = None
    last_error: str | None = None


class ToolCircuitBreaker:
    """Track repeated tool failures and temporarily open the circuit."""

    def __init__(self, failure_threshold: int = 3, reset_timeout_seconds: float = 60.0) -> None:
        self.failure_threshold = max(1, int(failure_threshold))
        self.reset_timeout_seconds = max(1.0, float(reset_timeout_seconds))
        self._state: dict[str, _CircuitState] = {}

    def can_execute(self, tool_name: str) -> tuple[bool, str | None]:
        """Return whether the tool is currently allowed to execute."""
        state = self._state.get(str(tool_name).strip())
        if state is None or state.opened_at is None:
            return True, None

        elapsed = time.monotonic() - state.opened_at
        if elapsed >= self.reset_timeout_seconds:
            self._state[tool_name] = _CircuitState()
            return True, None
        return False, f"circuit_open:{tool_name}:failures={state.failures}"

    def record_success(self, tool_name: str) -> None:
        """Close/reset tool circuit after a successful execution."""
        self._state[str(tool_name).strip()] = _CircuitState()

    def record_failure(self, tool_name: str, error: str | None = None) -> None:
        """Increment failure count and open circuit if threshold is reached."""
        key = str(tool_name).strip()
        state = self._state.setdefault(key, _CircuitState())
        state.failures += 1
        state.last_error = error
        if state.failures >= self.failure_threshold:
            state.opened_at = time.monotonic()

    def snapshot(self) -> dict[str, Any]:
        """Return serializable circuit breaker state."""
        return {
            tool_name: {
                "failures": state.failures,
                "opened_at": state.opened_at,
                "last_error": state.last_error,
            }
            for tool_name, state in self._state.items()
            if state.failures > 0 or state.opened_at is not None
        }

