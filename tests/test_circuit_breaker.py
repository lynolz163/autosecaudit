from __future__ import annotations

import time

from autosecaudit.agent_core.circuit_breaker import ToolCircuitBreaker


def test_circuit_breaker_resets_after_timeout() -> None:
    breaker = ToolCircuitBreaker(failure_threshold=1, reset_timeout_seconds=1.0)
    breaker.record_failure("demo", "timeout")

    allowed, reason = breaker.can_execute("demo")
    assert allowed is False
    assert reason is not None

    breaker._state["demo"].opened_at = time.monotonic() - 2.0  # noqa: SLF001
    allowed, reason = breaker.can_execute("demo")

    assert allowed is True
    assert reason is None


def test_circuit_breaker_record_success_clears_open_state() -> None:
    breaker = ToolCircuitBreaker(failure_threshold=1, reset_timeout_seconds=60.0)
    breaker.record_failure("demo", "timeout")
    breaker.record_success("demo")

    allowed, reason = breaker.can_execute("demo")
    snapshot = breaker.snapshot()

    assert allowed is True
    assert reason is None
    assert snapshot == {}
