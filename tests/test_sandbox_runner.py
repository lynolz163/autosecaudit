from __future__ import annotations

from autosecaudit.agent_core.sandbox_runner import SandboxRunner


def test_sandbox_runner_executes_python_code() -> None:
    runner = SandboxRunner()
    result = runner.run_python(code="print('sandbox-ok')\n", timeout_seconds=5)

    assert result.ok is True
    assert result.exit_code == 0
    assert "sandbox-ok" in result.stdout
    assert result.timed_out is False


def test_sandbox_runner_reports_timeout() -> None:
    runner = SandboxRunner()
    result = runner.run_python(
        code="import time\ntime.sleep(2)\nprint('late')\n",
        timeout_seconds=1,
    )

    assert result.ok is False
    assert result.timed_out is True
    assert result.exit_code == -1

