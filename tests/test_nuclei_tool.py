from __future__ import annotations

import subprocess

from autosecaudit.tools.nuclei_tool import NucleiTool


def test_build_command_uses_jsonl_flag_by_default() -> None:
    tool = NucleiTool()

    command = tool._build_command("https://example.com", {"severity": ["info"]})

    assert "-j" in command
    assert "-json" not in command


def test_run_falls_back_to_legacy_json_flag_when_jsonl_is_unsupported(monkeypatch) -> None:
    tool = NucleiTool()
    commands: list[list[str]] = []

    def fake_execute_command(*, command, target, timeout_seconds, started):
        del target, timeout_seconds, started
        commands.append(command)
        if "-j" in command:
            return subprocess.CompletedProcess(
                command,
                2,
                stdout="flag provided but not defined: -j",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(tool, "_execute_command", fake_execute_command)
    monkeypatch.setattr(tool, "_parse_jsonl_findings", lambda stdout, target: ([], 0))

    result = tool.run("https://example.com", {"severity": ["info"]})

    assert result.ok is True
    assert len(commands) == 2
    assert "-j" in commands[0]
    assert "-json" in commands[1]
    assert result.data["payload"]["command"] == commands[1]
