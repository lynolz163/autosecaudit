from __future__ import annotations

import subprocess
from pathlib import Path as SysPath
from pathlib import Path

import pytest

from autosecaudit.tools.dirsearch_tool import DirsearchTool


def test_dirsearch_uses_output_formats_and_output_file_flags() -> None:
    tool = DirsearchTool()

    args = tool._build_command_args(  # noqa: SLF001
        target="https://example.com/",
        options={"threads": 4, "max_results": 200},
        report_path=Path("/tmp/dirsearch_report.json"),
    )

    assert "-O" in args
    assert "json" in args
    assert "-o" in args
    assert str(SysPath(args[args.index("-o") + 1]).name) == "dirsearch_report.json"
    assert "--format=json" not in args
    assert not any(item.startswith("--json-report=") for item in args)


def test_dirsearch_uses_bundled_quick_wordlist_by_default(tmp_path: Path) -> None:
    tool = DirsearchTool()

    args = tool._build_command_args(  # noqa: SLF001
        target="https://example.com/",
        options={"threads": 4},
        report_path=tmp_path / "dirsearch_report.json",
    )

    assert "-w" in args
    wordlist_path = Path(args[args.index("-w") + 1])
    assert wordlist_path.exists()
    contents = wordlist_path.read_text(encoding="utf-8")
    assert "admin" in contents
    assert ".env" in contents


def test_dirsearch_timeout_soft_completes_without_marking_action_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = DirsearchTool()

    monkeypatch.setattr(tool, "_candidate_commands", lambda: [["dirsearch"]])

    def _raise_timeout(*args, **kwargs):  # noqa: ANN002, ANN003
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr("autosecaudit.tools.dirsearch_tool.subprocess.run", _raise_timeout)

    result = tool.run("https://example.com/", {})

    assert result.ok is True
    assert result.error is None
    assert result.data["status"] == "completed"
    assert result.data["payload"]["timed_out"] is True
    assert result.data["payload"]["entry_count"] == 0
    assert "timed out" in result.data["payload"]["warning"].lower()
    assert result.data["surface_delta"]["dirsearch_timed_out"] is True
