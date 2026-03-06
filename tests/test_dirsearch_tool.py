from __future__ import annotations

from pathlib import Path as SysPath
from pathlib import Path

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
