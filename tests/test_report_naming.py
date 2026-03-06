from __future__ import annotations

from pathlib import Path

from autosecaudit.core.models import AuditSessionResult
from autosecaudit.core.report import ReportWriter, create_report_snapshot


def test_create_report_snapshot_uses_target_slug_and_timestamp(tmp_path: Path) -> None:
    source = tmp_path / "agent_report.md"
    source.write_text("hello", encoding="utf-8")

    snapshot = create_report_snapshot(
        source,
        target="https://edu.360-24.com:443/path?q=1",
        timestamp="20260306T120000Z",
    )

    assert snapshot is not None
    assert snapshot.name == "agent_report_edu-360-24-com-443_20260306T120000Z.md"
    assert snapshot.read_text(encoding="utf-8") == "hello"


def test_create_report_snapshot_adds_numeric_suffix_on_collision(tmp_path: Path) -> None:
    source = tmp_path / "audit_report.json"
    source.write_text('{"ok": true}', encoding="utf-8")

    first = create_report_snapshot(
        source,
        target="example.com",
        timestamp="20260306T120000Z",
    )
    second = create_report_snapshot(
        source,
        target="example.com",
        timestamp="20260306T120000Z",
    )

    assert first is not None
    assert second is not None
    assert first.name == "audit_report_example-com_20260306T120000Z.json"
    assert second.name == "audit_report_example-com_20260306T120000Z_2.json"


def test_report_writer_keeps_canonical_reports_and_returns_snapshot_paths(tmp_path: Path) -> None:
    session = AuditSessionResult(
        target="https://lynolz.com",
        started_at="2026-03-06T00:00:00+00:00",
        ended_at="2026-03-06T00:05:00+00:00",
        plugin_results=[],
        summary={"total_findings": 0},
    )

    artifacts = ReportWriter().write(session, tmp_path)

    assert (tmp_path / "audit_report.json").exists()
    assert (tmp_path / "audit_report.md").exists()
    assert artifacts.json_report.name.startswith("audit_report_lynolz-com_")
    assert artifacts.markdown_report.name.startswith("audit_report_lynolz-com_")
    assert artifacts.json_report.suffix == ".json"
    assert artifacts.markdown_report.suffix == ".md"
