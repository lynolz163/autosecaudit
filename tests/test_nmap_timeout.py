from __future__ import annotations

import logging
from pathlib import Path

from autosecaudit.agent_core.builtin_tools import AgentNmapTool
from autosecaudit.core.command import SafeCommandRunner
from autosecaudit.core.logging_utils import OperationRecorder
from autosecaudit.core.models import AuditContext, RuntimeConfig
from autosecaudit.plugins.port_service_scan import PortServiceScanPlugin
from autosecaudit.decision import AuditDecisionMaker
from autosecaudit.tools.nmap_tool import NmapTool, ToolExecutionResult


def test_decision_maker_sets_nmap_timeout_to_300_seconds() -> None:
    maker = AuditDecisionMaker()
    state = {
        "scope": ["example.com"],
        "budget_remaining": 50,
        "breadcrumbs": [],
        "surface": {},
        "history": [],
    }

    plan = maker.plan_from_state(state, use_llm_hints=False)
    nmap_action = next(action for action in plan.actions if action.tool_name == "nmap_scan")

    assert nmap_action.options["timeout_seconds"] == 90
    assert nmap_action.options["ports"] == "top-100"
    assert nmap_action.options["version_detection"] is False


def test_agent_nmap_tool_uses_300_second_default_timeout(monkeypatch) -> None:
    captured: dict[str, float | str] = {}

    class _FakeNmapTool:
        DEFAULT_TIMEOUT_SECONDS = NmapTool.DEFAULT_TIMEOUT_SECONDS

        def __init__(self, *, timeout_seconds: float, scan_profile: str, version_detection: bool, **_kwargs) -> None:
            captured["timeout_seconds"] = float(timeout_seconds)
            captured["scan_profile"] = scan_profile
            captured["version_detection"] = version_detection

        def run(self, target: str, options: dict[str, object]) -> ToolExecutionResult:
            captured["target"] = target
            captured["ports"] = str(options.get("ports"))
            return ToolExecutionResult(ok=True, tool_name="nmap_tool", target=target, data={"hosts": []})

    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.NmapTool", _FakeNmapTool)

    tool = AgentNmapTool()
    result = tool.run(
        "example.com",
        {
            "ports": "top-100",
            "scan_profile": "conservative_service_discovery",
            "version_detection": False,
        },
    )

    assert result.ok is True
    assert captured["timeout_seconds"] == 90.0
    assert captured["ports"] == "top-100"
    assert captured["scan_profile"] == "conservative_service_discovery"
    assert captured["version_detection"] is False


def test_agent_nmap_tool_emits_structured_service_surface(monkeypatch) -> None:
    class _FakeNmapTool:
        DEFAULT_TIMEOUT_SECONDS = NmapTool.DEFAULT_TIMEOUT_SECONDS

        def __init__(self, **_kwargs) -> None:
            pass

        def run(self, target: str, options: dict[str, object]) -> ToolExecutionResult:  # noqa: ARG002
            return ToolExecutionResult(
                ok=True,
                tool_name="nmap_tool",
                target=target,
                data={
                    "hosts": [
                        {
                            "hostnames": ["example.com"],
                            "open_ports": [
                                {"port": 80, "service": "http"},
                                {"port": 8443, "service": "https-alt"},
                                {"port": 22, "service": "ssh"},
                            ],
                        }
                    ]
                },
            )

    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.NmapTool", _FakeNmapTool)

    tool = AgentNmapTool()
    result = tool.run("example.com", {"ports": "top-100"})

    assert result.ok is True
    assert isinstance(result.data, dict)
    assert {"type": "service", "data": "http://example.com:80"} in result.data["breadcrumbs_delta"]
    assert {"type": "service", "data": "https://example.com:8443"} in result.data["breadcrumbs_delta"]
    assert result.data["surface_delta"]["nmap_http_origins"] == ["http://example.com:80"]
    assert result.data["surface_delta"]["nmap_https_origins"] == ["https://example.com:8443"]
    assert result.data["surface_delta"]["nmap_service_origins"] == [
        "http://example.com:80",
        "https://example.com:8443",
    ]
    assert len(result.data["surface_delta"]["nmap_services"]) == 3


def test_port_service_scan_plugin_uses_options_based_nmap_interface(
    monkeypatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    class _FakeNmapTool:
        def __init__(self, *, timeout_seconds: float, **_kwargs) -> None:
            captured["timeout_seconds"] = float(timeout_seconds)

        def run(self, target: str, options: dict[str, object]) -> ToolExecutionResult:
            captured["target"] = target
            captured["ports"] = options.get("ports")
            return ToolExecutionResult(
                ok=True,
                tool_name="nmap_tool",
                target=target,
                data={"hosts": []},
            )

    monkeypatch.setattr("autosecaudit.tools.nmap_tool.NmapTool", _FakeNmapTool)

    plugin = PortServiceScanPlugin()
    context = AuditContext(
        config=RuntimeConfig(
            target="https://example.com",
            output_dir=tmp_path,
            log_dir=tmp_path,
            plugin_timeout_seconds=20.0,
        ),
        logger=logging.getLogger("test_port_service_scan"),
        recorder=OperationRecorder(tmp_path / "events.jsonl", logging.getLogger("test_port_service_scan")),
        command_runner=SafeCommandRunner(("python",)),
    )

    result = plugin.run(context)

    assert result.status == "passed"
    assert captured["target"] == "example.com"
    assert captured["ports"] == PortServiceScanPlugin._DEFAULT_PORTS
    assert captured["timeout_seconds"] == 19.0


def test_nmap_tool_builds_fast_conservative_command() -> None:
    tool = NmapTool(
        timeout_seconds=90.0,
        scan_profile="conservative_service_discovery",
        version_detection=False,
    )

    command = tool._build_command("example.com", "top-100")  # noqa: SLF001

    assert "--top-ports" in command
    assert "100" in command
    assert "-T4" in command
    assert "--host-timeout" in command
    assert "-sV" not in command
