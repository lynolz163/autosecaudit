from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from autosecaudit.agent_core.orchestrator import AgentOrchestrator
from autosecaudit.agent_core.scheduler import Action
from autosecaudit.agent_core.tools import BaseAgentTool
from autosecaudit.agent_core.tool_output_schema import StandardToolOutput
from autosecaudit.core.logging_utils import OperationRecorder
from autosecaudit.decision import ActionPlan, PlannedAction
from autosecaudit.tools.base_tool import ToolExecutionResult


class _RetryTool(BaseAgentTool):
    name = "retry_tool"
    retry_policy = {"max_retries": 1, "backoff_seconds": 0.0}

    def __init__(self) -> None:
        self.calls = 0

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("timeout while probing")
        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={"status": "completed", "payload": {"calls": self.calls}, "findings": [], "breadcrumbs_delta": [], "surface_delta": {}},
        )


class _FailingTool(BaseAgentTool):
    name = "failing_tool"
    retry_policy = {"max_retries": 0, "backoff_seconds": 0.0}

    def __init__(self) -> None:
        self.calls = 0

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        self.calls += 1
        raise RuntimeError("timeout while probing")


class _HeaderFindingTool(BaseAgentTool):
    name = "http_security_headers"
    retry_policy = {"max_retries": 0, "backoff_seconds": 0.0}

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": {"url": target},
                "findings": [
                    {
                        "title": "Missing HSTS Header",
                        "description": "Strict-Transport-Security is not present.",
                        "severity": "low",
                    }
                ],
                "breadcrumbs_delta": [],
                "surface_delta": {},
                "follow_up_hints": [],
                "metadata": {},
            },
        )


class _AssetTool(BaseAgentTool):
    name = "asset_tool"
    retry_policy = {"max_retries": 0, "backoff_seconds": 0.0}

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data=StandardToolOutput(
                status="completed",
                graph_assets=[
                    {
                        "kind": "service",
                        "id": "service:tcp:example.com:22:ssh",
                        "attributes": {"host": "example.com", "port": 22, "service": "ssh"},
                        "evidence": {"source": "test"},
                        "source_tool": self.name,
                    }
                ],
                surface_updates={},
            ),
        )


class _MetadataTool(BaseAgentTool):
    name = "metadata_tool"
    retry_policy = {"max_retries": 0, "backoff_seconds": 0.0}

    def run(self, target: str, options: dict[str, Any]) -> ToolExecutionResult:
        return ToolExecutionResult(
            ok=True,
            tool_name=self.name,
            target=target,
            data={
                "status": "completed",
                "payload": {"target": target},
                "findings": [],
                "breadcrumbs_delta": [],
                "surface_delta": {},
                "follow_up_hints": [],
                "metadata": {
                    "component": "redis",
                    "service": "redis",
                    "candidate_order": ["CVE-2025-0001", "CVE-2024-9999"],
                    "selected_templates": ["network/redis/example.yaml"],
                    "ignored_key": {"nested": True},
                },
            },
        )


def _build_orchestrator(tmp_path: Path, tool: BaseAgentTool) -> AgentOrchestrator:
    logger = logging.getLogger(f"autosecaudit-test-{tool.name}")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    recorder = OperationRecorder(tmp_path / "ops.jsonl", logger)
    return AgentOrchestrator(
        output_dir=tmp_path,
        logger=logger,
        recorder=recorder,
        tool_getter=lambda _name: tool,
    )


def _action(tool_name: str) -> Action:
    return Action(
        action_id="A1",
        tool_name=tool_name,
        target="https://example.com",
        options={},
        priority=0,
        cost=1,
        capabilities=["network_read"],
        idempotency_key=f"{tool_name}-key",
        reason="test",
        preconditions=[],
        stop_conditions=[],
    )


def test_execute_action_retries_retryable_errors(tmp_path: Path) -> None:
    tool = _RetryTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    result = orchestrator._execute_action(_action(tool.name))  # noqa: SLF001

    assert result["history_record"]["status"] == "completed"
    assert result["history_record"]["retry_attempts"] == 2
    assert tool.calls == 2


def test_execute_action_opens_circuit_after_repeated_failures(tmp_path: Path) -> None:
    tool = _FailingTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    for _ in range(3):
        result = orchestrator._execute_action(_action(tool.name))  # noqa: SLF001
        assert result["history_record"]["status"] == "error"

    fourth = orchestrator._execute_action(_action(tool.name))  # noqa: SLF001

    assert fourth["history_record"]["status"] == "error"
    assert "circuit_open" in fourth["history_record"]["error"]
    assert tool.calls == 3


def test_execute_action_applies_skill_follow_up_interpretation(tmp_path: Path) -> None:
    tool = _HeaderFindingTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    result = orchestrator._execute_action(_action(tool.name))  # noqa: SLF001

    assert result["history_record"]["status"] == "completed"
    assert "csp_evaluator" in result["follow_up_hints"]
    assert result["metadata"]["skill_name"] == "http_security_headers"


def test_build_state_normalizes_cve_runtime_fields(tmp_path: Path) -> None:
    tool = _HeaderFindingTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    state = orchestrator.build_state(
        target="https://example.com",
        scope=["example.com"],
        budget_remaining=20,
        surface={
            "authorization_confirmed": "true",
            "safe_only": "false",
            "allow_high_risk": "1",
            "cve_candidates": [
                {"cve_id": "cve-2024-1111", "target": "https://example.com"},
                {"cve_id": "cve-2024-1111", "target": "https://example.com"},
            ],
        },
    )

    assert state["authorization_confirmed"] is True
    assert state["cve_safe_only"] is False
    assert state["cve_allow_high_risk"] is True
    assert state["surface"]["authorization_confirmed"] is True
    assert state["surface"]["safe_only"] is False
    assert state["surface"]["allow_high_risk"] is True
    assert len(state["cve_candidates"]) == 1
    assert state["cve_candidates"][0]["cve_id"] == "CVE-2024-1111"


def test_build_state_normalizes_autonomy_runtime_fields(tmp_path: Path) -> None:
    tool = _HeaderFindingTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    state = orchestrator.build_state(
        target="https://example.com",
        scope=["example.com"],
        budget_remaining=20,
        surface={
            "autonomy_mode": "constrained",
            "disabled_tools": ["dynamic_crawl", "dynamic_crawl", "page_vision_analyzer"],
            "focus_ports": ["443", "8443", "443"],
            "preferred_origins": ["https://example.com:443/", "https://example.com:8443/"],
        },
    )

    assert state["autonomy_mode"] == "constrained"
    assert state["surface"]["autonomy_mode"] == "constrained"
    assert state["disabled_tools"] == ["dynamic_crawl", "page_vision_analyzer"]
    assert state["focus_ports"] == [443, 8443]
    assert state["preferred_origins"] == ["https://example.com:443/", "https://example.com:8443/"]


def test_build_state_attaches_compact_memory_context(tmp_path: Path) -> None:
    tool = _HeaderFindingTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    state = orchestrator.build_state(
        target="https://example.com",
        scope=["example.com"],
        budget_remaining=20,
        history=[
            {"tool": "nmap_scan", "target": "example.com", "status": "completed"},
            {"tool": "http_security_headers", "target": "https://example.com", "status": "completed"},
        ],
        surface={
            "tech_stack": ["nginx", "react"],
            "nmap_services": [{"host": "example.com", "port": 22, "service": "ssh"}],
        },
    )

    assert "memory_context" in state
    assert state["memory_context"]["compression_applied"] is True
    assert state["memory_context"]["known_services"][0]["service"] == "ssh"
    assert state["memory_context"]["history_total"] == 2


def test_execute_action_preserves_graph_assets(tmp_path: Path) -> None:
    tool = _AssetTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    result = orchestrator._execute_action(_action(tool.name))  # noqa: SLF001

    assert result["history_record"]["status"] == "completed"
    assert result["assets_delta"][0]["kind"] == "service"
    assert result["assets_delta"][0]["attributes"]["service"] == "ssh"


def test_execute_action_records_phase_and_compact_metadata(tmp_path: Path) -> None:
    tool = _MetadataTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    result = orchestrator._execute_action(_action(tool.name), phase_name="verification")  # noqa: SLF001

    assert result["history_record"]["phase"] == "verification"
    assert result["history_record"]["metadata_summary"]["component"] == "redis"
    assert result["history_record"]["metadata_summary"]["candidate_order"] == ["CVE-2025-0001", "CVE-2024-9999"]
    assert "ignored_key" not in result["history_record"]["metadata_summary"]


def test_plan_to_dict_includes_ranking_explanation(tmp_path: Path) -> None:
    orchestrator = _build_orchestrator(tmp_path, _MetadataTool())
    plan = ActionPlan(
        decision_summary="verification plan",
        actions=[
            PlannedAction(
                action_id="A1",
                tool_name="cve_verify",
                target="redis.example.com",
                options={
                    "component": "redis",
                    "service": "redis",
                    "version": "7.2.1",
                    "cve_ids": ["CVE-2025-0001", "CVE-2024-9999"],
                    "templates": ["network/redis/example.yaml"],
                    "safe_only": True,
                    "safety_grade": "aggressive",
                    "rag_recommended_tools": ["cve_verify", "poc_sandbox_exec"],
                    "template_capability_index": {
                        "CVE-2025-0001": {"protocol_tags": ["redis", "tcp"]},
                    },
                },
                priority=1,
                cost=10,
                capabilities=["network_read"],
                idempotency_key="plan-key",
                reason="test",
                preconditions=[],
                stop_conditions=[],
            )
        ],
    )

    payload = orchestrator._plan_to_dict(plan)  # noqa: SLF001

    explanation = payload["actions"][0]["ranking_explanation"]
    assert payload["ranking_overview"]
    assert explanation["selected_candidate"] == "CVE-2025-0001"
    assert "network/redis/example.yaml" in explanation["selected_templates"]
    assert "Protocol tags: redis, tcp" in explanation["reasons"]


def test_execute_action_artifact_includes_ranking_explanation(tmp_path: Path) -> None:
    tool = _MetadataTool()
    orchestrator = _build_orchestrator(tmp_path, tool)

    result = orchestrator._execute_action(_action(tool.name), phase_name="verification")  # noqa: SLF001
    artifact_path = Path(result["artifacts"][0]["path"])
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))

    assert result["history_record"]["ranking_explanation"]["component"] == "redis"
    assert result["history_record"]["ranking_explanation"]["selected_candidate"] == "CVE-2025-0001"
    assert payload["ranking_explanation"]["component"] == "redis"
    assert payload["action"]["ranking_explanation"]["selected_candidate"] == "CVE-2025-0001"


def test_execute_action_generic_reason_populates_ranking_explanation(tmp_path: Path) -> None:
    tool = _HeaderFindingTool()
    orchestrator = _build_orchestrator(tmp_path, tool)
    action = Action(
        action_id="A7",
        tool_name=tool.name,
        target="https://example.com",
        options={},
        priority=2,
        cost=3,
        capabilities=["network_read"],
        idempotency_key="headers-key",
        reason="Inspect HTTP response headers on the discovered origin.",
        preconditions=["target_in_scope", "not_already_done"],
        stop_conditions=["budget_exhausted"],
    )

    result = orchestrator._execute_action(action, phase_name="passive_recon")  # noqa: SLF001

    explanation = result["history_record"]["ranking_explanation"]
    assert "Inspect HTTP response headers on the discovered origin." in explanation["reasons"]
    assert "Scheduled in phase: passive_recon" in explanation["reasons"]
    assert "Preconditions satisfied: target_in_scope, not_already_done" in explanation["reasons"]


def test_execute_action_records_autonomy_adjustments(tmp_path: Path) -> None:
    tool = _RetryTool()
    orchestrator = _build_orchestrator(tmp_path, tool)
    action = Action(
        action_id="A9",
        tool_name="dirsearch_scan",
        target="https://example.com",
        options={"threads": 10, "timeout_seconds": 120, "max_results": 200},
        priority=2,
        cost=3,
        capabilities=["network_read"],
        idempotency_key="dirsearch-key",
        reason="test",
        preconditions=[],
        stop_conditions=[],
    )

    result = orchestrator._execute_action(  # noqa: SLF001
        action,
        phase_name="active_discovery",
        state={"surface": {"autonomy_mode": "constrained"}, "safety_grade": "balanced"},
    )

    assert result["history_record"]["autonomy_adjustments"] == [
        "threads -> 2",
        "timeout_seconds -> 45",
        "max_results -> 100",
    ]
