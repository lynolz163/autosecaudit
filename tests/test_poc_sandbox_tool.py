from __future__ import annotations

import pytest

from autosecaudit.agent_core.builtin_tools import AgentPocSandboxExecTool
from autosecaudit.agent_core.sandbox_runner import SandboxExecutionResult, SandboxRunner


def test_poc_sandbox_tool_requires_approval() -> None:
    tool = AgentPocSandboxExecTool()
    result = tool.run(
        target="https://example.com",
        options={
            "cve_id": "CVE-2024-1111",
            "authorization_confirmed": True,
            "approval_granted": False,
            "safe_mode": True,
            "safety_grade": "aggressive",
            "timeout_seconds": 10,
        },
    )

    assert result.ok is False
    assert "approval_required_for_poc_sandbox_exec" in str(result.error)


def test_poc_sandbox_tool_executes_and_emits_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_run(self, **kwargs):  # noqa: ANN001, ANN003
        del self
        del kwargs
        return SandboxExecutionResult(
            ok=True,
            exit_code=0,
            stdout=(
                'AUTOSECAUDIT_EVIDENCE {"component":"redis","host":"cache.example.com","ping_response":"+PONG","port":6379,'
                '"protocol":"redis","redis_version":"7.2.1","unauthenticated":true}\n'
                "VULNERABLE_SIGNAL CVE-2024-1111 cache.example.com:6379"
            ),
            stderr="",
            timed_out=False,
            duration_ms=120,
            working_dir="/tmp/autosecaudit-poc",
            command=["python", "-I", "poc_exec.py"],
        )

    monkeypatch.setattr(SandboxRunner, "run_python", _fake_run)
    tool = AgentPocSandboxExecTool()
    result = tool.run(
        target="cache.example.com",
        options={
            "cve_id": "CVE-2024-1111",
            "component": "redis",
            "service": "redis",
            "port": 6379,
            "authorization_confirmed": True,
            "approval_granted": True,
            "safe_mode": True,
            "safety_grade": "aggressive",
            "timeout_seconds": 10,
        },
    )

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert isinstance(data, dict)
    runs = data["surface_delta"]["poc_sandbox_runs"]
    assert runs[0]["vulnerability_signal"] is True
    assert runs[0]["template"] == "redis_ping_info_probe"
    protocol_evidence = data["surface_delta"]["poc_protocol_evidence"]
    assert protocol_evidence[0]["protocol"] == "redis"
    assert protocol_evidence[0]["redis_version"] == "7.2.1"
    findings = data["findings"]
    assert findings[0]["cve_verified"] is True
    assert findings[0]["evidence"]["protocol_evidence"]["protocol"] == "redis"


def test_poc_sandbox_tool_uses_ranked_cve_candidates_when_cve_id_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_run(self, **kwargs):  # noqa: ANN001, ANN003
        del self
        del kwargs
        return SandboxExecutionResult(
            ok=True,
            exit_code=0,
            stdout='AUTOSECAUDIT_EVIDENCE {"protocol":"ssh","banner":"SSH-2.0-OpenSSH_8.9"}\nVULNERABLE_SIGNAL CVE-2024-2002 ssh.example.com:22\n',
            stderr="",
            timed_out=False,
            duration_ms=90,
            working_dir="/tmp/autosecaudit-poc",
            command=["python", "-I", "poc_exec.py"],
        )

    def fake_capability(cve_id: str) -> dict[str, object]:
        if cve_id == "CVE-2024-2002":
            return {
                "cve_id": cve_id,
                "has_template": True,
                "template_count": 1,
                "template_paths": ["/tmp/nuclei/ssh/CVE-2024-2002.yaml"],
                "protocol_tags": ["openssh"],
            }
        return {
            "cve_id": cve_id,
            "has_template": True,
            "template_count": 2,
            "template_paths": ["/tmp/nuclei/http/CVE-2024-2001.yaml"],
            "protocol_tags": ["http"],
        }

    monkeypatch.setattr(SandboxRunner, "run_python", _fake_run)
    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.TemplateCapabilityIndex.get_capability", fake_capability)

    tool = AgentPocSandboxExecTool()
    result = tool.run(
        target="ssh.example.com",
        options={
            "cve_ids": ["CVE-2024-2001", "CVE-2024-2002"],
            "component": "openssh",
            "service": "ssh",
            "port": 22,
            "rag_intel_hits": [{"title": "OpenSSH legacy review", "tags": ["ssh", "openssh"]}],
            "rag_recommended_tools": ["poc_sandbox_exec"],
            "approval_granted": True,
            "authorization_confirmed": True,
            "timeout_seconds": 10,
            "safe_mode": True,
            "safety_grade": "aggressive",
        },
    )

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert data["metadata"]["candidate_order"] == ["CVE-2024-2002", "CVE-2024-2001"]
    assert data["metadata"]["template"] == "ssh_banner_probe"
    assert data["surface_delta"]["poc_sandbox_runs"][0]["effective_cve_id"] == "CVE-2024-2002"
