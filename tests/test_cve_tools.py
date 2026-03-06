from __future__ import annotations

import pytest

from autosecaudit.agent_core.builtin_tools import AgentCveLookupTool, AgentCveVerifyTool, AgentPocSandboxExecTool
from autosecaudit.tools.base_tool import ToolExecutionResult
from autosecaudit.tools.nuclei_tool import NucleiTool


def test_cve_lookup_tool_emits_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeService:
        def lookup_components(
            self,
            components: list[str],
            *,
            severity: str | None = None,
            max_results_per_component: int = 20,
            service: str | None = None,
            rag_hits: list[dict[str, object]] | None = None,
            rag_recommended_tools: list[str] | None = None,
        ):  # noqa: ARG002
            assert components == ["nginx/1.18"]
            assert service == "http"
            assert rag_hits and rag_hits[0]["title"] == "nginx alias"
            assert rag_recommended_tools == ["cve_lookup", "poc_sandbox_exec"]
            return [
                {
                    "cve_id": "CVE-2024-1111",
                    "severity": "high",
                    "description": "Demo CVE",
                    "affected_versions": [],
                    "has_nuclei_template": True,
                    "cvss_score": 8.7,
                    "rank": 1,
                    "template_capability": {
                        "has_template": True,
                        "template_count": 2,
                        "protocol_tags": ["nginx", "http"],
                    },
                }
            ]

    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.NvdCveService", lambda: _FakeService())
    tool = AgentCveLookupTool()
    result = tool.run(
        target="https://example.com",
        options={
            "component": "nginx",
            "version": "1.18",
            "service": "http",
            "rag_intel_hits": [{"title": "nginx alias", "tags": ["nginx"]}],
            "rag_recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
            "max_results": 5,
            "severity": "high",
        },
    )

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert isinstance(data, dict)
    assert data["surface_delta"]["cve_candidates"][0]["cve_id"] == "CVE-2024-1111"
    assert data["surface_delta"]["template_capability_index"]["CVE-2024-1111"]["template_count"] == 2
    assert data["follow_up_hints"] == ["cve_verify", "poc_sandbox_exec"]


def test_cve_verify_requires_authorization_confirmation() -> None:
    tool = AgentCveVerifyTool()
    result = tool.run(
        target="https://example.com",
        options={
            "cve_ids": ["CVE-2024-1111"],
            "safe_only": True,
            "authorization_confirmed": False,
            "allow_high_risk": False,
            "safety_grade": "balanced",
        },
    )

    assert result.ok is False
    assert "authorization_confirmed_required" in str(result.error)


def test_cve_verify_invokes_nuclei_and_marks_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "autosecaudit.agent_core.builtin_tools.TemplateCapabilityIndex.get_capability",
        lambda cve_id: {
            "cve_id": cve_id,
            "has_template": False,
            "template_count": 0,
            "template_paths": [],
            "protocol_tags": [],
        },
    )

    def fake_run(self: NucleiTool, target: str, options: dict[str, object]) -> ToolExecutionResult:  # noqa: ARG001
        assert options.get("templates") == ["cves/"]
        assert options.get("template_id") == ["CVE-2024-1111"]
        return ToolExecutionResult(
            ok=True,
            tool_name="nuclei_exploit_check",
            target=target,
            data={
                "status": "completed",
                "findings": [
                    {
                        "name": "Template match CVE-2024-1111",
                        "severity": "high",
                        "model": {"evidence": {"url": target}},
                    }
                ],
            },
            error=None,
        )

    monkeypatch.setattr(NucleiTool, "run", fake_run)
    tool = AgentCveVerifyTool()
    result = tool.run(
        target="https://example.com",
        options={
            "cve_ids": ["CVE-2024-1111"],
            "safe_only": True,
            "authorization_confirmed": True,
            "allow_high_risk": False,
            "safety_grade": "balanced",
        },
    )

    assert result.ok is True
    data = result.data.to_data() if hasattr(result.data, "to_data") else result.data
    assert isinstance(data, dict)
    verification_rows = data["surface_delta"]["cve_verification"]
    assert verification_rows[0]["cve_id"] == "CVE-2024-1111"
    assert verification_rows[0]["verified"] is True


def test_cve_verify_prioritizes_protocol_matched_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_capability(cve_id: str) -> dict[str, object]:
        if cve_id == "CVE-2024-2222":
            return {
                "cve_id": cve_id,
                "has_template": True,
                "template_count": 2,
                "template_paths": ["/tmp/nuclei/redis/CVE-2024-2222.yaml"],
                "protocol_tags": ["redis"],
            }
        return {
            "cve_id": cve_id,
            "has_template": True,
            "template_count": 1,
            "template_paths": [f"/tmp/nuclei/http/{cve_id}.yaml"],
            "protocol_tags": ["http"],
        }

    def fake_run(self: NucleiTool, target: str, options: dict[str, object]) -> ToolExecutionResult:  # noqa: ARG001
        captured["target"] = target
        captured["options"] = dict(options)
        return ToolExecutionResult(
            ok=True,
            tool_name="nuclei_exploit_check",
            target=target,
            data={"status": "completed", "findings": [], "payload": {}},
            error=None,
        )

    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.TemplateCapabilityIndex.get_capability", fake_capability)
    monkeypatch.setattr(NucleiTool, "run", fake_run)

    tool = AgentCveVerifyTool()
    result = tool.run(
        target="cache.example.com",
        options={
            "cve_ids": ["CVE-2024-1111", "CVE-2024-2222"],
            "component": "redis",
            "service": "redis",
            "authorization_confirmed": True,
            "safe_only": True,
            "allow_high_risk": False,
            "safety_grade": "aggressive",
        },
    )

    assert result.ok is True
    assert captured["target"] == "cache.example.com"
    assert captured["options"]["template_id"] == ["CVE-2024-2222", "CVE-2024-1111"]
    assert captured["options"]["templates"] == [
        "/tmp/nuclei/redis/CVE-2024-2222.yaml",
        "/tmp/nuclei/http/CVE-2024-1111.yaml",
    ]


def test_cve_verify_uses_rag_context_to_promote_protocol_specific_cves(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_capability(cve_id: str) -> dict[str, object]:
        if cve_id == "CVE-2024-3333":
            return {
                "cve_id": cve_id,
                "has_template": True,
                "template_count": 1,
                "template_paths": ["/tmp/nuclei/ssh/CVE-2024-3333.yaml"],
                "protocol_tags": ["openssh"],
            }
        return {
            "cve_id": cve_id,
            "has_template": True,
            "template_count": 2,
            "template_paths": ["/tmp/nuclei/http/CVE-2024-4444.yaml"],
            "protocol_tags": ["http"],
        }

    def fake_run(self: NucleiTool, target: str, options: dict[str, object]) -> ToolExecutionResult:  # noqa: ARG001
        captured["options"] = dict(options)
        return ToolExecutionResult(
            ok=True,
            tool_name="nuclei_exploit_check",
            target=target,
            data={"status": "completed", "findings": [], "payload": {}},
            error=None,
        )

    monkeypatch.setattr("autosecaudit.agent_core.builtin_tools.TemplateCapabilityIndex.get_capability", fake_capability)
    monkeypatch.setattr(NucleiTool, "run", fake_run)

    tool = AgentCveVerifyTool()
    result = tool.run(
        target="ssh.example.com",
        options={
            "cve_ids": ["CVE-2024-4444", "CVE-2024-3333"],
            "component": "openssh",
            "service": "ssh",
            "rag_intel_hits": [{"title": "OpenSSH legacy review", "tags": ["ssh", "openssh"]}],
            "rag_recommended_tools": ["cve_verify", "poc_sandbox_exec"],
            "authorization_confirmed": True,
            "safe_only": True,
            "allow_high_risk": False,
            "safety_grade": "aggressive",
        },
    )

    assert result.ok is True
    assert captured["options"]["template_id"] == ["CVE-2024-3333", "CVE-2024-4444"]


@pytest.mark.parametrize(
    ("target", "service", "component", "port", "needle"),
    [
        ("cache.example.com", "redis", "redis", 6379, "INFO server\\r\\n"),
        ("cache.example.com", "memcached", "memcached", 11211, "stats\\r\\n"),
        ("ssh.example.com", "ssh", "openssh", 22, "SSH-2.0-AutoSecAudit\\r\\n"),
        ("https://app.example.com", "tls", "tls", 443, "ssl.create_default_context"),
    ],
)
def test_poc_sandbox_auto_selects_protocol_specific_templates(
    target: str,
    service: str,
    component: str,
    port: int,
    needle: str,
) -> None:
    code = AgentPocSandboxExecTool._template_code(  # noqa: SLF001
        target=target,
        cve_id="CVE-2024-1111",
        template="auto",
        service=service,
        component=component,
        version="1.0",
        port=port,
    )

    assert needle in code
