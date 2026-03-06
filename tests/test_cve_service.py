from __future__ import annotations

from pathlib import Path

import pytest

from autosecaudit.agent_core.cve_service import NvdCveService
from autosecaudit.agent_core.template_capability_index import TemplateCapabilityIndex


def test_nvd_search_uses_cache_after_first_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = NvdCveService(
        cache_db_path=tmp_path / "nvd_cache.sqlite3",
        cache_ttl_seconds=3600,
    )
    calls = {"count": 0}
    sample_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-11111",
                    "descriptions": [{"lang": "en", "value": "Demo vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "configurations": [],
                }
            }
        ]
    }

    def fake_fetch(_params: dict[str, str]) -> dict[str, object]:
        calls["count"] += 1
        return sample_payload

    monkeypatch.setattr(service, "_fetch_nvd_payload", fake_fetch)

    first = service.search(keyword="nginx", max_results=5)
    second = service.search(keyword="nginx", max_results=5)

    assert calls["count"] == 1
    assert first == second
    assert first[0]["cve_id"] == "CVE-2024-11111"
    assert first[0]["severity"] == "critical"


def test_lookup_components_falls_back_to_keyword_when_cpe_search_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    service = NvdCveService(cache_ttl_seconds=0)
    seen_queries: list[tuple[str, str]] = []

    def fake_search(*, keyword: str | None = None, cpe_name: str | None = None, severity: str | None = None, max_results: int = 20):  # noqa: ARG001
        seen_queries.append((keyword or "", cpe_name or ""))
        if cpe_name:
            return []
        return [
            {
                "cve_id": "CVE-2023-2222",
                "severity": "high",
                "description": "Keyword matched vulnerability",
                "affected_versions": [],
                "has_nuclei_template": True,
                "cvss_score": 8.1,
            }
        ]

    monkeypatch.setattr(service, "search", fake_search)
    results = service.lookup_components(["nginx/1.18"], severity="high", max_results_per_component=3)

    assert results[0]["cve_id"] == "CVE-2023-2222"
    assert results[0]["component"] == "nginx"
    assert results[0]["version"] == "1.18"
    assert any(cpe for _keyword, cpe in seen_queries)
    assert any(keyword for keyword, _cpe in seen_queries)


def test_has_nuclei_template_scans_local_template_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    template_root = tmp_path / "nuclei-templates"
    (template_root / "http" / "cves").mkdir(parents=True, exist_ok=True)
    (template_root / "http" / "cves" / "CVE-2024-9999.yaml").write_text("id: CVE-2024-9999\n", encoding="utf-8")

    monkeypatch.setenv("AUTOSECAUDIT_NUCLEI_TEMPLATES_DIRS", str(template_root))
    monkeypatch.setenv("AUTOSECAUDIT_NUCLEI_TEMPLATE_CACHE_TTL_SECONDS", "1")
    NvdCveService._TEMPLATE_CACHE_IDS = None  # noqa: SLF001
    NvdCveService._TEMPLATE_CACHE_LOADED_AT = 0  # noqa: SLF001
    TemplateCapabilityIndex._CAPABILITY_CACHE = None  # noqa: SLF001
    TemplateCapabilityIndex._CACHE_LOADED_AT = 0  # noqa: SLF001

    assert NvdCveService._has_nuclei_template("CVE-2024-9999") is True  # noqa: SLF001
    assert NvdCveService._has_nuclei_template("CVE-2024-8888") is False  # noqa: SLF001


def test_template_capability_index_infers_protocol_tags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    template_root = tmp_path / "nuclei-templates"
    template_dir = template_root / "network" / "redis"
    template_dir.mkdir(parents=True, exist_ok=True)
    (template_dir / "CVE-2024-7777.yaml").write_text(
        "id: CVE-2024-7777\ninfo:\n  tags: cve,redis,network\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("AUTOSECAUDIT_NUCLEI_TEMPLATES_DIRS", str(template_root))
    monkeypatch.setenv("AUTOSECAUDIT_NUCLEI_TEMPLATE_CACHE_TTL_SECONDS", "1")
    TemplateCapabilityIndex._CAPABILITY_CACHE = None  # noqa: SLF001
    TemplateCapabilityIndex._CACHE_LOADED_AT = 0  # noqa: SLF001

    capability = TemplateCapabilityIndex.get_capability("CVE-2024-7777")

    assert capability["has_template"] is True
    assert capability["template_count"] == 1
    assert "redis" in capability["protocol_tags"]


def test_lookup_components_uses_rag_context_to_boost_protocol_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    service = NvdCveService(cache_ttl_seconds=0)

    def fake_search(*, keyword: str | None = None, cpe_name: str | None = None, severity: str | None = None, max_results: int = 20):  # noqa: ARG001
        return [
            {
                "cve_id": "CVE-2024-9000",
                "severity": "high",
                "description": "Generic cache weakness",
                "affected_versions": [],
                "has_nuclei_template": False,
                "cvss_score": 9.1,
                "template_capability": {"has_template": False, "template_count": 0, "protocol_tags": []},
            },
            {
                "cve_id": "CVE-2024-7777",
                "severity": "medium",
                "description": "Redis unauthenticated exposure pattern",
                "affected_versions": ["redis 7.2.1"],
                "has_nuclei_template": True,
                "cvss_score": 7.1,
                "template_capability": {
                    "has_template": True,
                    "template_count": 2,
                    "protocol_tags": ["redis"],
                },
            },
        ]

    monkeypatch.setattr(service, "search", fake_search)
    results = service.lookup_components(
        ["redis/7.2.1"],
        service="redis",
        rag_hits=[
            {
                "title": "Redis public exposure",
                "summary": "Redis network exposure",
                "tags": ["redis", "cache"],
                "recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
            }
        ],
        rag_recommended_tools=["cve_lookup", "poc_sandbox_exec"],
        max_results_per_component=5,
    )

    assert results[0]["cve_id"] == "CVE-2024-7777"
    assert results[0]["rank"] == 1
    assert results[0]["ranking_context"]["service"] == "redis"


def test_rank_cve_candidates_uses_protocol_aliases_and_rag_recommendations() -> None:
    ranked = NvdCveService.rank_cve_candidates(
        [
            {
                "cve_id": "CVE-2024-0001",
                "severity": "medium",
                "cvss_score": 6.0,
                "template_capability": {
                    "has_template": True,
                    "template_count": 1,
                    "protocol_tags": ["http"],
                },
            },
            {
                "cve_id": "CVE-2024-0002",
                "severity": "medium",
                "cvss_score": 6.0,
                "template_capability": {
                    "has_template": True,
                    "template_count": 1,
                    "protocol_tags": ["openssh"],
                },
            },
        ],
        component="openssh",
        version="8.9",
        service="ssh",
        rag_hits=[{"title": "OpenSSH legacy review", "tags": ["ssh", "openssh"], "recommended_tools": ["cve_verify", "poc_sandbox_exec"]}],
        rag_recommended_tools=["cve_verify", "poc_sandbox_exec"],
    )

    assert ranked[0]["cve_id"] == "CVE-2024-0002"
    assert ranked[0]["rank"] == 1
