"""Evidence correlation helpers for cross-tool corroboration and planning hints."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class _EvidenceClaim:
    """Internal mutable representation of one corroborated claim."""

    kind: str
    subject: str
    evidences: list[dict[str, Any]] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)


class EvidenceGraphBuilder:
    """Build a compact evidence graph from runtime state and findings."""

    _TECH_STACK_TOOL_HINTS: dict[str, tuple[str, ...]] = {
        "wordpress": ("dirsearch_scan", "nuclei_exploit_check", "source_map_detector"),
        "grafana": ("nuclei_exploit_check", "http_security_headers"),
        "jenkins": ("nuclei_exploit_check", "login_form_detector"),
        "spring": ("nuclei_exploit_check", "passive_config_audit"),
        "django": ("passive_config_audit", "api_schema_discovery"),
        "laravel": ("dirsearch_scan", "passive_config_audit"),
        "apache": ("http_security_headers", "error_page_analyzer"),
        "nginx": ("http_security_headers", "security_txt_check"),
        "tomcat": ("nuclei_exploit_check", "error_page_analyzer"),
    }

    def build(
        self,
        *,
        state: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build a UI/report/planner-friendly evidence graph."""
        claims: dict[tuple[str, str], _EvidenceClaim] = {}
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        breadcrumbs = state.get("breadcrumbs", []) if isinstance(state.get("breadcrumbs", []), list) else []
        history = state.get("history", []) if isinstance(state.get("history", []), list) else []

        for breadcrumb in breadcrumbs:
            if not isinstance(breadcrumb, dict):
                continue
            raw_data = str(breadcrumb.get("data", "")).strip()
            if not raw_data:
                continue
            breadcrumb_type = str(breadcrumb.get("type", "")).strip().lower()
            origin = self._origin_of(raw_data)
            if origin:
                self._add_claim(
                    claims,
                    kind="origin",
                    subject=origin,
                    source=f"breadcrumb:{breadcrumb_type or 'unknown'}",
                    target=origin,
                    metadata={"breadcrumb_type": breadcrumb_type},
                )
            if self._looks_like_endpoint(raw_data):
                self._add_claim(
                    claims,
                    kind="endpoint",
                    subject=raw_data,
                    source=f"breadcrumb:{breadcrumb_type or 'unknown'}",
                    target=raw_data,
                    metadata={},
                )

        for origin in self._surface_origins(surface):
            self._add_claim(
                claims,
                kind="origin",
                subject=origin,
                source="surface:origin",
                target=origin,
                metadata={},
            )

        for service in self._surface_services(surface):
            service_name = str(service.get("name", "")).strip().lower()
            target = str(service.get("target", "")).strip()
            if not service_name:
                continue
            self._add_claim(
                claims,
                kind="service",
                subject=service_name,
                source="surface:service",
                target=target,
                metadata={"port": service.get("port"), "banner": service.get("banner")},
            )

        tech_stack = surface.get("tech_stack", [])
        if isinstance(tech_stack, list):
            for item in tech_stack:
                tech = str(item).strip().lower()
                if not tech:
                    continue
                self._add_claim(
                    claims,
                    kind="tech_stack",
                    subject=tech,
                    source="surface:tech_stack",
                    target=self._best_target_from_surface(surface),
                    metadata={},
                )

        for endpoint, params in self._surface_parameterized_endpoints(surface).items():
            self._add_claim(
                claims,
                kind="parameterized_endpoint",
                subject=endpoint,
                source="surface:parameters",
                target=endpoint,
                metadata={"params": sorted(params)},
            )

        for candidate in surface.get("cve_candidates", []) if isinstance(surface.get("cve_candidates", []), list) else []:
            if not isinstance(candidate, dict):
                continue
            cve_id = str(candidate.get("cve_id", "")).strip().upper()
            if not cve_id:
                continue
            self._add_claim(
                claims,
                kind="cve_candidate",
                subject=cve_id,
                source="surface:cve_candidate",
                target=str(candidate.get("target", "")).strip(),
                metadata={
                    "severity": str(candidate.get("severity", "")).strip().lower(),
                    "cvss_score": candidate.get("cvss_score"),
                    "component": str(candidate.get("component", "")).strip(),
                    "version": str(candidate.get("version", "")).strip(),
                },
            )

        for item in findings:
            if not isinstance(item, dict):
                continue
            finding_name = str(item.get("name", "")).strip() or str(item.get("title", "")).strip()
            if not finding_name:
                continue
            evidence_target = self._extract_target_from_finding(item)
            self._add_claim(
                claims,
                kind="finding",
                subject=finding_name,
                source=f"finding:{str(item.get('severity', 'info')).strip().lower() or 'info'}",
                target=evidence_target,
                metadata={
                    "severity": str(item.get("severity", "")).strip().lower(),
                    "evidence": str(item.get("evidence", ""))[:240],
                },
            )

        for entry in history[-12:]:
            if not isinstance(entry, dict):
                continue
            tool_name = str(entry.get("tool", "")).strip()
            target = str(entry.get("target", "")).strip()
            if not tool_name or not target:
                continue
            self._add_claim(
                claims,
                kind="tool_trace",
                subject=tool_name,
                source=f"history:{str(entry.get('status', 'unknown')).strip().lower() or 'unknown'}",
                target=target,
                metadata={},
            )

        claims_output = [self._serialize_claim(item) for item in claims.values()]
        claims_output.sort(key=lambda item: (-float(item.get("confidence", 0.0)), item.get("kind", ""), item.get("subject", "")))

        recommended_tools, corroboration_hints = self._derive_recommendations(claims_output)
        priority_targets = self._derive_priority_targets(claims_output)
        path_graph = self._derive_path_graph(claims_output)
        remediation_priority = self._derive_remediation_priority(state=state, claims=claims_output, findings=findings)
        summary = {
            "claim_count": len(claims_output),
            "corroborated_claims": sum(1 for item in claims_output if bool(item.get("corroborated"))),
            "high_confidence_claims": sum(1 for item in claims_output if float(item.get("confidence", 0.0)) >= 0.75),
            "high_quality_claims": sum(1 for item in claims_output if str(item.get("quality_label", "")).strip() in {"high", "verified"}),
            "recommended_tool_count": len(recommended_tools),
            "priority_target_count": len(priority_targets),
            "remediation_priority_count": len(remediation_priority),
        }
        return {
            "version": 1,
            "summary": summary,
            "claims": claims_output[:36],
            "recommended_tools": recommended_tools,
            "priority_targets": priority_targets,
            "corroboration_hints": corroboration_hints[:40],
            "path_graph": path_graph,
            "remediation_priority": remediation_priority[:12],
        }

    def _derive_recommendations(
        self,
        claims: list[dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        recommended_tools: list[str] = []
        seen_tools: set[str] = set()
        hints: list[dict[str, Any]] = []
        seen_hints: set[str] = set()

        for claim in claims:
            confidence = float(claim.get("confidence", 0.0))
            kind = str(claim.get("kind", "")).strip()
            subject = str(claim.get("subject", "")).strip().lower()
            target = str(claim.get("primary_target", "")).strip()
            tools: list[str] = []

            if kind == "origin":
                tools.extend(["tech_stack_fingerprint", "http_security_headers", "passive_config_audit"])
                if target:
                    tools.extend(["dynamic_crawl", "dirsearch_scan"])
            elif kind == "parameterized_endpoint":
                tools.extend(["sql_sanitization_audit", "xss_protection_audit", "param_fuzzer"])
            elif kind == "tech_stack":
                tools.extend(self._TECH_STACK_TOOL_HINTS.get(subject, ()))
            elif kind == "cve_candidate":
                tools.append("cve_verify")
            elif kind == "finding" and subject:
                lowered = subject.lower()
                if "config" in lowered or ".env" in lowered or ".git" in lowered:
                    tools.append("passive_config_audit")
                if "sql" in lowered:
                    tools.append("sql_sanitization_audit")
                if "xss" in lowered:
                    tools.append("xss_protection_audit")

            for tool_name in tools:
                if tool_name not in seen_tools:
                    seen_tools.add(tool_name)
                    recommended_tools.append(tool_name)
                if not target:
                    continue
                hint_key = f"{tool_name}|{target}"
                if hint_key in seen_hints:
                    continue
                seen_hints.add(hint_key)
                hints.append(
                    {
                        "tool_name": tool_name,
                        "target": target,
                        "priority_delta": -6 if confidence >= 0.75 else -3,
                        "reason": f"Corroborate {claim.get('kind')} evidence for {claim.get('subject')}.",
                        "confidence": confidence,
                    }
                )
        return recommended_tools, hints

    def _derive_priority_targets(self, claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scores: dict[str, float] = defaultdict(float)
        reasons: dict[str, list[str]] = defaultdict(list)
        for claim in claims:
            target = str(claim.get("primary_target", "")).strip()
            if not target:
                continue
            confidence = float(claim.get("confidence", 0.0))
            scores[target] += confidence
            reason = f"{claim.get('kind')}:{claim.get('subject')}"
            if reason not in reasons[target]:
                reasons[target].append(reason)

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        return [
            {
                "target": target,
                "score": round(score, 2),
                "reasons": reasons[target][:4],
            }
            for target, score in ranked[:12]
        ]

    def _serialize_claim(self, claim: _EvidenceClaim) -> dict[str, Any]:
        evidence_count = len(claim.evidences)
        source_count = len(claim.sources)
        confidence = min(0.95, 0.35 + (0.18 * source_count) + (0.05 * max(0, evidence_count - 1)))
        quality_score = min(0.98, (confidence * 0.8) + min(0.18, evidence_count * 0.03))
        targets = sorted(item for item in claim.targets if item)
        return {
            "claim_id": f"{claim.kind}:{claim.subject}",
            "kind": claim.kind,
            "subject": claim.subject,
            "evidence_count": evidence_count,
            "source_count": source_count,
            "corroborated": source_count >= 2,
            "confidence": round(confidence, 2),
            "quality_score": round(quality_score, 2),
            "quality_label": self._quality_label(quality_score),
            "primary_target": targets[0] if targets else "",
            "targets": targets[:6],
            "evidence_preview": claim.evidences[:4],
            "metadata": claim.metadata,
        }

    def _derive_path_graph(self, claims: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            target = str(claim.get("primary_target", "")).strip()
            subject = str(claim.get("subject", "")).strip()
            kind = str(claim.get("kind", "")).strip().lower() or "claim"
            if target:
                nodes.setdefault(
                    target,
                    {
                        "id": target,
                        "label": target,
                        "type": "target",
                    },
                )
            if subject:
                claim_node_id = f"{kind}:{subject}"
                nodes.setdefault(
                    claim_node_id,
                    {
                        "id": claim_node_id,
                        "label": subject,
                        "type": kind,
                        "confidence": claim.get("confidence"),
                        "quality_label": claim.get("quality_label"),
                    },
                )
                if target:
                    edge_key = (target, claim_node_id, kind)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append(
                            {
                                "source": target,
                                "target": claim_node_id,
                                "kind": kind,
                                "confidence": claim.get("confidence"),
                            }
                        )
        return {
            "nodes": list(nodes.values())[:48],
            "edges": edges[:72],
        }

    def _derive_remediation_priority(
        self,
        *,
        state: dict[str, Any],
        claims: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        priority_targets = {
            str(item.get("target", "")).strip(): float(item.get("score", 0.0) or 0.0)
            for item in self._derive_priority_targets(claims)
            if isinstance(item, dict) and str(item.get("target", "")).strip()
        }
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            name = str(finding.get("name", "")).strip() or str(finding.get("title", "")).strip()
            severity = str(finding.get("severity", "info")).strip().lower() or "info"
            target = self._extract_target_from_finding(finding)
            signature = (name, target)
            if not name or signature in seen:
                continue
            seen.add(signature)
            output.append(
                {
                    "title": name,
                    "target": target or str(state.get("target", "")).strip(),
                    "severity": severity,
                    "priority": self._priority_label(severity, priority_targets.get(target or "", 0.0)),
                    "reason": self._remediation_reason(name=name, severity=severity, target_score=priority_targets.get(target or "", 0.0)),
                    "recommendation": str(finding.get("recommendation") or finding.get("remediation") or "").strip() or None,
                }
            )
        output.sort(
            key=lambda item: (
                -self._priority_weight(str(item.get("priority", "P4"))),
                -self._severity_weight(str(item.get("severity", "info")).strip().lower()),
                str(item.get("title", "")),
            )
        )
        return output

    @staticmethod
    def _quality_label(score: float) -> str:
        if score >= 0.85:
            return "verified"
        if score >= 0.72:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    @staticmethod
    def _priority_label(severity: str, target_score: float) -> str:
        weight = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }.get(str(severity).strip().lower(), 0)
        if target_score >= 1.8:
            weight += 1
        return {
            5: "P0",
            4: "P1",
            3: "P2",
            2: "P3",
            1: "P4",
            0: "P5",
        }.get(min(5, max(0, weight)), "P4")

    @staticmethod
    def _priority_weight(value: str) -> int:
        return {
            "P0": 6,
            "P1": 5,
            "P2": 4,
            "P3": 3,
            "P4": 2,
            "P5": 1,
        }.get(str(value).strip().upper(), 0)

    @staticmethod
    def _severity_weight(value: str) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(str(value).strip().lower(), 0)

    def _remediation_reason(self, *, name: str, severity: str, target_score: float) -> str:
        if target_score >= 1.8:
            return f"{name} sits on a highly corroborated target; fixing it reduces multiple follow-on paths."
        if severity in {"critical", "high"}:
            return f"{name} carries elevated severity and should be addressed before deeper validation."
        return f"{name} should be tracked as part of routine remediation for the observed surface."

    def _add_claim(
        self,
        claims: dict[tuple[str, str], _EvidenceClaim],
        *,
        kind: str,
        subject: str,
        source: str,
        target: str,
        metadata: dict[str, Any],
    ) -> None:
        normalized_subject = str(subject).strip()
        if not normalized_subject:
            return
        key = (kind, normalized_subject)
        claim = claims.get(key)
        if claim is None:
            claim = _EvidenceClaim(kind=kind, subject=normalized_subject)
            claims[key] = claim
        claim.sources.add(str(source).strip())
        if target:
            claim.targets.add(str(target).strip())
        claim.evidences.append(
            {
                "source": str(source).strip(),
                "target": str(target).strip(),
                "metadata": metadata,
            }
        )
        for meta_key, meta_value in metadata.items():
            if meta_key not in claim.metadata and meta_value not in ("", None, [], {}):
                claim.metadata[meta_key] = meta_value

    def _surface_origins(self, surface: dict[str, Any]) -> list[str]:
        origins: set[str] = set()
        for key in ("nmap_http_origins", "nmap_https_origins", "discovered_urls"):
            values = surface.get(key, [])
            if not isinstance(values, list):
                continue
            for item in values:
                origin = self._origin_of(str(item).strip())
                if origin:
                    origins.add(origin)
        api_endpoints = surface.get("api_endpoints", [])
        if isinstance(api_endpoints, list):
            for item in api_endpoints:
                if isinstance(item, dict):
                    raw_url = str(item.get("url", "")).strip()
                else:
                    raw_url = str(item).strip()
                origin = self._origin_of(raw_url)
                if origin:
                    origins.add(origin)
        return sorted(origins)

    def _surface_services(self, surface: dict[str, Any]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        services = surface.get("nmap_services", [])
        if isinstance(services, list):
            for item in services:
                if isinstance(item, dict):
                    output.append(
                        {
                            "name": item.get("service") or item.get("name"),
                            "target": item.get("origin") or item.get("target") or item.get("url") or "",
                            "port": item.get("port"),
                            "banner": item.get("banner") or item.get("version"),
                        }
                    )
                elif isinstance(item, str):
                    output.append({"name": item, "target": "", "port": None, "banner": ""})
        banners = surface.get("service_banners", [])
        if isinstance(banners, list):
            for item in banners:
                if not isinstance(item, dict):
                    continue
                output.append(
                    {
                        "name": item.get("service") or item.get("protocol") or item.get("banner"),
                        "target": item.get("target") or item.get("origin") or "",
                        "port": item.get("port"),
                        "banner": item.get("banner") or "",
                    }
                )
        return output

    def _surface_parameterized_endpoints(self, surface: dict[str, Any]) -> dict[str, set[str]]:
        output: dict[str, set[str]] = {}
        url_parameters = surface.get("url_parameters", {})
        if isinstance(url_parameters, dict):
            for endpoint, params in url_parameters.items():
                output.setdefault(str(endpoint).strip(), set()).update(self._coerce_params(params))
        parameter_origins = surface.get("parameter_origins", {})
        if isinstance(parameter_origins, dict):
            for endpoint, params in parameter_origins.items():
                output.setdefault(str(endpoint).strip(), set()).update(self._coerce_params(params))
        return {key: value for key, value in output.items() if key and value}

    @staticmethod
    def _coerce_params(value: Any) -> set[str]:
        if isinstance(value, dict):
            return {str(key).strip() for key in value.keys() if str(key).strip()}
        if isinstance(value, list):
            return {str(item).strip() for item in value if str(item).strip()}
        return set()

    def _best_target_from_surface(self, surface: dict[str, Any]) -> str:
        origins = self._surface_origins(surface)
        return origins[0] if origins else ""

    @staticmethod
    def _origin_of(value: str) -> str:
        raw = str(value or "").strip()
        if not raw or "://" not in raw:
            return ""
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    @staticmethod
    def _looks_like_endpoint(value: str) -> bool:
        return "://" in str(value or "") and bool(urlparse(str(value)).path)

    def _extract_target_from_finding(self, finding: dict[str, Any]) -> str:
        model = finding.get("model")
        if isinstance(model, dict):
            evidence = model.get("evidence", {})
            if isinstance(evidence, dict):
                for key in ("target", "matched_at", "url"):
                    value = str(evidence.get(key, "")).strip()
                    if value:
                        return value
        evidence_text = str(finding.get("evidence", "")).strip()
        if evidence_text.startswith("http://") or evidence_text.startswith("https://"):
            return evidence_text.split()[0]
        return ""
