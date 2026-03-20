"""Derived CVE validation pipeline state for staged, evidence-driven verification."""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse


class CveValidationPipeline:
    """Build staged CVE validation state from live surface and corroborated evidence."""

    def build(
        self,
        *,
        state: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build CVE staging summary for planning, UI, and reporting."""
        if not isinstance(state, dict):
            return {}
        surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
        evidence_graph = state.get("evidence_graph", {}) if isinstance(state.get("evidence_graph", {}), dict) else {}
        candidates = surface.get("cve_candidates", []) if isinstance(surface.get("cve_candidates", []), list) else []
        verification_rows = surface.get("cve_verification", []) if isinstance(surface.get("cve_verification", []), list) else []
        safe_findings = findings if isinstance(findings, list) else state.get("findings_preview", [])
        if not isinstance(safe_findings, list):
            safe_findings = []

        claims = evidence_graph.get("claims", []) if isinstance(evidence_graph.get("claims", []), list) else []
        target_claims = self._index_claims_by_target(claims)
        verified_pairs = self._verified_pairs(verification_rows, safe_findings)

        authorization_confirmed = self._coerce_bool(
            state.get("authorization_confirmed"),
            default=self._coerce_bool(surface.get("authorization_confirmed"), default=False),
        )
        approval_granted = self._coerce_bool(
            state.get("approval_granted"),
            default=self._coerce_bool(surface.get("approval_granted"), default=False),
        )
        safety_grade = str(state.get("safety_grade", "balanced")).strip().lower() or "balanced"

        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for raw in candidates:
            if not isinstance(raw, dict):
                continue
            cve_id = str(raw.get("cve_id", "")).strip().upper()
            if not cve_id:
                continue
            target = self._normalize_target(str(raw.get("target", "")).strip() or str(state.get("target", "")).strip())
            key = (target, cve_id)
            current = grouped.setdefault(
                key,
                {
                    "target": target,
                    "cve_id": cve_id,
                    "component": str(raw.get("component", "")).strip() or None,
                    "version": str(raw.get("version", "")).strip() or None,
                    "service": str(raw.get("service", "")).strip().lower() or None,
                    "severity": str(raw.get("severity", "medium")).strip().lower() or "medium",
                    "cvss_score": self._coerce_float(raw.get("cvss_score")),
                    "has_template": bool(raw.get("has_nuclei_template", False)),
                    "template_capability": raw.get("template_capability", {}) if isinstance(raw.get("template_capability", {}), dict) else {},
                },
            )
            if not current.get("component") and str(raw.get("component", "")).strip():
                current["component"] = str(raw.get("component", "")).strip()
            if not current.get("version") and str(raw.get("version", "")).strip():
                current["version"] = str(raw.get("version", "")).strip()
            if not current.get("service") and str(raw.get("service", "")).strip():
                current["service"] = str(raw.get("service", "")).strip().lower()
            if not current.get("has_template") and bool(raw.get("has_nuclei_template", False)):
                current["has_template"] = True
            current_cvss = current.get("cvss_score")
            candidate_cvss = self._coerce_float(raw.get("cvss_score"))
            if candidate_cvss is not None and (current_cvss is None or candidate_cvss > current_cvss):
                current["cvss_score"] = candidate_cvss
            current_severity = str(current.get("severity", "medium")).strip().lower()
            candidate_severity = str(raw.get("severity", "medium")).strip().lower() or "medium"
            if self._severity_weight(candidate_severity) > self._severity_weight(current_severity):
                current["severity"] = candidate_severity
            if isinstance(raw.get("template_capability"), dict) and raw.get("template_capability"):
                current["template_capability"] = raw.get("template_capability")

        items: list[dict[str, Any]] = []
        for item in grouped.values():
            related_claims = target_claims.get(item["target"], [])
            version_corroborated = self._is_version_corroborated(item, related_claims)
            template_verified = (item["target"], item["cve_id"]) in verified_pairs or ("*", item["cve_id"]) in verified_pairs
            sandbox_ready = bool(
                template_verified
                and authorization_confirmed
                and approval_granted
                and safety_grade == "aggressive"
            )
            blocked_reasons = self._blocked_reasons(
                version_corroborated=version_corroborated,
                template_verified=template_verified,
                authorization_confirmed=authorization_confirmed,
                approval_granted=approval_granted,
                safety_grade=safety_grade,
            )
            quality_score = self._quality_score(
                severity=item.get("severity"),
                cvss_score=item.get("cvss_score"),
                version_corroborated=version_corroborated,
                template_verified=template_verified,
                claim_count=len(related_claims),
                has_template=bool(item.get("has_template")),
            )
            recommended_next_step = self._recommended_next_step(
                version_corroborated=version_corroborated,
                template_verified=template_verified,
                sandbox_ready=sandbox_ready,
                blocked_reasons=blocked_reasons,
            )
            items.append(
                {
                    **item,
                    "version_corroborated": version_corroborated,
                    "template_verified": template_verified,
                    "sandbox_ready": sandbox_ready,
                    "quality_score": round(quality_score, 2),
                    "quality_label": self._quality_label(quality_score, template_verified=template_verified),
                    "recommended_next_step": recommended_next_step,
                    "blocked_reasons": blocked_reasons,
                    "related_claims": [
                        {
                            "kind": str(claim.get("kind", "")).strip(),
                            "subject": str(claim.get("subject", "")).strip(),
                            "confidence": float(claim.get("confidence", 0.0) or 0.0),
                        }
                        for claim in related_claims[:6]
                    ],
                }
            )

        items.sort(
            key=lambda row: (
                not bool(row.get("template_verified")),
                not bool(row.get("version_corroborated")),
                -float(row.get("quality_score", 0.0) or 0.0),
                -self._severity_weight(str(row.get("severity", "info")).strip().lower()),
                -(float(row.get("cvss_score")) if isinstance(row.get("cvss_score"), (int, float)) else 0.0),
                str(row.get("cve_id", "")),
            )
        )

        recommended_actions = self._recommended_actions(items)
        summary = {
            "candidate_count": len(items),
            "version_corroborated_count": sum(1 for item in items if item.get("version_corroborated")),
            "template_verified_count": sum(1 for item in items if item.get("template_verified")),
            "sandbox_ready_count": sum(1 for item in items if item.get("sandbox_ready")),
            "high_quality_count": sum(1 for item in items if float(item.get("quality_score", 0.0) or 0.0) >= 0.75),
            "authorization_confirmed": authorization_confirmed,
            "approval_granted": approval_granted,
            "safety_grade": safety_grade,
            "next_step": recommended_actions[0]["tool_name"] if recommended_actions else None,
        }
        return {
            "version": 1,
            "summary": summary,
            "candidates": items[:24],
            "recommended_actions": recommended_actions[:10],
        }

    def _index_claims_by_target(self, claims: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            primary_target = self._normalize_target(str(claim.get("primary_target", "")).strip())
            if primary_target:
                index[primary_target].append(claim)
            for target in claim.get("targets", []):
                normalized = self._normalize_target(str(target).strip())
                if normalized:
                    index[normalized].append(claim)
        return index

    def _verified_pairs(
        self,
        verification_rows: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> set[tuple[str, str]]:
        output: set[tuple[str, str]] = set()
        for row in verification_rows:
            if not isinstance(row, dict):
                continue
            cve_id = str(row.get("cve_id", "")).strip().upper()
            if not cve_id or not bool(row.get("verified")):
                continue
            target = self._normalize_target(str(row.get("target", "")).strip())
            output.add((target or "*", cve_id))
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            cve_id = str(finding.get("cve_id", "")).strip().upper()
            if not cve_id or not bool(finding.get("cve_verified")):
                continue
            model = finding.get("model", {}) if isinstance(finding.get("model", {}), dict) else {}
            evidence = model.get("evidence", {}) if isinstance(model.get("evidence", {}), dict) else {}
            target = self._normalize_target(str(evidence.get("target", "")).strip())
            output.add((target or "*", cve_id))
        return output

    def _is_version_corroborated(
        self,
        candidate: dict[str, Any],
        related_claims: list[dict[str, Any]],
    ) -> bool:
        component = str(candidate.get("component", "")).strip().lower()
        service = str(candidate.get("service", "")).strip().lower()
        version = str(candidate.get("version", "")).strip().lower()
        if component and version:
            return True
        for claim in related_claims:
            if not isinstance(claim, dict):
                continue
            kind = str(claim.get("kind", "")).strip().lower()
            subject = str(claim.get("subject", "")).strip().lower()
            metadata = claim.get("metadata", {}) if isinstance(claim.get("metadata", {}), dict) else {}
            if kind == "service" and service and subject == service:
                return True
            if kind == "tech_stack" and component and component in subject:
                return True
            if kind == "cve_candidate":
                meta_component = str(metadata.get("component", "")).strip().lower()
                meta_version = str(metadata.get("version", "")).strip().lower()
                if component and meta_component and component == meta_component:
                    return True
                if version and meta_version and version == meta_version:
                    return True
            if version:
                text_blob = " ".join(
                    [
                        subject,
                        str(metadata.get("banner", "")).strip().lower(),
                        str(metadata.get("version", "")).strip().lower(),
                    ]
                )
                if version in text_blob:
                    return True
        return False

    def _blocked_reasons(
        self,
        *,
        version_corroborated: bool,
        template_verified: bool,
        authorization_confirmed: bool,
        approval_granted: bool,
        safety_grade: str,
    ) -> list[str]:
        reasons: list[str] = []
        if not version_corroborated:
            reasons.append("version_not_corroborated")
        if not template_verified:
            reasons.append("template_not_verified")
        if not authorization_confirmed:
            reasons.append("authorization_required")
        if not approval_granted:
            reasons.append("approval_required")
        if safety_grade != "aggressive":
            reasons.append("aggressive_grade_required")
        return reasons

    def _recommended_next_step(
        self,
        *,
        version_corroborated: bool,
        template_verified: bool,
        sandbox_ready: bool,
        blocked_reasons: list[str],
    ) -> str:
        if sandbox_ready:
            return "poc_sandbox_exec"
        if version_corroborated and not template_verified:
            return "cve_verify"
        if "version_not_corroborated" in blocked_reasons:
            return "collect_more_evidence"
        if "approval_required" in blocked_reasons:
            return "await_approval"
        if "authorization_required" in blocked_reasons:
            return "await_authorization"
        return "monitor_only"

    def _recommended_actions(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in items:
            step = str(item.get("recommended_next_step", "")).strip()
            if not step or step in {"collect_more_evidence", "monitor_only", "await_authorization", "await_approval"}:
                continue
            target = str(item.get("target", "")).strip()
            cve_id = str(item.get("cve_id", "")).strip().upper()
            signature = (step, target, cve_id)
            if signature in seen:
                continue
            seen.add(signature)
            output.append(
                {
                    "tool_name": step,
                    "target": target,
                    "cve_id": cve_id,
                    "quality_score": round(float(item.get("quality_score", 0.0) or 0.0), 2),
                    "reason": (
                        "Version corroboration completed; run template verification next."
                        if step == "cve_verify"
                        else "Template verification succeeded and approvals are satisfied; minimal sandbox PoC is allowed."
                    ),
                }
            )
        return output

    def _quality_score(
        self,
        *,
        severity: str | None,
        cvss_score: float | None,
        version_corroborated: bool,
        template_verified: bool,
        claim_count: int,
        has_template: bool,
    ) -> float:
        score = 0.18
        score += min(0.16, max(0, claim_count) * 0.03)
        score += min(0.22, (float(cvss_score) / 10.0) * 0.22) if isinstance(cvss_score, (int, float)) else 0.0
        score += {
            "critical": 0.18,
            "high": 0.13,
            "medium": 0.08,
            "low": 0.04,
            "info": 0.02,
        }.get(str(severity or "info").strip().lower(), 0.02)
        if version_corroborated:
            score += 0.2
        if has_template:
            score += 0.08
        if template_verified:
            score += 0.22
        return min(0.98, score)

    @staticmethod
    def _quality_label(score: float, *, template_verified: bool) -> str:
        if template_verified and score >= 0.85:
            return "verified"
        if score >= 0.8:
            return "high"
        if score >= 0.55:
            return "medium"
        return "low"

    @staticmethod
    def _coerce_bool(value: Any, *, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        lowered = str(value).strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
        return default

    @staticmethod
    def _coerce_float(value: Any) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _severity_weight(value: str) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(str(value or "info").strip().lower(), 1)

    @staticmethod
    def _normalize_target(value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        if "://" not in raw:
            return raw.lower()
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            return raw.lower()
        path = parsed.path or ""
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
        return normalized.rstrip("/") if path else normalized
