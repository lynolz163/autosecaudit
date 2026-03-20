"""Report generation utilities."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

from .models import AuditSessionResult, Finding, PluginResult
from .report_visual import build_visual_analysis_payload


@dataclass(frozen=True)
class ReportArtifacts:
    """Paths to generated report artifacts."""

    json_report: Path
    markdown_report: Path


def create_report_snapshot(
    report_path: Path,
    *,
    target: str,
    timestamp: str | None = None,
) -> Path | None:
    """
    Copy one report artifact into a target/timestamp-stamped filename.

    Example:
    - `agent_report.md` -> `agent_report_example-com_20260306T102233Z.md`
    """
    try:
        payload = report_path.read_bytes()
    except OSError:
        return None

    stamp = str(timestamp or "").strip() or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target_slug = _slugify_report_target(target)
    base = f"{report_path.stem}_{target_slug}_{stamp}"
    candidate = report_path.with_name(f"{base}{report_path.suffix}")
    suffix = 2
    while candidate.exists():
        candidate = report_path.with_name(f"{base}_{suffix}{report_path.suffix}")
        suffix += 1
    try:
        candidate.write_bytes(payload)
    except OSError:
        return None
    return candidate


def _slugify_report_target(target: str) -> str:
    """Normalize target string into a filesystem-safe short slug."""
    raw = str(target or "").strip()
    if not raw:
        return "target"

    host_candidate = raw
    if "://" in raw:
        parsed = urlparse(raw)
        host_candidate = parsed.netloc or parsed.path or raw
    host_candidate = host_candidate.split("/", 1)[0]
    host_candidate = host_candidate.split("@")[-1]
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", host_candidate).strip("-").lower()
    if not slug:
        return "target"
    return slug[:64]


class ReportWriter:
    """Writes machine-readable and human-readable compliance reports."""

    def write(self, session: AuditSessionResult, output_dir: Path) -> ReportArtifacts:
        """Generate report files under `output_dir`."""
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "audit_report.json"
        markdown_path = output_dir / "audit_report.md"

        self._write_json(json_path, session)
        self._write_markdown(markdown_path, session)
        json_snapshot = create_report_snapshot(json_path, target=session.target)
        markdown_snapshot = create_report_snapshot(markdown_path, target=session.target)
        return ReportArtifacts(
            json_report=json_snapshot or json_path,
            markdown_report=markdown_snapshot or markdown_path,
        )

    def _write_json(self, output_path: Path, session: AuditSessionResult) -> None:
        payload = asdict(session)
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _write_markdown(self, output_path: Path, session: AuditSessionResult) -> None:
        lines: list[str] = []
        lines.append("# AutoSecAudit Report")
        lines.append("")
        lines.append(f"- Target: `{session.target}`")
        lines.append(f"- Started (UTC): `{session.started_at}`")
        lines.append(f"- Ended (UTC): `{session.ended_at}`")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        for key, value in session.summary.items():
            lines.append(f"- {key}: `{value}`")
        lines.append("")
        lines.append("## Plugin Results")
        lines.append("")

        for result in session.plugin_results:
            lines.extend(self._format_plugin_section(result))

        output_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")

    def _format_plugin_section(self, result: PluginResult) -> list[str]:
        lines: list[str] = []
        lines.append(f"### {result.plugin_name} (`{result.plugin_id}`)")
        lines.append("")
        lines.append(f"- Category: `{result.category}`")
        lines.append(f"- Status: `{result.status}`")
        lines.append(f"- Started: `{result.started_at}`")
        lines.append(f"- Ended: `{result.ended_at}`")
        if result.error:
            lines.append(f"- Error: `{result.error}`")
        lines.append("")

        if not result.findings:
            lines.append("- Findings: `0`")
            lines.append("")
            return lines

        lines.append(f"- Findings: `{len(result.findings)}`")
        lines.append("")
        for finding in result.findings:
            lines.extend(self._format_finding(finding))
        return lines

    def _format_finding(self, finding: Finding) -> list[str]:
        lines: list[str] = []
        lines.append(f"#### {finding.title} (`{finding.finding_id}`)")
        lines.append("")
        lines.append(f"- Severity: `{finding.severity}`")
        lines.append(f"- Description: {finding.description}")
        if finding.recommendation:
            lines.append(f"- Recommendation: {finding.recommendation}")
        if finding.evidence:
            lines.append(f"- Evidence: `{json.dumps(finding.evidence, ensure_ascii=False)}`")
        lines.append("")
        return lines


def normalize_report_lang(value: str | None) -> str:
    """Normalize report language flag into a stable value."""
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized.startswith("zh") or normalized in {"cn"}:
        return "zh-CN"
    return "en"


def generate_markdown_report(
    findings: list[dict[str, Any]],
    filename: str,
    *,
    recon_data: dict[str, Any] | None = None,
    evidence_graph: dict[str, Any] | None = None,
    report_lang: str = "en",
    coverage_data: dict[str, Any] | None = None,
    history_data: list[dict[str, Any]] | None = None,
    blocked_actions: list[dict[str, Any]] | None = None,
    state_data: dict[str, Any] | None = None,
    decision_summary: str | None = None,
) -> str:
    """
    Generate a standalone Markdown report from a findings list.

    Supports bilingual output (English / Chinese) and richer execution detail.
    """
    normalized_lang = normalize_report_lang(report_lang)
    zh = normalized_lang.startswith("zh")
    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text

    normalized = [
        {
            **_normalize_finding(item, index),
            "recommendation": _extract_recommendation(item),
            "category": str(item.get("category", "")).strip() or None,
        }
        for index, item in enumerate(findings, start=1)
    ]
    vulnerabilities = [item for item in normalized if item["type"] == "vuln"]
    generated_at = datetime.now(timezone.utc).isoformat()

    severity_order = ("critical", "high", "medium", "low", "info")
    severity_counts: dict[str, int] = {level: 0 for level in severity_order}
    for item in vulnerabilities:
        severity_counts[item["severity"]] += 1

    lines: list[str] = []
    lines.append(t("# Security Audit Report", "# 安全审计报告"))
    lines.append("")
    lines.append(f"- {t('Generated (UTC)', '生成时间（UTC）')}: `{generated_at}`")
    lines.append(f"- {t('Report Language', '报告语言')}: `{normalized_lang}`")
    lines.append(f"- {t('Total Findings', '发现总数')}: `{len(normalized)}`")
    lines.append(f"- {t('Vulnerabilities', '漏洞类发现')}: `{len(vulnerabilities)}`")
    lines.append("")

    if decision_summary:
        lines.append(t("## Decision Summary", "## 决策摘要"))
        lines.append("")
        lines.append(str(decision_summary).strip())
        lines.append("")

    lines.append(t("## Summary", "## 风险摘要"))
    lines.append("")
    if not vulnerabilities:
        lines.append(t("No vulnerability findings were provided.", "本次未产出漏洞类发现。"))
        lines.append("")
    else:
        for level in severity_order:
            lines.append(f"- {level.capitalize()}: `{severity_counts[level]}`")
        unique_names = sorted({item["name"] for item in vulnerabilities})
        lines.append(f"- {t('Unique Vulnerability Types', '漏洞类型去重数')}: `{len(unique_names)}`")
        lines.append("")
        lines.append(t("Top Vulnerability Names:", "主要漏洞名称："))
        for name in unique_names:
            lines.append(f"- {name}")
        lines.append("")

    if isinstance(state_data, dict):
        lines.append(t("## Runtime Profile", "## 运行画像"))
        lines.append("")
        lines.append(f"- {t('Target', '目标')}: `{state_data.get('target', '')}`")
        lines.append(f"- {t('Safety Grade', '安全等级')}: `{state_data.get('safety_grade', 'balanced')}`")
        lines.append(f"- {t('Iteration Count', '迭代次数')}: `{state_data.get('iteration_count', 0)}`")
        lines.append(f"- {t('Budget Remaining', '剩余预算')}: `{state_data.get('budget_remaining', 0)}`")
        lines.append(
            f"- {t('Resumed', '是否续跑')}: `{bool(state_data.get('resumed', False))}`"
        )
        resumed_from = str(state_data.get("resumed_from", "")).strip()
        if resumed_from:
            lines.append(f"- {t('Resumed From', '续跑来源')}: `{resumed_from}`")
        lines.append("")

    coverage = coverage_data if isinstance(coverage_data, dict) else {}
    if coverage:
        lines.append(t("## Execution Coverage", "## 执行覆盖"))
        lines.append("")
        lines.append(
            f"- {t('Unique Tools Executed', '执行工具去重数')}: "
            f"`{coverage.get('unique_tools_executed', 0)}`"
        )
        lines.append(
            f"- {t('Completed/Failed/Error Actions', '完成/失败/错误动作')}: "
            f"`{coverage.get('completed_actions', 0)}/{coverage.get('failed_actions', 0)}/{coverage.get('error_actions', 0)}`"
        )
        lines.append(
            f"- {t('Observed Service Origins', '观察到服务 Origin 数')}: "
            f"`{coverage.get('service_origins_observed', 0)}`"
        )
        lines.append(
            f"- {t('API Endpoints / URL Params', 'API 端点 / URL 参数')}: "
            f"`{coverage.get('api_endpoint_count', 0)} / {coverage.get('parameter_count', 0)}`"
        )
        highlights = coverage.get("highlights", [])
        if isinstance(highlights, list) and highlights:
            lines.append("")
            lines.append(t("Coverage Highlights:", "覆盖亮点："))
            for item in highlights[:10]:
                lines.append(f"- {item}")
        lines.append("")
        lines.append(t("### Tool Execution Matrix", "### 工具执行矩阵"))
        lines.append("")
        lines.append("| Tool | Total | Completed | Failed | Error |")
        lines.append("|------|------:|----------:|-------:|------:|")
        tool_stats = coverage.get("tool_stats", [])
        if isinstance(tool_stats, list) and tool_stats:
            for item in tool_stats:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"| {item.get('tool', 'unknown')} | {item.get('total', 0)} | "
                    f"{item.get('completed', 0)} | {item.get('failed', 0)} | {item.get('error', 0)} |"
                )
        else:
            lines.append("| - | 0 | 0 | 0 | 0 |")
        lines.append("")

    state_source = state_data if isinstance(state_data, dict) else {}
    lines.extend(_render_scope_snapshot_markdown(state_source, report_lang=normalized_lang))
    lines.extend(_render_knowledge_context_markdown(state_source, report_lang=normalized_lang))
    lines.extend(_render_evidence_graph_markdown(evidence_graph, report_lang=normalized_lang))
    lines.extend(_render_cve_validation_markdown(state_source.get("cve_validation"), report_lang=normalized_lang))
    remediation_priority = (
        evidence_graph.get("remediation_priority", [])
        if isinstance(evidence_graph, dict)
        else []
    )
    lines.extend(_render_remediation_priority_markdown(remediation_priority, report_lang=normalized_lang))

    if history_data:
        lines.extend(_render_history_markdown_detailed(history_data, report_lang=normalized_lang))

    if blocked_actions:
        lines.extend(_render_blocked_actions_markdown(blocked_actions, report_lang=normalized_lang))

    # -- Reconnaissance / Information Gathering Section ---------
    lines.extend(_render_recon_markdown(recon_data, report_lang=normalized_lang))

    lines.append(t("## Findings Catalog", "## 发现目录"))
    lines.append("")
    lines.append("| # | Name | Type | Severity | CVE |")
    lines.append("|---|------|------|----------|-----|")
    if normalized:
        for item in normalized:
            lines.append(
                f"| {item['index']} | {item['name']} | {item['type']} | {item['severity'].capitalize()} | {item.get('cve_id') or '-'} |"
            )
    else:
        lines.append("| - | None | - | - | - |")
    lines.append("")

    lines.append(t("## Detailed Evidence", "## 详细证据"))
    lines.append("")
    if normalized:
        for item in normalized:
            lines.append(
                f"### {item['index']}. {item['name']} "
                f"({t('Severity', '严重性')}: {item['severity'].capitalize()})"
            )
            lines.append("")
            lines.append(f"- {t('Type', '类型')}: `{item['type']}`")
            lines.append(f"- {t('Category', '类别')}: `{item.get('category') or '-'}`")
            if item.get("cve_id"):
                lines.append(f"- CVE: `{item['cve_id']}`")
            if item.get("cvss_score") is not None:
                lines.append(f"- CVSS: `{item['cvss_score']}`")
            lines.append(f"- {t('CVE Verified', 'CVE 是否已验证')}: `{bool(item.get('cve_verified', False))}`")
            lines.append("")
            lines.append(f"**{t('Evidence', '证据')}**")
            lines.append("")
            lines.append("```text")
            lines.append(item["evidence"] or t("No evidence provided.", "未提供证据。"))
            lines.append("```")
            lines.append("")
            lines.append(f"**{t('Reproduction Steps', '复现步骤')}**")
            lines.append("")
            if item["reproduction_steps"]:
                for step_no, step in enumerate(item["reproduction_steps"], start=1):
                    lines.append(f"{step_no}. {step}")
            else:
                lines.append(
                    t("1. Reproduction steps were not provided.", "1. 未提供可执行复现步骤。")
                )
            lines.append("")
            lines.append(f"**{t('Remediation', '修复建议')}**")
            lines.append("")
            lines.append(item.get("recommendation") or t("No remediation provided.", "未提供修复建议。"))
            lines.append("")
    else:
        lines.append(t("No findings evidence to display.", "无可展示的发现证据。"))
        lines.append("")

    markdown = "\n".join(lines).strip() + "\n"
    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return markdown


def _render_scope_snapshot_markdown(state: dict[str, Any], *, report_lang: str = "en") -> list[str]:
    """Render compact scope/surface snapshot into markdown."""
    zh = normalize_report_lang(report_lang).startswith("zh")
    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text
    lines: list[str] = []
    scope = state.get("scope", [])
    breadcrumbs = state.get("breadcrumbs", [])
    surface = state.get("surface", {})
    if not isinstance(scope, list):
        scope = []
    if not isinstance(breadcrumbs, list):
        breadcrumbs = []
    if not isinstance(surface, dict):
        surface = {}

    lines.append(t("## Scope Snapshot", "## 范围快照"))
    lines.append("")
    lines.append(f"- {t('Scope Entries', '范围条目数')}: `{len(scope)}`")
    lines.append(f"- {t('Breadcrumb Records', '面包屑记录数')}: `{len(breadcrumbs)}`")
    lines.append(f"- {t('Surface Keys', '资产面键数')}: `{len(surface.keys())}`")
    if scope:
        lines.append(f"- {t('Scope Samples', '范围样本')}: {', '.join(f'`{item}`' for item in scope[:10])}")
    lines.append("")
    return lines


def _render_knowledge_context_markdown(
    state: dict[str, Any],
    *,
    report_lang: str = "en",
) -> list[str]:
    """Render task-level knowledge context used to steer the audit."""
    zh = normalize_report_lang(report_lang).startswith("zh")

    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text

    surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
    knowledge = (
        surface.get("knowledge_context", {})
        if isinstance(surface.get("knowledge_context", {}), dict)
        else {}
    )
    summary = str(knowledge.get("summary", "")).strip()
    tags = [
        str(item).strip()
        for item in knowledge.get("tags", [])
        if str(item).strip()
    ] if isinstance(knowledge.get("tags", []), list) else []
    refs = [
        str(item).strip()
        for item in knowledge.get("references", [])
        if str(item).strip()
    ] if isinstance(knowledge.get("references", []), list) else []

    if not summary and not tags and not refs:
        return []

    lines: list[str] = []
    lines.append(t("## Knowledge Context", "## 任务知识上下文"))
    lines.append("")
    if summary:
        lines.append(f"- {t('Summary', '摘要')}: {summary}")
    if tags:
        lines.append(
            f"- {t('Tags', '标签')}: "
            + ", ".join(f"`{item}`" for item in tags[:12])
        )
    if refs:
        lines.append(f"- {t('References', '引用')}:")
        for item in refs[:10]:
            lines.append(f"  - `{item}`")
    lines.append("")
    return lines


def _render_evidence_graph_markdown(
    evidence_graph: dict[str, Any] | None,
    *,
    report_lang: str = "en",
) -> list[str]:
    """Render corroborated evidence chain summary into markdown."""
    if not isinstance(evidence_graph, dict) or not evidence_graph:
        return []
    zh = normalize_report_lang(report_lang).startswith("zh")

    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text

    summary = evidence_graph.get("summary", {}) if isinstance(evidence_graph.get("summary", {}), dict) else {}
    claims = evidence_graph.get("claims", []) if isinstance(evidence_graph.get("claims", []), list) else []
    priority_targets = (
        evidence_graph.get("priority_targets", [])
        if isinstance(evidence_graph.get("priority_targets", []), list)
        else []
    )
    path_graph = (
        evidence_graph.get("path_graph", {})
        if isinstance(evidence_graph.get("path_graph", {}), dict)
        else {}
    )
    remediation_priority = (
        evidence_graph.get("remediation_priority", [])
        if isinstance(evidence_graph.get("remediation_priority", []), list)
        else []
    )
    recommended_tools = [
        str(item).strip()
        for item in evidence_graph.get("recommended_tools", [])
        if str(item).strip()
    ]

    lines: list[str] = []
    lines.append(t("## Evidence Correlation", "## 证据关联"))
    lines.append("")
    lines.append(f"- {t('Claims', '证据声明')}: `{int(summary.get('claim_count', 0) or 0)}`")
    lines.append(
        f"- {t('Corroborated Claims', '交叉印证声明')}: "
        f"`{int(summary.get('corroborated_claims', 0) or 0)}`"
    )
    lines.append(
        f"- {t('High Confidence Leads', '高置信线索')}: "
        f"`{int(summary.get('high_confidence_claims', 0) or 0)}`"
    )
    lines.append(
        f"- {t('High Quality Claims', '高质量证据')}: "
        f"`{int(summary.get('high_quality_claims', 0) or 0)}`"
    )
    if isinstance(path_graph, dict):
        node_count = len(path_graph.get("nodes", [])) if isinstance(path_graph.get("nodes", []), list) else 0
        edge_count = len(path_graph.get("edges", [])) if isinstance(path_graph.get("edges", []), list) else 0
        lines.append(
            f"- {t('Path Graph', '攻击路径图')}: "
            f"`{node_count}` {t('nodes', '节点')} / `{edge_count}` {t('edges', '连边')}"
        )
    lines.append(
        f"- {t('Remediation Priorities', '修复优先事项')}: "
        f"`{len(remediation_priority)}`"
    )
    if recommended_tools:
        lines.append(
            f"- {t('Recommended Follow-up Tools', '推荐后续工具')}: "
            + ", ".join(f"`{item}`" for item in recommended_tools[:10])
        )
    lines.append("")

    if priority_targets:
        lines.append(t("### Priority Targets", "### 优先目标"))
        lines.append("")
        for item in priority_targets[:8]:
            if not isinstance(item, dict):
                continue
            target = str(item.get("target", "")).strip()
            if not target:
                continue
            reasons = [
                str(reason).strip()
                for reason in item.get("reasons", [])
                if str(reason).strip()
            ]
            lines.append(
                f"- `{target}` "
                f"({t('score', '评分')} `{item.get('score', 0)}`): "
                f"{'; '.join(reasons[:4]) or t('No explicit reason', '无明确理由')}"
            )
        lines.append("")

    if claims:
        lines.append(t("### Corroborated Claims", "### 已印证线索"))
        lines.append("")
        for item in claims[:12]:
            if not isinstance(item, dict):
                continue
            subject = str(item.get("subject", "")).strip() or "-"
            kind = str(item.get("kind", "")).strip() or "claim"
            confidence = item.get("confidence", 0)
            targets = [
                str(target).strip()
                for target in item.get("targets", [])
                if str(target).strip()
            ]
            lines.append(
                f"- `{kind}` / `{subject}` | "
                f"{t('confidence', '置信度')} `{confidence}` | "
                f"{t('quality', '质量')} `{item.get('quality_label', '-')}` | "
                f"{t('sources', '来源')} `{item.get('source_count', 0)}` | "
                f"{t('targets', '目标')} "
                f"{', '.join(f'`{target}`' for target in targets[:3]) if targets else '`-`'}"
            )
        lines.append("")
    return lines


def _render_cve_validation_markdown(
    cve_validation: dict[str, Any] | None,
    *,
    report_lang: str = "en",
) -> list[str]:
    """Render staged CVE validation pipeline summary."""
    if not isinstance(cve_validation, dict) or not cve_validation:
        return []

    zh = normalize_report_lang(report_lang).startswith("zh")

    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text

    summary = cve_validation.get("summary", {}) if isinstance(cve_validation.get("summary", {}), dict) else {}
    candidates = cve_validation.get("candidates", []) if isinstance(cve_validation.get("candidates", []), list) else []
    recommended = cve_validation.get("recommended_actions", []) if isinstance(cve_validation.get("recommended_actions", []), list) else []
    if not summary and not candidates and not recommended:
        return []

    lines: list[str] = []
    lines.append(t("## CVE Validation Pipeline", "## CVE 分级验证流水线"))
    lines.append("")
    if summary:
        lines.append(f"- {t('Candidates', '候选数量')}: `{summary.get('candidate_count', 0)}`")
        lines.append(f"- {t('Version Corroborated', '版本印证')}: `{summary.get('version_corroborated_count', 0)}`")
        lines.append(f"- {t('Template Verified', '模板验证')}: `{summary.get('template_verified_count', 0)}`")
        lines.append(f"- {t('Sandbox Ready', '沙箱就绪')}: `{summary.get('sandbox_ready_count', 0)}`")
        lines.append("")

    if recommended:
        lines.append(t("Recommended next actions:", "推荐的后续动作："))
        for item in recommended[:8]:
            lines.append(f"- `{item}`")
        lines.append("")

    if candidates:
        lines.append("| CVE | Target | Quality | Version | Template | Sandbox | Next Step |")
        lines.append("|-----|--------|---------|---------|----------|---------|-----------|")
        for item in candidates[:12]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {item.get('cve_id', '-')} | {item.get('target', '-')} | "
                f"{item.get('quality_label', '-')} | "
                f"{t('yes', '是') if item.get('version_corroborated') else t('no', '否')} | "
                f"{t('yes', '是') if item.get('template_verified') else t('no', '否')} | "
                f"{t('yes', '是') if item.get('sandbox_ready') else t('no', '否')} | "
                f"{item.get('recommended_next_step', '-')} |"
            )
        lines.append("")
    return lines


def _render_remediation_priority_markdown(
    remediation_priority: list[dict[str, Any]] | None,
    *,
    report_lang: str = "en",
) -> list[str]:
    """Render remediation ordering for operator and management review."""
    if not isinstance(remediation_priority, list) or not remediation_priority:
        return []

    zh = normalize_report_lang(report_lang).startswith("zh")

    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text

    lines: list[str] = []
    lines.append(t("## Remediation Priority", "## 修复优先级"))
    lines.append("")
    lines.append("| Priority | Severity | Title | Target | Reason |")
    lines.append("|----------|----------|-------|--------|--------|")
    for item in remediation_priority[:15]:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {item.get('priority', '-')} | {item.get('severity', '-')} | "
            f"{item.get('title', '-')} | {item.get('target', '-')} | {item.get('reason', '-')} |"
        )
    lines.append("")
    return lines


def _render_history_markdown(history: list[dict[str, Any]], *, report_lang: str = "en") -> list[str]:
    """Render action history with execution-level details."""
    zh = normalize_report_lang(report_lang).startswith("zh")
    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text
    lines: list[str] = []
    if not history:
        return lines
    lines.append(t("## Execution Timeline", "## 执行时间线"))
    lines.append("")
    lines.append("| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |")
    lines.append("|---|------|--------|--------|-----:|--------------:|-------------:|-------|")
    for index, item in enumerate(history, start=1):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {index} | {item.get('tool', '-')} | {item.get('target', '-')} | {item.get('status', '-')} "
            f"| {item.get('action_cost', 0)} | {item.get('budget_before', '-')} | {item.get('budget_after', '-')} "
            f"| {str(item.get('error', '')).strip() or '-'} |"
        )
    lines.append("")
    explained_items = [
        item
        for item in history
        if isinstance(item, dict) and isinstance(item.get("ranking_explanation"), dict) and item.get("ranking_explanation")
    ]
    if explained_items:
        lines.append(t("### Why These Actions Were Selected", "### 这些动作为何被选中"))
        lines.append("")
        for index, item in enumerate(explained_items, start=1):
            explanation = item.get("ranking_explanation", {})
            if not isinstance(explanation, dict):
                explanation = {}
            lines.append(
                f"#### {index}. `{item.get('tool', '-')}` -> `{item.get('target', '-')}`"
            )
            lines.append("")
            lines.append(
                f"- {t('Selected Candidate', '选中候选')}: "
                f"`{str(explanation.get('selected_candidate', '')).strip() or '-'}'"
            )
            lines[-1] = lines[-1].replace("`-'", "`-`")
            if explanation.get("component"):
                lines.append(f"- {t('Component', '组件')}: `{explanation.get('component')}`")
            if explanation.get("service"):
                lines.append(f"- {t('Service', '服务')}: `{explanation.get('service')}`")
            if explanation.get("version"):
                lines.append(f"- {t('Version', '版本')}: `{explanation.get('version')}`")
            candidate_order = explanation.get("candidate_order", [])
            if isinstance(candidate_order, list) and candidate_order:
                lines.append(
                    f"- {t('Candidate Order', '候选顺序')}: "
                    f"`{', '.join(str(value) for value in candidate_order if str(value).strip())}`"
                )
            selected_templates = explanation.get("selected_templates", [])
            if isinstance(selected_templates, list) and selected_templates:
                lines.append(f"- {t('Selected Templates', '选中模板')}:")
                for template in selected_templates[:8]:
                    lines.append(f"  - `{template}`")
            reasons = explanation.get("reasons", [])
            if isinstance(reasons, list) and reasons:
                lines.append(f"- {t('Selection Reasons', '选择原因')}:")
                for reason in reasons[:8]:
                    lines.append(f"  - {reason}")
            lines.append("")
    return lines


def _render_history_markdown_detailed(history: list[dict[str, Any]], *, report_lang: str = "en") -> list[str]:
    """Render action history plus ranking explanation details for report exports."""
    zh = normalize_report_lang(report_lang).startswith("zh")

    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text

    lines: list[str] = []
    if not history:
        return lines
    lines.append(t("## Execution Timeline", "## 执行时间线"))
    lines.append("")
    lines.append("| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |")
    lines.append("|---|------|--------|--------|-----:|--------------:|-------------:|-------|")
    for index, item in enumerate(history, start=1):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {index} | {item.get('tool', '-')} | {item.get('target', '-')} | {item.get('status', '-')} "
            f"| {item.get('action_cost', 0)} | {item.get('budget_before', '-')} | {item.get('budget_after', '-')} "
            f"| {str(item.get('error', '')).strip() or '-'} |"
        )
    lines.append("")

    explained_items = [
        item
        for item in history
        if isinstance(item, dict) and isinstance(item.get("ranking_explanation"), dict) and item.get("ranking_explanation")
    ]
    if not explained_items:
        return lines

    lines.append(t("### Why These Actions Were Selected", "### 这些动作为何被选中"))
    lines.append("")
    for index, item in enumerate(explained_items, start=1):
        explanation = item.get("ranking_explanation", {})
        if not isinstance(explanation, dict):
            explanation = {}
        lines.append(f"#### {index}. `{item.get('tool', '-')}` -> `{item.get('target', '-')}`")
        lines.append("")
        selected_candidate = str(explanation.get("selected_candidate", "")).strip() or "-"
        lines.append(f"- {t('Selected Candidate', '选中候选')}: `{selected_candidate}`")
        if explanation.get("component"):
            lines.append(f"- {t('Component', '组件')}: `{explanation.get('component')}`")
        if explanation.get("service"):
            lines.append(f"- {t('Service', '服务')}: `{explanation.get('service')}`")
        if explanation.get("version"):
            lines.append(f"- {t('Version', '版本')}: `{explanation.get('version')}`")
        candidate_order = explanation.get("candidate_order", [])
        if isinstance(candidate_order, list) and candidate_order:
            candidate_list = ", ".join(str(value) for value in candidate_order if str(value).strip())
            if candidate_list:
                lines.append(f"- {t('Candidate Order', '候选顺序')}: `{candidate_list}`")
        selected_templates = explanation.get("selected_templates", [])
        if isinstance(selected_templates, list) and selected_templates:
            lines.append(f"- {t('Selected Templates', '选中模板')}:")
            for template in selected_templates[:8]:
                lines.append(f"  - `{template}`")
        reasons = explanation.get("reasons", [])
        if isinstance(reasons, list) and reasons:
            lines.append(f"- {t('Selection Reasons', '选择原因')}:")
            for reason in reasons[:8]:
                lines.append(f"  - {reason}")
        lines.append("")
    return lines


def _render_blocked_actions_markdown(
    blocked_actions: list[dict[str, Any]],
    *,
    report_lang: str = "en",
) -> list[str]:
    """Render blocked action details for operator troubleshooting."""
    zh = normalize_report_lang(report_lang).startswith("zh")
    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text
    lines: list[str] = []
    if not blocked_actions:
        return lines
    lines.append(t("## Blocked Actions", "## 被阻断动作"))
    lines.append("")
    lines.append("| # | Tool | Target | Reason | Preconditions |")
    lines.append("|---|------|--------|--------|---------------|")
    for index, item in enumerate(blocked_actions, start=1):
        if not isinstance(item, dict):
            continue
        action = item.get("action", {})
        if not isinstance(action, dict):
            action = {}
        preconditions = action.get("preconditions", [])
        if not isinstance(preconditions, list):
            preconditions = []
        lines.append(
            f"| {index} | {action.get('tool_name', '-')} | {action.get('target', '-')} "
            f"| {item.get('reason', '-')} | {', '.join(str(p) for p in preconditions) or '-'} |"
        )
    lines.append("")
    return lines


def _normalize_finding(raw: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize a raw finding object into report-friendly fields."""
    finding_type = str(raw.get("type", "vuln")).strip().lower() or "vuln"
    title = str(raw.get("title", "")).strip()
    name = title or str(raw.get("name", f"Unnamed Finding {index}")).strip() or f"Unnamed Finding {index}"
    raw_evidence = raw.get("evidence", "")
    if isinstance(raw_evidence, (dict, list)):
        evidence = json.dumps(raw_evidence, ensure_ascii=False, sort_keys=True)
    else:
        evidence = str(raw_evidence).strip()

    severity_value = (
        str(raw.get("severity") or raw.get("risk") or raw.get("level") or "").strip().lower()
    )
    severity = _normalize_severity(severity_value, name)

    steps_raw = (
        raw.get("reproduction_steps")
        or raw.get("steps")
        or raw.get("reproduce")
        or raw.get("poc_steps")
        or raw.get("verification_steps")
    )
    reproduction_steps = _coerce_steps(steps_raw)

    return {
        "index": index,
        "type": finding_type,
        "name": name,
        "title": title or name,
        "category": str(raw.get("category", "")).strip() or None,
        "severity": severity,
        "evidence": evidence,
        "reproduction_steps": reproduction_steps,
        "related_asset_ids": [
            str(item).strip()
            for item in raw.get("related_asset_ids", [])
            if str(item).strip()
        ]
        if isinstance(raw.get("related_asset_ids", []), list)
        else [],
        "cve_id": str(raw.get("cve_id", "")).strip() or None,
        "cvss_score": _safe_float(raw.get("cvss_score"), default=None),
        "cve_verified": bool(raw.get("cve_verified", False)),
    }


def _coerce_steps(value: Any) -> list[str]:
    """Convert arbitrary step representation into a clean string list."""
    if value is None:
        return []
    if isinstance(value, str):
        cleaned = value.strip()
        return [cleaned] if cleaned else []
    if isinstance(value, list):
        steps: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                steps.append(text)
        return steps
    text = str(value).strip()
    return [text] if text else []


def _normalize_severity(value: str, name: str) -> str:
    """Normalize severity string with keyword fallback from vulnerability name."""
    allowed = {"critical", "high", "medium", "low", "info"}
    if value in allowed:
        return value

    lowered_name = name.lower()
    if any(token in lowered_name for token in ("rce", "remote code execution", "critical")):
        return "critical"
    if any(token in lowered_name for token in ("sql injection", "sqli", "command injection", "xss")):
        return "high"
    if any(token in lowered_name for token in ("csrf", "ssrf", "path traversal", "idor")):
        return "medium"
    if any(token in lowered_name for token in ("information disclosure", "info leak", "misconfig")):
        return "low"
    return "medium"


def generate_agent_json_report(
    *,
    findings: list[dict[str, Any]],
    state: dict[str, Any],
    output_path: Path,
    decision_summary: str | None = None,
    report_lang: str | None = None,
    blocked_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Generate an agent-oriented JSON report from agent runtime state + findings.

    The payload is intentionally UI-friendly for downstream HTML rendering.
    """
    normalized_findings = [
        {
            **_normalize_finding(item, index),
            "recommendation": _extract_recommendation(item),
            "raw": item,
        }
        for index, item in enumerate(findings, start=1)
    ]
    vulnerabilities = [item for item in normalized_findings if item["type"] == "vuln"]

    severity_order = ("critical", "high", "medium", "low", "info")
    severity_counts: dict[str, int] = {level: 0 for level in severity_order}
    for item in vulnerabilities:
        severity_counts[item["severity"]] += 1

    history = state.get("history", [])
    history_items = history if isinstance(history, list) else []
    blocked_items = blocked_actions if isinstance(blocked_actions, list) else []
    effective_lang = state.get("report_lang") if report_lang is None else report_lang
    normalized_lang = normalize_report_lang(effective_lang)
    budget_trace, inferred_start_budget = _build_budget_trace(history_items, state)
    audit_score = _compute_audit_score(severity_counts)
    coverage = _build_coverage_summary(history_items, state)
    recon = _build_recon_summary(state)
    infrastructure = _build_infrastructure_summary(recon=recon, state=state)
    risk_matrix = _build_risk_matrix(normalized_findings=normalized_findings, audit_score=audit_score)
    attack_surface = _build_attack_surface(recon=recon, state=state)
    evidence_graph = state.get("evidence_graph", {}) if isinstance(state.get("evidence_graph", {}), dict) else {}
    cve_validation = state.get("cve_validation", {}) if isinstance(state.get("cve_validation", {}), dict) else {}
    knowledge_context = (
        state.get("surface", {}).get("knowledge_context", {})
        if isinstance(state.get("surface", {}), dict)
        and isinstance(state.get("surface", {}).get("knowledge_context", {}), dict)
        else {}
    )
    path_graph = evidence_graph.get("path_graph", {}) if isinstance(evidence_graph.get("path_graph", {}), dict) else {}
    remediation_priority = (
        evidence_graph.get("remediation_priority", [])
        if isinstance(evidence_graph.get("remediation_priority", []), list)
        else []
    )
    failed_actions = [
        _compact_history_record(item, index)
        for index, item in enumerate(history_items, start=1)
        if isinstance(item, dict) and str(item.get("status", "")).strip().lower() in {"failed", "error"}
    ]

    payload: dict[str, Any] = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": str(state.get("target", "")).strip(),
            "decision_summary": str(decision_summary or "").strip(),
            "report_lang": normalized_lang,
            "resumed": bool(state.get("resumed", False)),
            "resumed_from": str(state.get("resumed_from", "")).strip() or None,
            "current_phase": str(state.get("current_phase", "")).strip() or None,
            "session_status": str(state.get("session_status", "completed")).strip() or "completed",
        },
        "summary": {
            "audit_score": audit_score,
            "score_label": _score_label(audit_score),
            "total_findings": len(normalized_findings),
            "vulnerability_findings": len(vulnerabilities),
            "severity_counts": severity_counts,
            "history_count": len(history_items),
            "iteration_count": int(state.get("iteration_count", 0) or 0),
            "budget_remaining": _safe_int(state.get("budget_remaining", 0), default=0),
            "budget_start_inferred": inferred_start_budget,
            "unique_tools_executed": coverage["unique_tools_executed"],
            "service_origins_observed": coverage["service_origins_observed"],
            "api_endpoint_count": coverage["api_endpoint_count"],
            "blocked_actions_count": len(blocked_items),
            "failed_actions_count": len(failed_actions),
            "safety_grade": str(state.get("safety_grade", "balanced")),
            "pending_approval": bool(state.get("pending_approval")),
            "corroborated_claims": int(evidence_graph.get("summary", {}).get("corroborated_claims", 0) or 0)
            if isinstance(evidence_graph.get("summary", {}), dict)
            else 0,
            "priority_targets_count": int(evidence_graph.get("summary", {}).get("priority_target_count", 0) or 0)
            if isinstance(evidence_graph.get("summary", {}), dict)
            else 0,
            "cve_candidates": int(cve_validation.get("summary", {}).get("candidate_count", 0) or 0)
            if isinstance(cve_validation.get("summary", {}), dict)
            else 0,
            "sandbox_ready_cves": int(cve_validation.get("summary", {}).get("sandbox_ready_count", 0) or 0)
            if isinstance(cve_validation.get("summary", {}), dict)
            else 0,
        },
        "history": [_compact_history_record(item, index) for index, item in enumerate(history_items, start=1)],
        "budget_trace": budget_trace,
        "coverage": coverage,
        "recon": recon,
        "infrastructure": infrastructure,
        "risk_matrix": risk_matrix,
        "attack_surface": attack_surface,
        "execution": {
            "blocked_actions": blocked_items,
            "failed_actions": failed_actions,
            "current_phase": str(state.get("current_phase", "")).strip() or None,
            "phase_history": [
                item
                for item in state.get("phase_history", [])
                if isinstance(item, dict)
            ] if isinstance(state.get("phase_history", []), list) else [],
            "runtime": {
                "safety_grade": str(state.get("safety_grade", "balanced")),
                "iteration_count": int(state.get("iteration_count", 0) or 0),
                "total_budget": _safe_int(state.get("total_budget", inferred_start_budget or 0), default=0),
                "budget_remaining": _safe_int(state.get("budget_remaining", 0), default=0),
                "resumed": bool(state.get("resumed", False)),
                "resumed_from": str(state.get("resumed_from", "")).strip() or None,
                "session_status": str(state.get("session_status", "completed")).strip() or "completed",
                "pending_approval": state.get("pending_approval", {}) if isinstance(state.get("pending_approval", {}), dict) else {},
                "loop_guard": state.get("loop_guard", {}) if isinstance(state.get("loop_guard", {}), dict) else {},
                "feedback": state.get("feedback", {}) if isinstance(state.get("feedback", {}), dict) else {},
                "circuit_breaker": state.get("circuit_breaker", {}) if isinstance(state.get("circuit_breaker", {}), dict) else {},
            },
        },
        "scope": {
            "scope": state.get("scope", []) if isinstance(state.get("scope", []), list) else [],
            "breadcrumbs": (
                state.get("breadcrumbs", [])
                if isinstance(state.get("breadcrumbs", []), list)
                else []
            ),
            "assets": state.get("assets", []) if isinstance(state.get("assets", []), list) else [],
            "surface": state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {},
        },
        "findings": [
            {
                "index": item["index"],
                "type": item["type"],
                "name": item["name"],
                "category": item.get("category"),
                "severity": item["severity"],
                "evidence": item["evidence"],
                "reproduction_steps": item["reproduction_steps"],
                "related_asset_ids": item["related_asset_ids"],
                "recommendation": item.get("recommendation"),
                "cve_id": item.get("cve_id"),
                "cvss_score": item.get("cvss_score"),
                "cve_verified": bool(item.get("cve_verified", False)),
            }
            for item in normalized_findings
        ],
        "thought_stream": (
            state.get("thought_stream", [])
            if isinstance(state.get("thought_stream", []), list)
            else []
        ),
        "evidence_graph": evidence_graph,
        "cve_validation": cve_validation,
        "remediation_priority": remediation_priority,
        "path_graph": path_graph,
        "knowledge_context": knowledge_context,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def generate_agent_visual_html_report(
    *,
    audit_report_json_path: Path,
    agent_state_json_path: Path,
    output_html_path: Path,
) -> str:
    """
    Generate a single-file static HTML report.

    The generated page has no frontend framework dependency and can be opened directly.
    """
    audit_payload = _read_json_object(audit_report_json_path)
    state_payload = _read_json_object(agent_state_json_path)
    audit_payload = {
        **audit_payload,
        "visual_analysis": build_visual_analysis_payload(
            audit_payload=audit_payload,
            state_payload=state_payload,
            audit_report_json_path=audit_report_json_path,
        ),
    }
    html_content = _build_agent_visual_html(audit_payload, state_payload)
    output_html_path.parent.mkdir(parents=True, exist_ok=True)
    output_html_path.write_text(html_content, encoding="utf-8")
    return html_content


def _read_json_object(path: Path) -> dict[str, Any]:
    """Read a JSON file and return an object payload, falling back to empty dict."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_recommendation(raw: dict[str, Any]) -> str | None:
    """Extract remediation recommendation from raw finding payload."""
    direct = raw.get("recommendation") or raw.get("remediation")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    model = raw.get("model")
    if isinstance(model, dict):
        nested = model.get("recommendation") or model.get("remediation")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return _default_recommendation_for_name(str(raw.get("title") or raw.get("name") or ""))


def _default_recommendation_for_name(name: str) -> str | None:
    """Provide lightweight fallback recommendations for common finding types."""
    lowered = name.lower()
    if "sql" in lowered:
        return "Use parameterized queries / ORM parameter binding and centralized input validation."
    if "xss" in lowered:
        return "Apply context-aware output encoding and CSP; avoid unsafe DOM sinks."
    if ".env" in lowered or "config" in lowered or ".git" in lowered:
        return "Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files."
    if "nuclei" in lowered or "cve" in lowered:
        return "Validate affected version and apply vendor patches / mitigations according to asset ownership."
    return "Review evidence, confirm impact, and apply least-privilege plus secure configuration controls."


def _compute_audit_score(severity_counts: dict[str, int]) -> int:
    """Compute a simple risk-weighted audit score (0-100, higher is better)."""
    penalties = (
        severity_counts.get("critical", 0) * 25
        + severity_counts.get("high", 0) * 15
        + severity_counts.get("medium", 0) * 8
        + severity_counts.get("low", 0) * 3
        + severity_counts.get("info", 0) * 1
    )
    return max(0, min(100, 100 - penalties))


def _score_label(score: int) -> str:
    """Map numeric score into a label for quick visual interpretation."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Needs Attention"
    if score >= 40:
        return "High Risk"
    return "Critical Risk"


def _safe_int(value: Any, default: int = 0) -> int:
    """Coerce any value to int with fallback."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float | None = None) -> float | None:
    """Coerce any value to float with fallback."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _build_coverage_summary(history: list[Any], state: dict[str, Any]) -> dict[str, Any]:
    """Summarize execution coverage and discovered surface for richer reports."""
    tool_stats: dict[str, dict[str, int]] = {}
    for raw in history:
        if not isinstance(raw, dict):
            continue
        tool_name = str(raw.get("tool", "")).strip() or "unknown"
        status = str(raw.get("status", "unknown")).strip().lower() or "unknown"
        bucket = tool_stats.setdefault(
            tool_name,
            {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "error": 0,
            },
        )
        bucket["total"] += 1
        if status in bucket:
            bucket[status] += 1

    ordered_tool_stats = [
        {"tool": tool_name, **counts}
        for tool_name, counts in sorted(
            tool_stats.items(),
            key=lambda item: (-item[1]["completed"], -item[1]["total"], item[0]),
        )
    ]

    breadcrumbs = state.get("breadcrumbs", [])
    service_origins: set[str] = set()
    if isinstance(breadcrumbs, list):
        for item in breadcrumbs:
            if not isinstance(item, dict):
                continue
            if str(item.get("type", "")).strip().lower() != "service":
                continue
            value = str(item.get("data", "")).strip()
            if value.startswith(("http://", "https://")):
                service_origins.add(value)

    surface = state.get("surface", {})
    api_endpoint_count = 0
    discovered_url_count = 0
    parameter_count = 0
    tech_stack: list[str] = []
    config_exposure_count = 0
    if isinstance(surface, dict):
        raw_api_endpoints = surface.get("api_endpoints", [])
        raw_discovered_urls = surface.get("discovered_urls", [])
        raw_url_parameters = surface.get("url_parameters", {})
        raw_tech_stack = surface.get("tech_stack", [])
        raw_config_exposures = surface.get("config_exposures", [])

        if isinstance(raw_api_endpoints, list):
            api_endpoint_count = len(raw_api_endpoints)
        if isinstance(raw_discovered_urls, list):
            discovered_url_count = len(raw_discovered_urls)
        if isinstance(raw_url_parameters, dict):
            parameter_count = len(raw_url_parameters)
        if isinstance(raw_tech_stack, list):
            tech_stack = sorted({str(item).strip() for item in raw_tech_stack if str(item).strip()})
        if isinstance(raw_config_exposures, list):
            config_exposure_count = len(raw_config_exposures)

    status_totals = {
        "completed_actions": sum(item["completed"] for item in tool_stats.values()),
        "failed_actions": sum(item["failed"] for item in tool_stats.values()),
        "error_actions": sum(item["error"] for item in tool_stats.values()),
    }

    highlights: list[str] = []
    if service_origins:
        highlights.append(f"Observed {len(service_origins)} HTTP(S) service origin(s).")
    if api_endpoint_count:
        highlights.append(f"Discovered {api_endpoint_count} API endpoint candidate(s).")
    if parameter_count:
        highlights.append(f"Captured {parameter_count} parameter name(s) for follow-up input audits.")
    if tech_stack:
        highlights.append(f"Detected technology hints: {', '.join(tech_stack[:6])}.")
    if config_exposure_count:
        highlights.append(f"Found {config_exposure_count} configuration exposure candidate(s).")
    if not highlights:
        highlights.append("Coverage remained shallow; few concrete HTTP artifacts were discovered.")

    return {
        "tool_stats": ordered_tool_stats,
        "unique_tools_executed": len(tool_stats),
        "service_origins_observed": len(service_origins),
        "service_origins": sorted(service_origins),
        "api_endpoint_count": api_endpoint_count,
        "discovered_url_count": discovered_url_count,
        "parameter_count": parameter_count,
        "tech_stack": tech_stack,
        "config_exposure_count": config_exposure_count,
        **status_totals,
        "highlights": highlights,
    }


# ---------------------------------------------------------------------------
# Recon summary builder
# ---------------------------------------------------------------------------

def _build_recon_summary(state: dict[str, Any]) -> dict[str, Any]:
    """Build a structured reconnaissance summary from agent state.

    Extracts information-gathering data from ``state["surface"]``,
    ``state["breadcrumbs"]``, ``state["scope"]``, and ``state["history"]``
    without performing any additional network requests.
    """
    surface: dict[str, Any] = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
    breadcrumbs = state.get("breadcrumbs", []) if isinstance(state.get("breadcrumbs", []), list) else []
    scope = state.get("scope", []) if isinstance(state.get("scope", []), list) else []
    history = state.get("history", []) if isinstance(state.get("history", []), list) else []
    raw_assets = state.get("assets", []) if isinstance(state.get("assets", []), list) else []

    # -- Target info --
    service_origins: list[str] = sorted({
        str(item.get("data", "")).strip()
        for item in breadcrumbs
        if isinstance(item, dict) and str(item.get("type", "")).strip().lower() == "service"
        and str(item.get("data", "")).strip().startswith(("http://", "https://"))
    })

    target_info: dict[str, Any] = {
        "target": str(state.get("target", "")).strip(),
        "scope": list(scope),
        "service_origins": service_origins,
    }

    # -- Subdomains --
    raw_subdomains = surface.get("discovered_subdomains", [])
    subdomains: list[str] = sorted({str(s).strip() for s in raw_subdomains if str(s).strip()}) if isinstance(raw_subdomains, list) else []

    # -- DNS records --
    dns_records = surface.get("dns_records", {}) if isinstance(surface.get("dns_records", {}), dict) else {}

    # -- Ports & services --
    raw_ports = surface.get("ports", [])
    ports: list[Any] = list(raw_ports) if isinstance(raw_ports, list) else []
    raw_services = surface.get("services", [])
    services: list[Any] = list(raw_services) if isinstance(raw_services, list) else []
    asset_inventory: list[dict[str, Any]] = []
    service_assets: list[dict[str, Any]] = []
    for asset in raw_assets:
        if not isinstance(asset, dict):
            continue
        attributes = asset.get("attributes", {})
        if not isinstance(attributes, dict):
            attributes = {}
        inventory_row = {
            "id": str(asset.get("id", "")).strip(),
            "kind": str(asset.get("kind", "")).strip().lower() or "asset",
            "source_tool": str(asset.get("source_tool", "")).strip() or None,
            "attributes": attributes,
        }
        asset_inventory.append(inventory_row)
        if inventory_row["kind"] == "service":
            service_assets.append(inventory_row)
    if not ports and service_assets:
        ports = [
            {
                "port": attributes.get("port", "-"),
                "protocol": attributes.get("proto", "-"),
                "state": "open",
                "service": attributes.get("service", "-"),
            }
            for attributes in [item.get("attributes", {}) for item in service_assets]
            if isinstance(attributes, dict)
        ]
    if not services and service_assets:
        services = [
            {
                "host": attributes.get("host"),
                "port": attributes.get("port"),
                "service": attributes.get("service"),
                "tls": attributes.get("tls"),
                "auth_required": attributes.get("auth_required"),
            }
            for attributes in [item.get("attributes", {}) for item in service_assets]
            if isinstance(attributes, dict)
        ]

    # -- TLS / SSL Certificate --
    tls_metadata = surface.get("tls_metadata", {}) if isinstance(surface.get("tls_metadata", {}), dict) else {}

    # -- HTTP Security Headers --
    http_headers = surface.get("http_security_headers", {}) if isinstance(surface.get("http_security_headers", {}), dict) else {}

    # -- Tech stack --
    raw_tech = surface.get("tech_stack", [])
    tech_stack: list[str] = sorted({str(t).strip() for t in raw_tech if str(t).strip()}) if isinstance(raw_tech, list) else []

    # -- WAF / CDN --
    raw_waf = surface.get("waf_vendors", [])
    waf_vendors: list[str] = sorted({str(w).strip() for w in raw_waf if str(w).strip()}) if isinstance(raw_waf, list) else []

    # -- Security policies --
    security_txt = surface.get("security_txt", {}) if isinstance(surface.get("security_txt", {}), dict) else {}
    csp_evaluation = surface.get("csp_evaluation", {}) if isinstance(surface.get("csp_evaluation", {}), dict) else {}
    raw_cookies = surface.get("cookies", [])
    cookies: list[Any] = list(raw_cookies) if isinstance(raw_cookies, list) else []

    # -- Login forms --
    raw_login = surface.get("login_forms", [])
    login_forms: list[Any] = list(raw_login) if isinstance(raw_login, list) else []

    # -- API Schemas --
    raw_schemas = surface.get("api_schemas", [])
    api_schemas: list[Any] = list(raw_schemas) if isinstance(raw_schemas, list) else []

    # -- Config exposures --
    raw_exposures = surface.get("config_exposures", [])
    config_exposures: list[Any] = list(raw_exposures) if isinstance(raw_exposures, list) else []

    # -- Git / VCS exposures --
    raw_git = surface.get("git_exposures", [])
    git_exposures: list[Any] = list(raw_git) if isinstance(raw_git, list) else []

    # -- Source maps --
    raw_smaps = surface.get("source_maps", [])
    source_maps: list[str] = sorted({str(s).strip() for s in raw_smaps if str(s).strip()}) if isinstance(raw_smaps, list) else []

    # -- Discovered URLs --
    raw_urls = surface.get("discovered_urls", [])
    discovered_urls: list[str] = sorted({str(u).strip() for u in raw_urls if str(u).strip()}) if isinstance(raw_urls, list) else []

    # -- API endpoints --
    raw_api = surface.get("api_endpoints", [])
    api_endpoints: list[Any] = list(raw_api) if isinstance(raw_api, list) else []

    # -- URL parameters --
    raw_params = surface.get("url_parameters", {})
    url_parameters: dict[str, Any] = dict(raw_params) if isinstance(raw_params, dict) else {}

    # -- Error page markers --
    raw_markers = surface.get("error_page_markers", [])
    error_page_markers: list[str] = list(raw_markers) if isinstance(raw_markers, list) else []

    # -- Tool execution timeline --
    tools_executed: list[dict[str, Any]] = []
    for rec in history:
        if not isinstance(rec, dict):
            continue
        tools_executed.append({
            "tool": str(rec.get("tool", "")).strip(),
            "target": str(rec.get("target", "")).strip(),
            "status": str(rec.get("status", "")).strip(),
            "duration_ms": rec.get("duration_ms"),
        })

    return {
        "target_info": target_info,
        "subdomains": subdomains,
        "dns_records": dns_records,
        "ports_services": {"ports": ports, "services": services},
        "asset_inventory": asset_inventory,
        "tls_certificate": tls_metadata,
        "http_headers": http_headers,
        "tech_stack": tech_stack,
        "waf_cdn": waf_vendors,
        "security_policies": {
            "security_txt": security_txt,
            "csp_evaluation": csp_evaluation,
            "cookies": cookies,
        },
        "login_forms": login_forms,
        "api_schemas": api_schemas,
        "config_exposures": config_exposures,
        "git_exposures": git_exposures,
        "source_maps": source_maps,
        "discovered_urls": discovered_urls,
        "api_endpoints": api_endpoints,
        "url_parameters": url_parameters,
        "error_page_markers": error_page_markers,
        "tools_executed": tools_executed,
    }


# ---------------------------------------------------------------------------
# Infrastructure / risk / attack-surface summaries
# ---------------------------------------------------------------------------

def _build_infrastructure_summary(*, recon: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Derive infrastructure-oriented report fields from recon state."""
    ports_services = recon.get("ports_services", {}) if isinstance(recon, dict) else {}
    ports = ports_services.get("ports", []) if isinstance(ports_services, dict) else []
    services = ports_services.get("services", []) if isinstance(ports_services, dict) else []
    target_info = recon.get("target_info", {}) if isinstance(recon, dict) else {}
    headers = recon.get("http_headers", {}) if isinstance(recon, dict) else {}
    tech_stack = recon.get("tech_stack", []) if isinstance(recon, dict) else []
    waf_vendors = recon.get("waf_cdn", []) if isinstance(recon, dict) else []
    tls_certificate = recon.get("tls_certificate", {}) if isinstance(recon, dict) else {}
    dns_records = recon.get("dns_records", {}) if isinstance(recon, dict) else {}

    normalized_ports = _normalize_infrastructure_ports(
        ports=ports if isinstance(ports, list) else [],
        services=services if isinstance(services, list) else [],
        target=str(target_info.get("target", "")).strip(),
    )
    middleware = _infer_middleware(
        headers=headers if isinstance(headers, dict) else {},
        tech_stack=tech_stack if isinstance(tech_stack, list) else [],
        services=services if isinstance(services, list) else [],
    )
    surface = state.get("surface", {}) if isinstance(state.get("surface", {}), dict) else {}
    raw_waf = surface.get("waf", {}) if isinstance(surface.get("waf", {}), dict) else {}
    waf = {
        "detected": bool(waf_vendors) or bool(raw_waf),
        "vendors": sorted({str(item).strip() for item in waf_vendors if str(item).strip()}),
        "confidence": _safe_float(raw_waf.get("confidence"), default=None),
        "signals": raw_waf.get("signals", []) if isinstance(raw_waf.get("signals", []), list) else [],
        "notes": str(raw_waf.get("summary", "")).strip() or None,
    }
    certificates = [tls_certificate] if isinstance(tls_certificate, dict) and tls_certificate else []
    return {
        "ports": normalized_ports,
        "middleware": middleware,
        "waf": waf,
        "tech_stack": sorted({str(item).strip() for item in tech_stack if str(item).strip()}) if isinstance(tech_stack, list) else [],
        "certificates": certificates,
        "dns": {
            "scope": list(target_info.get("scope", [])) if isinstance(target_info.get("scope", []), list) else [],
            "records": dns_records if isinstance(dns_records, dict) else {},
            "subdomains": list(recon.get("subdomains", [])) if isinstance(recon.get("subdomains", []), list) else [],
        },
    }


def _normalize_infrastructure_ports(*, ports: list[Any], services: list[Any], target: str) -> list[dict[str, Any]]:
    default_host = urlparse(target if "://" in target else f"https://{target}").hostname or str(target).strip()
    output: list[dict[str, Any]] = []
    service_rows: dict[tuple[str, str], dict[str, Any]] = {}
    for service in services:
        if not isinstance(service, dict):
            continue
        port = str(service.get("port", "")).strip()
        protocol = str(service.get("protocol") or service.get("proto") or "tcp").strip().lower() or "tcp"
        if not port:
            continue
        service_rows[(port, protocol)] = service
    for entry in ports:
        if not isinstance(entry, dict):
            continue
        port = str(entry.get("port", "")).strip()
        protocol = str(entry.get("protocol") or entry.get("proto") or "tcp").strip().lower() or "tcp"
        service_row = service_rows.get((port, protocol), {})
        output.append(
            {
                "host": str(service_row.get("host") or default_host or "").strip() or None,
                "port": _safe_int(port, default=0) if port else None,
                "protocol": protocol,
                "state": str(entry.get("state", "")).strip() or "open",
                "service": str(entry.get("service") or service_row.get("service") or "").strip() or None,
                "tls": bool(service_row.get("tls", False)),
                "auth_required": bool(service_row.get("auth_required", False)),
            }
        )
    return output


def _infer_middleware(*, headers: dict[str, Any], tech_stack: list[Any], services: list[Any]) -> list[dict[str, Any]]:
    patterns = {
        "nginx": "reverse_proxy",
        "apache": "web_server",
        "iis": "web_server",
        "caddy": "reverse_proxy",
        "traefik": "reverse_proxy",
        "envoy": "gateway",
        "haproxy": "load_balancer",
        "tomcat": "app_server",
        "jetty": "app_server",
        "uvicorn": "app_server",
        "gunicorn": "app_server",
        "grafana": "application",
    }
    signals: list[tuple[str, str]] = []
    for source_name, raw_value in (
        ("server_header", headers.get("server")),
        ("x_powered_by", headers.get("x-powered-by")),
    ):
        text = str(raw_value or "").strip().lower()
        if text:
            signals.append((source_name, text))
    for item in tech_stack:
        text = str(item).strip().lower()
        if text:
            signals.append(("tech_stack", text))
    for item in services:
        if not isinstance(item, dict):
            continue
        text = str(item.get("service", "")).strip().lower()
        if text:
            signals.append(("service_probe", text))

    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source_name, text in signals:
        for token, category in patterns.items():
            if token not in text:
                continue
            key = (token, source_name)
            if key in seen:
                continue
            seen.add(key)
            output.append({"name": token, "category": category, "source": source_name})
    output.sort(key=lambda item: (item["name"], item["source"]))
    return output


def _build_risk_matrix(*, normalized_findings: list[dict[str, Any]], audit_score: int) -> dict[str, Any]:
    """Group findings into higher-level risk categories."""
    categories = {
        name: {
            "name": name,
            "score": 0,
            "finding_count": 0,
            "severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
        }
        for name in ("network", "application", "configuration", "authentication")
    }
    for item in normalized_findings:
        category = _classify_risk_category(item)
        bucket = categories[category]
        severity = str(item.get("severity", "info")).strip().lower() or "info"
        bucket["finding_count"] += 1
        bucket["score"] += _severity_risk_points(severity)
        if severity not in bucket["severity_counts"]:
            severity = "info"
        bucket["severity_counts"][severity] += 1

    ordered = sorted(categories.values(), key=lambda item: (-int(item["score"]), -int(item["finding_count"]), item["name"]))
    return {
        "total_score": max(0, min(100, 100 - audit_score)),
        "categories": ordered,
    }


def _classify_risk_category(item: dict[str, Any]) -> str:
    raw = item.get("raw", {}) if isinstance(item.get("raw", {}), dict) else {}
    category = str(item.get("category") or raw.get("category") or "").strip().lower()
    title = str(item.get("title") or item.get("name") or "").strip().lower()
    evidence = str(item.get("evidence") or raw.get("evidence") or "").strip().lower()
    haystack = "\n".join([category, title, evidence])
    if any(token in haystack for token in ("auth", "jwt", "token", "session", "login", "password", "credential", "cookie")):
        return "authentication"
    if any(token in haystack for token in ("config", "misconfig", ".env", ".git", "secret", "header", "cors", "csp", "security.txt", "exposure")):
        return "configuration"
    if any(token in haystack for token in ("dns", "port", "service", "network", "tls", "ssl", "smtp", "ssh", "redis", "mysql", "postgres", "waf")):
        return "network"
    return "application"


def _severity_risk_points(severity: str) -> int:
    return {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1,
    }.get(str(severity or "info").strip().lower(), 1)


def _build_attack_surface(*, recon: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Summarize exposed entry points, services, and sensitive paths."""
    target_info = recon.get("target_info", {}) if isinstance(recon, dict) else {}
    ports_services = recon.get("ports_services", {}) if isinstance(recon, dict) else {}
    login_forms = recon.get("login_forms", []) if isinstance(recon, dict) else []
    api_endpoints = recon.get("api_endpoints", []) if isinstance(recon, dict) else []
    discovered_urls = recon.get("discovered_urls", []) if isinstance(recon, dict) else []
    config_exposures = recon.get("config_exposures", []) if isinstance(recon, dict) else []
    git_exposures = recon.get("git_exposures", []) if isinstance(recon, dict) else []
    source_maps = recon.get("source_maps", []) if isinstance(recon, dict) else []
    api_schemas = recon.get("api_schemas", []) if isinstance(recon, dict) else []

    entry_points = _dedupe_summary_rows(
        [
            *[
                {"type": "origin", "url": str(origin).strip(), "method": "GET", "source": "service_origin"}
                for origin in target_info.get("service_origins", [])
                if str(origin).strip()
            ],
            *[
                {"type": "login_form", "url": str(form.get("action") or "").strip(), "method": str(form.get("method") or "POST").upper(), "source": "login_form"}
                for form in login_forms
                if isinstance(form, dict) and str(form.get("action") or "").strip()
            ],
            *[
                {"type": "api_endpoint", "url": str(item.get("url") or "").strip(), "method": str(item.get("method") or "GET").upper(), "source": str(item.get("source") or "api").strip() or "api"}
                for item in api_endpoints
                if isinstance(item, dict) and str(item.get("url") or "").strip()
            ],
            *[
                {"type": "discovered_url", "url": str(item).strip(), "method": "GET", "source": "crawler"}
                for item in discovered_urls
                if str(item).strip()
            ],
        ]
    )

    exposed_services = _dedupe_summary_rows(
        [
            {
                "host": str(item.get("host") or "").strip() or None,
                "port": _safe_int(item.get("port"), default=0) if item.get("port") not in (None, "") else None,
                "service": str(item.get("service") or "").strip() or None,
                "protocol": str(item.get("protocol") or item.get("proto") or "tcp").strip().lower() or "tcp",
                "tls": bool(item.get("tls", False)),
                "auth_required": bool(item.get("auth_required", False)),
            }
            for item in ports_services.get("services", [])
            if isinstance(item, dict)
        ]
    )
    if not exposed_services:
        exposed_services = _dedupe_summary_rows(
            [
                {
                    "host": urlparse(str(target_info.get("target") or "")).hostname or None,
                    "port": _safe_int(item.get("port"), default=0) if isinstance(item, dict) and item.get("port") not in (None, "") else None,
                    "service": str(item.get("service") or "").strip() or None,
                    "protocol": str(item.get("protocol") or "tcp").strip().lower() or "tcp",
                    "tls": False,
                    "auth_required": False,
                }
                for item in ports_services.get("ports", [])
                if isinstance(item, dict)
            ]
        )

    sensitive_paths = _dedupe_summary_rows(
        [
            *[
                {"type": "config_exposure", "path": str(item.get("path") or "").strip() or None, "url": str(item.get("url") or "").strip() or None, "source": "config_exposures"}
                for item in config_exposures
                if isinstance(item, dict)
            ],
            *[
                {"type": str(item.get("type") or "git_exposure").strip() or "git_exposure", "path": None, "url": str(item.get("url") or "").strip() or None, "source": "git_exposures"}
                for item in git_exposures
                if isinstance(item, dict)
            ],
            *[
                {"type": "source_map", "path": None, "url": str(item).strip(), "source": "source_maps"}
                for item in source_maps
                if str(item).strip()
            ],
            *[
                {"type": str(item.get("kind") or "api_schema").strip() or "api_schema", "path": None, "url": str(item.get("url") or "").strip() or None, "source": "api_schemas"}
                for item in api_schemas
                if isinstance(item, dict)
            ],
        ]
    )

    return {
        "entry_points": entry_points[:40],
        "exposed_services": exposed_services[:40],
        "sensitive_paths": sensitive_paths[:40],
    }


def _dedupe_summary_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


# ---------------------------------------------------------------------------
# Markdown recon renderer
# ---------------------------------------------------------------------------

def _render_recon_markdown(
    recon: dict[str, Any] | None,
    *,
    report_lang: str = "en",
) -> list[str]:
    """Render reconnaissance data as Markdown sections."""
    if not recon:
        return []
    zh = normalize_report_lang(report_lang).startswith("zh")
    def t(en_text: str, zh_text: str) -> str:
        return zh_text if zh else en_text
    lines: list[str] = []
    lines.append(t("## Reconnaissance & Information Gathering", "## 侦察与信息收集"))
    lines.append("")

    # Target info
    target_info = recon.get("target_info", {})
    if target_info:
        lines.append(t("### Target Overview", "### 目标概览"))
        lines.append("")
        lines.append(f"- **{t('Target', '目标')}**: `{target_info.get('target', 'N/A')}`")
        scope = target_info.get("scope", [])
        if scope:
            lines.append(f"- **{t('Scope', '范围')}**: {', '.join(f'`{s}`' for s in scope)}")
        origins = target_info.get("service_origins", [])
        if origins:
            lines.append(f"- **{t('Service Origins', '服务 Origin')}**: {len(origins)}")
            for origin in origins[:20]:
                lines.append(f"  - `{origin}`")
        lines.append("")

    # Subdomains
    subdomains = recon.get("subdomains", [])
    if subdomains:
        lines.append(t("### Subdomain Enumeration", "### 子域名枚举"))
        lines.append("")
        lines.append(
            t(
                f"Discovered **{len(subdomains)}** subdomain(s) via passive enumeration:",
                f"通过被动枚举发现 **{len(subdomains)}** 个子域名：",
            )
        )
        lines.append("")
        for sub in subdomains[:50]:
            lines.append(f"- `{sub}`")
        if len(subdomains) > 50:
            lines.append(
                t(
                    f"- *... and {len(subdomains) - 50} more*",
                    f"- *... 另外 {len(subdomains) - 50} 个*",
                )
            )
        lines.append("")

    # DNS
    dns = recon.get("dns_records", {})
    if dns:
        lines.append("### DNS Records")
        lines.append("")
        for rtype, records in dns.items():
            if isinstance(records, list) and records:
                lines.append(f"- **{rtype.upper()}**: {', '.join(f'`{r}`' for r in records)}")
            elif isinstance(records, str):
                lines.append(f"- **{rtype.upper()}**: `{records}`")
        lines.append("")

    # Ports & Services
    ps = recon.get("ports_services", {})
    ports = ps.get("ports", []) if isinstance(ps, dict) else []
    services = ps.get("services", []) if isinstance(ps, dict) else []
    if ports or services:
        lines.append(t("### Ports & Services", "### 端口与服务"))
        lines.append("")
        if ports:
            lines.append("| Port | Protocol | State | Service |")
            lines.append("|------|----------|-------|---------|")
            for p in ports[:30]:
                if isinstance(p, dict):
                    lines.append(f"| {p.get('port', '-')} | {p.get('protocol', '-')} | {p.get('state', '-')} | {p.get('service', '-')} |")
                else:
                    lines.append(f"| {p} | - | - | - |")
            if len(ports) > 30:
                lines.append(f"| ... | {len(ports) - 30} more | | |")
        lines.append("")

    asset_inventory = recon.get("asset_inventory", [])
    if isinstance(asset_inventory, list) and asset_inventory:
        lines.append(t("### Asset Inventory", "### 资产清单"))
        lines.append("")
        lines.append("| Kind | Identifier | Source Tool |")
        lines.append("|------|------------|-------------|")
        for item in asset_inventory[:30]:
            if not isinstance(item, dict):
                continue
            attributes = item.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            identifier = (
                f"{attributes.get('host', '-')}:"
                f"{attributes.get('port', '-')}"
                if str(item.get("kind", "")) == "service"
                else item.get("id", "-")
            )
            lines.append(
                f"| {item.get('kind', '-')} | {identifier} | {item.get('source_tool', '-') or '-'} |"
            )
        if len(asset_inventory) > 30:
            lines.append(f"| ... | {len(asset_inventory) - 30} more | |")
        lines.append("")

    # TLS Certificate
    tls = recon.get("tls_certificate", {})
    if tls:
        lines.append("### SSL/TLS Certificate")
        lines.append("")
        lines.append(f"- **Host**: `{tls.get('host', 'N/A')}:{tls.get('port', 443)}`")
        lines.append(f"- **TLS Version**: `{tls.get('tls_version', 'N/A')}`")
        lines.append(f"- **Days Until Expiry**: `{tls.get('days_left', 'N/A')}`")
        lines.append(f"- **Expires At**: `{tls.get('expires_at', 'N/A')}`")
        san = tls.get("subject_alt_name", [])
        if san:
            san_display = []
            for entry in san:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    san_display.append(f"{entry[0]}={entry[1]}")
                else:
                    san_display.append(str(entry))
            lines.append(f"- **SAN**: {', '.join(f'`{s}`' for s in san_display)}")
        lines.append("")

    # HTTP Security Headers
    headers = recon.get("http_headers", {})
    if headers:
        lines.append("### HTTP Security Headers")
        lines.append("")
        lines.append("| Header | Value |")
        lines.append("|--------|-------|")
        for hdr, val in headers.items():
            display_val = str(val)[:120]
            if len(str(val)) > 120:
                display_val += "..."
            lines.append(f"| `{hdr}` | `{display_val}` |")
        lines.append("")

    # Tech Stack
    tech = recon.get("tech_stack", [])
    if tech:
        lines.append("### Technology Stack")
        lines.append("")
        for t in tech:
            lines.append(f"- `{t}`")
        lines.append("")

    # WAF / CDN
    waf = recon.get("waf_cdn", [])
    if waf:
        lines.append("### WAF / CDN Detection")
        lines.append("")
        for w in waf:
            lines.append(f"- `{w}`")
        lines.append("")

    # Security Policies
    policies = recon.get("security_policies", {})
    if isinstance(policies, dict):
        stxt = policies.get("security_txt", {})
        csp = policies.get("csp_evaluation", {})
        cookies = policies.get("cookies", [])

        if stxt:
            lines.append("### security.txt")
            lines.append("")
            lines.append(f"- **Present**: `{stxt.get('present', False)}`")
            if stxt.get("present"):
                lines.append(f"- **Has Contact**: `{stxt.get('has_contact', False)}`")
                lines.append(f"- **Has Expires**: `{stxt.get('has_expires', False)}`")
                preview = stxt.get("content_preview", "")
                if preview:
                    lines.append("")
                    lines.append("```text")
                    lines.append(str(preview)[:500])
                    lines.append("```")
            lines.append("")

        if csp:
            lines.append("### Content Security Policy (CSP)")
            lines.append("")
            lines.append(f"- **Present**: `{csp.get('present', False)}`")
            if csp.get("present"):
                lines.append(f"- **Has script-src**: `{csp.get('has_script_src', False)}`")
                lines.append(f"- **Has default-src**: `{csp.get('has_default_src', False)}`")
                risky = csp.get("risky_tokens", [])
                if risky:
                    lines.append(f"- **Risky Tokens**: {', '.join(f'`{t}`' for t in risky)}")
                policy = csp.get("policy", "")
                if policy:
                    lines.append("")
                    lines.append("```text")
                    lines.append(str(policy)[:500])
                    lines.append("```")
            lines.append("")

        if cookies:
            lines.append("### Cookie Security Audit")
            lines.append("")
            lines.append("| Cookie Name | Secure | HttpOnly | SameSite |")
            lines.append("|-------------|--------|----------|----------|")
            for c in cookies:
                if isinstance(c, dict):
                    lines.append(
                        f"| `{c.get('name', '-')}` "
                        f"| {'✅' if c.get('secure') else '❌'} "
                        f"| {'✅' if c.get('httponly') else '❌'} "
                        f"| {'✅' if c.get('samesite') else '❌'} |"
                    )
            lines.append("")

    # Login Forms
    login = recon.get("login_forms", [])
    if login:
        lines.append("### Login Form Detection")
        lines.append("")
        for form in login:
            if isinstance(form, dict):
                lines.append(f"- **Action**: `{form.get('action', '-')}` ({form.get('method', 'GET')})")
                params = form.get("params", {})
                if params:
                    lines.append(f"  - Parameters: {', '.join(f'`{k}`' for k in params.keys())}")
        lines.append("")

    # API Schemas
    schemas = recon.get("api_schemas", [])
    if schemas:
        lines.append("### API Schema Discovery")
        lines.append("")
        for s in schemas:
            if isinstance(s, dict):
                lines.append(f"- `{s.get('url', '-')}` ({s.get('kind', '-')}) — HTTP {s.get('status_code', '-')}")
        lines.append("")

    # Git / VCS Exposures
    git = recon.get("git_exposures", [])
    if git:
        lines.append("### VCS Exposure Detection")
        lines.append("")
        for g in git:
            if isinstance(g, dict):
                lines.append(f"- `{g.get('url', '-')}` ({g.get('type', '-')}) — HTTP {g.get('status_code', '-')}")
        lines.append("")

    # Source Maps
    smaps = recon.get("source_maps", [])
    if smaps:
        lines.append("### Source Map Detection")
        lines.append("")
        for s in smaps:
            lines.append(f"- `{s}`")
        lines.append("")

    # Config Exposures
    configs = recon.get("config_exposures", [])
    if configs:
        lines.append("### Configuration Exposure")
        lines.append("")
        for c in configs:
            if isinstance(c, dict):
                lines.append(f"- `{c.get('url', c.get('path', '-'))}` — HTTP {c.get('status_code', '-')}")
            else:
                lines.append(f"- `{c}`")
        lines.append("")

    # Discovered URLs summary
    urls = recon.get("discovered_urls", [])
    if urls:
        lines.append("### Crawled URLs")
        lines.append("")
        lines.append(f"Total discovered URLs: **{len(urls)}**")
        lines.append("")
        for u in urls[:30]:
            lines.append(f"- `{u}`")
        if len(urls) > 30:
            lines.append(f"- *... and {len(urls) - 30} more*")
        lines.append("")

    # API Endpoints
    endpoints = recon.get("api_endpoints", [])
    if endpoints:
        lines.append("### API Endpoints")
        lines.append("")
        lines.append(f"Total API endpoints: **{len(endpoints)}**")
        lines.append("")
        lines.append("| URL | Method | Source |")
        lines.append("|-----|--------|--------|")
        for ep in endpoints[:30]:
            if isinstance(ep, dict):
                lines.append(f"| `{ep.get('url', '-')}` | {ep.get('method', '-')} | {ep.get('source', '-')} |")
        if len(endpoints) > 30:
            lines.append(f"| ... | {len(endpoints) - 30} more | |")
        lines.append("")

    # URL Parameters
    params = recon.get("url_parameters", {})
    if params:
        lines.append("### URL Parameters")
        lines.append("")
        for pname, pvals in params.items():
            if isinstance(pvals, list):
                lines.append(f"- `{pname}`: {', '.join(f'`{v}`' for v in pvals[:5])}")
            else:
                lines.append(f"- `{pname}`: `{pvals}`")
        lines.append("")

    # Error Page Markers
    markers = recon.get("error_page_markers", [])
    if markers:
        lines.append("### Error Page Analysis")
        lines.append("")
        lines.append(f"Debug markers detected: {', '.join(f'`{m}`' for m in markers)}")
        lines.append("")

    # If we emitted only the title with no data, remove it
    if len(lines) == 2:
        return []

    return lines


def _compact_history_record(raw: Any, index: int) -> dict[str, Any]:
    """Normalize a history record for UI consumption."""
    if not isinstance(raw, dict):
        return {
            "index": index,
            "tool": "",
            "target": "",
            "status": "unknown",
        }
    return {
        "index": index,
        "tool": str(raw.get("tool", "")).strip(),
        "target": str(raw.get("target", "")).strip(),
        "phase": str(raw.get("phase", "")).strip() or None,
        "status": str(raw.get("status", "unknown")).strip(),
        "started_at": str(raw.get("started_at", "")).strip(),
        "ended_at": str(raw.get("ended_at", "")).strip(),
        "action_cost": _safe_int(raw.get("action_cost"), default=0),
        "budget_before": _safe_int(raw.get("budget_before"), default=0)
        if raw.get("budget_before") is not None
        else None,
        "budget_after": _safe_int(raw.get("budget_after"), default=0)
        if raw.get("budget_after") is not None
        else None,
        "error": str(raw.get("error", "")).strip() or None,
        "metadata_summary": (
            raw.get("metadata_summary")
            if isinstance(raw.get("metadata_summary"), dict)
            else {}
        ),
        "ranking_explanation": (
            raw.get("ranking_explanation")
            if isinstance(raw.get("ranking_explanation"), dict)
            else {}
        ),
    }


def _build_budget_trace(
    history: list[Any],
    state: dict[str, Any],
) -> tuple[list[dict[str, Any]], int | None]:
    """
    Build budget consumption trace for visualization.

    Prefers explicit `budget_before`/`budget_after` recorded in history; falls back to
    inferred values from `budget_remaining + sum(action_cost)`.
    """
    current_remaining = _safe_int(state.get("budget_remaining", 0), default=0)
    costs = [
        _safe_int(item.get("action_cost"), default=0)
        for item in history
        if isinstance(item, dict)
    ]
    inferred_start = current_remaining + sum(costs) if costs else None

    trace: list[dict[str, Any]] = []
    running_spent = 0
    running_budget = inferred_start
    if inferred_start is not None:
        trace.append(
            {
                "step": 0,
                "label": "Start",
                "tool": "",
                "cost": 0,
                "budget_before": inferred_start,
                "budget_after": inferred_start,
                "cumulative_spent": 0,
            }
        )

    for index, item in enumerate(history, start=1):
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("tool", "")).strip()
        cost = _safe_int(item.get("action_cost"), default=0)
        budget_before_raw = _safe_float(item.get("budget_before"))
        budget_after_raw = _safe_float(item.get("budget_after"))

        if budget_before_raw is None and running_budget is not None:
            budget_before = running_budget
        else:
            budget_before = int(budget_before_raw) if budget_before_raw is not None else None

        if budget_after_raw is None:
            if budget_before is not None:
                budget_after = budget_before - cost
            else:
                budget_after = None
        else:
            budget_after = int(budget_after_raw)

        running_spent += max(0, cost)
        running_budget = budget_after if budget_after is not None else running_budget

        trace.append(
            {
                "step": index,
                "label": f"{index}. {tool_name}" if tool_name else str(index),
                "tool": tool_name,
                "cost": max(0, cost),
                "budget_before": budget_before,
                "budget_after": budget_after,
                "cumulative_spent": running_spent,
            }
        )

    return trace, inferred_start


def _build_visual_analysis_payload(
    *,
    audit_payload: dict[str, Any],
    state_payload: dict[str, Any],
    audit_report_json_path: Path,
) -> dict[str, Any]:
    return build_visual_analysis_payload(
        audit_payload=audit_payload,
        state_payload=state_payload,
        audit_report_json_path=audit_report_json_path,
    )


def _extract_visual_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_findings = payload.get("findings", []) if isinstance(payload, dict) else []
    output: list[dict[str, Any]] = []
    if not isinstance(raw_findings, list):
        return output
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "severity": _normalize_severity(str(item.get("severity", "")).strip().lower(), str(item.get("name", ""))),
                "related_asset_ids": [
                    str(asset_id).strip()
                    for asset_id in item.get("related_asset_ids", [])
                    if str(asset_id).strip()
                ] if isinstance(item.get("related_asset_ids", []), list) else [],
            }
        )
    return output


def _extract_visual_assets(
    payload: dict[str, Any],
    *,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    scope = payload.get("scope", {}) if isinstance(payload, dict) else {}
    raw_assets = scope.get("assets", []) if isinstance(scope, dict) else []
    if not isinstance(raw_assets, list):
        return []

    finding_count_by_asset: dict[str, int] = {}
    highest_severity_by_asset: dict[str, str] = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = _normalize_severity(str(item.get("severity", "")).strip().lower(), "")
        for asset_id in item.get("related_asset_ids", []):
            key = str(asset_id).strip()
            if not key:
                continue
            finding_count_by_asset[key] = finding_count_by_asset.get(key, 0) + 1
            current = highest_severity_by_asset.get(key, "info")
            if severity_rank.get(severity, 9) < severity_rank.get(current, 9):
                highest_severity_by_asset[key] = severity

    output: list[dict[str, Any]] = []
    for asset in raw_assets:
        if not isinstance(asset, dict):
            continue
        asset_id = str(asset.get("id", "")).strip()
        output.append(
            {
                "id": asset_id,
                "kind": str(asset.get("kind", "")).strip().lower() or "asset",
                "source_tool": str(asset.get("source_tool", "")).strip() or None,
                "attributes": asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {},
                "finding_count": int(finding_count_by_asset.get(asset_id, 0)),
                "highest_severity": highest_severity_by_asset.get(asset_id, "info"),
            }
        )
    return output


def _summarize_visual_assets(assets: list[dict[str, Any]]) -> dict[str, int]:
    total_assets = len(assets)
    service_assets = 0
    linked_findings = 0
    for asset in assets:
        if str(asset.get("kind", "")).strip().lower() == "service":
            service_assets += 1
        linked_findings += int(asset.get("finding_count", 0) or 0)
    return {
        "total_assets": total_assets,
        "service_assets": service_assets,
        "asset_linked_findings": linked_findings,
    }


def _normalize_visual_phase_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    return re.sub(r"[^a-z0-9_]+", "_", text)


def _visual_phase_sort_key(value: str) -> tuple[int, str]:
    order = {
        "passive_recon": 0,
        "active_discovery": 1,
        "deep_testing": 2,
        "verification": 3,
        "reporting": 4,
        "unknown": 98,
    }
    normalized = _normalize_visual_phase_name(value)
    return order.get(normalized, 97), normalized


def _build_visual_asset_phase_trends(
    payload: dict[str, Any],
    *,
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    execution = payload.get("execution", {}) if isinstance(payload, dict) else {}
    history = payload.get("history", []) if isinstance(payload, dict) else []
    phase_history = execution.get("phase_history", []) if isinstance(execution, dict) else []
    current_phase = _normalize_visual_phase_name(
        (execution.get("current_phase") if isinstance(execution, dict) else None)
        or (payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}).get("current_phase")
    )
    rows: dict[str, dict[str, Any]] = {}
    first_phase_by_tool: dict[str, str] = {}
    asset_phase_by_id: dict[str, str] = {}

    def ensure_row(phase_name: str) -> dict[str, Any]:
        normalized = _normalize_visual_phase_name(phase_name)
        if normalized not in rows:
            rows[normalized] = {
                "phase": normalized,
                "executed_actions": 0,
                "unique_tools": 0,
                "tool_names": [],
                "asset_count": 0,
                "service_assets": 0,
                "linked_findings": 0,
                "finding_count": 0,
                "delta_assets": 0,
                "reason": None,
                "is_current": normalized == current_phase,
            }
        return rows[normalized]

    if isinstance(history, list):
        for entry in history:
            if not isinstance(entry, dict):
                continue
            phase_name = _normalize_visual_phase_name(entry.get("phase"))
            row = ensure_row(phase_name)
            row["executed_actions"] += 1
            tool_name = str(entry.get("tool", "")).strip()
            if tool_name:
                if tool_name not in row["tool_names"]:
                    row["tool_names"].append(tool_name)
                first_phase_by_tool.setdefault(tool_name, phase_name)

    if isinstance(phase_history, list):
        for entry in phase_history:
            if not isinstance(entry, dict):
                continue
            phase_name = _normalize_visual_phase_name(entry.get("phase"))
            row = ensure_row(phase_name)
            reason = str(entry.get("reason", "")).strip() or None
            if reason and not row.get("reason"):
                row["reason"] = reason

    for asset in assets:
        source_tool = str(asset.get("source_tool", "")).strip()
        phase_name = first_phase_by_tool.get(source_tool) or current_phase
        row = ensure_row(phase_name)
        row["asset_count"] += 1
        if str(asset.get("kind", "")).strip().lower() == "service":
            row["service_assets"] += 1
        asset_id = str(asset.get("id", "")).strip()
        if asset_id:
            asset_phase_by_id[asset_id] = phase_name

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        related_asset_ids = [
            str(asset_id).strip()
            for asset_id in finding.get("related_asset_ids", [])
            if str(asset_id).strip()
        ]
        matched_phases = {
            asset_phase_by_id[asset_id]
            for asset_id in related_asset_ids
            if asset_id in asset_phase_by_id
        }
        if not matched_phases:
            matched_phases = {current_phase}
        for phase_name in matched_phases:
            row = ensure_row(phase_name)
            row["finding_count"] += 1
            row["linked_findings"] += 1

    ordered_rows = sorted(rows.values(), key=lambda item: _visual_phase_sort_key(item.get("phase", "")))
    previous_assets = 0
    for row in ordered_rows:
        row["unique_tools"] = len(row["tool_names"])
        row["delta_assets"] = int(row["asset_count"] or 0) - previous_assets
        previous_assets = int(row["asset_count"] or 0)
    return ordered_rows


def _build_visual_asset_batch_trends(
    *,
    audit_payload: dict[str, Any],
    state_payload: dict[str, Any],
    audit_report_json_path: Path,
) -> list[dict[str, Any]]:
    current_target = str(
        (audit_payload.get("meta", {}) if isinstance(audit_payload.get("meta", {}), dict) else {}).get("target")
        or state_payload.get("target", "")
    ).strip()
    target_slug = _slugify_report_target(current_target)
    if not target_slug:
        return []

    current_job_dir = audit_report_json_path.parent.parent if audit_report_json_path.parent.name == "agent" else audit_report_json_path.parent
    current_job_id = current_job_dir.name
    root_dir = current_job_dir.parent
    if not root_dir.exists() or not root_dir.is_dir():
        return []

    collected: list[dict[str, Any]] = []
    for candidate_dir in root_dir.iterdir():
        if not candidate_dir.is_dir():
            continue
        payload_path = None
        for candidate in (candidate_dir / "agent" / "audit_report.json", candidate_dir / "audit_report.json"):
            if candidate.is_file():
                payload_path = candidate
                break
        if payload_path is None:
            continue
        payload = audit_payload if candidate_dir == current_job_dir else _read_json_object(payload_path)
        meta = payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}
        candidate_target = str(meta.get("target", "")).strip()
        if _slugify_report_target(candidate_target) != target_slug:
            continue
        findings = _extract_visual_findings(payload)
        assets = _extract_visual_assets(payload, findings=findings)
        summary = _summarize_visual_assets(assets)
        collected.append(
            {
                "job_id": candidate_dir.name,
                "ended_at": str(meta.get("generated_at", "")).strip() or None,
                "updated_at": str(meta.get("generated_at", "")).strip() or None,
                "status": "completed",
                "finding_total": len(findings),
                "total_assets": summary["total_assets"],
                "service_assets": summary["service_assets"],
                "linked_findings": summary["asset_linked_findings"],
                "is_current": candidate_dir.name == current_job_id,
            }
        )

    ordered = sorted(
        collected,
        key=lambda item: (
            str(item.get("ended_at") or item.get("updated_at") or ""),
            str(item.get("job_id") or ""),
        ),
    )
    previous_assets = 0
    previous_findings = 0
    for row in ordered:
        row["delta_assets"] = int(row.get("total_assets", 0) or 0) - previous_assets
        row["delta_findings"] = int(row.get("finding_total", 0) or 0) - previous_findings
        previous_assets = int(row.get("total_assets", 0) or 0)
        previous_findings = int(row.get("finding_total", 0) or 0)
    return ordered


def _visual_finding_fingerprint(item: dict[str, Any]) -> str:
    payload = {
        "name": str(item.get("name") or item.get("title") or "").strip(),
        "severity": str(item.get("severity") or "").strip().lower(),
        "cve_id": str(item.get("cve_id") or "").strip().upper(),
        "evidence": item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {},
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _visual_asset_fingerprint(item: dict[str, Any]) -> str:
    asset_id = str(item.get("id", "")).strip()
    if asset_id:
        return asset_id
    payload = {
        "kind": str(item.get("kind", "")).strip().lower(),
        "attributes": item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {},
        "source_tool": str(item.get("source_tool", "")).strip(),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _visual_service_fingerprint(item: dict[str, Any]) -> str:
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    host = str(attributes.get("host", "")).strip().lower()
    port = str(attributes.get("port", "")).strip()
    service = str(attributes.get("service", "")).strip().lower()
    proto = str(attributes.get("proto", "")).strip().lower()
    if host or port or service:
        return "::".join((host, port, service, proto))
    return _visual_asset_fingerprint(item)


def _display_visual_asset_name(item: dict[str, Any]) -> str:
    kind = str(item.get("kind", "")).strip().lower() or "asset"
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    if kind == "service":
        host = str(attributes.get("host", "")).strip()
        port = str(attributes.get("port", "")).strip()
        service = str(attributes.get("service", "")).strip() or "service"
        if host and port:
            return f"{host}:{port} ({service})"
    if kind == "host":
        host = str(attributes.get("host", "")).strip()
        if host:
            return host
    if kind == "domain":
        domain = str(attributes.get("domain", "")).strip()
        if domain:
            return domain
    if kind == "ip":
        address = str(attributes.get("address", "")).strip()
        if address:
            return address
    if kind == "origin":
        origin = str(attributes.get("origin", "")).strip()
        if origin:
            return origin
    return str(item.get("id", "")).strip() or kind


def _compact_visual_asset_entries(items: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    ordered = sorted(
        (item for item in items if isinstance(item, dict)),
        key=lambda item: (
            0 if str(item.get("kind", "")).strip().lower() == "service" else 1,
            -int(item.get("finding_count", 0) or 0),
            _display_visual_asset_name(item),
        ),
    )
    output: list[dict[str, Any]] = []
    for item in ordered[:limit]:
        attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
        output.append(
            {
                "id": str(item.get("id", "")).strip() or None,
                "kind": str(item.get("kind", "")).strip().lower() or "asset",
                "display_name": _display_visual_asset_name(item),
                "source_tool": str(item.get("source_tool", "")).strip() or None,
                "host": str(attributes.get("host", "")).strip() or None,
                "port": str(attributes.get("port", "")).strip() or None,
                "service": str(attributes.get("service", "")).strip() or None,
                "proto": str(attributes.get("proto", "")).strip() or None,
                "finding_count": int(item.get("finding_count", 0) or 0),
            }
        )
    return output


def _visual_asset_highest_severity(item: dict[str, Any]) -> str:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    value = str(item.get("highest_severity", "")).strip().lower()
    if value in rank:
        return value
    return "info"


def _build_visual_asset_severity_breakdown(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for item in items:
        if not isinstance(item, dict):
            continue
        counts[_visual_asset_highest_severity(item)] += 1
    return counts


def _visual_service_protocol_label(item: dict[str, Any]) -> str:
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    service = str(attributes.get("service", "")).strip().lower()
    proto = str(attributes.get("proto", "")).strip().lower()
    if service and proto:
        return f"{service}/{proto}"
    if service:
        return service
    if proto:
        return proto
    return str(item.get("kind", "")).strip().lower() or "asset"


def _build_visual_protocol_breakdown(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        label = _visual_service_protocol_label(item)
        counts[label] = counts.get(label, 0) + 1
    return [
        {"label": key, "count": value}
        for key, value in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    ]


def _build_visual_batch_diff(
    *,
    audit_payload: dict[str, Any],
    state_payload: dict[str, Any],
    audit_report_json_path: Path,
) -> dict[str, Any]:
    batch_rows = _build_visual_asset_batch_trends(
        audit_payload=audit_payload,
        state_payload=state_payload,
        audit_report_json_path=audit_report_json_path,
    )
    current_row = next((item for item in batch_rows if item.get("is_current")), None)
    if current_row is None:
        return {}
    baseline_row = None
    for item in reversed(batch_rows):
        if item.get("job_id") == current_row.get("job_id"):
            continue
        baseline_row = item
        break
    if baseline_row is None:
        return {
            "baseline_job_id": None,
            "new_count": 0,
            "resolved_count": 0,
            "persistent_count": 0,
            "new_findings": [],
            "resolved_findings": [],
            "new_assets_count": 0,
            "resolved_assets_count": 0,
            "persistent_assets_count": 0,
            "new_assets": [],
            "resolved_assets": [],
            "new_services_count": 0,
            "resolved_services_count": 0,
            "persistent_services_count": 0,
            "new_services": [],
            "resolved_services": [],
            "new_asset_severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
            "resolved_asset_severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
            "persistent_asset_severity_counts": {level: 0 for level in ("critical", "high", "medium", "low", "info")},
            "new_service_protocol_counts": [],
            "resolved_service_protocol_counts": [],
            "persistent_service_protocol_counts": [],
        }

    current_job_dir = audit_report_json_path.parent.parent if audit_report_json_path.parent.name == "agent" else audit_report_json_path.parent
    root_dir = current_job_dir.parent
    baseline_job_dir = root_dir / str(baseline_row.get("job_id") or "")
    baseline_payload_path = baseline_job_dir / "agent" / "audit_report.json"
    if not baseline_payload_path.is_file():
        baseline_payload_path = baseline_job_dir / "audit_report.json"
    baseline_payload = _read_json_object(baseline_payload_path)

    current_findings_raw = [item for item in audit_payload.get("findings", []) if isinstance(item, dict)]
    baseline_findings_raw = [item for item in baseline_payload.get("findings", []) if isinstance(item, dict)]
    current_map = {_visual_finding_fingerprint(item): item for item in current_findings_raw}
    baseline_map = {_visual_finding_fingerprint(item): item for item in baseline_findings_raw}
    current_assets = _extract_visual_assets(audit_payload, findings=_extract_visual_findings(audit_payload))
    baseline_assets = _extract_visual_assets(baseline_payload, findings=_extract_visual_findings(baseline_payload))
    current_asset_map = {_visual_asset_fingerprint(item): item for item in current_assets}
    baseline_asset_map = {_visual_asset_fingerprint(item): item for item in baseline_assets}
    current_service_map = {
        _visual_service_fingerprint(item): item
        for item in current_assets
        if str(item.get("kind", "")).strip().lower() == "service"
    }
    baseline_service_map = {
        _visual_service_fingerprint(item): item
        for item in baseline_assets
        if str(item.get("kind", "")).strip().lower() == "service"
    }

    def _compact_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for item in items[:8]:
            output.append(
                {
                    "name": str(item.get("name") or item.get("title") or "").strip() or "Unnamed finding",
                    "severity": str(item.get("severity") or "info").strip().lower() or "info",
                    "cve_id": str(item.get("cve_id") or "").strip() or None,
                }
            )
        return output

    new_items = [current_map[key] for key in current_map.keys() - baseline_map.keys()]
    resolved_items = [baseline_map[key] for key in baseline_map.keys() - current_map.keys()]
    persistent_items = [current_map[key] for key in current_map.keys() & baseline_map.keys()]
    new_asset_items = [current_asset_map[key] for key in current_asset_map.keys() - baseline_asset_map.keys()]
    resolved_asset_items = [baseline_asset_map[key] for key in baseline_asset_map.keys() - current_asset_map.keys()]
    persistent_asset_items = [current_asset_map[key] for key in current_asset_map.keys() & baseline_asset_map.keys()]
    new_service_items = [current_service_map[key] for key in current_service_map.keys() - baseline_service_map.keys()]
    resolved_service_items = [baseline_service_map[key] for key in baseline_service_map.keys() - current_service_map.keys()]
    persistent_service_items = [current_service_map[key] for key in current_service_map.keys() & baseline_service_map.keys()]
    baseline_meta = baseline_payload.get("meta", {}) if isinstance(baseline_payload.get("meta"), dict) else {}
    return {
        "baseline_job_id": baseline_row.get("job_id"),
        "baseline_generated_at": baseline_meta.get("generated_at"),
        "new_count": len(new_items),
        "resolved_count": len(resolved_items),
        "persistent_count": len(persistent_items),
        "new_findings": _compact_findings(new_items),
        "resolved_findings": _compact_findings(resolved_items),
        "new_assets_count": len(new_asset_items),
        "resolved_assets_count": len(resolved_asset_items),
        "persistent_assets_count": len(persistent_asset_items),
        "new_assets": _compact_visual_asset_entries(new_asset_items),
        "resolved_assets": _compact_visual_asset_entries(resolved_asset_items),
        "new_services_count": len(new_service_items),
        "resolved_services_count": len(resolved_service_items),
        "persistent_services_count": len(persistent_service_items),
        "new_services": _compact_visual_asset_entries(new_service_items),
        "resolved_services": _compact_visual_asset_entries(resolved_service_items),
        "new_asset_severity_counts": _build_visual_asset_severity_breakdown(new_asset_items),
        "resolved_asset_severity_counts": _build_visual_asset_severity_breakdown(resolved_asset_items),
        "persistent_asset_severity_counts": _build_visual_asset_severity_breakdown(persistent_asset_items),
        "new_service_protocol_counts": _build_visual_protocol_breakdown(new_service_items),
        "resolved_service_protocol_counts": _build_visual_protocol_breakdown(resolved_service_items),
        "persistent_service_protocol_counts": _build_visual_protocol_breakdown(persistent_service_items),
    }


def _normalize_visual_target_value(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        if "://" in text:
            parsed = urlparse(text)
            host = (parsed.hostname or "").lower()
            port = str(parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else "")).strip()
            path = (parsed.path or "/").rstrip("/") or "/"
            return f"{parsed.scheme.lower()}://{host}:{port}{path}"
    except ValueError:
        return text.rstrip("/").lower()
    return text.rstrip("/").lower()


def _match_visual_ranked_candidate(
    *,
    cve_id: str,
    rows: list[dict[str, Any]],
    target: str | None,
    component: str | None,
    service: str | None,
    version: str | None,
) -> dict[str, Any]:
    best_row: dict[str, Any] = {}
    best_score = -1
    normalized_target = _normalize_visual_target_value(target)
    for row in rows:
        if str(row.get("cve_id", "")).strip().upper() != cve_id:
            continue
        score = 0
        if normalized_target and _normalize_visual_target_value(row.get("target")) == normalized_target:
            score += 4
        if component and str(row.get("component", "")).strip().lower() == component:
            score += 3
        if service and str(row.get("service", "")).strip().lower() == service:
            score += 2
        if version and str(row.get("version", "")).strip() == version:
            score += 1
        if int(row.get("rank", 0) or 0) > 0:
            score += 1
        if score > best_score:
            best_row = row
            best_score = score
    return best_row


def _build_visual_ranked_candidate_entry(
    *,
    cve_id: str,
    row: dict[str, Any],
    block_tool: str,
    verification_map: dict[str, bool],
    template_index: dict[str, dict[str, Any]],
    selected_candidate: str | None,
) -> dict[str, Any]:
    ranking_context = row.get("ranking_context", {}) if isinstance(row.get("ranking_context"), dict) else {}
    capability = row.get("template_capability", {}) if isinstance(row.get("template_capability"), dict) else {}
    if not capability:
        capability = template_index.get(cve_id, {}) if isinstance(template_index.get(cve_id, {}), dict) else {}

    template_count = int(capability.get("template_count", 0) or 0)
    protocol_tags = capability.get("protocol_tags", [])
    if not isinstance(protocol_tags, list):
        protocol_tags = []
    recommended_tools = ranking_context.get("rag_recommended_tools", [])
    if not isinstance(recommended_tools, list):
        recommended_tools = []
    rag_tags = ranking_context.get("rag_tags", [])
    if not isinstance(rag_tags, list):
        rag_tags = []
    aliases = ranking_context.get("protocol_aliases", [])
    if not isinstance(aliases, list):
        aliases = []

    normalized_tool = str(block_tool or "").strip().lower()
    component = str(ranking_context.get("component", "")).strip()
    service = str(ranking_context.get("service", "")).strip()
    version = str(ranking_context.get("version", "")).strip()
    reasons: list[str] = []
    if component:
        reasons.append(f"Component match: {component}")
    if service:
        reasons.append(f"Service match: {service}")
    if version:
        reasons.append(f"Version hint: {version}")
    if normalized_tool and normalized_tool in {str(item).strip().lower() for item in recommended_tools}:
        reasons.append(f"RAG recommended {normalized_tool}")
    if template_count > 0:
        reasons.append(f"Matched {template_count} template(s)")
    elif bool(row.get("has_nuclei_template", False)):
        reasons.append("Has nuclei template coverage")
    if protocol_tags:
        reasons.append(f"Protocol tags: {', '.join(str(item) for item in protocol_tags[:4])}")
    if aliases:
        reasons.append(f"Protocol aliases: {', '.join(str(item) for item in aliases[:4])}")
    if rag_tags:
        reasons.append(f"RAG tags: {', '.join(str(item) for item in rag_tags[:4])}")

    verified = verification_map.get(cve_id)
    if verified is True:
        reasons.append("Verified during nuclei validation")
    elif verified is False:
        reasons.append("Checked but not positively verified")

    return {
        "cve_id": cve_id,
        "rank": int(row.get("rank", 0) or 0) or None,
        "severity": _normalize_severity(str(row.get("severity", "")).strip().lower(), cve_id),
        "cvss_score": _safe_float(row.get("cvss_score")),
        "has_nuclei_template": bool(row.get("has_nuclei_template", template_count > 0)),
        "template_count": template_count,
        "template_capability": capability,
        "verified": verified,
        "selected": bool(selected_candidate and cve_id == selected_candidate),
        "ranking_context": ranking_context,
        "reasons": reasons,
    }


def _build_visual_verification_ranking(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scope = payload.get("scope", {}) if isinstance(payload, dict) else {}
    surface = scope.get("surface", {}) if isinstance(scope, dict) else {}
    history = payload.get("history", []) if isinstance(payload, dict) else []
    if not isinstance(surface, dict):
        surface = {}
    lookup_results = [item for item in surface.get("cve_lookup_results", []) if isinstance(item, dict)]
    verification_rows = [item for item in surface.get("cve_verification", []) if isinstance(item, dict)]
    template_index = surface.get("template_capability_index", {})
    if not isinstance(template_index, dict):
        template_index = {}

    verification_map = {
        str(item.get("cve_id", "")).strip().upper(): bool(item.get("verified"))
        for item in verification_rows
        if str(item.get("cve_id", "")).strip()
    }

    blocks: list[dict[str, Any]] = []
    grouped_lookup: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for row in lookup_results:
        key = (
            str(row.get("target", "")).strip(),
            str(row.get("component", "")).strip().lower(),
            str(row.get("service", "")).strip().lower(),
            str(row.get("version", "")).strip(),
        )
        grouped_lookup.setdefault(key, []).append(row)

    for key, rows in grouped_lookup.items():
        ordered_rows = sorted(
            rows,
            key=lambda item: (
                int(item.get("rank", 999) or 999),
                -(float(item.get("cvss_score", 0.0) or 0.0)),
                str(item.get("cve_id", "")),
            ),
        )
        items = [
            _build_visual_ranked_candidate_entry(
                cve_id=str(row.get("cve_id", "")).strip().upper(),
                row=row,
                block_tool="cve_lookup",
                verification_map=verification_map,
                template_index=template_index,
                selected_candidate=None,
            )
            for row in ordered_rows
            if str(row.get("cve_id", "")).strip()
        ]
        if items:
            blocks.append(
                {
                    "tool": "cve_lookup",
                    "target": key[0] or None,
                    "component": key[1] or None,
                    "service": key[2] or None,
                    "version": key[3] or None,
                    "selected_candidate": items[0]["cve_id"],
                    "selected_templates": [],
                    "items": items,
                }
            )

    if not isinstance(history, list):
        return blocks

    for entry in history:
        if not isinstance(entry, dict):
            continue
        tool_name = str(entry.get("tool", "")).strip()
        if tool_name not in {"cve_verify", "poc_sandbox_exec", "nuclei_exploit_check"}:
            continue
        metadata = entry.get("metadata_summary", {}) if isinstance(entry.get("metadata_summary"), dict) else {}
        if tool_name == "cve_verify":
            candidate_order = metadata.get("verification_order", [])
        elif tool_name == "nuclei_exploit_check":
            candidate_order = metadata.get("requested_cve_ids", [])
        else:
            candidate_order = metadata.get("candidate_order", [])
        if not isinstance(candidate_order, list):
            candidate_order = []
        normalized_order: list[str] = []
        seen_ids: set[str] = set()
        for item in candidate_order:
            cve_id = str(item).strip().upper()
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            normalized_order.append(cve_id)
        selected_candidate = normalized_order[0] if normalized_order else None
        selected_templates = metadata.get("selected_templates", [])
        if not isinstance(selected_templates, list):
            selected_templates = []
        template_name = str(metadata.get("template", "")).strip()
        if template_name and template_name not in selected_templates:
            selected_templates = [template_name, *selected_templates]
        component = str(metadata.get("component") or "").strip().lower() or None
        service = str(metadata.get("service") or "").strip().lower() or None
        version = str(metadata.get("version") or "").strip() or None
        target = str(entry.get("target") or "").strip() or None
        items = []
        for cve_id in normalized_order:
            row = _match_visual_ranked_candidate(
                cve_id=cve_id,
                rows=lookup_results,
                target=target,
                component=component,
                service=service,
                version=version,
            )
            items.append(
                _build_visual_ranked_candidate_entry(
                    cve_id=cve_id,
                    row=row,
                    block_tool=tool_name,
                    verification_map=verification_map,
                    template_index=template_index,
                    selected_candidate=selected_candidate,
                )
            )
        if items:
            blocks.append(
                {
                    "tool": tool_name,
                    "target": target,
                    "component": component,
                    "service": service,
                    "version": version,
                    "selected_candidate": selected_candidate,
                    "selected_templates": selected_templates[:12],
                    "items": items,
                }
            )
    return blocks


def _build_agent_visual_html(audit_report: dict[str, Any], agent_state: dict[str, Any]) -> str:
    """Render a single-file static HTML report without frontend framework dependencies."""
    meta_payload = audit_report.get("meta", {}) if isinstance(audit_report.get("meta"), dict) else {}
    visual_analysis = audit_report.get("visual_analysis", {}) if isinstance(audit_report.get("visual_analysis"), dict) else {}
    scope_payload = audit_report.get("scope", {}) if isinstance(audit_report.get("scope"), dict) else {}
    findings = audit_report.get("findings", []) if isinstance(audit_report.get("findings"), list) else []
    history = audit_report.get("history", []) if isinstance(audit_report.get("history"), list) else []
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = _normalize_severity(str(item.get("severity", "")).strip().lower(), str(item.get("name", "")))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    audit_score = _compute_audit_score(severity_counts)
    score_label = _score_label(audit_score)
    target = str(meta_payload.get("target") or agent_state.get("target") or "AutoSecAudit Agent Report").strip() or "AutoSecAudit Agent Report"
    html_lang = "zh-CN" if normalize_report_lang(meta_payload.get("report_lang") or agent_state.get("report_lang")) == "zh-CN" else "en"

    assets = scope_payload.get("assets", []) if isinstance(scope_payload, dict) and isinstance(scope_payload.get("assets"), list) else []
    surface = scope_payload.get("surface", {}) if isinstance(scope_payload, dict) and isinstance(scope_payload.get("surface"), dict) else {}
    protocol_evidence = surface.get("poc_protocol_evidence", []) if isinstance(surface.get("poc_protocol_evidence"), list) else []
    cve_validation = audit_report.get("cve_validation", {}) if isinstance(audit_report.get("cve_validation"), dict) else {}
    evidence_graph = audit_report.get("evidence_graph", {}) if isinstance(audit_report.get("evidence_graph"), dict) else {}
    path_graph = audit_report.get("path_graph", {}) if isinstance(audit_report.get("path_graph"), dict) else {}
    remediation_priority = audit_report.get("remediation_priority", []) if isinstance(audit_report.get("remediation_priority"), list) else []
    knowledge_context = audit_report.get("knowledge_context", {}) if isinstance(audit_report.get("knowledge_context"), dict) else {}

    metric_cards = [
        ("Target", target),
        ("Audit Score", f"{audit_score} ({score_label})"),
        ("Findings", len(findings)),
        ("Critical / High", f"{severity_counts.get('critical', 0)} / {severity_counts.get('high', 0)}"),
        ("Assets", len(assets)),
        ("Executed Actions", len(history)),
    ]

    scope_json = {
        "scope": scope_payload.get("scope", agent_state.get("scope", [])),
        "assets": assets,
        "surface": surface,
        "findings": findings,
    }
    protocol_glossary = {
        "Redis Version": "Common validation label retained for compatibility and service-version rendering.",
        "TLS Supported": "Boolean protocol capability field.",
        "Banner": "Observed service banner or greeting.",
    }

    protocol_breakdown: dict[str, int] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        attrs = asset.get("attributes", {}) if isinstance(asset.get("attributes"), dict) else {}
        service = str(attrs.get("service") or asset.get("kind") or "asset").strip().lower()
        proto = str(attrs.get("proto") or "tcp").strip().lower()
        if not service:
            continue
        key = f"{service}/{proto or 'tcp'}"
        protocol_breakdown[key] = protocol_breakdown.get(key, 0) + 1

    severity_by_asset: dict[str, str] = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = _normalize_severity(str(item.get("severity", "")).strip().lower(), str(item.get("name", "")))
        for asset_id in item.get("related_asset_ids", []) if isinstance(item.get("related_asset_ids"), list) else []:
            key = str(asset_id).strip()
            if not key:
                continue
            current = severity_by_asset.get(key, "info")
            if severity_rank.get(severity, 9) < severity_rank.get(current, 9):
                severity_by_asset[key] = severity

    asset_severity_breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for severity in severity_by_asset.values():
        asset_severity_breakdown[severity] = asset_severity_breakdown.get(severity, 0) + 1

    sections = [
        _html_section("Asset Topology", _html_pre(_pretty_json(scope_json))),
        _html_section(
            "Asset Trends",
            _html_pre(_pretty_json(visual_analysis.get("asset_phase_trends", []))),
            subtitle="Static execution-phase summary derived from the exported report.",
        ),
        _html_section(
            "Structured Validation",
            _html_pre(_pretty_json({"protocol_evidence": protocol_evidence, "cve_validation": cve_validation, "field_glossary": protocol_glossary})),
            subtitle="Protocol evidence, conservative validation output, and common field labels.",
        ),
        _html_section(
            "Verification Ranking",
            _html_pre(_pretty_json(visual_analysis.get("verification_ranking", []))),
        ),
        _html_section(
            "Run Batch Trends",
            _html_pre(_pretty_json(visual_analysis.get("asset_batch_trends", []))),
        ),
        _html_section(
            "Phase Trends",
            _html_pre(_pretty_json(visual_analysis.get("asset_phase_trends", []))),
        ),
        _html_section(
            "New / Resolved Since Previous Batch",
            _html_pre(_pretty_json((visual_analysis.get("batch_diff", {}) if isinstance(visual_analysis.get("batch_diff"), dict) else {}))),
        ),
        _html_section(
            "Asset Inventory Changes",
            _html_pre(_pretty_json((visual_analysis.get("batch_diff", {}) if isinstance(visual_analysis.get("batch_diff"), dict) else {}).get("asset_inventory_changes", (visual_analysis.get("batch_diff", {}) if isinstance(visual_analysis.get("batch_diff"), dict) else {})))),
        ),
        _html_section(
            "Service Changes",
            _html_pre(_pretty_json((visual_analysis.get("batch_diff", {}) if isinstance(visual_analysis.get("batch_diff"), dict) else {}).get("service_changes", (visual_analysis.get("batch_diff", {}) if isinstance(visual_analysis.get("batch_diff"), dict) else {})))),
        ),
        _html_section(
            "Executed Actions and Selection Rationale",
            _html_pre(_pretty_json(history)),
        ),
        _html_section(
            "Asset Severity Breakdown",
            _html_pre(_pretty_json(asset_severity_breakdown)),
        ),
        _html_section(
            "Service Protocol Breakdown",
            _html_pre(_pretty_json(protocol_breakdown)),
        ),
        _html_section(
            "Evidence Correlation",
            _html_pre(_pretty_json(evidence_graph)),
        ),
        _html_section(
            "Attack Path",
            _html_pre(_pretty_json(path_graph)),
        ),
        _html_section(
            "Remediation Priority",
            _html_pre(_pretty_json(remediation_priority)),
        ),
        _html_section(
            "Knowledge Context",
            _html_pre(_pretty_json(knowledge_context)),
        ),
        _html_section(
            "Raw Report Payload",
            _html_pre(_pretty_json(audit_report)),
            subtitle="Included for agent-to-human traceability."
        ),
    ]

    metrics_html = "".join(
        f'<div class="metric"><div class="metric-label">{html.escape(str(label))}</div><div class="metric-value">{html.escape(str(value))}</div></div>'
        for label, value in metric_cards
    )

    return f"""<!doctype html>
<html lang="{html_lang}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AutoSecAudit Report - {html.escape(target)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --stroke: #d9e1ec;
      --muted: #5b6b80;
      --text: #142033;
      --accent: #0f6cbd;
      --shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 0; font-family: Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.55; }}
    .page {{ max-width: 1280px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero {{ background: var(--panel); border: 1px solid var(--stroke); border-radius: 18px; padding: 24px; box-shadow: var(--shadow); }}
    h1 {{ margin: 0 0 8px; font-size: 32px; }}
    .subtle {{ color: var(--muted); font-size: 14px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-top: 20px; }}
    .metric {{ background: #f8fafc; border: 1px solid var(--stroke); border-radius: 14px; padding: 14px; }}
    .metric-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }}
    .metric-value {{ margin-top: 6px; font-size: 24px; font-weight: 700; word-break: break-word; }}
    .stack {{ margin-top: 20px; display: grid; gap: 16px; }}
    .section {{ background: var(--panel); border: 1px solid var(--stroke); border-radius: 18px; box-shadow: var(--shadow); overflow: hidden; }}
    .section > summary {{ cursor: pointer; list-style: none; padding: 16px 18px; font-weight: 700; border-bottom: 1px solid var(--stroke); }}
    .section > summary::-webkit-details-marker {{ display: none; }}
    .section-body {{ padding: 18px; }}
    .section-subtitle {{ margin: -4px 0 14px; color: var(--muted); font-size: 13px; }}
    pre {{ margin: 0; white-space: pre-wrap; word-break: break-word; background: #f8fafc; border: 1px solid var(--stroke); border-radius: 12px; padding: 14px; overflow: auto; font-family: Consolas, Monaco, monospace; font-size: 12px; }}
    code {{ font-family: Consolas, Monaco, monospace; }}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <h1>AutoSecAudit Static Report</h1>
      <div class="subtle">Target: {html.escape(target)} | Framework-free HTML export for agent and operator review.</div>
      <div class="metrics">{metrics_html}</div>
    </section>
    <section class="stack">
      {''.join(sections)}
    </section>
  </div>
</body>
</html>"""


def _html_section(title: str, body: str, *, subtitle: str | None = None) -> str:
    subtitle_html = f'<div class="section-subtitle">{html.escape(subtitle)}</div>' if subtitle else ''
    return (
        '<details class="section" open>'
        f'<summary>{html.escape(title)}</summary>'
        f'<div class="section-body">{subtitle_html}{body}</div>'
        '</details>'
    )


def _html_pre(payload: str) -> str:
    return f'<pre>{html.escape(payload)}</pre>'


def _pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


def _json_for_html_script_tag(payload: dict[str, Any]) -> str:
    """
    Serialize JSON for embedding inside `<script type="application/json">`.

    Important: do not HTML-escape quotes here, otherwise `JSON.parse()` will
    receive entity text (`&quot;`) and fail. Only neutralize `</script>` sequences.
    """
    serialized = json.dumps(payload, ensure_ascii=False)
    return serialized.replace("</", "<\\/")
