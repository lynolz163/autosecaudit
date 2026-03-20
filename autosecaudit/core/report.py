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
    Generate a single-file visual HTML report (React + Tailwind CDN).

    The generated page is static and can be mounted by any lightweight backend.
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
    """Render a single-file React + Tailwind visual HTML report."""
    audit_json = _json_for_html_script_tag(audit_report)
    state_json = _json_for_html_script_tag(agent_state)
    meta_payload = audit_report.get("meta", {}) if isinstance(audit_report.get("meta"), dict) else {}
    html_lang = (
        "zh-CN"
        if normalize_report_lang(
            meta_payload.get("report_lang")
            or (agent_state.get("report_lang") if isinstance(agent_state, dict) else None)
        )
        == "zh-CN"
        else "en"
    )
    title = html.escape(
        str(
            meta_payload.get(
                "target",
                "AutoSecAudit Agent Report",
            )
        )
    )
    template = """<!doctype html>
<html lang="__HTML_LANG__">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AutoSecAudit Visual Report - __TITLE__</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <style>
    * {
      box-sizing: border-box;
    }
    html {
      -webkit-text-size-adjust: 100%;
    }
    body {
      font-family: "Noto Sans SC", "Noto Sans CJK SC", "Source Han Sans SC", "Microsoft YaHei UI",
        "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", "Heiti SC", "SimHei", "Segoe UI",
        system-ui, sans-serif;
      background:
        radial-gradient(circle at 12% 18%, rgba(14,165,233,0.10), transparent 34%),
        radial-gradient(circle at 88% 12%, rgba(16,185,129,0.10), transparent 38%),
        linear-gradient(180deg, #f8fafc, #eef2ff 46%, #f8fafc);
      line-height: 1.6;
      text-rendering: optimizeLegibility;
      font-synthesis-weight: none;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    html[lang="zh-CN"] body {
      font-family: "Noto Sans SC", "Noto Sans CJK SC", "Source Han Sans SC", "Microsoft YaHei UI",
        "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", "Heiti SC", "SimHei", system-ui, sans-serif;
    }
    .glass {
      background: rgba(255,255,255,0.80);
      border: 1px solid rgba(148,163,184,0.22);
      box-shadow: 0 18px 40px rgba(15,23,42,0.06);
      backdrop-filter: blur(10px);
      overflow-wrap: anywhere;
    }
  </style>
</head>
<body class="min-h-screen text-slate-900">
  <script id="audit-report-data" type="application/json">__AUDIT_JSON__</script>
  <script id="agent-state-data" type="application/json">__STATE_JSON__</script>
  <div id="root"></div>
  <script type="text/babel">
    const auditReport = JSON.parse(document.getElementById("audit-report-data").textContent || "{}");
    const agentState = JSON.parse(document.getElementById("agent-state-data").textContent || "{}");
    const reportMeta = auditReport.meta || {};
    const langTag = String(reportMeta.report_lang || agentState.report_lang || navigator.language || document.documentElement.lang || "").toLowerCase();
    const isZh = langTag.startsWith("zh");
    const tt = (en, zh) => isZh ? zh : en;
    const scoreLabelMap = {
      "Excellent": "优秀",
      "Good": "良好",
      "Needs Attention": "需要关注",
      "High Risk": "高风险",
      "Critical Risk": "严重风险",
    };
    const renderScoreLabel = (value) => {
      const text = String(value || "N/A");
      return isZh ? (scoreLabelMap[text] || text) : text;
    };

    const severityRank = ["critical", "high", "medium", "low", "info"];
    const severityBadge = {
      critical: "bg-rose-600 text-white",
      high: "bg-orange-500 text-white",
      medium: "bg-amber-300 text-slate-900",
      low: "bg-emerald-300 text-slate-900",
      info: "bg-sky-200 text-slate-900"
    };

    function MetricCard({ label, value, sub }) {
      return (
        <div className="glass rounded-2xl p-4">
          <div className="text-xs uppercase tracking-[0.14em] text-slate-500">{label}</div>
          <div className="mt-2 text-2xl font-semibold tabular-nums">{value}</div>
          {sub ? <div className="mt-1 text-sm text-slate-500">{sub}</div> : null}
        </div>
      );
    }

    function BudgetLineChart({ trace }) {
      const points = Array.isArray(trace) ? trace.filter((p) => typeof p.cumulative_spent === "number") : [];
      if (!points.length) {
        return <div className="text-sm text-slate-500">{tt("No budget trace available.", "暂无预算消耗轨迹。")}</div>;
      }
      const width = 760;
      const height = 220;
      const pad = 26;
      const maxY = Math.max(1, ...points.map((p) => p.cumulative_spent || 0));
      const maxX = Math.max(1, points.length - 1);
      const coords = points.map((p, i) => {
        const x = pad + ((width - pad * 2) * (points.length === 1 ? 0 : i / maxX));
        const y = height - pad - ((height - pad * 2) * ((p.cumulative_spent || 0) / maxY));
        return { ...p, x, y };
      });
      const linePath = coords.map((p, idx) => (idx === 0 ? "M" : "L") + p.x + "," + p.y).join(" ");
      const areaPath = linePath + " L" + coords[coords.length - 1].x + "," + (height - pad) + " L" + coords[0].x + "," + (height - pad) + " Z";
      return (
        <div>
          <div className="w-full overflow-x-auto">
            <svg viewBox={"0 0 " + width + " " + height} className="w-full min-w-[520px]">
              <defs>
                <linearGradient id="budgetFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0.26" />
                  <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0.03" />
                </linearGradient>
              </defs>
              <rect x="0" y="0" width={width} height={height} rx="16" fill="#ffffff" opacity="0.75" />
              {[0, 0.25, 0.5, 0.75, 1].map((r, idx) => {
                const y = pad + (height - pad * 2) * r;
                return <line key={idx} x1={pad} y1={y} x2={width - pad} y2={y} stroke="#e2e8f0" strokeWidth="1" />;
              })}
              {coords.length > 1 ? <path d={areaPath} fill="url(#budgetFill)" /> : null}
              <path d={linePath} fill="none" stroke="#0284c7" strokeWidth="3" strokeLinecap="round" />
              {coords.map((p) => (
                <g key={p.step}>
                  <circle cx={p.x} cy={p.y} r="4" fill="#0284c7" />
                  <text x={p.x} y={height - 7} textAnchor="middle" fontSize="10" fill="#475569">{p.step}</text>
                </g>
              ))}
            </svg>
          </div>
          <div className="mt-3 space-y-1 text-xs text-slate-600">
            {points.slice(-10).map((p) => (
              <div key={"legend-" + p.step} className="flex justify-between gap-3">
                <span className="break-all">{p.label}</span>
                <span className="tabular-nums">+{p.cost || 0} ({tt("total", "累计")} {p.cumulative_spent || 0})</span>
              </div>
            ))}
          </div>
        </div>
      );
    }

    function ScopeMap({ scopePayload }) {
      const scopeList = Array.isArray(scopePayload?.scope) ? scopePayload.scope : [];
      const breadcrumbs = Array.isArray(scopePayload?.breadcrumbs) ? scopePayload.breadcrumbs : [];
      const surface = scopePayload?.surface && typeof scopePayload.surface === "object" ? scopePayload.surface : {};
      const discoveredUrls = Array.isArray(surface.discovered_urls) ? surface.discovered_urls : [];
      const apiEndpoints = Array.isArray(surface.api_endpoints) ? surface.api_endpoints : [];
      return (
        <div className="glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">{tt("Scope Asset Map", "范围资产地图")}</h2>
            <div className="text-xs text-slate-500">{tt("Scope / breadcrumbs / surface", "范围 / 面包屑 / 资产面")}</div>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Scope", "范围")}</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {scopeList.length ? scopeList.map((item, idx) => (
                  <span key={idx} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">{item}</span>
                )) : <span className="text-sm text-slate-500">{tt("No scope entries", "无范围条目")}</span>}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Breadcrumbs", "面包屑")}</div>
              <div className="mt-2 max-h-48 space-y-1 overflow-auto rounded-xl bg-slate-50 p-2 text-xs">
                {breadcrumbs.length ? breadcrumbs.map((b, idx) => (
                  <div key={idx} className="flex gap-2">
                    <span className="w-16 shrink-0 text-slate-500">{b.type}</span>
                    <span className="break-all text-slate-700">{b.data}</span>
                  </div>
                )) : <div className="text-slate-500">{tt("No breadcrumbs", "无面包屑记录")}</div>}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Surface", "资产面")}</div>
              <div className="mt-2 text-xs text-slate-700 space-y-1">
                <div>{tt("Discovered URLs", "已发现 URL")}: <span className="font-semibold">{discoveredUrls.length}</span></div>
                <div>{tt("API Endpoints", "API 端点")}: <span className="font-semibold">{apiEndpoints.length}</span></div>
                <div className="mt-2 max-h-40 overflow-auto rounded-xl bg-slate-50 p-2">
                  {discoveredUrls.slice(0, 12).map((u, idx) => <div key={idx} className="break-all">{u}</div>)}
                  {discoveredUrls.length > 12 ? <div className="text-slate-500">... {discoveredUrls.length - 12} {tt("more", "条")}</div> : null}
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    }

    function EvidenceCorrelationPanel({ evidenceGraph }) {
      const graph = evidenceGraph && typeof evidenceGraph === "object" ? evidenceGraph : {};
      const summary = graph.summary && typeof graph.summary === "object" ? graph.summary : {};
      const claims = Array.isArray(graph.claims) ? graph.claims : [];
      const priorityTargets = Array.isArray(graph.priority_targets) ? graph.priority_targets : [];
      const recommendedTools = Array.isArray(graph.recommended_tools) ? graph.recommended_tools : [];
      if (!claims.length && !priorityTargets.length && !recommendedTools.length) return null;

      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Evidence Correlation", "\\u8bc1\\u636e\\u5173\\u8054")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Cross-validated Leads", "\\u4ea4\\u53c9\\u5370\\u8bc1\\u7ebf\\u7d22")}</h2>
            </div>
            <div className="text-xs text-slate-500">
              {tt("Corroborated", "\\u5df2\\u5370\\u8bc1")} {summary.corroborated_claims ?? 0}
              {" | "}
              {tt("High confidence", "\\u9ad8\\u7f6e\\u4fe1")} {summary.high_confidence_claims ?? 0}
            </div>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-[0.95fr_1.05fr]">
            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
              <div className="text-sm font-semibold">{tt("Priority Targets", "\\u4f18\\u5148\\u76ee\\u6807")}</div>
              <div className="mt-3 space-y-3">
                {priorityTargets.length ? priorityTargets.slice(0, 8).map((item, index) => (
                  <div key={"evidence-target-" + index} className="rounded-xl border border-slate-200 bg-slate-50/70 px-3 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-medium break-all">{item.target || "-"}</div>
                      <span className="rounded-full bg-slate-900 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-white">
                        {tt("Score", "\\u8bc4\\u5206")} {item.score ?? 0}
                      </span>
                    </div>
                    <div className="mt-2 space-y-1 text-xs text-slate-600">
                      {(Array.isArray(item.reasons) ? item.reasons : []).slice(0, 4).map((reason, reasonIndex) => (
                        <div key={"evidence-target-reason-" + index + "-" + reasonIndex}>- {reason}</div>
                      ))}
                    </div>
                  </div>
                )) : (
                  <div className="text-sm text-slate-500">{tt("No priority targets were derived.", "\\u6682\\u65e0\\u4f18\\u5148\\u76ee\\u6807\\u3002")}</div>
                )}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
              <div className="text-sm font-semibold">{tt("Corroborated Claims", "\\u5df2\\u5370\\u8bc1\\u58f0\\u660e")}</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {recommendedTools.slice(0, 10).map((toolName, index) => (
                  <span key={"evidence-tool-" + index} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">
                    {toolName}
                  </span>
                ))}
              </div>
              <div className="mt-3 space-y-3">
                {claims.length ? claims.slice(0, 10).map((claim, index) => (
                  <div key={"evidence-claim-" + index} className="rounded-xl border border-slate-200 bg-slate-50/70 px-3 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium">{claim.subject || "-"}</div>
                        <div className="mt-1 text-xs text-slate-500">
                          {(claim.kind || "claim")} | {tt("Sources", "\\u6765\\u6e90")} {claim.source_count ?? 0} | {tt("Evidence", "\\u8bc1\\u636e")} {claim.evidence_count ?? 0}
                        </div>
                      </div>
                      <span className="rounded-full bg-cyan-50 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-cyan-700">
                        {tt("Confidence", "\\u7f6e\\u4fe1")} {claim.confidence ?? 0}
                      </span>
                    </div>
                    {Array.isArray(claim.targets) && claim.targets.length ? (
                      <div className="mt-2 text-xs text-slate-600 break-all">
                        {tt("Targets", "\\u76ee\\u6807")}: {claim.targets.slice(0, 3).join(", ")}
                      </div>
                    ) : null}
                  </div>
                )) : (
                  <div className="text-sm text-slate-500">{tt("No corroborated claims yet.", "\\u6682\\u65e0\\u5df2\\u5370\\u8bc1\\u7ebf\\u7d22\\u3002")}</div>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    function KnowledgeContextPanel({ knowledgeContext }) {
      const context = knowledgeContext && typeof knowledgeContext === "object" ? knowledgeContext : {};
      const summary = String(context.summary || "").trim();
      const tags = Array.isArray(context.tags) ? context.tags : [];
      const references = Array.isArray(context.references) ? context.references : [];
      if (!summary && !tags.length && !references.length) return null;

      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Knowledge Context", "任务知识上下文")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Task-Level Context", "任务级上下文")}</h2>
            </div>
            <div className="text-xs text-slate-500">{tt("Swagger, architecture notes, and internal references", "Swagger、架构说明与内部引用")}</div>
          </div>
          {summary ? <div className="mt-4 rounded-2xl border border-slate-200 bg-white/70 p-4 text-sm text-slate-700">{summary}</div> : null}
          {tags.length ? (
            <div className="mt-4 flex flex-wrap gap-2">
              {tags.slice(0, 12).map((item, index) => (
                <span key={"knowledge-tag-" + index} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">
                  {item}
                </span>
              ))}
            </div>
          ) : null}
          {references.length ? (
            <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("References", "引用")}</div>
              <div className="mt-3 space-y-2 text-sm text-slate-700">
                {references.slice(0, 10).map((item, index) => (
                  <div key={"knowledge-ref-" + index} className="break-all">{item}</div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      );
    }

    function CveValidationPanel({ cveValidation }) {
      const pipeline = cveValidation && typeof cveValidation === "object" ? cveValidation : {};
      const summary = pipeline.summary && typeof pipeline.summary === "object" ? pipeline.summary : {};
      const candidates = Array.isArray(pipeline.candidates) ? pipeline.candidates : [];
      const recommendedActions = Array.isArray(pipeline.recommended_actions) ? pipeline.recommended_actions : [];
      if (!candidates.length && !recommendedActions.length) return null;

      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("CVE Validation Pipeline", "CVE 分级验证流水线")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Version -> Template -> Sandbox", "版本印证 -> 模板验证 -> 沙箱最小 PoC")}</h2>
            </div>
            <div className="text-xs text-slate-500">
              {tt("Candidates", "候选")} {summary.candidate_count ?? candidates.length}
              {" | "}
              {tt("Sandbox ready", "沙箱就绪")} {summary.sandbox_ready_count ?? 0}
            </div>
          </div>
          {recommendedActions.length ? (
            <div className="mt-4 flex flex-wrap gap-2">
              {recommendedActions.slice(0, 8).map((toolName, index) => (
                <span key={"cve-pipeline-action-" + index} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">
                  {toolName}
                </span>
              ))}
            </div>
          ) : null}
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <MetricCard label={tt("Version Corroborated", "版本印证")} value={summary.version_corroborated_count ?? 0} sub={tt("Multi-source version matches", "多源版本匹配")} />
            <MetricCard label={tt("Template Verified", "模板验证")} value={summary.template_verified_count ?? 0} sub={tt("Nuclei or equivalent confirmations", "Nuclei 或等效模板确认")} />
          </div>
          <div className="mt-4 space-y-3">
            {candidates.slice(0, 10).map((item, index) => (
              <div key={"cve-pipeline-candidate-" + index} className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold">{item.cve_id || tt("Unknown CVE", "未知 CVE")}</div>
                    <div className="mt-1 text-xs text-slate-500 break-all">{item.target || "-"}</div>
                  </div>
                  <span className="rounded-full bg-slate-900 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-white">
                    {item.quality_label || "low"}
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  <span className="rounded-full bg-emerald-50 px-3 py-1 font-medium text-emerald-700">
                    {tt("Version", "版本")}: {item.version_corroborated ? tt("yes", "是") : tt("no", "否")}
                  </span>
                  <span className="rounded-full bg-sky-50 px-3 py-1 font-medium text-sky-700">
                    {tt("Template", "模板")}: {item.template_verified ? tt("yes", "是") : tt("no", "否")}
                  </span>
                  <span className="rounded-full bg-violet-50 px-3 py-1 font-medium text-violet-700">
                    {tt("Sandbox", "沙箱")}: {item.sandbox_ready ? tt("ready", "就绪") : tt("hold", "待定")}
                  </span>
                </div>
                <div className="mt-3 text-sm text-slate-600">
                  {tt("Next step", "下一步")}: {item.recommended_next_step || "-"}
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }

    function AttackPathPanel({ pathGraph }) {
      const graph = pathGraph && typeof pathGraph === "object" ? pathGraph : {};
      const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
      const edges = Array.isArray(graph.edges) ? graph.edges : [];
      if (!nodes.length && !edges.length) return null;

      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Attack Path Graph", "攻击路径图")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Evidence-Linked Path View", "证据关联路径视图")}</h2>
            </div>
            <div className="text-xs text-slate-500">
              {nodes.length} {tt("nodes", "节点")} | {edges.length} {tt("edges", "连边")}
            </div>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
              <div className="text-sm font-semibold">{tt("Graph nodes", "图节点")}</div>
              <div className="mt-3 space-y-2 text-sm text-slate-700">
                {nodes.slice(0, 10).map((node, index) => (
                  <div key={"path-node-" + index} className="flex items-center justify-between gap-3 rounded-xl bg-slate-50/70 px-3 py-2">
                    <span className="break-all">{node.label || node.id || "-"}</span>
                    <span className="rounded-full bg-slate-100 px-2 py-1 text-[11px] font-medium uppercase tracking-wider">{node.type || "node"}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
              <div className="text-sm font-semibold">{tt("Correlated edges", "关联路径")}</div>
              <div className="mt-3 space-y-2 text-sm text-slate-700">
                {edges.slice(0, 12).map((edge, index) => (
                  <div key={"path-edge-" + index} className="rounded-xl bg-slate-50/70 px-3 py-2">
                    <div className="break-all">{edge.source || "-"} -> {edge.target || "-"}</div>
                    <div className="mt-1 text-xs text-slate-500">{tt("Kind", "类型")}: {edge.kind || "edge"} | {tt("Confidence", "置信度")}: {edge.confidence ?? 0}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    }

    function RemediationPriorityPanel({ items }) {
      const rows = Array.isArray(items) ? items : [];
      if (!rows.length) return null;

      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Remediation Priority", "修复优先级")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Where remediation breaks the most paths", "优先修复能切断最多路径的点")}</h2>
            </div>
            <div className="text-xs text-slate-500">{rows.length} {tt("tracked items", "条待修复项")}</div>
          </div>
          <div className="mt-4 space-y-3">
            {rows.slice(0, 10).map((item, index) => (
              <div key={"remediation-row-" + index} className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold">{item.title || "-"}</div>
                    <div className="mt-1 text-xs text-slate-500 break-all">{item.target || "-"}</div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <span className="rounded-full bg-slate-900 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-white">{item.priority || "P4"}</span>
                    <span className="rounded-full bg-amber-50 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-amber-700">{item.severity || "info"}</span>
                  </div>
                </div>
                <div className="mt-3 text-sm text-slate-600">{item.reason || "-"}</div>
                {item.recommendation ? <div className="mt-2 text-sm text-slate-500">{tt("Recommendation", "建议")}: {item.recommendation}</div> : null}
              </div>
            ))}
          </div>
        </div>
      );
    }

    function AssetTopologyPanel({ scopePayload, findings }) {
      const assets = Array.isArray(scopePayload?.assets) ? scopePayload.assets : [];
      const surface = scopePayload?.surface && typeof scopePayload.surface === "object" ? scopePayload.surface : {};
      const pocProtocolEvidence = Array.isArray(surface?.poc_protocol_evidence) ? surface.poc_protocol_evidence : [];
      const safeFindings = Array.isArray(findings) ? findings : [];
      if (!assets.length) return null;

      const assetCounts = assets.reduce((acc, item) => {
        const kind = String(item?.kind || "asset").toLowerCase();
        acc[kind] = Number(acc[kind] || 0) + 1;
        return acc;
      }, {});
      const linkedFindingsByAsset = new Map();
      safeFindings.forEach((item) => {
        const relatedIds = Array.isArray(item?.related_asset_ids) ? item.related_asset_ids : [];
        relatedIds.forEach((assetId) => {
          const key = String(assetId || "").trim();
          if (!key) return;
          if (!linkedFindingsByAsset.has(key)) {
            linkedFindingsByAsset.set(key, []);
          }
          linkedFindingsByAsset.get(key).push(item);
        });
      });

      const serviceAssets = assets.filter((item) => String(item?.kind || "").toLowerCase() === "service");
      const otherAssets = assets.filter((item) => String(item?.kind || "").toLowerCase() !== "service");
      const linkedFindingCount = Array.from(linkedFindingsByAsset.values()).reduce((total, rows) => total + rows.length, 0);

      const assetDisplayName = (asset) => {
        const attrs = asset?.attributes && typeof asset.attributes === "object" ? asset.attributes : {};
        if (String(asset?.kind || "").toLowerCase() === "service") {
          const host = String(attrs.host || "-");
          const port = String(attrs.port || "-");
          const service = String(attrs.service || "service");
          return host + ":" + port + " / " + service;
        }
        return String(asset?.id || tt("Unknown asset", "\\u672a\\u77e5\\u8d44\\u4ea7"));
      };

      const boolLabel = (value) => {
        if (value === true) return tt("Yes", "\\u662f");
        if (value === false) return tt("No", "\\u5426");
        return "-";
      };
      const formatTitleCase = (value) => String(value || "")
        .replace(/[_-]+/g, " ")
        .replace(/\\s+/g, " ")
        .trim()
        .replace(/\\b\\w/g, (match) => match.toUpperCase());
      const evidenceFieldLabels = {
        ping_response: tt("PING Response", "PING \\u54cd\\u5e94"),
        redis_version: tt("Redis Version", "Redis \\u7248\\u672c"),
        unauthenticated: tt("Unauthenticated Access", "\\u672a\\u8ba4\\u8bc1\\u8bbf\\u95ee"),
        stats_preview: tt("Stats Preview", "\\u7edf\\u8ba1\\u9884\\u89c8"),
        reported_version: tt("Reported Version", "\\u56de\\u62a5\\u7248\\u672c"),
        banner: tt("Banner", "Banner"),
        tls_version: tt("TLS Version", "TLS \\u7248\\u672c"),
        cipher: tt("Cipher Suite", "\\u5bc6\\u7801\\u5957\\u4ef6"),
        weak_tls: tt("Weak TLS", "\\u5f31 TLS"),
        tls_supported: tt("TLS Supported", "\\u652f\\u6301 TLS"),
      };
      const renderEvidenceFieldLabel = (key) => {
        const normalized = String(key || "").trim().toLowerCase();
        if (!normalized) return "-";
        return evidenceFieldLabels[normalized] || formatTitleCase(normalized);
      };

      const normalizeLower = (value) => String(value || "").trim().toLowerCase();
      const displayServiceName = (value) => {
        const normalized = normalizeLower(value);
        if (["tls", "ssl", "https"].includes(normalized)) return "TLS/HTTPS";
        if (["ssh", "openssh"].includes(normalized)) return "SSH";
        if (["postgres", "postgresql"].includes(normalized)) return "PostgreSQL";
        if (["mysql", "mariadb"].includes(normalized)) return "MySQL";
        if (!normalized) return tt("Unknown service", "\\u672a\\u77e5\\u670d\\u52a1");
        return formatTitleCase(normalized);
      };
      const serviceAliases = (value) => {
        const normalized = normalizeLower(value);
        if (!normalized) return [];
        if (["tls", "ssl", "https"].includes(normalized)) return ["tls", "ssl", "https"];
        if (["ssh", "openssh"].includes(normalized)) return ["ssh", "openssh"];
        if (["postgres", "postgresql"].includes(normalized)) return ["postgres", "postgresql"];
        if (["mysql", "mariadb"].includes(normalized)) return ["mysql", "mariadb"];
        return [normalized];
      };
      const parseTargetMeta = (value) => {
        const text = String(value || "").trim();
        if (!text) return { host: "", port: 0 };
        try {
          if (text.includes("://")) {
            const parsed = new URL(text);
            const fallbackPort = parsed.protocol === "https:" ? 443 : (parsed.protocol === "http:" ? 80 : 0);
            return {
              host: normalizeLower(parsed.hostname),
              port: Number(parsed.port || fallbackPort || 0),
            };
          }
        } catch (error) {
          void error;
        }
        return { host: normalizeLower(text), port: 0 };
      };
      const renderEvidenceValue = (value) => {
        if (value === true || value === false) return boolLabel(value);
        if (Array.isArray(value)) return value.map((item) => renderEvidenceValue(item)).join(", ");
        if (value && typeof value === "object") return JSON.stringify(value);
        return String(value ?? "-");
      };
      const structuredEvidenceForAsset = (asset) => {
        const attrs = asset?.attributes && typeof asset.attributes === "object" ? asset.attributes : {};
        const assetHost = normalizeLower(attrs.host);
        const assetPort = Number(attrs.port || 0);
        const assetServiceAliases = serviceAliases(attrs.service || asset.kind);
        return pocProtocolEvidence.filter((item) => {
          if (!item || typeof item !== "object") return false;
          const targetMeta = parseTargetMeta(item.target);
          const itemHost = normalizeLower(item.host || targetMeta.host);
          const itemPort = Number(item.port || targetMeta.port || 0);
          const itemServiceAliases = serviceAliases(item.service || item.protocol || item.component);
          const sameHost = assetHost && itemHost && assetHost === itemHost;
          const samePort = !assetPort || !itemPort || assetPort === itemPort;
          const sameService = !assetServiceAliases.length || !itemServiceAliases.length || assetServiceAliases.some((value) => itemServiceAliases.includes(value));
          return sameHost && samePort && sameService;
        });
      };
      const serviceTrendRows = Object.values(serviceAssets.reduce((acc, asset) => {
        const attrs = asset?.attributes && typeof asset.attributes === "object" ? asset.attributes : {};
        const serviceKey = normalizeLower(attrs.service || asset.kind || "service") || "service";
        const structuredEvidence = structuredEvidenceForAsset(asset);
        const relatedFindings = Array.isArray(linkedFindingsByAsset.get(asset.id)) ? linkedFindingsByAsset.get(asset.id) : [];
        const highestSeverity = relatedFindings.reduce((current, item) => {
          const severity = String(item?.severity || "info").toLowerCase();
          return severityRank.indexOf(severity) < severityRank.indexOf(current) ? severity : current;
        }, "info");
        if (!acc[serviceKey]) {
          acc[serviceKey] = {
            key: serviceKey,
            label: displayServiceName(serviceKey),
            assetCount: 0,
            findingCount: 0,
            validationCount: 0,
            highestSeverity: "info",
          };
        }
        acc[serviceKey].assetCount += 1;
        acc[serviceKey].findingCount += relatedFindings.length;
        acc[serviceKey].validationCount += structuredEvidence.length;
        if (severityRank.indexOf(highestSeverity) < severityRank.indexOf(acc[serviceKey].highestSeverity)) {
          acc[serviceKey].highestSeverity = highestSeverity;
        }
        return acc;
      }, {})).sort((a, b) => {
        if (b.findingCount !== a.findingCount) return b.findingCount - a.findingCount;
        if (b.validationCount !== a.validationCount) return b.validationCount - a.validationCount;
        return String(a.label).localeCompare(String(b.label));
      });
      const maxTrendValue = Math.max(1, ...serviceTrendRows.map((item) => Math.max(item.assetCount, item.findingCount, item.validationCount)));

      return (
        <div className="glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Asset View", "\\u8d44\\u4ea7\\u89c6\\u56fe")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Asset Topology", "\\u8d44\\u4ea7\\u62d3\\u6251")}</h2>
            </div>
            <div className="text-xs text-slate-500">{tt("Assets, services, and linked findings in the exported report", "\\u5bfc\\u51fa\\u62a5\\u544a\\u4e2d\\u7684\\u8d44\\u4ea7\\u3001\\u670d\\u52a1\\u4e0e\\u5173\\u8054\\u53d1\\u73b0")}</div>
          </div>

          <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard label={tt("Assets", "\\u8d44\\u4ea7")} value={assets.length} sub={tt("Kinds", "\\u7c7b\\u578b") + ": " + Object.keys(assetCounts).length} />
            <MetricCard label={tt("Services", "\\u670d\\u52a1")} value={serviceAssets.length} sub={tt("Other Assets", "\\u5176\\u4ed6\\u8d44\\u4ea7") + ": " + otherAssets.length} />
            <MetricCard label={tt("Linked Findings", "\\u5173\\u8054\\u53d1\\u73b0")} value={linkedFindingCount} sub={tt("Mapped Assets", "\\u5df2\\u5173\\u8054\\u8d44\\u4ea7") + ": " + linkedFindingsByAsset.size} />
            <MetricCard label={tt("Kinds", "\\u7c7b\\u578b")} value={Object.keys(assetCounts).length} sub={tt("Services with findings", "\\u6709\\u53d1\\u73b0\\u7684\\u670d\\u52a1") + ": " + linkedFindingsByAsset.size} />
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {Object.entries(assetCounts).sort((a, b) => String(a[0]).localeCompare(String(b[0]))).map(([kind, count]) => (
              <span key={kind} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">
                {kind} x{count}
              </span>
            ))}
          </div>

          {serviceTrendRows.length ? (
            <div className="mt-5 rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Asset Trends", "\\u8d44\\u4ea7\\u8d70\\u52bf")}</div>
                  <h3 className="mt-1 text-base font-semibold">{tt("Service-Level Trend Snapshot", "\\u670d\\u52a1\\u7ea7\\u8d70\\u52bf\\u5feb\\u7167")}</h3>
                </div>
                <div className="text-xs text-slate-500">{tt("Assets, linked findings, and structured validations per service", "\\u6309\\u670d\\u52a1\\u7ef4\\u5ea6\\u6c47\\u603b\\u8d44\\u4ea7\\u6570\\u3001\\u5173\\u8054\\u53d1\\u73b0\\u4e0e\\u7ed3\\u6784\\u5316\\u9a8c\\u8bc1")}</div>
              </div>
              <div className="mt-4 space-y-3">
                {serviceTrendRows.map((item) => (
                  <div key={"trend-" + item.key} className="rounded-xl border border-slate-200 bg-slate-50/80 px-3 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-medium">{item.label}</div>
                      <span className={"rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider " + (severityBadge[item.highestSeverity] || severityBadge.info)}>
                        {item.highestSeverity}
                      </span>
                    </div>
                    <div className="mt-2 grid gap-2 text-xs text-slate-600 md:grid-cols-3">
                      <div>{tt("Assets", "\\u8d44\\u4ea7")}: <span className="font-medium text-slate-900">{item.assetCount}</span></div>
                      <div>{tt("Findings", "\\u53d1\\u73b0")}: <span className="font-medium text-slate-900">{item.findingCount}</span></div>
                      <div>{tt("Structured Validations", "\\u7ed3\\u6784\\u5316\\u9a8c\\u8bc1")}: <span className="font-medium text-slate-900">{item.validationCount}</span></div>
                    </div>
                    <div className="mt-3 space-y-2">
                      {[
                        [tt("Assets", "\\u8d44\\u4ea7"), item.assetCount, "bg-slate-500"],
                        [tt("Findings", "\\u53d1\\u73b0"), item.findingCount, "bg-cyan-500"],
                        [tt("Structured Validations", "\\u7ed3\\u6784\\u5316\\u9a8c\\u8bc1"), item.validationCount, "bg-emerald-500"],
                      ].map(([label, value, color]) => (
                        <div key={item.key + "-" + label} className="space-y-1">
                          <div className="flex items-center justify-between text-[11px] text-slate-500">
                            <span>{label}</span>
                            <span className="font-medium text-slate-700">{value}</span>
                          </div>
                          <div className="h-2 overflow-hidden rounded-full bg-slate-200">
                            <div className={String(color) + " h-full rounded-full"} style={{ width: Math.max(6, Math.round((Number(value) / maxTrendValue) * 100)) + "%" }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {serviceAssets.length ? (
            <div className="mt-5 grid gap-4 xl:grid-cols-2">
              {serviceAssets.map((asset) => {
                const attrs = asset?.attributes && typeof asset.attributes === "object" ? asset.attributes : {};
                const evidence = asset?.evidence && typeof asset.evidence === "object" ? asset.evidence : {};
                const structuredEvidence = structuredEvidenceForAsset(asset);
                const relatedFindings = Array.isArray(linkedFindingsByAsset.get(asset.id)) ? [...linkedFindingsByAsset.get(asset.id)] : [];
                relatedFindings.sort((a, b) => severityRank.indexOf(String(a?.severity || "info")) - severityRank.indexOf(String(b?.severity || "info")));
                return (
                  <article key={asset.id} className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold break-all">{assetDisplayName(asset)}</div>
                        <div className="mt-1 text-xs text-slate-500">{tt("Source", "\\u6765\\u6e90")}: {asset.source_tool || "-"}</div>
                      </div>
                      <span className="rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-white">
                        {displayServiceName(attrs.service || asset.kind || "service")}
                      </span>
                    </div>
                    <div className="mt-3 grid gap-2 text-xs text-slate-600 md:grid-cols-2">
                      <div>{tt("Proto", "\\u534f\\u8bae")}: <span className="font-medium text-slate-800">{String(attrs.proto || "-")}</span></div>
                      <div>TLS: <span className="font-medium text-slate-800">{boolLabel(attrs.tls)}</span></div>
                      <div>{tt("Auth", "\\u8ba4\\u8bc1")}: <span className="font-medium text-slate-800">{boolLabel(attrs.auth_required)}</span></div>
                      <div>{tt("Linked Findings", "\\u5173\\u8054\\u53d1\\u73b0")}: <span className="font-medium text-slate-800">{relatedFindings.length}</span></div>
                    </div>
                    {(attrs.banner || evidence.banner) ? (
                      <pre className="mt-3 max-h-32 overflow-auto rounded-xl bg-slate-900 p-3 text-xs leading-relaxed text-slate-100 whitespace-pre-wrap">
{String(attrs.banner || evidence.banner)}
                      </pre>
                    ) : null}
                    {structuredEvidence.length ? (
                      <div className="mt-3">
                        <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Structured Validation", "\\u7ed3\\u6784\\u5316\\u9a8c\\u8bc1")}</div>
                        <div className="mt-2 space-y-2">
                          {structuredEvidence.map((item, idx) => {
                            const detailEntries = Object.entries(item).filter(([key, value]) => {
                              if (["target", "host", "port", "service", "protocol", "template", "cve_id", "component", "version"].includes(String(key))) {
                                return false;
                              }
                              if (value === null || value === undefined || value === "") return false;
                              if (Array.isArray(value) && !value.length) return false;
                              if (typeof value === "object" && !Array.isArray(value) && !Object.keys(value).length) return false;
                              return true;
                            });
                            return (
                              <div key={asset.id + "-structured-" + idx} className="rounded-xl border border-cyan-200 bg-cyan-50/60 px-3 py-3">
                                <div className="flex items-start justify-between gap-3">
                                  <div className="text-sm font-medium break-all">
                                    {displayServiceName(item.protocol || item.service || attrs.service || tt("protocol probe", "\\u534f\\u8bae\\u63a2\\u6d4b"))}
                                  </div>
                                  <span className="rounded-full bg-slate-900 px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-white">
                                    {String(item.template || tt("probe", "\\u63a2\\u6d4b"))}
                                  </span>
                                </div>
                                <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-slate-600">
                                  {item.cve_id ? <span className="rounded-full bg-white px-2 py-1 font-medium">{String(item.cve_id)}</span> : null}
                                  {item.component ? <span className="rounded-full bg-white px-2 py-1 font-medium">{String(item.component)}{item.version ? " " + String(item.version) : ""}</span> : null}
                                  {item.port ? <span className="rounded-full bg-white px-2 py-1 font-medium">{tt("Port", "\\u7aef\\u53e3")}: {String(item.port)}</span> : null}
                                </div>
                                {detailEntries.length ? (
                                  <div className="mt-2 grid gap-2 md:grid-cols-2">
                                    {detailEntries.map(([key, value]) => (
                                      <div key={asset.id + "-structured-detail-" + idx + "-" + key} className="rounded-lg bg-white px-2.5 py-2 text-xs text-slate-700">
                                        <div className="uppercase tracking-wider text-slate-400">{renderEvidenceFieldLabel(key)}</div>
                                        <div className="mt-1 break-all font-medium text-slate-900">{renderEvidenceValue(value)}</div>
                                      </div>
                                    ))}
                                  </div>
                                ) : null}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ) : null}
                    <div className="mt-3 space-y-2">
                      {relatedFindings.length ? relatedFindings.map((item, idx) => {
                        const severity = String(item?.severity || "info").toLowerCase();
                        return (
                          <div key={asset.id + "-" + idx} className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2">
                            <div className="flex items-start justify-between gap-3">
                              <div className="text-sm font-medium break-all">{String(item?.name || item?.title || tt("Unnamed finding", "\\u672a\\u547d\\u540d\\u53d1\\u73b0"))}</div>
                              <span className={"rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider " + (severityBadge[severity] || severityBadge.info)}>
                                {severity}
                              </span>
                            </div>
                            <div className="mt-1 text-xs text-slate-500 break-all">{tt("Tool", "\\u5de5\\u5177")}: {String(item?.tool || "-")}</div>
                          </div>
                        );
                      }) : (
                        <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-500">
                          {tt("No findings linked to this service.", "\\u8be5\\u670d\\u52a1\\u6682\\u65e0\\u5173\\u8054\\u53d1\\u73b0")}
                        </div>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          ) : null}

          {otherAssets.length ? (
            <div className="mt-5 space-y-2">
              {otherAssets.map((asset) => {
                const relatedFindings = Array.isArray(linkedFindingsByAsset.get(asset.id)) ? linkedFindingsByAsset.get(asset.id) : [];
                return (
                  <div key={asset.id} className="rounded-2xl border border-slate-200 bg-white/70 px-4 py-3 shadow-sm">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold break-all">{assetDisplayName(asset)}</div>
                        <div className="mt-1 text-xs text-slate-500">{tt("Source", "\\u6765\\u6e90")}: {asset.source_tool || "-"}</div>
                      </div>
                      <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">{String(asset.kind || "asset")}</span>
                    </div>
                    <div className="mt-2 text-xs text-slate-600">{tt("Linked Findings", "\\u5173\\u8054\\u53d1\\u73b0")}: <span className="font-medium text-slate-800">{relatedFindings.length}</span></div>
                  </div>
                );
              })}
            </div>
          ) : null}
        </div>
      );
    }

    function VulnerabilityCard({ item }) {
      const severity = String(item?.severity || "medium").toLowerCase();
      const steps = Array.isArray(item?.reproduction_steps) ? item.reproduction_steps : [];
      return (
        <div className="glass rounded-2xl p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm text-slate-500">{tt("Finding", "发现")} #{item.index}</div>
              <h3 className="mt-1 text-lg font-semibold">{item.name}</h3>
            </div>
            <span className={"rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wider " + (severityBadge[severity] || severityBadge.medium)}>
              {severity}
            </span>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Evidence", "证据")}</div>
              <pre className="mt-2 max-h-56 overflow-auto rounded-xl bg-slate-900 p-3 text-xs leading-relaxed text-slate-100 whitespace-pre-wrap">
{String(item.evidence || tt("No evidence provided.", "未提供证据。"))}
              </pre>
            </div>
            <div className="space-y-4">
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Reproduction Steps", "复现步骤")}</div>
                <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-slate-700">
                  {steps.length ? steps.map((s, idx) => <li key={idx}>{s}</li>) : <li>{tt("No steps provided.", "未提供步骤。")}</li>}
                </ol>
              </div>
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-emerald-700">{tt("Fix Guidance", "修复建议")}</div>
                <p className="mt-1 text-sm text-emerald-900 leading-relaxed">
                  {item.recommendation || tt("No remediation recommendation provided.", "未提供修复建议。")}
                </p>
              </div>
            </div>
          </div>
        </div>
      );
    }

    function ReconSection({ recon }) {
      if (!recon) return null;
      const ti = recon.target_info || {};
      const tls = recon.tls_certificate || {};
      const subdomains = Array.isArray(recon.subdomains) ? recon.subdomains : [];
      const waf = Array.isArray(recon.waf_cdn) ? recon.waf_cdn : [];
      const tech = Array.isArray(recon.tech_stack) ? recon.tech_stack : [];
      const policies = recon.security_policies || {};
      const stxt = policies.security_txt || {};
      const csp = policies.csp_evaluation || {};
      const cookies = Array.isArray(policies.cookies) ? policies.cookies : [];
      const login = Array.isArray(recon.login_forms) ? recon.login_forms : [];
      const schemas = Array.isArray(recon.api_schemas) ? recon.api_schemas : [];
      const git = Array.isArray(recon.git_exposures) ? recon.git_exposures : [];
      const smaps = Array.isArray(recon.source_maps) ? recon.source_maps : [];
      const ps = recon.ports_services || {};
      const ports = Array.isArray(ps.ports) ? ps.ports : [];
      const hdrs = recon.http_headers || {};
      const markers = Array.isArray(recon.error_page_markers) ? recon.error_page_markers : [];
      const hasData = Object.keys(tls).length || subdomains.length || waf.length || tech.length || cookies.length || login.length || schemas.length || git.length || smaps.length || ports.length || Object.keys(hdrs).length || markers.length || Object.keys(stxt).length || Object.keys(csp).length;
      if (!hasData) return null;

      const Chip = ({ label, color }) => (
        <span className={"inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold mr-1.5 mb-1 " + (color || "bg-slate-100 text-slate-600")}>{label}</span>
      );
      const KV = ({ k, v }) => <div className="flex justify-between text-sm"><span className="text-slate-500">{k}</span><span className="font-medium tabular-nums">{v}</span></div>;

      return (
        <div className="mt-6">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-lg font-semibold">{tt("Reconnaissance & Information Gathering", "侦察与信息收集")}</h2>
            <div className="text-xs text-slate-500">{tt("Data collected from passive and active scanning", "来自被动与主动扫描的数据")}</div>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {/* TLS */}
            {Object.keys(tls).length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("SSL / TLS Certificate", "SSL / TLS 证书")}</div>
                <div className="space-y-1">
                  <KV k={tt("Host", "主机")} v={String(tls.host || "-") + ":" + String(tls.port || 443)} />
                  <KV k={tt("TLS Version", "TLS 版本")} v={tls.tls_version || "-"} />
                  <KV k={tt("Days Left", "剩余天数")} v={tls.days_left ?? "-"} />
                  <KV k={tt("Expires", "到期时间")} v={tls.expires_at || "-"} />
                  {Array.isArray(tls.subject_alt_name) && tls.subject_alt_name.length > 0 && (
                    <div className="mt-2">
                      <div className="text-xs text-slate-500 mb-1">SAN</div>
                      <div className="flex flex-wrap">{tls.subject_alt_name.map((e, i) => <Chip key={i} label={Array.isArray(e) ? e.join("=") : String(e)} />)}</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Subdomains */}
            {subdomains.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Subdomains", "子域名")} ({subdomains.length})</div>
                <div className="max-h-48 overflow-auto rounded-xl bg-slate-50 p-2 text-xs space-y-0.5">
                  {subdomains.slice(0, 40).map((s, i) => <div key={i} className="break-all">{s}</div>)}
                  {subdomains.length > 40 && <div className="text-slate-400">... {subdomains.length - 40} {tt("more", "条")}</div>}
                </div>
              </div>
            )}

            {/* WAF / CDN */}
            {waf.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("WAF / CDN", "WAF / CDN")}</div>
                <div className="flex flex-wrap">{waf.map((w, i) => <Chip key={i} label={w} color="bg-amber-100 text-amber-700" />)}</div>
              </div>
            )}

            {/* Tech Stack */}
            {tech.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Technology Stack", "技术栈")}</div>
                <div className="flex flex-wrap">{tech.map((t, i) => <Chip key={i} label={t} color="bg-cyan-100 text-cyan-700" />)}</div>
              </div>
            )}

            {/* Ports */}
            {ports.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Open Ports", "开放端口")} ({ports.length})</div>
                <div className="max-h-48 overflow-auto text-xs space-y-0.5">
                  {ports.slice(0, 20).map((p, i) => (
                    <div key={i} className="flex justify-between">
                      <span>{typeof p === "object" ? (p.port + "/" + (p.protocol || "-")) : p}</span>
                      <span className="text-slate-500">{typeof p === "object" ? (p.service || "-") : ""}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* HTTP Headers */}
            {Object.keys(hdrs).length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("HTTP Headers", "HTTP 响应头")}</div>
                <div className="max-h-48 overflow-auto text-xs space-y-0.5">
                  {Object.entries(hdrs).map(([k, v], i) => (
                    <div key={i}><span className="font-medium">{k}:</span> <span className="text-slate-600 break-all">{String(v)}</span></div>
                  ))}
                </div>
              </div>
            )}

            {/* CSP */}
            {Object.keys(csp).length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Content Security Policy", "内容安全策略")}</div>
                <div className="space-y-1">
                  <KV k={tt("Present", "是否存在")} v={csp.present ? tt("Yes", "是") : tt("No", "否")} />
                  {csp.present && <KV k="script-src" v={csp.has_script_src ? tt("Yes", "是") : tt("No", "否")} />}
                  {csp.present && <KV k="default-src" v={csp.has_default_src ? tt("Yes", "是") : tt("No", "否")} />}
                  {Array.isArray(csp.risky_tokens) && csp.risky_tokens.length > 0 && (
                    <div className="mt-2"><div className="flex flex-wrap">{csp.risky_tokens.map((t, i) => <Chip key={i} label={t} color="bg-red-100 text-red-700" />)}</div></div>
                  )}
                </div>
              </div>
            )}

            {/* Cookies */}
            {cookies.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Cookies", "Cookie")} ({cookies.length})</div>
                <div className="max-h-48 overflow-auto text-xs space-y-1">
                  {cookies.map((c, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="font-medium break-all">{c.name || "-"}</span>
                      <Chip label={c.secure ? "Secure" : tt("Not Secure", "非 Secure")} color={c.secure ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"} />
                      <Chip label={c.httponly ? "HttpOnly" : tt("No HttpOnly", "非 HttpOnly")} color={c.httponly ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"} />
                      <Chip label={c.samesite ? "SameSite" : tt("No SameSite", "无 SameSite")} color={c.samesite ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* security.txt */}
            {Object.keys(stxt).length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">security.txt</div>
                <div className="space-y-1">
                  <KV k={tt("Present", "是否存在")} v={stxt.present ? tt("Yes", "是") : tt("No", "否")} />
                  {stxt.present && <KV k={tt("Contact", "联系方式")} v={stxt.has_contact ? tt("Yes", "是") : tt("No", "否")} />}
                  {stxt.present && <KV k={tt("Expires", "过期字段")} v={stxt.has_expires ? tt("Yes", "是") : tt("No", "否")} />}
                </div>
              </div>
            )}

            {/* Login Forms */}
            {login.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Login Forms", "登录表单")} ({login.length})</div>
                <div className="max-h-48 overflow-auto text-xs space-y-1">
                  {login.map((f, i) => (
                    <div key={i}><span className="font-medium">{f.method || "GET"}</span> <span className="text-slate-600 break-all">{f.action || "-"}</span></div>
                  ))}
                </div>
              </div>
            )}

            {/* API Schemas */}
            {schemas.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("API Schemas", "API 架构")} ({schemas.length})</div>
                <div className="max-h-48 overflow-auto text-xs space-y-1">
                  {schemas.map((s, i) => (
                    <div key={i}><Chip label={s.kind || "-"} color="bg-blue-100 text-blue-700" /><span className="break-all">{s.url || "-"}</span></div>
                  ))}
                </div>
              </div>
            )}

            {/* Git Exposures */}
            {git.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("VCS Exposures", "版本库泄露")} ({git.length})</div>
                <div className="max-h-48 overflow-auto text-xs space-y-1">
                  {git.map((g, i) => (
                    <div key={i}><Chip label={g.type || "-"} color="bg-red-100 text-red-700" /><span className="break-all">{g.url || "-"}</span></div>
                  ))}
                </div>
              </div>
            )}

            {/* Source Maps */}
            {smaps.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Source Maps", "Source Map")} ({smaps.length})</div>
                <div className="max-h-48 overflow-auto text-xs space-y-0.5">
                  {smaps.slice(0, 15).map((s, i) => <div key={i} className="break-all">{s}</div>)}
                </div>
              </div>
            )}

            {/* Error Page Markers */}
            {markers.length > 0 && (
              <div className="glass rounded-2xl p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">{tt("Error Page Markers", "错误页标记")}</div>
                <div className="flex flex-wrap">{markers.map((m, i) => <Chip key={i} label={m} color="bg-orange-100 text-orange-700" />)}</div>
              </div>
            )}
          </div>
        </div>
      );
    }

    function signedDelta(value) {
      const numeric = Number(value || 0);
      return numeric > 0 ? "+" + numeric : String(numeric);
    }

    function VerificationRankingPanel({ blocks }) {
      const safeBlocks = Array.isArray(blocks) ? blocks : [];
      if (!safeBlocks.length) return null;
      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Verification Context", "\\u9a8c\\u8bc1\\u4e0a\\u4e0b\\u6587")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Verification Ranking", "\\u9a8c\\u8bc1\\u6392\\u5e8f\\u89e3\\u91ca")}</h2>
            </div>
            <div className="text-xs text-slate-500">{tt("Explain why a CVE or PoC was selected first during verification.", "\\u89e3\\u91ca\\u4e3a\\u4f55\\u5728\\u9a8c\\u8bc1\\u9636\\u6bb5\\u5148\\u9009\\u62e9\\u67d0\\u4e2a CVE \\u6216 PoC\\u3002")}</div>
          </div>
          <div className="mt-4 space-y-4">
            {safeBlocks.map((block, blockIndex) => {
              const items = Array.isArray(block?.items) ? block.items : [];
              const selectedTemplates = Array.isArray(block?.selected_templates) ? block.selected_templates : [];
              return (
                <article key={(block.tool || "tool") + "-" + blockIndex} className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold">{block.tool || "-"}</div>
                      <div className="mt-1 text-xs text-slate-500 break-all">
                        {tt("Target", "\\u76ee\\u6807")}: {block.target || "-"} | {tt("Component", "\\u7ec4\\u4ef6")}: {block.component || "-"} | {tt("Service", "\\u670d\\u52a1")}: {block.service || "-"} | {tt("Version", "\\u7248\\u672c")}: {block.version || "-"}
                      </div>
                    </div>
                    <span className="rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-white">
                      {block.selected_candidate || "-"}
                    </span>
                  </div>
                  {selectedTemplates.length ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {selectedTemplates.slice(0, 8).map((item) => (
                        <span key={(block.tool || "tool") + "-" + item} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">
                          {item}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <div className="mt-3 space-y-3">
                    {items.map((item) => {
                      const reasons = Array.isArray(item?.reasons) ? item.reasons : [];
                      const protocolTags = Array.isArray(item?.template_capability?.protocol_tags) ? item.template_capability.protocol_tags : [];
                      return (
                        <div key={(block.tool || "tool") + "-" + (item.cve_id || "candidate")} className={"rounded-xl border px-3 py-3 " + (item.selected ? "border-cyan-300 bg-cyan-50/60" : "border-slate-200 bg-slate-50/60")}>
                          <div className="flex items-center justify-between gap-3">
                            <div className="text-sm font-medium">{item.cve_id || "-"}</div>
                            <div className="text-xs text-slate-600">
                              {(item.severity || "info").toUpperCase()}
                              {item.rank ? " #" + item.rank : ""}
                              {" | CVSS "}
                              {item.cvss_score ?? "-"}
                            </div>
                          </div>
                          {protocolTags.length ? (
                            <div className="mt-2 flex flex-wrap gap-2">
                              {protocolTags.map((tag) => (
                                <span key={(item.cve_id || "candidate") + "-" + tag} className="rounded-full bg-slate-100 px-2.5 py-1 text-[11px] font-medium">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          ) : null}
                          <div className="mt-2 space-y-1 text-xs text-slate-600">
                            {reasons.length ? reasons.slice(0, 5).map((reason) => (
                              <div key={(item.cve_id || "candidate") + "-" + reason}>- {reason}</div>
                            )) : (
                              <div>{tt("No detailed ranking reason recorded.", "\\u672a\\u8bb0\\u5f55\\u66f4\\u7ec6\\u7684\\u6392\\u5e8f\\u4f9d\\u636e\\u3002")}</div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </article>
              );
            })}
          </div>
        </div>
      );
    }

    function ExecutionHistoryPanel({ rows }) {
      const safeRows = Array.isArray(rows) ? rows : [];
      if (!safeRows.length) return null;
      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Execution Context", "\\u6267\\u884c\\u4e0a\\u4e0b\\u6587")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("Executed Actions and Selection Rationale", "\\u5df2\\u6267\\u884c\\u52a8\\u4f5c\\u4e0e\\u9009\\u62e9\\u539f\\u56e0")}</h2>
            </div>
            <div className="text-xs text-slate-500">{tt("Track why each executed action was selected.", "\\u8ffd\\u8e2a\\u6bcf\\u4e2a\\u5df2\\u6267\\u884c\\u52a8\\u4f5c\\u4e3a\\u4f55\\u88ab\\u9009\\u4e2d\\u3002")}</div>
          </div>
          <div className="mt-4 space-y-4">
            {safeRows.map((row, index) => {
              const explanation = row && typeof row.ranking_explanation === "object" ? row.ranking_explanation : {};
              const reasons = Array.isArray(explanation?.reasons) ? explanation.reasons : [];
              const selectedTemplates = Array.isArray(explanation?.selected_templates) ? explanation.selected_templates : [];
              const candidateOrder = Array.isArray(explanation?.candidate_order) ? explanation.candidate_order : [];
              return (
                <article key={(row?.tool || "tool") + "-" + (row?.target || "target") + "-" + index} className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold">{row?.tool || "-"}</div>
                      <div className="mt-1 text-xs text-slate-500 break-all">
                        {tt("Target", "\\u76ee\\u6807")}: {row?.target || "-"} | {tt("Phase", "\\u9636\\u6bb5")}: {row?.phase || "-"} | {tt("Status", "\\u72b6\\u6001")}: {row?.status || "-"}
                      </div>
                    </div>
                    {explanation?.selected_candidate ? (
                      <span className="rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-white">
                        {explanation.selected_candidate}
                      </span>
                    ) : null}
                  </div>
                  {selectedTemplates.length ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {selectedTemplates.slice(0, 8).map((item) => (
                        <span key={(row?.tool || "tool") + "-template-" + item} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium">
                          {item}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <div className="mt-3 grid gap-2 text-xs text-slate-600 md:grid-cols-4">
                    <div>{tt("Cost", "\\u6210\\u672c")}: <span className="font-medium text-slate-900">{row?.action_cost ?? 0}</span></div>
                    <div>{tt("Budget Before", "\\u6267\\u884c\\u524d\\u9884\\u7b97")}: <span className="font-medium text-slate-900">{row?.budget_before ?? "-"}</span></div>
                    <div>{tt("Budget After", "\\u6267\\u884c\\u540e\\u9884\\u7b97")}: <span className="font-medium text-slate-900">{row?.budget_after ?? "-"}</span></div>
                    <div>{tt("Retry Attempts", "\\u91cd\\u8bd5\\u6b21\\u6570")}: <span className="font-medium text-slate-900">{row?.retry_attempts ?? "-"}</span></div>
                  </div>
                  {candidateOrder.length ? (
                    <div className="mt-2 text-xs text-slate-500 break-all">
                      {tt("Candidate Order", "\\u5019\\u9009\\u987a\\u5e8f")}: {candidateOrder.join(", ")}
                    </div>
                  ) : null}
                  <div className="mt-2 space-y-1 text-xs text-slate-600">
                    {reasons.length ? reasons.slice(0, 8).map((reason) => (
                      <div key={(row?.tool || "tool") + "-reason-" + reason}>- {reason}</div>
                    )) : (
                      <div>{tt("No detailed ranking reason recorded.", "\\u672a\\u8bb0\\u5f55\\u66f4\\u7ec6\\u7684\\u6392\\u5e8f\\u4f9d\\u636e\\u3002")}</div>
                    )}
                  </div>
                  {row?.error ? (
                    <div className="mt-3 rounded-xl border border-rose-200 bg-rose-50/70 px-3 py-2 text-xs text-rose-700 break-all">
                      {row.error}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        </div>
      );
    }

    function AssetTrendPanels({ phaseRows, batchRows }) {
      const safePhaseRows = Array.isArray(phaseRows) ? phaseRows : [];
      const safeBatchRows = Array.isArray(batchRows) ? batchRows : [];
      if (!safePhaseRows.length && !safeBatchRows.length) return null;
      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Asset Trends", "\\u8d44\\u4ea7\\u8d70\\u52bf")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("By Phase / By Batch", "\\u6309\\u9636\\u6bb5 / \\u6309\\u6279\\u6b21\\u5bf9\\u6bd4")}</h2>
            </div>
            <div className="text-xs text-slate-500">{tt("Compare the current run by phase and the target history by batch.", "\\u540c\\u65f6\\u5bf9\\u6bd4\\u5f53\\u524d\\u8fd0\\u884c\\u7684\\u9636\\u6bb5\\u63a8\\u8fdb\\u548c\\u540c\\u76ee\\u6807\\u5386\\u53f2\\u6279\\u6b21\\u53d8\\u5316\\u3002")}</div>
          </div>

          {safePhaseRows.length ? (
            <div className="mt-4">
              <div className="mb-3 text-sm font-semibold">{tt("Phase Trends", "\\u9636\\u6bb5\\u8d70\\u52bf")}</div>
              <div className="space-y-3">
                {safePhaseRows.map((row) => (
                  <div key={"phase-" + row.phase} className={"rounded-xl border px-3 py-3 " + (row.is_current ? "border-cyan-300 bg-cyan-50/60" : "border-slate-200 bg-slate-50/60")}>
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-medium">{row.phase || "-"}</div>
                      <div className="text-xs text-slate-600">{tt("Actions", "\\u52a8\\u4f5c")}: {row.executed_actions || 0}</div>
                    </div>
                    <div className="mt-2 grid gap-2 text-xs text-slate-600 md:grid-cols-5">
                      <div>{tt("Tools", "\\u5de5\\u5177")}: <span className="font-medium text-slate-900">{row.unique_tools || 0}</span></div>
                      <div>{tt("Assets", "\\u8d44\\u4ea7")}: <span className="font-medium text-slate-900">{row.asset_count || 0}</span></div>
                      <div>{tt("Services", "\\u670d\\u52a1")}: <span className="font-medium text-slate-900">{row.service_assets || 0}</span></div>
                      <div>{tt("Findings", "\\u53d1\\u73b0")}: <span className="font-medium text-slate-900">{row.finding_count || 0}</span></div>
                      <div>{tt("Asset Delta", "\\u8d44\\u4ea7\\u589e\\u91cf")}: <span className="font-medium text-slate-900">{signedDelta(row.delta_assets)}</span></div>
                    </div>
                    {Array.isArray(row.tool_names) && row.tool_names.length ? (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {row.tool_names.slice(0, 8).map((tool) => (
                          <span key={row.phase + "-" + tool} className="rounded-full bg-slate-100 px-2.5 py-1 text-[11px] font-medium">{tool}</span>
                        ))}
                      </div>
                    ) : null}
                    {row.reason ? <div className="mt-2 text-xs text-slate-500">{row.reason}</div> : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {safeBatchRows.length ? (
            <div className="mt-6">
              <div className="mb-3 text-sm font-semibold">{tt("Run Batch Trends", "\\u8fd0\\u884c\\u6279\\u6b21\\u8d70\\u52bf")}</div>
              <div className="space-y-3">
                {safeBatchRows.map((row) => (
                  <div key={"batch-" + row.job_id} className={"rounded-xl border px-3 py-3 " + (row.is_current ? "border-cyan-300 bg-cyan-50/60" : "border-slate-200 bg-slate-50/60")}>
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-medium break-all">{row.job_id || "-"}</div>
                      <div className="text-xs text-slate-500">{row.ended_at || row.updated_at || "-"}</div>
                    </div>
                    <div className="mt-2 grid gap-2 text-xs text-slate-600 md:grid-cols-5">
                      <div>{tt("Assets", "\\u8d44\\u4ea7")}: <span className="font-medium text-slate-900">{row.total_assets || 0}</span></div>
                      <div>{tt("Services", "\\u670d\\u52a1")}: <span className="font-medium text-slate-900">{row.service_assets || 0}</span></div>
                      <div>{tt("Findings", "\\u53d1\\u73b0")}: <span className="font-medium text-slate-900">{row.finding_total || 0}</span></div>
                      <div>{tt("Asset Delta", "\\u8d44\\u4ea7\\u589e\\u91cf")}: <span className="font-medium text-slate-900">{signedDelta(row.delta_assets)}</span></div>
                      <div>{tt("Finding Delta", "\\u53d1\\u73b0\\u589e\\u91cf")}: <span className="font-medium text-slate-900">{signedDelta(row.delta_findings)}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      );
    }

    function BaselineDiffPanel({ diff }) {
      const safeDiff = diff && typeof diff === "object" ? diff : {};
      const newFindings = Array.isArray(safeDiff.new_findings) ? safeDiff.new_findings : [];
      const resolvedFindings = Array.isArray(safeDiff.resolved_findings) ? safeDiff.resolved_findings : [];
      const newAssets = Array.isArray(safeDiff.new_assets) ? safeDiff.new_assets : [];
      const resolvedAssets = Array.isArray(safeDiff.resolved_assets) ? safeDiff.resolved_assets : [];
      const newServices = Array.isArray(safeDiff.new_services) ? safeDiff.new_services : [];
      const resolvedServices = Array.isArray(safeDiff.resolved_services) ? safeDiff.resolved_services : [];
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const newAssetSeverity = safeDiff.new_asset_severity_counts && typeof safeDiff.new_asset_severity_counts === "object" ? safeDiff.new_asset_severity_counts : {};
      const resolvedAssetSeverity = safeDiff.resolved_asset_severity_counts && typeof safeDiff.resolved_asset_severity_counts === "object" ? safeDiff.resolved_asset_severity_counts : {};
      const persistentAssetSeverity = safeDiff.persistent_asset_severity_counts && typeof safeDiff.persistent_asset_severity_counts === "object" ? safeDiff.persistent_asset_severity_counts : {};
      const newServiceProtocols = Array.isArray(safeDiff.new_service_protocol_counts) ? safeDiff.new_service_protocol_counts : [];
      const resolvedServiceProtocols = Array.isArray(safeDiff.resolved_service_protocol_counts) ? safeDiff.resolved_service_protocol_counts : [];
      const persistentServiceProtocols = Array.isArray(safeDiff.persistent_service_protocol_counts) ? safeDiff.persistent_service_protocol_counts : [];
      const renderAssetEntries = (items, emptyText, tone) => (
        <div className={"rounded-2xl border p-4 " + tone}>
          <div className="mt-3 space-y-2">
            {items.length ? items.map((item, index) => (
              <div key={(item.id || item.display_name || "item") + "-" + index} className="rounded-xl border border-white/70 bg-white/80 px-3 py-2">
                <div className="text-sm font-medium break-all">{item.display_name || item.id || "-"}</div>
                <div className="mt-1 text-xs text-slate-600 break-all">
                  {(item.kind || "asset").toUpperCase()}
                  {item.service ? " | " + item.service : ""}
                  {item.port ? " | " + tt("Port", "\\u7aef\\u53e3") + " " + item.port : ""}
                  {item.source_tool ? " | " + tt("Source", "\\u6765\\u6e90") + " " + item.source_tool : ""}
                </div>
              </div>
            )) : (
              <div className="text-sm text-slate-500">{emptyText}</div>
            )}
          </div>
        </div>
      );
      const renderCountChips = (counts, emptyText) => {
        const entries = severityOrder
          .map((level) => [level, Number(counts?.[level] || 0)])
          .filter(([, value]) => value > 0);
        if (!entries.length) {
          return <div className="text-sm text-slate-500">{emptyText}</div>;
        }
        return (
          <div className="flex flex-wrap gap-2">
            {entries.map(([label, value]) => (
              <span key={"severity-" + label} className="rounded-full bg-white px-3 py-1 text-xs font-medium">
                {String(label).toUpperCase()} x{value}
              </span>
            ))}
          </div>
        );
      };
      const renderProtocolChips = (rows, emptyText) => {
        if (!rows.length) {
          return <div className="text-sm text-slate-500">{emptyText}</div>;
        }
        return (
          <div className="flex flex-wrap gap-2">
            {rows.slice(0, 10).map((row, index) => (
              <span key={"protocol-" + (row.label || "row") + "-" + index} className="rounded-full bg-white px-3 py-1 text-xs font-medium">
                {row.label || "-"} x{row.count || 0}
              </span>
            ))}
          </div>
        );
      };
      if (!safeDiff.baseline_job_id && !newFindings.length && !resolvedFindings.length && !newAssets.length && !resolvedAssets.length && !newServices.length && !resolvedServices.length) {
        return null;
      }
      return (
        <div className="mt-6 glass rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-500">{tt("Baseline Comparison", "\\u57fa\\u7ebf\\u5bf9\\u6bd4")}</div>
              <h2 className="mt-1 text-lg font-semibold">{tt("New / Resolved Since Previous Batch", "\\u76f8\\u5bf9\\u4e0a\\u4e00\\u6279\\u6b21\\u7684\\u65b0\\u589e / \\u5df2\\u89e3\\u51b3")}</h2>
            </div>
            <div className="text-xs text-slate-500 break-all">
              {safeDiff.baseline_job_id
                ? tt("Baseline", "\\u57fa\\u7ebf") + ": " + safeDiff.baseline_job_id
                : tt("No earlier baseline available.", "\\u6682\\u65e0\\u66f4\\u65e9\\u57fa\\u7ebf\\u3002")}
            </div>
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-3 xl:grid-cols-6">
            <MetricCard label={tt("New Findings", "\\u65b0\\u589e\\u53d1\\u73b0")} value={safeDiff.new_count ?? 0} sub={tt("Current batch only", "\\u4ec5\\u5f53\\u524d\\u6279\\u6b21")} />
            <MetricCard label={tt("Resolved Findings", "\\u5df2\\u89e3\\u51b3\\u53d1\\u73b0")} value={safeDiff.resolved_count ?? 0} sub={tt("Missing from current batch", "\\u5f53\\u524d\\u6279\\u6b21\\u5df2\\u4e0d\\u518d\\u51fa\\u73b0")} />
            <MetricCard label={tt("Persistent Findings", "\\u6301\\u7eed\\u5b58\\u5728")} value={safeDiff.persistent_count ?? 0} sub={tt("Still present", "\\u4ecd\\u7136\\u5b58\\u5728")} />
            <MetricCard label={tt("New Assets", "\\u65b0\\u589e\\u8d44\\u4ea7")} value={safeDiff.new_assets_count ?? 0} sub={tt("Asset inventory delta", "\\u8d44\\u4ea7\\u5e93\\u589e\\u91cf")} />
            <MetricCard label={tt("Resolved Assets", "\\u5df2\\u79fb\\u9664\\u8d44\\u4ea7")} value={safeDiff.resolved_assets_count ?? 0} sub={tt("Missing from current batch", "\\u5f53\\u524d\\u6279\\u6b21\\u5df2\\u4e0d\\u518d\\u51fa\\u73b0")} />
            <MetricCard label={tt("Service Delta", "\\u670d\\u52a1\\u589e\\u91cf")} value={(safeDiff.new_services_count ?? 0) - (safeDiff.resolved_services_count ?? 0)} sub={tt("Added minus resolved services", "\\u65b0\\u589e\\u670d\\u52a1\\u51cf\\u5df2\\u89e3\\u51b3\\u670d\\u52a1")} />
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            <div className="rounded-2xl border border-emerald-200 bg-emerald-50/70 p-4">
              <div className="text-sm font-semibold text-emerald-700">{tt("New Findings", "\\u65b0\\u589e\\u53d1\\u73b0")}</div>
              <div className="mt-3 space-y-2">
                {newFindings.length ? newFindings.map((item, index) => (
                  <div key={"new-" + index} className="rounded-xl border border-emerald-200 bg-white/70 px-3 py-2">
                    <div className="text-sm font-medium">{item.name || "-"}</div>
                    <div className="mt-1 text-xs text-slate-600">{String(item.severity || "info").toUpperCase()}{item.cve_id ? " | " + item.cve_id : ""}</div>
                  </div>
                )) : (
                  <div className="text-sm text-slate-500">{tt("No new findings relative to the baseline.", "\\u76f8\\u5bf9\\u57fa\\u7ebf\\u6ca1\\u6709\\u65b0\\u589e\\u53d1\\u73b0\\u3002")}</div>
                )}
              </div>
            </div>
            <div className="rounded-2xl border border-sky-200 bg-sky-50/70 p-4">
              <div className="text-sm font-semibold text-sky-700">{tt("Resolved Findings", "\\u5df2\\u89e3\\u51b3\\u53d1\\u73b0")}</div>
              <div className="mt-3 space-y-2">
                {resolvedFindings.length ? resolvedFindings.map((item, index) => (
                  <div key={"resolved-" + index} className="rounded-xl border border-sky-200 bg-white/70 px-3 py-2">
                    <div className="text-sm font-medium">{item.name || "-"}</div>
                    <div className="mt-1 text-xs text-slate-600">{String(item.severity || "info").toUpperCase()}{item.cve_id ? " | " + item.cve_id : ""}</div>
                  </div>
                )) : (
                  <div className="text-sm text-slate-500">{tt("No resolved findings relative to the baseline.", "\\u76f8\\u5bf9\\u57fa\\u7ebf\\u6682\\u65e0\\u5df2\\u89e3\\u51b3\\u9879\\u3002")}</div>
                )}
              </div>
            </div>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            <div className="space-y-4">
              <div className="text-sm font-semibold text-slate-700">{tt("Asset Inventory Changes", "\\u8d44\\u4ea7\\u5e93\\u53d8\\u66f4")}</div>
              {renderAssetEntries(
                newAssets,
                tt("No new assets relative to the baseline.", "\\u76f8\\u5bf9\\u57fa\\u7ebf\\u6ca1\\u6709\\u65b0\\u589e\\u8d44\\u4ea7\\u3002"),
                "border-violet-200 bg-violet-50/70",
              )}
              {renderAssetEntries(
                resolvedAssets,
                tt("No resolved assets relative to the baseline.", "\\u76f8\\u5bf9\\u57fa\\u7ebf\\u6682\\u65e0\\u5df2\\u79fb\\u9664\\u8d44\\u4ea7\\u3002"),
                "border-slate-200 bg-slate-50/70",
              )}
            </div>
            <div className="space-y-4">
              <div className="text-sm font-semibold text-slate-700">{tt("Service Changes", "\\u670d\\u52a1\\u53d8\\u66f4")}</div>
              {renderAssetEntries(
                newServices,
                tt("No new services relative to the baseline.", "\\u76f8\\u5bf9\\u57fa\\u7ebf\\u6ca1\\u6709\\u65b0\\u589e\\u670d\\u52a1\\u3002"),
                "border-cyan-200 bg-cyan-50/70",
              )}
              {renderAssetEntries(
                resolvedServices,
                tt("No resolved services relative to the baseline.", "\\u76f8\\u5bf9\\u57fa\\u7ebf\\u6682\\u65e0\\u5df2\\u89e3\\u51b3\\u670d\\u52a1\\u3002"),
                "border-sky-200 bg-sky-50/70",
              )}
            </div>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            <div className="rounded-2xl border border-amber-200 bg-amber-50/70 p-4">
              <div className="text-sm font-semibold text-amber-700">{tt("Asset Severity Breakdown", "\\u8d44\\u4ea7\\u4e25\\u91cd\\u7ea7\\u5206\\u5e03")}</div>
              <div className="mt-3 space-y-3">
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{tt("New Assets", "\\u65b0\\u589e\\u8d44\\u4ea7")}</div>
                  {renderCountChips(newAssetSeverity, tt("No new asset severity signal.", "\\u6682\\u65e0\\u65b0\\u589e\\u8d44\\u4ea7\\u4e25\\u91cd\\u7ea7\\u4fe1\\u53f7\\u3002"))}
                </div>
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{tt("Resolved Assets", "\\u5df2\\u79fb\\u9664\\u8d44\\u4ea7")}</div>
                  {renderCountChips(resolvedAssetSeverity, tt("No resolved asset severity signal.", "\\u6682\\u65e0\\u5df2\\u79fb\\u9664\\u8d44\\u4ea7\\u4e25\\u91cd\\u7ea7\\u4fe1\\u53f7\\u3002"))}
                </div>
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{tt("Persistent Assets", "\\u6301\\u7eed\\u5b58\\u5728\\u8d44\\u4ea7")}</div>
                  {renderCountChips(persistentAssetSeverity, tt("No persistent asset severity signal.", "\\u6682\\u65e0\\u6301\\u7eed\\u8d44\\u4ea7\\u4e25\\u91cd\\u7ea7\\u4fe1\\u53f7\\u3002"))}
                </div>
              </div>
            </div>
            <div className="rounded-2xl border border-indigo-200 bg-indigo-50/70 p-4">
              <div className="text-sm font-semibold text-indigo-700">{tt("Service Protocol Breakdown", "\\u670d\\u52a1\\u534f\\u8bae\\u5206\\u5e03")}</div>
              <div className="mt-3 space-y-3">
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{tt("New Services", "\\u65b0\\u589e\\u670d\\u52a1")}</div>
                  {renderProtocolChips(newServiceProtocols, tt("No new protocol changes.", "\\u6682\\u65e0\\u65b0\\u534f\\u8bae\\u53d8\\u5316\\u3002"))}
                </div>
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{tt("Resolved Services", "\\u5df2\\u89e3\\u51b3\\u670d\\u52a1")}</div>
                  {renderProtocolChips(resolvedServiceProtocols, tt("No resolved protocol changes.", "\\u6682\\u65e0\\u5df2\\u89e3\\u51b3\\u7684\\u534f\\u8bae\\u53d8\\u5316\\u3002"))}
                </div>
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{tt("Persistent Services", "\\u6301\\u7eed\\u5b58\\u5728\\u670d\\u52a1")}</div>
                  {renderProtocolChips(persistentServiceProtocols, tt("No persistent protocol changes.", "\\u6682\\u65e0\\u6301\\u7eed\\u534f\\u8bae\\u5206\\u5e03\\u53d8\\u5316\\u3002"))}
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    }

    function App() {
      const summary = auditReport.summary || {};
      const meta = auditReport.meta || {};
      const scopePayload = auditReport.scope || {};
      const visualAnalysis = auditReport.visual_analysis || {};
      const evidenceGraph = auditReport.evidence_graph || {};
      const cveValidation = auditReport.cve_validation || {};
      const knowledgeContext = auditReport.knowledge_context || {};
      const remediationPriority = Array.isArray(auditReport.remediation_priority) ? auditReport.remediation_priority : [];
      const pathGraph = auditReport.path_graph || {};
      const recon = auditReport.recon || {};
      const findings = Array.isArray(auditReport.findings) ? auditReport.findings : [];
      const executionHistory = Array.isArray(auditReport.history) ? auditReport.history : [];
      const verificationRanking = Array.isArray(visualAnalysis.verification_ranking) ? visualAnalysis.verification_ranking : [];
      const assetPhaseTrends = Array.isArray(visualAnalysis.asset_phase_trends) ? visualAnalysis.asset_phase_trends : [];
      const assetBatchTrends = Array.isArray(visualAnalysis.asset_batch_trends) ? visualAnalysis.asset_batch_trends : [];
      const batchDiff = visualAnalysis.batch_diff || {};
      const vulnFindings = findings
        .filter((f) => String(f.type || "").toLowerCase() === "vuln")
        .sort((a, b) => severityRank.indexOf(String(a.severity || "info")) - severityRank.indexOf(String(b.severity || "info")));
      const severityCounts = summary.severity_counts || {};
      const highCritical = Number(severityCounts.critical || 0) + Number(severityCounts.high || 0);

      return (
        <div className="mx-auto max-w-7xl px-4 py-8 md:px-6">
          <div className="glass rounded-3xl p-6">
            <div className="flex flex-wrap items-start justify-between gap-5">
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">{tt("AutoSecAudit Agent", "AutoSecAudit \\u667a\\u80fd\\u4f53")}</div>
                <h1 className="mt-2 text-2xl font-semibold md:text-3xl">{tt("Visual Audit Report", "\\u53ef\\u89c6\\u5316\\u5ba1\\u8ba1\\u62a5\\u544a")}</h1>
                <div className="mt-2 break-all text-sm text-slate-700">{meta.target || agentState.target || tt("Unknown target", "\\u672a\\u77e5\\u76ee\\u6807")}</div>
                <div className="mt-1 text-sm text-slate-500 whitespace-pre-wrap break-all">{meta.decision_summary || tt("No decision summary available.", "\\u6682\\u65e0\\u51b3\\u7b56\\u6458\\u8981\\u3002")}</div>
              </div>
              <div className="rounded-2xl bg-slate-900 px-5 py-4 text-white">
                <div className="text-xs uppercase tracking-wider text-slate-300">{tt("Audit Score", "\\u5ba1\\u8ba1\\u8bc4\\u5206")}</div>
                <div className="mt-1 text-3xl font-semibold tabular-nums">{summary.audit_score ?? 0}</div>
                <div className="text-xs text-slate-300">{renderScoreLabel(summary.score_label || "N/A")}</div>
              </div>
            </div>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard label={tt("Findings", "\\u53d1\\u73b0\\u603b\\u6570")} value={summary.total_findings ?? 0} sub={tt("Vulns", "\\u6f0f\\u6d1e") + ": " + (summary.vulnerability_findings ?? 0)} />
            <MetricCard label={tt("High/Critical", "\\u9ad8\\u5371/\\u4e25\\u91cd")} value={highCritical} sub={tt("Critical", "\\u4e25\\u91cd") + " " + (severityCounts.critical || 0) + " / " + tt("High", "\\u9ad8\\u5371") + " " + (severityCounts.high || 0)} />
            <MetricCard label={tt("Budget Remaining", "\\u5269\\u4f59\\u9884\\u7b97")} value={summary.budget_remaining ?? 0} sub={tt("Iterations", "\\u8fed\\u4ee3") + " " + (summary.iteration_count ?? 0)} />
            <MetricCard label={tt("Executed Actions", "\\u6267\\u884c\\u52a8\\u4f5c")} value={summary.history_count ?? 0} sub={meta.resumed ? (tt("Resumed", "\\u7eed\\u8dd1") + ": " + (meta.resumed_from || "state")) : tt("Fresh run", "\\u5168\\u65b0\\u8fd0\\u884c")} />
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <div className="glass rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">{tt("Action Budget Consumption", "\\u9884\\u7b97\\u6d88\\u8017\\u8d70\\u52bf")}</h2>
                <div className="text-xs text-slate-500">{tt("Cumulative cost line chart", "\\u7d2f\\u8ba1\\u6210\\u672c\\u66f2\\u7ebf")}</div>
              </div>
              <div className="mt-4">
                <BudgetLineChart trace={auditReport.budget_trace || []} />
              </div>
            </div>
            <div className="glass rounded-2xl p-5">
              <h2 className="text-lg font-semibold">{tt("Severity Distribution", "\\u4e25\\u91cd\\u6027\\u5206\\u5e03")}</h2>
              <div className="mt-4 space-y-3">
                {severityRank.map((sev) => {
                  const value = Number(severityCounts[sev] || 0);
                  const all = severityRank.map((k) => Number(severityCounts[k] || 0));
                  const max = Math.max(1, ...all);
                  const pct = value ? Math.max(5, Math.round((value / max) * 100)) : 0;
                  return (
                    <div key={sev}>
                      <div className="mb-1 flex justify-between text-sm">
                        <span className="capitalize">{sev}</span>
                        <span className="tabular-nums text-slate-600">{value}</span>
                      </div>
                      <div className="h-2 rounded-full bg-slate-100">
                        <div className="h-2 rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" style={{ width: pct + "%" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="mt-6">
            <ScopeMap scopePayload={scopePayload} />
          </div>

          <RemediationPriorityPanel items={remediationPriority} />

          <div className="mt-6">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-lg font-semibold">{tt("Vulnerability Cards", "\\u6f0f\\u6d1e\\u5361\\u7247")}</h2>
              <div className="text-xs text-slate-500">{tt("Evidence + remediation suggestions", "\\u8bc1\\u636e\\u4e0e\\u4fee\\u590d\\u5efa\\u8bae")}</div>
            </div>
            <div className="space-y-4">
              {vulnFindings.length ? vulnFindings.map((item) => (
                <VulnerabilityCard key={String(item.index) + "-" + String(item.name)} item={item} />
              )) : (
                <div className="glass rounded-2xl p-6 text-sm text-slate-500">{tt("No vulnerability findings available.", "\\u6682\\u65e0\\u6f0f\\u6d1e\\u53d1\\u73b0\\u3002")}</div>
              )}
            </div>
          </div>

          <details className="mt-6 glass rounded-2xl p-5">
            <summary className="cursor-pointer list-none text-sm font-semibold text-slate-900">
              {tt("Technical appendix", "\\u6280\\u672f\\u9644\\u5f55")}
            </summary>
            <div className="mt-5 space-y-6">
              <KnowledgeContextPanel knowledgeContext={knowledgeContext} />

              <EvidenceCorrelationPanel evidenceGraph={evidenceGraph} />

              <CveValidationPanel cveValidation={cveValidation} />

              <AttackPathPanel pathGraph={pathGraph} />

              <div className="mt-6">
                <AssetTopologyPanel scopePayload={scopePayload} findings={findings} />
              </div>

              <VerificationRankingPanel blocks={verificationRanking} />

              <ExecutionHistoryPanel rows={executionHistory} />

              <AssetTrendPanels phaseRows={assetPhaseTrends} batchRows={assetBatchTrends} />

              <BaselineDiffPanel diff={batchDiff} />

              {/* ---------- Reconnaissance Section ---------- */}
              <ReconSection recon={recon} />
            </div>
          </details>
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById("root")).render(<App />);
  </script>
</body>
</html>
"""
    return (
        template.replace("__TITLE__", title)
        .replace("__AUDIT_JSON__", audit_json)
        .replace("__STATE_JSON__", state_json)
        .replace("__HTML_LANG__", html_lang)
    )


def _json_for_html_script_tag(payload: dict[str, Any]) -> str:
    """
    Serialize JSON for embedding inside `<script type="application/json">`.

    Important: do not HTML-escape quotes here, otherwise `JSON.parse()` will
    receive entity text (`&quot;`) and fail. Only neutralize `</script>` sequences.
    """
    serialized = json.dumps(payload, ensure_ascii=False)
    return serialized.replace("</", "<\\/")
