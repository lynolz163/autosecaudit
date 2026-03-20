import { useMemo } from "react";
import StatusBadge from "../StatusBadge";
import { useI18n } from "../../i18n";
import { buildSeverityMap, computeAuditScore, describeAuditScore } from "../../lib/reporting";
import ReportDownloadPanel from "./ReportDownloadPanel";

function renderScoreLabel(value, tt) {
  if (value === "Stable") return tt("Stable", "稳定");
  if (value === "Watch") return tt("Watch", "关注");
  if (value === "At Risk") return tt("At Risk", "有风险");
  if (value === "Action Required") return tt("Action Required", "需要立即处理");
  return value;
}

export default function ReportOverviewPanel({
  report,
  analysis,
  token,
  canAccessRag,
  onOpenRag,
  onOpenFollowUpMission,
}) {
  const { t, language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const findings = useMemo(() => analysis?.findings || [], [analysis]);
  const diff = analysis?.diff || {};
  const history = useMemo(() => analysis?.history || [], [analysis]);
  const severity = useMemo(() => buildSeverityMap(findings), [findings]);
  const auditScore = useMemo(() => computeAuditScore(findings), [findings]);

  if (!report) {
    return (
      <section className="panel">
        <div className="empty-state">{t("reportPreview.empty")}</div>
      </section>
    );
  }

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{tt("Executive summary", "执行摘要")}</p>
            <h3>{report.target || report.job_id}</h3>
            <p className="report-summary-copy">
              {report.decision_summary || tt(
                "Focus on current risk posture, change since the previous run, and the next remediation action.",
                "重点查看当前风险态势、相对上一次运行的变化，以及下一步修复动作。",
              )}
            </p>
          </div>
          <div className="report-summary-actions">
            <StatusBadge status={report.status} />
            <button
              type="button"
              className="ghost-button"
              onClick={() => onOpenFollowUpMission?.({
                composer: `Continue the audit from the evidence in report ${report.job_id} for ${report.target}. Reuse the existing trail and validate the next highest-value path.`,
                form: {
                  target: report.target,
                  mode: "agent",
                  safety_grade: "aggressive",
                  approval_mode: "granted",
                  multi_agent: true,
                },
              })}
            >
              {tt("Continue from this report", "基于此报告继续")}
            </button>
            <button
              type="button"
              className="ghost-button"
              onClick={() => onOpenFollowUpMission?.({
                composer: `Re-validate ${report.target} and verify whether the previously reported issues have been remediated.`,
                form: {
                  target: report.target,
                  mode: "agent",
                  safety_grade: "balanced",
                  approval_mode: "auto",
                  multi_agent: false,
                },
              })}
            >
              {tt("Re-check remediation", "重新验证修复")}
            </button>
            {canAccessRag ? (
              <button type="button" className="ghost-button" onClick={onOpenRag}>
                {tt("Open knowledge base", "打开知识库")}
              </button>
            ) : null}
          </div>
        </div>

        <div className="report-summary-grid">
          <article className="report-summary-card is-score">
            <span className="report-summary-label">{tt("Audit score", "审计得分")}</span>
            <strong>{auditScore}</strong>
            <p>{renderScoreLabel(describeAuditScore(auditScore), tt)}</p>
          </article>
          <article className="report-summary-card">
            <span className="report-summary-label">{tt("Findings", "发现数")}</span>
            <strong>{report.finding_total || findings.length || 0}</strong>
            <p>{tt("Critical", "严重")} {severity.critical} / {tt("High", "高危")} {severity.high}</p>
          </article>
          <article className="report-summary-card">
            <span className="report-summary-label">{tt("Net change", "净变化")}</span>
            <strong>{(diff.new_count || 0) - (diff.resolved_count || 0)}</strong>
            <p>{tt("New", "新增")} {diff.new_count || 0} / {tt("Resolved", "已解决")} {diff.resolved_count || 0}</p>
          </article>
          <article className="report-summary-card">
            <span className="report-summary-label">{tt("History", "历史")}</span>
            <strong>{analysis?.history_count || history.length || 0}</strong>
            <p>{tt("Mode", "模式")} {report.mode || "-"}</p>
          </article>
        </div>
      </section>

      <ReportDownloadPanel report={report} analysis={analysis} token={token} />
    </>
  );
}
