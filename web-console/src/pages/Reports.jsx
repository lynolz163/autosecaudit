import { useEffect, useMemo, useState } from "react";
import DisclosureSection from "../components/DisclosureSection";
import EvidenceGraphPanel from "../components/EvidenceGraphPanel";
import PaginationControls from "../components/PaginationControls";
import StatusBadge from "../components/StatusBadge";
import ReportBaselineComparison from "../components/reports/ReportBaselineComparison";
import ReportContentView from "../components/reports/ReportContentView";
import ReportOverviewPanel from "../components/reports/ReportOverviewPanel";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";

const PAGE_SIZE = 8;

export default function Reports({
  reports,
  selectedReport,
  selectedBaselineJobId,
  onSelectReport,
  onSelectBaseline,
  reportContent,
  reportAnalysis,
  token,
  canAccessRag,
  onOpenRag,
  onOpenFollowUpMission,
}) {
  const { t, language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const [page, setPage] = useState(1);
  const pagination = paginateItems(reports, page, PAGE_SIZE);
  const findings = useMemo(() => reportAnalysis?.findings || [], [reportAnalysis]);
  const history = useMemo(() => reportAnalysis?.history || [], [reportAnalysis]);
  const topFindings = useMemo(() => findings.slice(0, 5), [findings]);
  const recentHistory = useMemo(() => history.slice(0, 4), [history]);

  useEffect(() => {
    setPage((prev) => (prev !== pagination.page ? pagination.page : prev));
  }, [pagination.page]);

  return (
    <div className="reports-layout">
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("reports.archiveEyebrow")}</p>
            <h3>{t("reports.centerTitle")}</h3>
          </div>
        </div>

        <div className="table-list">
          {pagination.items.map((report) => (
            <button
              key={report.job_id}
              type="button"
              className={selectedReport?.job_id === report.job_id ? "table-row is-active" : "table-row"}
              onClick={() => onSelectReport(report)}
            >
              <div className="table-title">
                <strong>{truncateMiddle(report.target || report.job_id, 82)}</strong>
                <StatusBadge status={report.status} />
              </div>
              <div className="table-meta">
                {t("reports.findingsMeta", {
                  count: report.finding_total,
                  formats: (report.available_formats || []).join(", "),
                })}
              </div>
              <div className="table-meta">
                {t("reports.updatedMeta", {
                  value: formatDateTime(report.ended_at || report.updated_at || "-", language),
                })}
              </div>
              {report.decision_summary ? <div className="table-meta clamp-2">{report.decision_summary}</div> : null}
            </button>
          ))}
          {!pagination.totalItems ? <div className="empty-state">{t("reports.noReports")}</div> : null}
        </div>
        <PaginationControls {...pagination} onPageChange={setPage} />
      </section>

      <div className="space-y-4 min-w-0">
        <ReportOverviewPanel
          report={selectedReport}
          analysis={reportAnalysis}
          token={token}
          canAccessRag={canAccessRag}
          onOpenRag={onOpenRag}
          onOpenFollowUpMission={onOpenFollowUpMission}
        />

        {selectedReport ? (
          <ReportBaselineComparison
            analysis={reportAnalysis}
            selectedBaselineJobId={selectedBaselineJobId}
            onSelectBaseline={onSelectBaseline}
          />
        ) : null}

        {selectedReport ? (
          <div className="report-management-grid">
            <section className="report-highlights-card">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">{tt("Priority queue", "优先队列")}</p>
                  <h3>{tt("Priority issues", "优先问题")}</h3>
                </div>
              </div>
              <div className="finding-list report-finding-briefs">
                {topFindings.map((item) => (
                  <article key={item.fingerprint} className="finding-card finding-brief-card">
                    <div className="table-title">
                      <strong>{item.title}</strong>
                      <span className="panel-chip">{String(item.severity || "info").toUpperCase()}</span>
                    </div>
                    <div className="table-meta">{item.plugin_name || "agent"} {item.finding_id ? `| ${item.finding_id}` : ""}</div>
                    {item.description ? <p>{item.description}</p> : null}
                    {item.recommendation ? <p className="table-meta">{tt("Recommendation", "建议")}: {item.recommendation}</p> : null}
                  </article>
                ))}
                {!topFindings.length ? <div className="empty-state">{tt("No findings available for executive summary.", "暂无可用于管理摘要的发现。")}</div> : null}
              </div>
            </section>

            <section className="report-highlights-card">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">{tt("History", "历史")}</p>
                  <h3>{tt("Recent audit trail", "最近审计轨迹")}</h3>
                </div>
              </div>
              <div className="report-history-strip">
                {recentHistory.map((item) => (
                  <div key={item.job_id} className={`report-history-node ${item.is_current ? "is-current" : ""}`}>
                    <strong>{truncateMiddle(item.job_id, 22)}</strong>
                    <span>{item.finding_total || 0} {tt("findings", "项发现")}</span>
                    <span>{formatDateTime(item.ended_at || item.updated_at || "-", language)}</span>
                  </div>
                ))}
                {!recentHistory.length ? <div className="empty-state">{tt("No prior baseline history for this target.", "该目标暂时没有可用基线历史。")}</div> : null}
              </div>
            </section>
          </div>
        ) : null}

        {selectedReport && (reportAnalysis?.cve_validation?.summary || reportAnalysis?.knowledge_context?.summary) ? (
          <section className="panel">
            <div className="report-management-grid">
              {reportAnalysis?.cve_validation?.summary ? (
                <section className="report-highlights-card">
                  <div className="panel-head">
                    <div>
                      <p className="eyebrow">{tt("CVE validation", "CVE 验证")}</p>
                      <h3>{tt("Staged pipeline", "分级验证流水线")}</h3>
                    </div>
                  </div>
                  <div className="report-history-strip">
                    <div className="report-history-node is-current">
                      <strong>{tt("Candidates", "候选")} {reportAnalysis.cve_validation.summary.candidate_count || 0}</strong>
                      <span>{tt("Version", "版本印证")} {reportAnalysis.cve_validation.summary.version_corroborated_count || 0}</span>
                      <span>{tt("Template", "模板验证")} {reportAnalysis.cve_validation.summary.template_verified_count || 0}</span>
                    </div>
                    <div className="report-history-node">
                      <strong>{tt("Sandbox ready", "沙箱就绪")} {reportAnalysis.cve_validation.summary.sandbox_ready_count || 0}</strong>
                      <span>{tt("Recommended actions", "推荐动作")} {(reportAnalysis.cve_validation.recommended_actions || []).length}</span>
                    </div>
                  </div>
                </section>
              ) : null}
              {reportAnalysis?.knowledge_context?.summary ? (
                <section className="report-highlights-card">
                  <div className="panel-head">
                    <div>
                      <p className="eyebrow">{tt("Knowledge context", "知识上下文")}</p>
                      <h3>{tt("Task-level references", "任务级引用")}</h3>
                    </div>
                  </div>
                  <div className="table-meta">{reportAnalysis.knowledge_context.summary}</div>
                  <div className="finding-list report-finding-briefs">
                    {(reportAnalysis.knowledge_context.tags || []).slice(0, 8).map((item) => (
                      <span key={item} className="panel-chip">{item}</span>
                    ))}
                  </div>
                </section>
              ) : null}
            </div>
          </section>
        ) : null}

        {selectedReport && findings.length ? (
          <DisclosureSection
            title={tt("All findings", "全部发现")}
            subtitle={tt("Detailed list", "详细列表")}
            aside={tt("Hidden by default", "默认折叠")}
          >
            <div className="finding-list">
              {findings.map((item) => (
                <article key={item.fingerprint} className="finding-card">
                  <div className="table-title">
                    <strong>{item.title}</strong>
                    <span className="panel-chip">{String(item.severity || "info").toUpperCase()}</span>
                  </div>
                  <div className="table-meta">
                    {item.plugin_name || "agent"} {item.finding_id ? `| ${item.finding_id}` : ""}
                  </div>
                  {item.description ? <p>{item.description}</p> : null}
                  {item.recommendation ? <p className="table-meta">{tt("Recommendation", "建议")}: {item.recommendation}</p> : null}
                </article>
              ))}
            </div>
          </DisclosureSection>
        ) : null}

        {selectedReport && reportAnalysis ? (
          <DisclosureSection
            title={tt("Technical appendix", "技术附录")}
            subtitle={tt("Evidence graph", "证据图谱")}
            aside={tt("Hidden by default", "默认折叠")}
          >
            <EvidenceGraphPanel analysis={reportAnalysis} mode="report" />
          </DisclosureSection>
        ) : null}

        <section className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{tt("Report preview", "报告预览")}</p>
              <h3>{tt("Readable report output", "可读报告输出")}</h3>
            </div>
          </div>
          <ReportContentView
            report={selectedReport}
            content={reportContent}
            emptyLabel={t("reportPreview.empty")}
            missingContentLabel={tt("Report content is not ready yet.", "报告内容尚未生成。")}
          />
        </section>
      </div>
    </div>
  );
}
