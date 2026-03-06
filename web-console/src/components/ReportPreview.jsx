import ReactMarkdown from "react-markdown";
import { buildAuthedUrl } from "../lib/api";
import { useI18n } from "../i18n";
import AssetGraphPanel from "./AssetGraphPanel";
import AssetTrendPanel from "./AssetTrendPanel";
import VerificationRankingPanel from "./VerificationRankingPanel";

function exportHref(report, token, format) {
  return buildAuthedUrl(`/api/reports/${encodeURIComponent(report.job_id)}/export?format=${encodeURIComponent(format)}`, token);
}

export default function ReportPreview({ report, content, analysis, token }) {
  const { t, formatMode, formatPluginCategory, formatStatus } = useI18n();
  const diff = analysis?.diff || {};
  const findings = analysis?.findings || [];
  const history = analysis?.history || [];
  const availableExports = analysis?.available_exports || ["html"];

  return (
    <section className="panel report-preview">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{t("reportPreview.eyebrow")}</p>
          <h3>{report ? report.target || report.job_id : t("reportPreview.readerTitle")}</h3>
        </div>
        {report ? (
          <div className="inline-actions">
            {availableExports.includes("html") ? (
              <a className="ghost-button" href={exportHref(report, token, "html")} target="_blank" rel="noreferrer">
                {t("reportPreview.exportHtml")}
              </a>
            ) : null}
            {availableExports.includes("markdown") ? (
              <a className="ghost-button" href={exportHref(report, token, "markdown")} target="_blank" rel="noreferrer">
                {t("reportPreview.exportMarkdown")}
              </a>
            ) : null}
            {availableExports.includes("json") ? (
              <a className="ghost-button" href={exportHref(report, token, "json")} target="_blank" rel="noreferrer">
                {t("reportPreview.exportJson")}
              </a>
            ) : null}
          </div>
        ) : null}
      </div>

      {!report ? (
        <div className="empty-state">{t("reportPreview.empty")}</div>
      ) : (
        <>
          <div className="severity-grid">
            <div className="severity-cell">
              <p className="eyebrow">{t("common.findings")}</p>
              <strong>{report.finding_total || 0}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{t("reportPreview.newCount")}</p>
              <strong>{diff.new_count || 0}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{t("reportPreview.resolvedCount")}</p>
              <strong>{diff.resolved_count || 0}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{t("reportPreview.persistentCount")}</p>
              <strong>{diff.persistent_count || 0}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{t("reportPreview.historyCount")}</p>
              <strong>{analysis?.history_count || 0}</strong>
            </div>
          </div>

          <div className="page-grid">
            <section className="panel">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">{t("reportPreview.diffEyebrow")}</p>
                  <h3>{t("reportPreview.baselineComparison")}</h3>
                </div>
              </div>
              <div className="table-list">
                <div className="table-row">
                  <div className="table-title">
                    <strong>{t("reportPreview.baselineJob")}</strong>
                  </div>
                  <div className="table-meta">{diff.baseline_job_id || t("reportPreview.noEarlierBaseline")}</div>
                </div>
                {(diff.new_findings || []).slice(0, 5).map((item) => (
                  <div key={`new-${item.fingerprint}`} className="table-row">
                    <div className="table-title">
                      <strong>{item.title}</strong>
                      <span className="panel-chip">{formatStatus(item.severity)}</span>
                    </div>
                    <div className="table-meta">{t("reportPreview.newFindingMeta", { plugin: item.plugin_name })}</div>
                  </div>
                ))}
                {(diff.resolved_findings || []).slice(0, 3).map((item) => (
                  <div key={`resolved-${item.fingerprint}`} className="table-row">
                    <div className="table-title">
                      <strong>{item.title}</strong>
                      <span className="panel-chip">{formatStatus("resolved")}</span>
                    </div>
                    <div className="table-meta">{t("reportPreview.resolvedFindingMeta", { plugin: item.plugin_name })}</div>
                  </div>
                ))}
                {!diff.baseline_job_id ? (
                  <div className="empty-state">{t("reportPreview.diffHint")}</div>
                ) : null}
              </div>
            </section>

            <section className="panel">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">{t("reportPreview.trendEyebrow")}</p>
                  <h3>{t("reportPreview.targetHistory")}</h3>
                </div>
              </div>
              <div className="table-list">
                {history.map((item) => (
                  <div key={item.job_id} className={item.is_current ? "table-row is-active" : "table-row"}>
                    <div className="table-title">
                      <strong>{item.job_id}</strong>
                      <span className="panel-chip">{t("reportPreview.findingsChip", { count: item.finding_total })}</span>
                    </div>
                    <div className="table-meta">
                      {item.ended_at || item.updated_at || "-"} | {formatStatus(item.status)} | {formatMode(item.mode)}
                    </div>
                  </div>
                ))}
                {!history.length ? <div className="empty-state">{t("reportPreview.noHistory")}</div> : null}
              </div>
            </section>
          </div>

          <AssetGraphPanel analysis={analysis} mode="report" />
          <VerificationRankingPanel analysis={analysis} mode="report" />
          <AssetTrendPanel analysis={analysis} />

          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">{t("reportPreview.findingsEyebrow")}</p>
                <h3>{t("reportPreview.structuredFindings")}</h3>
              </div>
            </div>
            <div className="finding-list">
              {findings.map((item) => (
                <article key={item.fingerprint} className="finding-card">
                  <div className="table-title">
                    <strong>{item.title}</strong>
                    <span className="panel-chip">{formatStatus(item.severity)}</span>
                  </div>
                  <div className="table-meta">
                    {item.plugin_name} {item.category ? `| ${formatPluginCategory(item.category)}` : ""} {item.finding_id ? `| ${item.finding_id}` : ""}
                  </div>
                  {item.description ? <p>{item.description}</p> : null}
                  {item.recommendation ? <p className="table-meta">{t("reportPreview.recommendation", { value: item.recommendation })}</p> : null}
                  <pre className="report-code finding-evidence">{item.evidence_text || "{}"}</pre>
                </article>
              ))}
              {!findings.length ? <div className="empty-state">{t("reportPreview.noFindings")}</div> : null}
            </div>
          </section>

          {report.preview_path?.endsWith(".html") ? (
            <iframe className="report-frame" title={report.job_id} srcDoc={content || t("reportPreview.noHtmlContent")} />
          ) : report.preview_path?.endsWith(".json") ? (
            <pre className="report-code">{content || t("reportPreview.noJsonContent")}</pre>
          ) : (
            <div className="report-markdown">
              <ReactMarkdown>{content || t("reportPreview.noMarkdownContent")}</ReactMarkdown>
            </div>
          )}
        </>
      )}
    </section>
  );
}
