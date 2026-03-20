import { useI18n } from "../i18n";
import AssetGraphPanel from "./AssetGraphPanel";
import AssetTrendPanel from "./AssetTrendPanel";
import VerificationRankingPanel from "./VerificationRankingPanel";
import ReportContentView from "./reports/ReportContentView";
import ReportExportButtons from "./reports/ReportExportButtons";

export default function ReportPreview({ report, content, analysis, token }) {
  const { t, formatMode, formatPluginCategory, formatStatus, formatBoolean, language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const diff = analysis?.diff || {};
  const findings = analysis?.findings || [];
  const history = analysis?.history || [];
  const infrastructure = analysis?.infrastructure || {};
  const riskMatrix = analysis?.risk_matrix || {};
  const attackSurface = analysis?.attack_surface || {};
  const infraPorts = Array.isArray(infrastructure?.ports) ? infrastructure.ports : [];
  const infraMiddleware = Array.isArray(infrastructure?.middleware) ? infrastructure.middleware : [];
  const infraTech = Array.isArray(infrastructure?.tech_stack) ? infrastructure.tech_stack : [];
  const infraCertificates = Array.isArray(infrastructure?.certificates) ? infrastructure.certificates : [];
  const riskCategories = Array.isArray(riskMatrix?.categories) ? riskMatrix.categories : [];
  const entryPoints = Array.isArray(attackSurface?.entry_points) ? attackSurface.entry_points : [];
  const exposedServices = Array.isArray(attackSurface?.exposed_services) ? attackSurface.exposed_services : [];
  const sensitivePaths = Array.isArray(attackSurface?.sensitive_paths) ? attackSurface.sensitive_paths : [];

  return (
    <section className="panel report-preview">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{t("reportPreview.eyebrow")}</p>
          <h3>{report ? report.target || report.job_id : t("reportPreview.readerTitle")}</h3>
        </div>
        {report ? <ReportExportButtons report={report} analysis={analysis} token={token} /> : null}
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
                {!diff.baseline_job_id ? <div className="empty-state">{t("reportPreview.diffHint")}</div> : null}
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

          {(infraPorts.length || infraMiddleware.length || infraTech.length || infraCertificates.length || riskCategories.length || entryPoints.length || exposedServices.length || sensitivePaths.length) ? (
            <div className="page-grid">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">{tt("Infrastructure", "基础设施")}</p>
                    <h3>{tt("Surface summary", "表面摘要")}</h3>
                  </div>
                </div>
                <div className="severity-grid">
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Ports", "端口")}</p>
                    <strong>{infraPorts.length}</strong>
                  </div>
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Middleware", "中间件")}</p>
                    <strong>{infraMiddleware.length}</strong>
                  </div>
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Tech Stack", "技术栈")}</p>
                    <strong>{infraTech.length}</strong>
                  </div>
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Certificates", "证书")}</p>
                    <strong>{infraCertificates.length}</strong>
                  </div>
                </div>
                <div className="table-list">
                  {infraPorts.slice(0, 5).map((item, index) => (
                    <div key={`port-${item.host || "host"}-${item.port || index}`} className="table-row">
                      <div className="table-title">
                        <strong>{item.host || "-"}</strong>
                        <span className="panel-chip">{item.port || "-"}/{item.protocol || "-"}</span>
                      </div>
                      <div className="table-meta">{item.service || "-"} · TLS {formatBoolean(Boolean(item.tls))}</div>
                    </div>
                  ))}
                  {infraMiddleware.slice(0, 5).map((item, index) => (
                    <div key={`middleware-${item.name || index}-${item.source || "-"}`} className="table-row">
                      <div className="table-title">
                        <strong>{item.name || "-"}</strong>
                        <span className="panel-chip">{item.category || "-"}</span>
                      </div>
                      <div className="table-meta">{item.source || "-"}</div>
                    </div>
                  ))}
                  {!infraPorts.length && !infraMiddleware.length ? <div className="empty-state">{tt("No infrastructure summary available.", "暂无基础设施摘要。")}</div> : null}
                </div>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">{tt("Risk Matrix", "风险矩阵")}</p>
                    <h3>{tt("Category breakdown", "分类拆解")}</h3>
                  </div>
                </div>
                <div className="severity-grid">
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Total Risk", "总风险")}</p>
                    <strong>{riskMatrix?.total_score || 0}</strong>
                  </div>
                </div>
                <div className="table-list">
                  {riskCategories.map((item) => (
                    <div key={item.name} className="table-row">
                      <div className="table-title">
                        <strong>{item.name || "-"}</strong>
                        <span className="panel-chip">{tt("Findings", "发现")} {item.finding_count || 0}</span>
                      </div>
                      <div className="table-meta">
                        {tt("Score", "分数")} {item.score || 0} · C {item.severity_counts?.critical || 0} / H {item.severity_counts?.high || 0} / M {item.severity_counts?.medium || 0}
                      </div>
                    </div>
                  ))}
                  {!riskCategories.length ? <div className="empty-state">{tt("No categorized risk data.", "暂无分类风险数据。")}</div> : null}
                </div>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">{tt("Attack Surface", "攻击面")}</p>
                    <h3>{tt("Entry points and exposures", "入口点与暴露面")}</h3>
                  </div>
                </div>
                <div className="severity-grid">
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Entry Points", "入口点")}</p>
                    <strong>{entryPoints.length}</strong>
                  </div>
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Services", "服务")}</p>
                    <strong>{exposedServices.length}</strong>
                  </div>
                  <div className="severity-cell">
                    <p className="eyebrow">{tt("Sensitive Paths", "敏感路径")}</p>
                    <strong>{sensitivePaths.length}</strong>
                  </div>
                </div>
                <div className="table-list">
                  {entryPoints.slice(0, 4).map((item, index) => (
                    <div key={`entry-${item.url || index}`} className="table-row">
                      <div className="table-title">
                        <strong>{item.type || "-"}</strong>
                        <span className="panel-chip">{item.method || "-"}</span>
                      </div>
                      <div className="table-meta">{item.url || "-"}</div>
                    </div>
                  ))}
                  {sensitivePaths.slice(0, 4).map((item, index) => (
                    <div key={`path-${item.url || item.path || index}`} className="table-row">
                      <div className="table-title">
                        <strong>{item.type || "-"}</strong>
                        <span className="panel-chip">{item.path || "-"}</span>
                      </div>
                      <div className="table-meta">{item.url || "-"}</div>
                    </div>
                  ))}
                  {!entryPoints.length && !sensitivePaths.length ? <div className="empty-state">{tt("No attack-surface summary available.", "暂无攻击面摘要。")}</div> : null}
                </div>
              </section>
            </div>
          ) : null}

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

          <ReportContentView
            report={report}
            content={content}
            emptyLabel={t("reportPreview.empty")}
            missingContentLabel={tt("Report content is not ready yet.", "报告内容尚未生成。")}
          />
        </>
      )}
    </section>
  );
}
