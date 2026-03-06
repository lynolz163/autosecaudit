import MetricCard from "../components/MetricCard";
import { useI18n } from "../i18n";
import { formatDateTime, truncateMiddle } from "../lib/formatters";

export default function Dashboard({ summary }) {
  const { t, formatStatus, formatMode, language } = useI18n();
  const metrics = summary?.metrics || {};
  const severityCounts = summary?.severity_counts || {};

  return (
    <>
      <section className="metrics-grid">
        <MetricCard label={t("dashboard.totalJobs")} value={metrics.total_jobs ?? 0} detail={t("dashboard.allIndexedRuns")} />
        <MetricCard
          label={t("dashboard.successRate")}
          value={`${metrics.success_rate ?? 0}%`}
          tone="teal"
          detail={t("dashboard.completedCount", { count: metrics.completed_jobs ?? 0 })}
        />
        <MetricCard
          label={t("dashboard.running")}
          value={metrics.running_jobs ?? 0}
          tone="amber"
          detail={t("dashboard.queuedAndActive")}
        />
        <MetricCard
          label={t("dashboard.findings")}
          value={metrics.total_findings ?? 0}
          tone="red"
          detail={t("dashboard.distinctTargets", { count: metrics.distinct_targets ?? 0 })}
        />
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("dashboard.severityMix")}</p>
            <h3>{t("dashboard.findingsDistribution")}</h3>
          </div>
        </div>
        <div className="severity-grid">
          {["critical", "high", "medium", "low", "info"].map((level) => (
            <div key={level} className="severity-cell">
              <p className="eyebrow">{formatStatus(level)}</p>
              <div className="metric-value">{severityCounts[level] ?? 0}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("dashboard.recent")}</p>
            <h3>{t("dashboard.lastUpdatedJobs")}</h3>
          </div>
        </div>
        <div className="table-list">
          {(summary?.recent_jobs || []).map((job) => (
            <div key={job.job_id} className="table-row is-static">
              <div className="table-title">
                <strong>{truncateMiddle(job.target, 84)}</strong>
                <span className="panel-chip">{formatStatus(job.status)}</span>
              </div>
              <div className="record-grid">
                <div>
                  <span className="record-label">{language === "zh-CN" ? "模式" : "Mode"}</span>
                  <div className="record-value">{formatMode(job.mode)}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "任务 ID" : "Job ID"}</span>
                  <div className="record-value mono">{truncateMiddle(job.job_id, 36)}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "更新时间" : "Updated"}</span>
                  <div className="record-value">{formatDateTime(job.updated_at || "-", language)}</div>
                </div>
              </div>
            </div>
          ))}
          {!summary?.recent_jobs?.length ? <div className="empty-state">{t("dashboard.noJobs")}</div> : null}
        </div>
      </section>
    </>
  );
}
