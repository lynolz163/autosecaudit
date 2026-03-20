import { useMemo } from "react";
import DisclosureSection from "../DisclosureSection";
import { useI18n } from "../../i18n";
import { formatDateTime, truncateMiddle } from "../../lib/formatters";

function FindingBriefList({ eyebrow, title, items, emptyLabel, warning = false }) {
  return (
    <section className="report-highlights-card">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h3>{title}</h3>
        </div>
      </div>
      <div className="finding-list report-finding-briefs">
        {items.map((item) => (
          <article key={item.fingerprint} className="finding-card finding-brief-card">
            <div className="table-title">
              <strong>{item.title}</strong>
              <span className={warning ? "panel-chip is-warning" : "panel-chip"}>
                {String(item.severity || "info").toUpperCase()}
              </span>
            </div>
            <div className="table-meta">{item.plugin_name || "agent"} {item.finding_id ? `| ${item.finding_id}` : ""}</div>
            {item.description ? <p>{item.description}</p> : null}
          </article>
        ))}
        {!items.length ? <div className="empty-state">{emptyLabel}</div> : null}
      </div>
    </section>
  );
}

export default function ReportBaselineComparison({
  analysis,
  selectedBaselineJobId,
  onSelectBaseline,
}) {
  const { language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const history = useMemo(() => analysis?.history || [], [analysis]);
  const diff = analysis?.diff || {};
  const baselineOptions = useMemo(() => history.filter((item) => !item.is_current), [history]);
  const baselineValue = selectedBaselineJobId === "" ? "" : (selectedBaselineJobId || analysis?.baseline_job_id || "");
  const selectedBaseline = useMemo(
    () => baselineOptions.find((item) => item.job_id === (analysis?.baseline_job_id || baselineValue)) || null,
    [analysis?.baseline_job_id, baselineOptions, baselineValue],
  );
  const newFindings = useMemo(() => (diff.new_findings || []).slice(0, 4), [diff.new_findings]);
  const resolvedFindings = useMemo(() => (diff.resolved_findings || []).slice(0, 4), [diff.resolved_findings]);
  const persistentFindings = useMemo(() => (diff.persistent_findings || []).slice(0, 4), [diff.persistent_findings]);

  return (
    <DisclosureSection
      title={tt("Baseline comparison and drift", "基线对比与漂移")}
      subtitle={tt("Diff view", "差异视图")}
      defaultOpen={Boolean(analysis?.baseline_job_id || baselineOptions.length)}
    >
      <div className="panel-head">
        <div>
          <p className="eyebrow">{tt("Baseline", "基线")}</p>
          <h3>{tt("Choose a previous run to compare", "选择历史运行进行对比")}</h3>
          <p className="report-summary-copy">
            {selectedBaseline
              ? tt(
                `Comparing against ${selectedBaseline.job_id} from ${formatDateTime(selectedBaseline.ended_at || selectedBaseline.updated_at || "-", language)}.`,
                `当前对比基线为 ${selectedBaseline.job_id}（${formatDateTime(selectedBaseline.ended_at || selectedBaseline.updated_at || "-", language)}）。`,
              )
              : tt("No historical baseline is available yet for this target.", "这个目标暂时还没有可用的历史基线。")}
          </p>
        </div>
        <div className="inline-actions items-end">
          <label className="report-baseline-select">
            <span>{tt("Baseline run", "基线运行")}</span>
            <select
              value={baselineValue}
              onChange={(event) => onSelectBaseline?.(event.target.value)}
              disabled={!baselineOptions.length}
            >
              <option value="">{tt("Auto previous run", "自动选择上一轮")}</option>
              {baselineOptions.map((item) => (
                <option key={item.job_id} value={item.job_id}>
                  {truncateMiddle(item.job_id, 28)} · {formatDateTime(item.ended_at || item.updated_at || "-", language)}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <div className="report-summary-grid">
        <article className="report-summary-card">
          <span className="report-summary-label">{tt("New findings", "新增发现")}</span>
          <strong>{diff.new_count || 0}</strong>
          <p>{tt("Assets", "资产")} {diff.new_assets_count || 0} / {tt("Services", "服务")} {diff.new_services_count || 0}</p>
        </article>
        <article className="report-summary-card">
          <span className="report-summary-label">{tt("Resolved findings", "已解决发现")}</span>
          <strong>{diff.resolved_count || 0}</strong>
          <p>{tt("Assets", "资产")} {diff.resolved_assets_count || 0} / {tt("Services", "服务")} {diff.resolved_services_count || 0}</p>
        </article>
        <article className="report-summary-card">
          <span className="report-summary-label">{tt("Persistent findings", "持续存在")}</span>
          <strong>{diff.persistent_count || 0}</strong>
          <p>{tt("Assets", "资产")} {diff.persistent_assets_count || 0} / {tt("Services", "服务")} {diff.persistent_services_count || 0}</p>
        </article>
        <article className="report-summary-card">
          <span className="report-summary-label">{tt("Protocol drift", "协议漂移")}</span>
          <strong>{(diff.new_service_protocol_counts || []).length + (diff.resolved_service_protocol_counts || []).length}</strong>
          <p>{tt("Current baseline", "当前基线")} {analysis?.baseline_job_id || tt("none", "无")}</p>
        </article>
      </div>

      <div className="report-management-grid">
        <FindingBriefList
          eyebrow={tt("New", "新增")}
          title={tt("New findings since baseline", "相对基线新增的发现")}
          items={newFindings}
          emptyLabel={tt("No new findings versus the selected baseline.", "相对所选基线暂无新增发现。")}
          warning
        />
        <FindingBriefList
          eyebrow={tt("Resolved", "已解决")}
          title={tt("Resolved findings", "已解决发现")}
          items={resolvedFindings}
          emptyLabel={tt("No findings have been resolved relative to this baseline.", "相对该基线暂无已解决发现。")}
        />
      </div>

      <FindingBriefList
        eyebrow={tt("Persistent", "持续")}
        title={tt("Persistent high-signal findings", "持续存在的高信号发现")}
        items={persistentFindings}
        emptyLabel={tt(
          "No persistent findings were carried over from the selected baseline.",
          "所选基线没有持续遗留到本轮的发现。",
        )}
      />
    </DisclosureSection>
  );
}
