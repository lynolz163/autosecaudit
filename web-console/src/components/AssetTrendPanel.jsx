import { useI18n } from "../i18n";

function signedValue(value) {
  const numeric = Number(value || 0);
  return numeric > 0 ? `+${numeric}` : String(numeric);
}

export default function AssetTrendPanel({ analysis }) {
  const { language } = useI18n();
  const phaseRows = Array.isArray(analysis?.asset_phase_trends) ? analysis.asset_phase_trends : [];
  const batchRows = Array.isArray(analysis?.asset_batch_trends) ? analysis.asset_batch_trends : [];

  if (!phaseRows.length && !batchRows.length) {
    return null;
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{language === "zh-CN" ? "资产趋势" : "Asset Trends"}</p>
          <h3>{language === "zh-CN" ? "按阶段 / 按批次对比" : "By Phase / By Batch"}</h3>
        </div>
        <div className="table-meta">
          {language === "zh-CN"
            ? "同时对比当前运行阶段推进和同目标历史批次变化。"
            : "Compare the current run by phase and the target history by batch."}
        </div>
      </div>

      {phaseRows.length ? (
        <div className="trend-section">
          <div className="table-title">
            <strong>{language === "zh-CN" ? "阶段趋势" : "Phase Trends"}</strong>
          </div>
          <div className="table-list">
            {phaseRows.map((row) => (
              <div key={`phase-${row.phase}`} className={row.is_current ? "table-row is-active is-static" : "table-row is-static"}>
                <div className="table-title">
                  <strong>{row.phase || "-"}</strong>
                  <span className="panel-chip">
                    {language === "zh-CN" ? "动作" : "Actions"} {row.executed_actions || 0}
                  </span>
                </div>
                <div className="asset-meta">
                  <span>{language === "zh-CN" ? "工具" : "Tools"}: {row.unique_tools || 0}</span>
                  <span>{language === "zh-CN" ? "资产" : "Assets"}: {row.asset_count || 0}</span>
                  <span>{language === "zh-CN" ? "服务" : "Services"}: {row.service_assets || 0}</span>
                  <span>{language === "zh-CN" ? "发现" : "Findings"}: {row.finding_count || 0}</span>
                  <span>{language === "zh-CN" ? "资产增量" : "Asset Delta"}: {signedValue(row.delta_assets)}</span>
                </div>
                {Array.isArray(row.tool_names) && row.tool_names.length ? (
                  <div className="ranking-chip-row">
                    {row.tool_names.slice(0, 8).map((tool) => (
                      <span key={`${row.phase}-${tool}`} className="panel-chip">{tool}</span>
                    ))}
                  </div>
                ) : null}
                {row.reason ? <div className="table-meta">{row.reason}</div> : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {batchRows.length ? (
        <div className="trend-section">
          <div className="table-title">
            <strong>{language === "zh-CN" ? "运行批次趋势" : "Run Batch Trends"}</strong>
          </div>
          <div className="table-list">
            {batchRows.map((row) => (
              <div key={`batch-${row.job_id}`} className={row.is_current ? "table-row is-active is-static" : "table-row is-static"}>
                <div className="table-title">
                  <strong>{row.job_id || "-"}</strong>
                  <span className="panel-chip">{row.ended_at || row.updated_at || "-"}</span>
                </div>
                <div className="asset-meta">
                  <span>{language === "zh-CN" ? "资产" : "Assets"}: {row.total_assets || 0}</span>
                  <span>{language === "zh-CN" ? "服务" : "Services"}: {row.service_assets || 0}</span>
                  <span>{language === "zh-CN" ? "发现" : "Findings"}: {row.finding_total || 0}</span>
                  <span>{language === "zh-CN" ? "资产增量" : "Asset Delta"}: {signedValue(row.delta_assets)}</span>
                  <span>{language === "zh-CN" ? "发现增量" : "Finding Delta"}: {signedValue(row.delta_findings)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
