import { useI18n } from "../i18n";

const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function boolLabel(value, language) {
  if (value === true) {
    return language === "zh-CN" ? "是" : "Yes";
  }
  if (value === false) {
    return language === "zh-CN" ? "否" : "No";
  }
  return "-";
}

function formatAssetSummary(summary) {
  if (!summary || typeof summary !== "object") {
    return [];
  }
  return Object.entries(summary.assets_by_kind || {}).sort((a, b) => String(a[0]).localeCompare(String(b[0])));
}

export default function AssetGraphPanel({ analysis, mode = "report" }) {
  const { language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const assets = Array.isArray(analysis?.assets) ? analysis.assets : [];
  const summary = analysis?.asset_summary && typeof analysis.asset_summary === "object" ? analysis.asset_summary : {};
  const serviceAssets = assets.filter((item) => item?.kind === "service");
  const otherAssets = assets.filter((item) => item?.kind !== "service");
  const title = mode === "job" ? tt("Dynamic attack surface", "动态攻击面") : tt("Normalized asset topology", "标准化资产拓扑");
  const subtitle = mode === "job"
    ? tt("The graph below reflects what the agent has uncovered so far during the current run.", "下方视图反映了 Agent 在当前任务中已发现的资产与服务。")
    : tt("This report view consolidates discovered assets, services, and linked findings.", "该视图汇总了发现到的资产、服务与关联发现。");

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{tt("Surface Map", "资产地图")}</p>
          <h3>{title}</h3>
        </div>
        <div className="table-meta">{subtitle}</div>
      </div>

      {!assets.length ? (
        <div className="empty-state">{tt("No normalized assets were archived for this run.", "本次运行没有归档可用的标准化资产。")}</div>
      ) : (
        <>
          <div className="asset-summary-grid">
            <div className="severity-cell">
              <p className="eyebrow">{tt("Assets", "资产")}</p>
              <strong>{summary.total_assets || assets.length}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{tt("Services", "服务")}</p>
              <strong>{summary.service_assets || serviceAssets.length}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{tt("Linked Findings", "关联发现")}</p>
              <strong>{summary.asset_linked_findings || 0}</strong>
            </div>
            <div className="severity-cell">
              <p className="eyebrow">{tt("Kinds", "类型")}</p>
              <strong>{formatAssetSummary(summary).length}</strong>
            </div>
          </div>

          <div className="asset-kind-strip">
            {formatAssetSummary(summary).map(([kind, count]) => (
              <span key={kind} className="panel-chip">
                {kind} x{count}
              </span>
            ))}
          </div>

          {serviceAssets.length ? (
            <div className="asset-graph-grid">
              {serviceAssets.map((asset) => {
                const attributes = asset.attributes || {};
                const relatedFindings = Array.isArray(asset.related_findings) ? [...asset.related_findings] : [];
                relatedFindings.sort((a, b) => {
                  const severityDiff = (SEVERITY_ORDER[a?.severity] ?? 9) - (SEVERITY_ORDER[b?.severity] ?? 9);
                  if (severityDiff !== 0) return severityDiff;
                  return String(a?.title || "").localeCompare(String(b?.title || ""));
                });
                return (
                  <article key={asset.id} className="asset-service-card">
                    <div className="table-title">
                      <strong>{asset.display_name || asset.id}</strong>
                      <span className="panel-chip">{attributes.service || asset.kind}</span>
                    </div>
                    <div className="asset-meta">
                      <span>{tt("Source", "来源")}: {asset.source_tool || "-"}</span>
                      <span>{tt("Proto", "协议")}: {attributes.proto || "-"}</span>
                      <span>TLS: {boolLabel(attributes.tls, language)}</span>
                      <span>{tt("Auth", "认证")}: {boolLabel(attributes.auth_required, language)}</span>
                    </div>
                    {attributes.banner ? <pre className="report-code asset-banner">{String(attributes.banner)}</pre> : null}
                    <div className="asset-finding-list">
                      {relatedFindings.length ? relatedFindings.map((item) => (
                        <div key={`${asset.id}-${item.fingerprint}`} className="table-row">
                          <div className="table-title">
                            <strong>{item.title}</strong>
                            <span className="panel-chip">{item.severity}</span>
                          </div>
                          <div className="table-meta">{item.plugin_name || "-"}</div>
                        </div>
                      )) : (
                        <div className="empty-state">{tt("No findings linked to this service yet.", "该服务尚未关联发现。")}</div>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          ) : null}

          {otherAssets.length ? (
            <div className="table-list">
              {otherAssets.map((asset) => (
                <div key={asset.id} className="table-row">
                  <div className="table-title">
                    <strong>{asset.display_name || asset.id}</strong>
                    <span className="panel-chip">{asset.kind}</span>
                  </div>
                  <div className="asset-meta">
                    <span>{tt("Source", "来源")}: {asset.source_tool || "-"}</span>
                    <span>{tt("Linked Findings", "关联发现")}: {asset.finding_count || 0}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}
