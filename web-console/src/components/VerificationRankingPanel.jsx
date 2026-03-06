import { useI18n } from "../i18n";

function boolLabel(value, language) {
  if (value === true) {
    return language === "zh-CN" ? "已命中" : "Verified";
  }
  if (value === false) {
    return language === "zh-CN" ? "已验证未命中" : "Checked";
  }
  return language === "zh-CN" ? "待验证" : "Pending";
}

export default function VerificationRankingPanel({ analysis, mode = "job" }) {
  const { language } = useI18n();
  const blocks = Array.isArray(analysis?.verification_ranking) ? analysis.verification_ranking : [];
  const title = language === "zh-CN" ? "验证排序解释" : "Verification Ranking";
  const subtitle =
    mode === "job"
      ? (language === "zh-CN" ? "解释当前任务为何先验某个 CVE 或 PoC。" : "Explain why this job verified a CVE or PoC first.")
      : (language === "zh-CN" ? "解释报告中的 CVE / PoC 排序与模板选择。" : "Explain the CVE / PoC ordering and template selection in this report.");

  if (!blocks.length) {
    return null;
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{language === "zh-CN" ? "验证上下文" : "Verification Context"}</p>
          <h3>{title}</h3>
        </div>
        <div className="table-meta">{subtitle}</div>
      </div>

      <div className="ranking-block-list">
        {blocks.map((block, blockIndex) => {
          const items = Array.isArray(block?.items) ? block.items : [];
          const selectedTemplates = Array.isArray(block?.selected_templates) ? block.selected_templates : [];
          return (
            <article key={`${block.tool || "tool"}-${blockIndex}`} className="ranking-block">
              <div className="table-title">
                <strong>{block.tool || "-"}</strong>
                <span className="panel-chip">{block.selected_candidate || "-"}</span>
              </div>
              <div className="asset-meta">
                <span>{language === "zh-CN" ? "目标" : "Target"}: {block.target || "-"}</span>
                <span>{language === "zh-CN" ? "组件" : "Component"}: {block.component || "-"}</span>
                <span>{language === "zh-CN" ? "服务" : "Service"}: {block.service || "-"}</span>
                <span>{language === "zh-CN" ? "版本" : "Version"}: {block.version || "-"}</span>
              </div>
              {selectedTemplates.length ? (
                <div className="ranking-chip-row">
                  {selectedTemplates.slice(0, 8).map((item) => (
                    <span key={item} className="panel-chip">{item}</span>
                  ))}
                </div>
              ) : null}
              <div className="table-list">
                {items.map((item) => {
                  const reasons = Array.isArray(item?.reasons) ? item.reasons : [];
                  const protocolTags = Array.isArray(item?.template_capability?.protocol_tags)
                    ? item.template_capability.protocol_tags
                    : [];
                  return (
                    <div key={`${block.tool || "tool"}-${item.cve_id || "candidate"}`} className={item.selected ? "table-row is-active is-static" : "table-row is-static"}>
                      <div className="table-title">
                        <strong>{item.cve_id || "-"}</strong>
                        <span className="panel-chip">
                          {(item.severity || "info").toUpperCase()}
                          {item.rank ? ` #${item.rank}` : ""}
                        </span>
                      </div>
                      <div className="asset-meta">
                        <span>CVSS: {item.cvss_score ?? "-"}</span>
                        <span>{language === "zh-CN" ? "模板" : "Templates"}: {item.template_count ?? 0}</span>
                        <span>{language === "zh-CN" ? "状态" : "Status"}: {boolLabel(item.verified, language)}</span>
                      </div>
                      {protocolTags.length ? (
                        <div className="ranking-chip-row">
                          {protocolTags.map((tag) => (
                            <span key={`${item.cve_id}-${tag}`} className="panel-chip">{tag}</span>
                          ))}
                        </div>
                      ) : null}
                      <div className="ranking-reason-list">
                        {reasons.length ? reasons.map((reason) => (
                          <div key={`${item.cve_id}-${reason}`} className="ranking-reason-item">{reason}</div>
                        )) : (
                          <div className="empty-state">{language === "zh-CN" ? "未记录更细的排序依据。" : "No detailed ranking reason recorded."}</div>
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
    </section>
  );
}
