import StatusBadge from "./StatusBadge";
import { useI18n } from "../i18n";

function formatBudgetDelta(entry) {
  const before = Number(entry?.budget_before);
  const after = Number(entry?.budget_after);
  if (!Number.isFinite(before) || !Number.isFinite(after)) {
    return null;
  }
  return before - after;
}

export default function ExecutionHistoryPanel({ analysis }) {
  const { language } = useI18n();
  const rows = Array.isArray(analysis?.execution_history) ? analysis.execution_history : [];
  const tt = (english, chinese) => (language === "zh-CN" ? chinese : english);

  if (!rows.length) {
    return null;
  }

  return (
    <section className="panel thought-stream-panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{tt("Thought Stream", "\u601d\u8003\u6d41")}</p>
          <h3>{tt("Why the agent chose each step", "Agent \u4e3a\u4f55\u9009\u62e9\u6bcf\u4e00\u6b65")}</h3>
        </div>
        <div className="table-meta">
          {tt(
            "Each entry explains the selected action, the ranking context, and the resulting outcome.",
            "\u6bcf\u4e00\u9879\u4f1a\u89e3\u91ca\u672c\u6b21\u52a8\u4f5c\u7684\u9009\u62e9\u4f9d\u636e\u3001\u6392\u5e8f\u4e0a\u4e0b\u6587\u548c\u6700\u7ec8\u7ed3\u679c\u3002"
          )}
        </div>
      </div>

      <div className="ranking-block-list">
        {rows.map((entry, index) => {
          const ranking = entry?.ranking_explanation && typeof entry.ranking_explanation === "object"
            ? entry.ranking_explanation
            : {};
          const reasons = Array.isArray(ranking?.reasons) ? ranking.reasons : [];
          const selectedTemplates = Array.isArray(ranking?.selected_templates) ? ranking.selected_templates : [];
          const candidateOrder = Array.isArray(ranking?.candidate_order) ? ranking.candidate_order : [];
          const budgetSpent = formatBudgetDelta(entry);
          return (
            <article key={`${entry?.tool || "tool"}-${entry?.target || "target"}-${index}`} className="ranking-block">
              <div className="table-title">
                <strong>{entry?.tool || "-"}</strong>
                <StatusBadge status={entry?.status} />
              </div>
              <div className="asset-meta">
                <span>{tt("Target", "\u6b65\u9aa4")}: {entry?.target || "-"}</span>
                <span>{tt("Phase", "\u6b65\u9aa4")}: {entry?.phase || "-"}</span>
                <span>{tt("Step", "\u6b65\u9aa4")}: {entry?.index ?? index + 1}</span>
                {budgetSpent !== null ? <span>{tt("Budget Spent", "\u5019\u9009\u987a\u5e8f")}: {budgetSpent}</span> : null}
              </div>

              {ranking?.selected_candidate || ranking?.component || ranking?.service ? (
                <div className="ranking-chip-row">
                  {ranking?.selected_candidate ? <span className="panel-chip">{ranking.selected_candidate}</span> : null}
                  {ranking?.component ? <span className="panel-chip">{ranking.component}</span> : null}
                  {ranking?.service ? <span className="panel-chip">{ranking.service}</span> : null}
                  {ranking?.version ? <span className="panel-chip">{ranking.version}</span> : null}
                </div>
              ) : null}

              {selectedTemplates.length ? (
                <div className="ranking-chip-row">
                  {selectedTemplates.slice(0, 8).map((item) => (
                    <span key={`${entry?.tool || "tool"}-tpl-${item}`} className="panel-chip">{item}</span>
                  ))}
                </div>
              ) : null}

              {candidateOrder.length ? (
                <div className="asset-meta">
                  <span>{tt("Candidate Order", "\u5019\u9009\u987a\u5e8f")}: {candidateOrder.join(", ")}</span>
                </div>
              ) : null}

              <div className="ranking-reason-list">
                {reasons.length ? reasons.map((reason) => (
                  <div key={`${entry?.tool || "tool"}-${reason}`} className="ranking-reason-item">{reason}</div>
                )) : (
                  <div className="empty-state">
                    {tt("No detailed selection reason was recorded for this action.", "\u5f53\u524d\u52a8\u4f5c\u6ca1\u6709\u8bb0\u5f55\u66f4\u8be6\u7ec6\u7684\u9009\u62e9\u539f\u56e0\u3002")}
                  </div>
                )}
              </div>

              {entry?.error ? <div className="error-toast">{entry.error}</div> : null}
            </article>
          );
        })}
      </div>
    </section>
  );
}
