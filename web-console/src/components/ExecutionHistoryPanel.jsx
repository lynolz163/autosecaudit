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

  if (!rows.length) {
    return null;
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{language === "zh-CN" ? "执行解释" : "Execution Context"}</p>
          <h3>{language === "zh-CN" ? "已执行动作解释" : "Executed Action History"}</h3>
        </div>
        <div className="table-meta">
          {language === "zh-CN"
            ? "逐条解释动作为何被选中，并对齐执行结果。"
            : "Explain why each executed action was selected and how it completed."}
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
                <span>{language === "zh-CN" ? "目标" : "Target"}: {entry?.target || "-"}</span>
                <span>{language === "zh-CN" ? "阶段" : "Phase"}: {entry?.phase || "-"}</span>
                <span>{language === "zh-CN" ? "序号" : "Step"}: {entry?.index ?? index + 1}</span>
                {budgetSpent !== null ? <span>{language === "zh-CN" ? "预算消耗" : "Budget Spent"}: {budgetSpent}</span> : null}
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
                  <span>{language === "zh-CN" ? "候选顺序" : "Candidate Order"}: {candidateOrder.join(", ")}</span>
                </div>
              ) : null}

              <div className="ranking-reason-list">
                {reasons.length ? reasons.map((reason) => (
                  <div key={`${entry?.tool || "tool"}-${reason}`} className="ranking-reason-item">{reason}</div>
                )) : (
                  <div className="empty-state">
                    {language === "zh-CN" ? "该动作未记录更细的选择原因。" : "No detailed selection reason was recorded for this action."}
                  </div>
                )}
              </div>

              {entry?.error ? (
                <div className="error-toast">
                  {entry.error}
                </div>
              ) : null}
            </article>
          );
        })}
      </div>
    </section>
  );
}
