import { useI18n } from "../i18n";

function boolLabel(value, language) {
  if (value === true) return language === "zh-CN" ? "是" : "Yes";
  if (value === false) return language === "zh-CN" ? "否" : "No";
  return "-";
}

function RankingExplanationCard({ explanation, language }) {
  if (!explanation || typeof explanation !== "object") {
    return null;
  }
  const reasons = Array.isArray(explanation.reasons) ? explanation.reasons : [];
  const selectedTemplates = Array.isArray(explanation.selected_templates) ? explanation.selected_templates : [];
  const protocolTags = Array.isArray(explanation.protocol_tags) ? explanation.protocol_tags : [];
  return (
    <div className="ranking-block">
      <div className="table-title">
        <strong>{explanation.tool || "-"}</strong>
        <span className="panel-chip">{explanation.selected_candidate || "-"}</span>
      </div>
      <div className="asset-meta">
        <span>{language === "zh-CN" ? "目标" : "Target"}: {explanation.target || "-"}</span>
        <span>{language === "zh-CN" ? "组件" : "Component"}: {explanation.component || "-"}</span>
        <span>{language === "zh-CN" ? "服务" : "Service"}: {explanation.service || "-"}</span>
        <span>{language === "zh-CN" ? "版本" : "Version"}: {explanation.version || "-"}</span>
      </div>
      {selectedTemplates.length ? (
        <div className="ranking-chip-row">
          {selectedTemplates.slice(0, 8).map((item) => (
            <span key={item} className="panel-chip">{item}</span>
          ))}
        </div>
      ) : null}
      {protocolTags.length ? (
        <div className="ranking-chip-row">
          {protocolTags.slice(0, 8).map((item) => (
            <span key={`tag-${item}`} className="panel-chip">{item}</span>
          ))}
        </div>
      ) : null}
      <div className="ranking-reason-list">
        {reasons.length ? reasons.map((reason) => (
          <div key={reason} className="ranking-reason-item">{reason}</div>
        )) : (
          <div className="empty-state">{language === "zh-CN" ? "未记录排序依据。" : "No ranking reason recorded."}</div>
        )}
      </div>
    </div>
  );
}

function ActionPlanInspector({ payload, language }) {
  const actions = Array.isArray(payload?.actions) ? payload.actions : [];
  const rankingOverview = Array.isArray(payload?.ranking_overview) ? payload.ranking_overview : [];
  return (
    <div className="ranking-block-list">
      <div className="table-meta">
        {payload?.decision_summary || (language === "zh-CN" ? "无决策摘要。" : "No decision summary.")}
      </div>
      {rankingOverview.length ? (
        <div className="ranking-block">
          <div className="table-title">
            <strong>{language === "zh-CN" ? "计划排序总览" : "Plan Ranking Overview"}</strong>
            <span className="panel-chip">{rankingOverview.length}</span>
          </div>
          <div className="ranking-reason-list">
            {rankingOverview.slice(0, 8).map((item, index) => (
              <div key={`${item.tool || "tool"}-${index}`} className="ranking-reason-item">
                {(item.tool || "-")}: {(item.selected_candidate || item.selected_templates?.[0] || "-")}
              </div>
            ))}
          </div>
        </div>
      ) : null}
      <div className="table-list">
        {actions.length ? actions.map((action) => (
          <div key={action.action_id || `${action.tool_name}-${action.target}`} className="table-row is-static">
            <div className="table-title">
              <strong>{action.tool_name || "-"}</strong>
              <span className="panel-chip">{action.action_id || "-"}</span>
            </div>
            <div className="asset-meta">
              <span>{language === "zh-CN" ? "目标" : "Target"}: {action.target || "-"}</span>
              <span>{language === "zh-CN" ? "成本" : "Cost"}: {action.cost ?? "-"}</span>
              <span>{language === "zh-CN" ? "优先级" : "Priority"}: {action.priority ?? "-"}</span>
            </div>
            {action.ranking_explanation ? <RankingExplanationCard explanation={action.ranking_explanation} language={language} /> : null}
          </div>
        )) : (
          <div className="empty-state">{language === "zh-CN" ? "当前计划没有可执行动作。" : "No executable actions in this plan."}</div>
        )}
      </div>
    </div>
  );
}

function ActionArtifactInspector({ payload, language }) {
  const action = payload?.action && typeof payload.action === "object" ? payload.action : {};
  const ranking = payload?.ranking_explanation || action?.ranking_explanation || null;
  return (
    <div className="ranking-block-list">
      <div className="ranking-block">
        <div className="table-title">
          <strong>{action.tool_name || "-"}</strong>
          <span className="panel-chip">{payload?.status || "-"}</span>
        </div>
        <div className="asset-meta">
          <span>{language === "zh-CN" ? "动作" : "Action"}: {action.action_id || "-"}</span>
          <span>{language === "zh-CN" ? "目标" : "Target"}: {action.target || "-"}</span>
          <span>{language === "zh-CN" ? "耗时" : "Duration"}: {payload?.duration_ms ?? "-"} ms</span>
          <span>{language === "zh-CN" ? "重试" : "Attempts"}: {payload?.attempts ?? "-"}</span>
        </div>
        {payload?.error ? <div className="table-meta">{payload.error}</div> : null}
      </div>
      {ranking ? <RankingExplanationCard explanation={ranking} language={language} /> : null}
      {payload?.metadata && typeof payload.metadata === "object" ? (
        <div className="ranking-block">
          <div className="table-title">
            <strong>{language === "zh-CN" ? "执行元数据" : "Execution Metadata"}</strong>
          </div>
          <div className="asset-meta">
            {Object.entries(payload.metadata)
              .filter(([, value]) => value !== null && value !== undefined && value !== "")
              .slice(0, 10)
              .map(([key, value]) => (
                <span key={key}>
                  {key}: {Array.isArray(value) ? value.join(", ") : String(typeof value === "object" ? JSON.stringify(value) : value)}
                </span>
              ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function ArtifactInspector({ artifact, payload }) {
  const { language } = useI18n();

  if (!artifact) {
    return null;
  }

  const path = String(artifact.path || "");
  const isActionPlan = path.endsWith("ActionPlan.json");
  const isActionArtifact = path.includes("/agent/artifacts/") && path.endsWith(".json");

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{language === "zh-CN" ? "工件详情" : "Artifact Detail"}</p>
          <h3>{path || "-"}</h3>
        </div>
        <div className="table-meta">
          {language === "zh-CN" ? "查看计划、执行和排序解释。" : "Inspect plan, execution, and ranking context."}
        </div>
      </div>

      {!payload ? (
        <div className="empty-state">{language === "zh-CN" ? "选择 JSON 工件后可查看详情。" : "Select a JSON artifact to inspect."}</div>
      ) : isActionPlan ? (
        <ActionPlanInspector payload={payload} language={language} />
      ) : isActionArtifact ? (
        <ActionArtifactInspector payload={payload} language={language} />
      ) : (
        <div className="ranking-block-list">
          <div className="ranking-block">
            <div className="table-title">
              <strong>{language === "zh-CN" ? "原始内容" : "Raw Content"}</strong>
              <span className="panel-chip">{typeof payload}</span>
            </div>
            <pre className="report-code">{typeof payload === "string" ? payload : JSON.stringify(payload, null, 2)}</pre>
          </div>
        </div>
      )}
    </section>
  );
}
