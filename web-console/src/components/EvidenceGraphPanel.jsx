import { useI18n } from "../i18n";

function normalizeEvidenceGraph(analysis) {
  const graph = analysis?.evidence_graph;
  const pathGraph = analysis?.path_graph;
  const remediationPriority = analysis?.remediation_priority;
  const cveValidation = analysis?.cve_validation;
  return {
    summary: graph && typeof graph.summary === "object" ? graph.summary : {},
    claims: Array.isArray(graph?.claims) ? graph.claims : [],
    priorityTargets: Array.isArray(graph?.priority_targets) ? graph.priority_targets : [],
    recommendedTools: Array.isArray(graph?.recommended_tools) ? graph.recommended_tools : [],
    pathGraph: pathGraph && typeof pathGraph === "object" ? pathGraph : {},
    remediationPriority: Array.isArray(remediationPriority) ? remediationPriority : [],
    cveValidation: cveValidation && typeof cveValidation === "object" ? cveValidation : {},
  };
}

export default function EvidenceGraphPanel({ analysis, mode = "report" }) {
  const { language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const {
    summary,
    claims,
    priorityTargets,
    recommendedTools,
    pathGraph,
    remediationPriority,
    cveValidation,
  } = normalizeEvidenceGraph(analysis);
  const pathNodes = Array.isArray(pathGraph?.nodes) ? pathGraph.nodes : [];
  const pathEdges = Array.isArray(pathGraph?.edges) ? pathGraph.edges : [];
  const cveSummary = cveValidation?.summary && typeof cveValidation.summary === "object"
    ? cveValidation.summary
    : {};

  if (
    !claims.length
    && !priorityTargets.length
    && !recommendedTools.length
    && !pathNodes.length
    && !remediationPriority.length
    && !Object.keys(cveSummary).length
  ) {
    return null;
  }

  return (
    <section className="panel evidence-graph-panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{tt("Evidence Correlation", "证据关联")}</p>
          <h3>{mode === "job" ? tt("Cross-validated live leads", "实时交叉印证线索") : tt("Corroborated evidence chain", "证据链与交叉印证")}</h3>
        </div>
        <div className="table-meta">
          {tt("Corroborated", "已印证")} {summary.corroborated_claims || 0}
          {" | "}
          {tt("High confidence", "高置信")} {summary.high_confidence_claims || 0}
          {" | "}
          {tt("High quality", "高质量")} {summary.high_quality_claims || 0}
        </div>
      </div>

      <div className="evidence-graph-grid">
        <article className="evidence-card">
          <div className="table-title">
            <strong>{tt("Priority targets", "优先目标")}</strong>
            <span className="panel-chip">{priorityTargets.length}</span>
          </div>
          <div className="evidence-card-list">
            {priorityTargets.length ? priorityTargets.slice(0, 8).map((item, index) => (
              <div key={`${item.target || "target"}-${index}`} className="evidence-entry">
                <div className="table-title">
                  <strong>{item.target || "-"}</strong>
                  <span className="panel-chip">{tt("Score", "评分")} {item.score ?? 0}</span>
                </div>
                <div className="ranking-reason-list">
                  {(Array.isArray(item.reasons) ? item.reasons : []).slice(0, 4).map((reason) => (
                    <div key={`${item.target || "target"}-${reason}`} className="ranking-reason-item">{reason}</div>
                  ))}
                </div>
              </div>
            )) : (
              <div className="empty-state">{tt("No priority targets derived yet.", "暂无已推导的优先目标。")}</div>
            )}
          </div>
        </article>

        <article className="evidence-card">
          <div className="table-title">
            <strong>{tt("Corroborated claims", "已印证声明")}</strong>
            <span className="panel-chip">{claims.length}</span>
          </div>
          <div className="evidence-tool-row">
            {recommendedTools.slice(0, 10).map((toolName) => (
              <span key={toolName} className="panel-chip">{toolName}</span>
            ))}
          </div>
          <div className="evidence-card-list">
            {claims.length ? claims.slice(0, 10).map((claim, index) => (
              <div key={`${claim.claim_id || claim.subject || "claim"}-${index}`} className="evidence-entry">
                <div className="table-title">
                  <strong>{claim.subject || "-"}</strong>
                  <span className="panel-chip">
                    {tt("Confidence", "置信度")} {claim.confidence ?? 0}
                  </span>
                </div>
                <div className="asset-meta">
                  <span>{claim.kind || tt("claim", "声明")}</span>
                  <span>{tt("Sources", "来源")} {claim.source_count ?? 0}</span>
                  <span>{tt("Evidence", "证据")} {claim.evidence_count ?? 0}</span>
                  <span>{tt("Quality", "质量")} {claim.quality_label || "-"}</span>
                </div>
                {Array.isArray(claim.targets) && claim.targets.length ? (
                  <div className="table-meta">
                    {tt("Targets", "目标")}: {claim.targets.slice(0, 3).join(", ")}
                  </div>
                ) : null}
              </div>
            )) : (
              <div className="empty-state">{tt("No corroborated claims yet.", "暂无已印证线索。")}</div>
            )}
          </div>
        </article>
      </div>

      {(pathNodes.length || pathEdges.length) ? (
        <div className="evidence-graph-grid">
          <article className="evidence-card">
            <div className="table-title">
              <strong>{tt("Attack path graph", "攻击路径图")}</strong>
              <span className="panel-chip">{pathNodes.length} / {pathEdges.length}</span>
            </div>
            <div className="table-meta">
              {tt("Nodes / edges extracted from corroborated claims", "从交叉印证声明中提取的节点和连边")}
            </div>
            <div className="evidence-card-list">
              {pathEdges.length ? pathEdges.slice(0, 10).map((edge, index) => (
                <div key={`${edge.source || "source"}-${edge.target || "target"}-${index}`} className="evidence-entry">
                  <div className="table-title">
                    <strong>{edge.source || "-"}</strong>
                    <span className="panel-chip">{edge.kind || "edge"}</span>
                  </div>
                  <div className="table-meta">
                    {tt("To", "到")}: {edge.target || "-"} | {tt("Confidence", "置信度")} {edge.confidence ?? 0}
                  </div>
                </div>
              )) : (
                <div className="empty-state">{tt("No path edges yet.", "暂无路径连边。")}</div>
              )}
            </div>
          </article>

          <article className="evidence-card">
            <div className="table-title">
              <strong>{tt("Remediation priority", "修复优先级")}</strong>
              <span className="panel-chip">{remediationPriority.length}</span>
            </div>
            <div className="evidence-card-list">
              {remediationPriority.length ? remediationPriority.slice(0, 8).map((item, index) => (
                <div key={`${item.title || "issue"}-${index}`} className="evidence-entry">
                  <div className="table-title">
                    <strong>{item.title || "-"}</strong>
                    <span className="panel-chip">{item.priority || "P4"}</span>
                  </div>
                  <div className="asset-meta">
                    <span>{item.severity || "info"}</span>
                    <span>{item.target || "-"}</span>
                  </div>
                  <div className="table-meta">{item.reason || "-"}</div>
                </div>
              )) : (
                <div className="empty-state">{tt("No remediation priorities yet.", "暂无修复优先级。")}</div>
              )}
            </div>
          </article>
        </div>
      ) : null}

      {Object.keys(cveSummary).length ? (
        <div className="evidence-card">
          <div className="table-title">
            <strong>{tt("CVE validation pipeline", "CVE 分级验证流水线")}</strong>
            <span className="panel-chip">{cveSummary.candidate_count || 0}</span>
          </div>
          <div className="asset-meta">
            <span>{tt("Version", "版本印证")} {cveSummary.version_corroborated_count || 0}</span>
            <span>{tt("Template", "模板验证")} {cveSummary.template_verified_count || 0}</span>
            <span>{tt("Sandbox", "沙箱就绪")} {cveSummary.sandbox_ready_count || 0}</span>
          </div>
        </div>
      ) : null}
    </section>
  );
}
