const TOOL_LABELS = {
  passive_config_audit: "Passive Config Audit",
  dynamic_crawl: "Dynamic Crawl",
  dirsearch_scan: "Dirsearch Scan",
  sql_sanitization_audit: "SQL Sanitization Audit",
  xss_protection_audit: "XSS Protection Audit",
  nmap_scan: "Nmap Scan",
  nuclei_exploit_check: "Nuclei Exploit Check",
};

export function selectDashboardViewModel({
  auditReport,
  agentState,
  actionPlan,
  blockedActions,
}) {
  const summary = auditReport?.summary ?? {};
  const meta = auditReport?.meta ?? {};
  const findings = Array.isArray(auditReport?.findings) ? auditReport.findings : [];
  const history = Array.isArray(auditReport?.history)
    ? auditReport.history
    : Array.isArray(agentState?.history)
    ? agentState.history
    : [];
  const planActions = Array.isArray(actionPlan?.actions) ? actionPlan.actions : [];
  const blocked = Array.isArray(blockedActions) ? blockedActions : [];

  const metrics = [
    {
      key: "score",
      label: "Audit Score",
      value: String(summary.audit_score ?? 0),
      subtext: summary.score_label ?? "N/A",
      tone: "sky",
    },
    {
      key: "vulns",
      label: "Findings",
      value: String(summary.vulnerability_findings ?? findings.length ?? 0),
      subtext: buildSeveritySummary(summary.severity_counts),
      tone: "rose",
    },
    {
      key: "budget",
      label: "Budget Remaining",
      value: String(summary.budget_remaining ?? agentState?.budget_remaining ?? 0),
      subtext: `Iteration ${summary.iteration_count ?? agentState?.iteration_count ?? 0}`,
      tone: "emerald",
    },
    {
      key: "actions",
      label: "Action State",
      value: `${history.length}/${planActions.length || history.length || 0}`,
      subtext: `Executed ${history.length} / Blocked ${blocked.length}`,
      tone: "amber",
    },
  ];

  const activityItems = [
    ...history.map((item) => ({
      id: `history-${item.index ?? Math.random()}`,
      kind: mapHistoryKind(item),
      title: `${formatToolName(item.tool)} | ${item.status ?? "unknown"}`,
      message: `${item.target ?? ""}${formatBudgetLine(item)}`,
      time: formatTime(item.ended_at || item.started_at),
      raw: item,
    })),
    ...blocked.map((item, idx) => ({
      id: `blocked-${idx}`,
      kind: "blocked",
      title: `${formatToolName(item?.action?.tool_name)} | blocked`,
      message: `${item?.action?.target ?? ""} | ${item?.reason ?? "policy_block"}`,
      time: "Policy",
      raw: item,
    })),
  ].sort(sortActivityNewestFirst);

  const plannedActions = planActions.map((action) => ({
    ...action,
    tool_label: formatToolName(action.tool_name),
  }));

  const findingsItems = findings
    .filter((item) => String(item?.type ?? "").toLowerCase() === "vuln")
    .map((item) => ({
      ...item,
      severity: String(item.severity ?? "medium").toLowerCase(),
    }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  const scopePanel = {
    target: meta.target ?? agentState?.target ?? "",
    resumed: Boolean(meta.resumed ?? agentState?.resumed),
    resumedFrom: meta.resumed_from ?? agentState?.resumed_from ?? null,
    scope: auditReport?.scope?.scope ?? agentState?.scope ?? [],
    breadcrumbs: auditReport?.scope?.breadcrumbs ?? agentState?.breadcrumbs ?? [],
    surface: auditReport?.scope?.surface ?? agentState?.surface ?? {},
  };

  const toolCoverage = buildToolCoverage({
    history,
    planActions,
    blocked,
  });

  return {
    meta: {
      appName: "AutoSecAudit",
      target: scopePanel.target,
      status: inferGlobalStatus({ findings: findingsItems, blocked, history }),
      statusDetail: meta.decision_summary ?? actionPlan?.decision_summary ?? "No decision summary",
      updatedAt: meta.generated_at ?? null,
      resumed: scopePanel.resumed,
      resumedFrom: scopePanel.resumedFrom,
    },
    metrics,
    activityItems,
    plannedActions,
    blockedActions: blocked,
    findingsItems,
    budgetTrace: Array.isArray(auditReport?.budget_trace) ? auditReport.budget_trace : [],
    scopePanel,
    toolCoverage,
  };
}

function buildSeveritySummary(counts) {
  if (!counts || typeof counts !== "object") {
    return "No severity distribution";
  }
  const c = Number(counts.critical || 0);
  const h = Number(counts.high || 0);
  const m = Number(counts.medium || 0);
  const l = Number(counts.low || 0);
  return `C${c} / H${h} / M${m} / L${l}`;
}

function formatToolName(toolName) {
  if (!toolName) return "Unknown Tool";
  return TOOL_LABELS[toolName] ?? toolName;
}

function formatBudgetLine(item) {
  const before = item?.budget_before;
  const after = item?.budget_after;
  const cost = item?.action_cost;
  if (
    typeof before === "number" &&
    typeof after === "number" &&
    typeof cost === "number"
  ) {
    return ` | cost ${cost} | budget ${before}->${after}`;
  }
  return "";
}

function formatTime(value) {
  if (!value) return "N/A";
  try {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleTimeString();
  } catch {
    return String(value);
  }
}

function mapHistoryKind(item) {
  const status = String(item?.status ?? "").toLowerCase();
  if (status === "error") return "warning";
  if (status === "failed") return "warning";
  if (status === "completed") return "action";
  return "info";
}

function severityRank(level) {
  const rank = ["critical", "high", "medium", "low", "info"].indexOf(level);
  return rank < 0 ? 999 : rank;
}

function inferGlobalStatus({ findings, blocked, history }) {
  const hasCritical = findings.some((item) => item.severity === "critical");
  if (hasCritical) return "High Risk";
  const hasBlocked = (blocked?.length ?? 0) > 0;
  if (hasBlocked) return "Policy Blocks";
  const hasErrors = (history ?? []).some((item) =>
    ["failed", "error"].includes(String(item?.status ?? "").toLowerCase())
  );
  if (hasErrors) return "Warnings";
  return "Healthy";
}

function sortActivityNewestFirst(a, b) {
  const ta = Date.parse(a?.raw?.ended_at ?? a?.raw?.started_at ?? "");
  const tb = Date.parse(b?.raw?.ended_at ?? b?.raw?.started_at ?? "");
  const validA = Number.isFinite(ta);
  const validB = Number.isFinite(tb);
  if (validA && validB) return tb - ta;
  if (validA) return -1;
  if (validB) return 1;
  return 0;
}

function buildToolCoverage({ history, planActions, blocked }) {
  const seen = new Map();
  for (const item of history ?? []) {
    const tool = String(item?.tool ?? "").trim();
    if (!tool) continue;
    seen.set(tool, {
      tool,
      label: formatToolName(tool),
      executed: (seen.get(tool)?.executed ?? 0) + 1,
      planned: seen.get(tool)?.planned ?? 0,
      blocked: seen.get(tool)?.blocked ?? 0,
    });
  }
  for (const item of planActions ?? []) {
    const tool = String(item?.tool_name ?? "").trim();
    if (!tool) continue;
    seen.set(tool, {
      tool,
      label: formatToolName(tool),
      executed: seen.get(tool)?.executed ?? 0,
      planned: (seen.get(tool)?.planned ?? 0) + 1,
      blocked: seen.get(tool)?.blocked ?? 0,
    });
  }
  for (const item of blocked ?? []) {
    const tool = String(item?.action?.tool_name ?? "").trim();
    if (!tool) continue;
    seen.set(tool, {
      tool,
      label: formatToolName(tool),
      executed: seen.get(tool)?.executed ?? 0,
      planned: seen.get(tool)?.planned ?? 0,
      blocked: (seen.get(tool)?.blocked ?? 0) + 1,
    });
  }
  return Array.from(seen.values()).sort((a, b) => a.label.localeCompare(b.label));
}
