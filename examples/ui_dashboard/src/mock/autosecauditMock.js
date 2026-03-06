export const auditReport = {
  meta: {
    generated_at: "2026-02-22T09:03:19.055691+00:00",
    target: "https://example.com",
    decision_summary:
      "Proposed 3 safe action(s), total estimated cost 25, remaining budget after plan 5.",
    resumed: false,
    resumed_from: null,
  },
  summary: {
    audit_score: 84,
    score_label: "Good",
    total_findings: 3,
    vulnerability_findings: 3,
    severity_counts: {
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      info: 0,
    },
    history_count: 6,
    iteration_count: 2,
    budget_remaining: 17,
    budget_start_inferred: 50,
  },
  history: [
    {
      index: 1,
      tool: "passive_config_audit",
      target: "https://example.com:443",
      status: "completed",
      started_at: "2026-02-22T09:01:00Z",
      ended_at: "2026-02-22T09:01:01Z",
      action_cost: 3,
      budget_before: 50,
      budget_after: 47,
      error: null,
    },
    {
      index: 2,
      tool: "dynamic_crawl",
      target: "https://example.com:443/",
      status: "completed",
      started_at: "2026-02-22T09:01:02Z",
      ended_at: "2026-02-22T09:01:13Z",
      action_cost: 12,
      budget_before: 47,
      budget_after: 35,
      error: null,
    },
    {
      index: 3,
      tool: "dirsearch_scan",
      target: "https://example.com:443",
      status: "completed",
      started_at: "2026-02-22T09:01:14Z",
      ended_at: "2026-02-22T09:01:25Z",
      action_cost: 10,
      budget_before: 35,
      budget_after: 25,
      error: null,
    },
    {
      index: 4,
      tool: "xss_protection_audit",
      target: "https://example.com/search",
      status: "completed",
      started_at: "2026-02-22T09:01:26Z",
      ended_at: "2026-02-22T09:01:28Z",
      action_cost: 8,
      budget_before: 25,
      budget_after: 17,
      error: null,
    },
  ],
  budget_trace: [
    { step: 0, label: "Start", tool: "", cost: 0, cumulative_spent: 0, budget_after: 50 },
    { step: 1, label: "1. passive_config_audit", tool: "passive_config_audit", cost: 3, cumulative_spent: 3, budget_after: 47 },
    { step: 2, label: "2. dynamic_crawl", tool: "dynamic_crawl", cost: 12, cumulative_spent: 15, budget_after: 35 },
    { step: 3, label: "3. dirsearch_scan", tool: "dirsearch_scan", cost: 10, cumulative_spent: 25, budget_after: 25 },
    { step: 4, label: "4. xss_protection_audit", tool: "xss_protection_audit", cost: 8, cumulative_spent: 33, budget_after: 17 },
  ],
  scope: {
    scope: ["example.com"],
    breadcrumbs: [
      { type: "service", data: "https://example.com" },
      { type: "endpoint", data: "https://example.com/" },
      { type: "endpoint", data: "https://example.com/search?q=test" },
    ],
    surface: {
      discovered_urls: [
        "https://example.com/",
        "https://example.com/search?q=test",
        "https://example.com/login",
        "https://example.com/admin",
      ],
      api_endpoints: [
        { url: "https://example.com/api/search?q=test", method: "GET" },
      ],
      dirsearch_results: [
        { url: "https://example.com/.env", path: "/.env", status: 200, content_length: 642 },
        { url: "https://example.com/admin/", path: "/admin/", status: 403, content_length: 0 },
      ],
    },
  },
  findings: [
    {
      index: 1,
      type: "vuln",
      name: "Sensitive File Exposure: .env",
      severity: "critical",
      evidence: "{\"url\":\"https://example.com/.env\",\"status\":200}",
      reproduction_steps: [
        "Send GET request to https://example.com/.env.",
        "Confirm HTTP 200 and inspect response in authorized scope.",
      ],
      recommendation:
        "Remove public access, rotate secrets, and enforce deny-by-default for sensitive files.",
    },
    {
      index: 2,
      type: "vuln",
      name: "Potential XSS Reflection / Encoding Weakness",
      severity: "high",
      evidence: "context=html_body; snippet=<div>canary_xxx</div>",
      reproduction_steps: [
        "Request /search?q=<canary>.",
        "Observe unencoded reflection in response body.",
      ],
      recommendation:
        "Apply context-aware output encoding and avoid unsafe DOM sinks.",
    },
    {
      index: 3,
      type: "vuln",
      name: "Backup File Exposure",
      severity: "medium",
      evidence: "{\"url\":\"https://example.com/config.php.bak\",\"status\":200}",
      reproduction_steps: [
        "Send GET request to backup file URL.",
        "Verify unintended backup artifact exposure.",
      ],
      recommendation:
        "Remove backup artifacts from web root and harden deployment pipeline.",
    },
  ],
};

export const agentState = {
  scope: ["example.com"],
  breadcrumbs: auditReport.scope.breadcrumbs,
  history: auditReport.history,
  surface: auditReport.scope.surface,
  budget_remaining: 17,
  target: "https://example.com",
  iteration_count: 2,
  resumed: false,
  resumed_from: null,
};

export const actionPlan = {
  decision_summary: auditReport.meta.decision_summary,
  actions: [
    {
      action_id: "A1",
      tool_name: "passive_config_audit",
      target: "https://example.com:443",
      options: {},
      priority: 0,
      cost: 3,
      capabilities: ["network_read"],
      reason: "Low-cost high-value check for exposed configuration artifacts.",
      preconditions: ["target_in_scope", "not_already_done"],
      stop_conditions: ["budget_exhausted", "scope_violation_detected"],
    },
    {
      action_id: "A2",
      tool_name: "dynamic_crawl",
      target: "https://example.com:443/",
      options: { max_depth: 2, allow_domain: ["example.com"] },
      priority: 20,
      cost: 12,
      capabilities: ["network_read"],
      reason: "Expand in-scope surface and discover hidden endpoints/forms.",
      preconditions: ["target_in_scope", "http_service_confirmed", "not_already_done"],
      stop_conditions: ["budget_exhausted", "scope_violation_detected"],
    },
  ],
};

export const blockedActions = [
  {
    action: {
      action_id: "A9",
      tool_name: "nuclei_exploit_check",
      target: "https://example.com/admin",
      cost: 20,
      priority: 40,
    },
    reason: "insufficient_budget",
  },
  {
    action: {
      action_id: "A10",
      tool_name: "dynamic_crawl",
      target: "https://out-of-scope.example.net",
      cost: 12,
      priority: 20,
    },
    reason: "scope_fail_closed_resolved_ip_out_of_scope",
  },
];
