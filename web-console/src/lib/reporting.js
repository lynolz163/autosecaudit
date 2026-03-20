import { buildAuthedUrl } from "./api";

const SEVERITY_BASE = Object.freeze({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

export function buildSeverityMap(findings) {
  const severityMap = { ...SEVERITY_BASE };
  for (const item of findings || []) {
    const key = String(item?.severity || "info").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(severityMap, key)) {
      severityMap[key] += 1;
    } else {
      severityMap.info += 1;
    }
  }
  return severityMap;
}

export function computeAuditScore(findings) {
  const severity = buildSeverityMap(findings);
  const penalty = (severity.critical * 18) + (severity.high * 10) + (severity.medium * 4) + severity.low;
  return Math.max(0, 100 - penalty);
}

export function describeAuditScore(score) {
  if (score >= 85) return "Stable";
  if (score >= 70) return "Watch";
  if (score >= 50) return "At Risk";
  return "Action Required";
}

export function buildReportExportUrl(report, token = "", format = "html") {
  if (!report?.job_id) {
    return "";
  }

  return buildAuthedUrl(
    `/api/reports/${encodeURIComponent(report.job_id)}/export?format=${encodeURIComponent(format)}`,
    token,
  );
}

export function normalizeAvailableReportExports(analysis, report, fallback = []) {
  const rawFormats = analysis?.available_exports || report?.available_formats || fallback;
  return Array.from(
    new Set(
      (Array.isArray(rawFormats) ? rawFormats : [])
        .map((item) => String(item || "").trim().toLowerCase())
        .filter(Boolean),
    ),
  );
}
