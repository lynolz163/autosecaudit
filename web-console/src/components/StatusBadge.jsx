import { useI18n } from "../i18n";

export default function StatusBadge({ status }) {
  const { formatStatus } = useI18n();
  const normalized = String(status || "unknown").toLowerCase();
  let tone = "slate";
  if (normalized === "completed" || normalized === "passed" || normalized === "active" || normalized === "builtin" || normalized === "safe") tone = "green";
  else if (normalized === "running" || normalized === "queued") tone = "cyan";
  else if (normalized === "failed" || normalized === "error") tone = "red";
  else if (normalized === "canceled" || normalized === "skipped" || normalized === "frozen" || normalized === "disabled" || normalized === "low" || normalized === "external") tone = "amber";
  else if (normalized === "medium") tone = "red";

  return <span className={`status-badge status-${tone}`}>{formatStatus(status)}</span>;
}
