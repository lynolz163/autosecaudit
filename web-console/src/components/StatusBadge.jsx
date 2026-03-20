import { useI18n } from "../i18n";

export default function StatusBadge({ status }) {
  const { formatStatus } = useI18n();
  const normalized = String(status || "unknown").toLowerCase();
  let toneClass = "border-slate-200 bg-white/86 text-slate-600";

  if (["completed", "passed", "active", "builtin", "safe"].includes(normalized)) {
    toneClass = "border-emerald-200 bg-emerald-50 text-emerald-700";
  } else if (["running", "queued"].includes(normalized)) {
    toneClass = "border-sky-200 bg-sky-50 text-sky-700";
  } else if (["failed", "error", "environment_blocked", "medium"].includes(normalized)) {
    toneClass = "border-rose-200 bg-rose-50 text-rose-700";
  } else if (["waiting_approval", "partial_complete", "canceled", "skipped", "frozen", "disabled", "low", "external"].includes(normalized)) {
    toneClass = "border-amber-200 bg-amber-50 text-amber-700";
  }

  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium shadow-[0_10px_20px_-18px_rgba(15,23,42,0.18)] ${toneClass}`}>
      {formatStatus(status)}
    </span>
  );
}
