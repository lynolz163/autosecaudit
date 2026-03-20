function statusTone(report) {
  const summary = report?.summary || {};
  if (Number(summary.fail || 0) > 0) {
    return "critical";
  }
  if (Number(summary.warn || 0) > 0) {
    return "warning";
  }
  return "healthy";
}

function statusLabel(tone) {
  if (tone === "critical") {
    return "Critical";
  }
  if (tone === "warning") {
    return "Attention";
  }
  return "Healthy";
}

export default function SystemHealthIndicator({ report, compact = false }) {
  if (!report) {
    return null;
  }

  const summary = report.summary || {};
  const tone = statusTone(report);
  const issues = Array.isArray(report.checks)
    ? report.checks.filter((item) => item?.status !== "pass").slice(0, compact ? 1 : 2)
    : [];
  const toneStyles = {
    healthy: "border-emerald-200 bg-emerald-50/88 text-emerald-700",
    warning: "border-amber-200 bg-amber-50/88 text-amber-700",
    critical: "border-rose-200 bg-rose-50/88 text-rose-700",
  };
  const toneClass = toneStyles[tone] || toneStyles.healthy;

  if (compact) {
    return (
      <div className={`inline-flex flex-wrap items-center gap-2 rounded-full border px-3 py-2 text-xs font-medium shadow-[0_14px_28px_-24px_rgba(15,23,42,0.18)] ${toneClass}`}>
        <span className="h-2 w-2 rounded-full bg-current" />
        <span>{statusLabel(tone)}</span>
        <span className="text-current/75">Pass {summary.pass || 0}</span>
        <span className="text-current/75">Warn {summary.warn || 0}</span>
        <span className="text-current/75">Fail {summary.fail || 0}</span>
      </div>
    );
  }

  return (
    <section className={`rounded-[26px] border px-4 py-3 backdrop-blur-xl shadow-[0_22px_42px_-34px_rgba(15,23,42,0.18)] ${toneClass}`}>
      <div className="flex items-start gap-3">
        <div className="mt-1 h-2.5 w-2.5 rounded-full bg-current" />
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-current/70">Environment</p>
          <strong className="text-sm font-semibold">{statusLabel(tone)}</strong>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 text-xs text-current/80">
        <span>Pass {summary.pass || 0}</span>
        <span>Warn {summary.warn || 0}</span>
        <span>Fail {summary.fail || 0}</span>
      </div>
      {issues.length ? (
        <div className="mt-3 space-y-2">
          {issues.map((item) => (
            <div key={item.check_id} className="rounded-[22px] border border-white/60 bg-white/55 px-3 py-2 text-xs leading-5 shadow-[0_14px_24px_-22px_rgba(15,23,42,0.15)]">
              <strong className="block">{item.message}</strong>
              {item.detail ? <span className="text-current/80">{item.detail}</span> : null}
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
