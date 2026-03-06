function severityBadge(severity) {
  const s = String(severity || "").toLowerCase();
  const map = {
    critical: "bg-rose-100 text-rose-700",
    high: "bg-orange-100 text-orange-700",
    medium: "bg-amber-100 text-amber-700",
    low: "bg-emerald-100 text-emerald-700",
    info: "bg-sky-100 text-sky-700",
  };
  return map[s] ?? map.info;
}

export default function FindingsPanel({ items }) {
  return (
    <section className="rounded-2xl bg-white p-5 shadow-[0_16px_36px_-22px_rgba(15,23,42,0.16)]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
            Findings
          </p>
          <h2 className="mt-1 text-lg font-semibold tracking-tight text-slate-900">
            Vulnerability Findings (`audit_report.findings`)
          </h2>
        </div>
        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
          {items.length} items
        </span>
      </div>

      <div className="space-y-3">
        {items.length === 0 ? (
          <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-500">
            No findings.
          </div>
        ) : null}

        {items.map((item) => (
          <button
            key={`${item.index}-${item.name}`}
            type="button"
            className="w-full rounded-2xl bg-slate-50 p-4 text-left transition hover:bg-white hover:shadow-[0_14px_28px_-18px_rgba(15,23,42,0.18)]"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold text-slate-900">
                  {item.name}
                </div>
                <div className="mt-1 text-xs text-slate-500">Finding #{item.index}</div>
              </div>
              <span
                className={`rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider ${severityBadge(
                  item.severity
                )}`}
              >
                {item.severity}
              </span>
            </div>

            <p className="mt-3 line-clamp-2 text-sm leading-relaxed text-slate-600">
              {String(item.evidence || "No evidence").slice(0, 180)}
            </p>

            {item.recommendation ? (
              <div className="mt-3 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-800">
                <span className="font-semibold">Fix:</span> {item.recommendation}
              </div>
            ) : null}
          </button>
        ))}
      </div>
    </section>
  );
}
