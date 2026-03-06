function statusTone(status) {
  const s = String(status || "").toLowerCase();
  if (s.includes("high risk")) {
    return {
      dot: "bg-rose-500",
      pill: "bg-rose-50 text-rose-700",
    };
  }
  if (s.includes("block")) {
    return {
      dot: "bg-amber-500",
      pill: "bg-amber-50 text-amber-700",
    };
  }
  if (s.includes("warning")) {
    return {
      dot: "bg-orange-500",
      pill: "bg-orange-50 text-orange-700",
    };
  }
  return {
    dot: "bg-emerald-500",
    pill: "bg-emerald-50 text-emerald-700",
  };
}

export default function HeaderBar({
  appName,
  target,
  status,
  statusDetail,
  updatedAt,
  resumed,
  resumedFrom,
}) {
  const tone = statusTone(status);

  return (
    <header className="rounded-2xl border border-white/60 bg-white/70 px-4 py-3 shadow-[0_14px_40px_-22px_rgba(15,23,42,0.2)] backdrop-blur-xl sm:px-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-slate-900 to-slate-700 text-sm font-semibold text-white">
            AS
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold tracking-tight text-slate-900">
              {appName}
            </div>
            <div className="truncate text-xs text-slate-500">
              Target: <span className="font-medium text-slate-700">{target || "N/A"}</span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
          <div className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium ${tone.pill}`}>
            <span className={`h-2.5 w-2.5 rounded-full ${tone.dot}`} />
            <span>{status}</span>
          </div>
          <div className="rounded-full bg-slate-100/90 px-3 py-1.5 text-xs text-slate-600">
            {resumed ? "Resumed Run" : "Fresh Run"}
          </div>
          {updatedAt ? (
            <div className="rounded-full bg-white/80 px-3 py-1.5 text-xs text-slate-500">
              Updated {new Date(updatedAt).toLocaleString()}
            </div>
          ) : null}
        </div>
      </div>

      <div className="mt-3 grid gap-2 lg:grid-cols-[1fr_auto] lg:items-center">
        <div className="rounded-xl bg-white/80 px-3 py-2 text-sm text-slate-600 shadow-[0_8px_24px_-20px_rgba(15,23,42,0.25)]">
          <span className="font-medium text-slate-700">Decision:</span> {statusDetail}
        </div>
        {resumed && resumedFrom ? (
          <div className="truncate rounded-xl bg-slate-100 px-3 py-2 text-xs text-slate-500">
            resumed_from: {resumedFrom}
          </div>
        ) : null}
      </div>
    </header>
  );
}
