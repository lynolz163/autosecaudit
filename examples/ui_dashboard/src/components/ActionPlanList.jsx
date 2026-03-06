function PriorityBadge({ priority }) {
  const p = Number(priority ?? 99);
  const ui =
    p === 0
      ? "bg-emerald-50 text-emerald-700"
      : p <= 20
      ? "bg-sky-50 text-sky-700"
      : p <= 30
      ? "bg-amber-50 text-amber-700"
      : "bg-slate-100 text-slate-700";
  return (
    <span className={`rounded-full px-2 py-1 text-[11px] font-semibold ${ui}`}>
      P{p}
    </span>
  );
}

export default function ActionPlanList({ actions }) {
  return (
    <section className="rounded-2xl bg-white p-5 shadow-[0_16px_36px_-22px_rgba(15,23,42,0.16)]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
            Action Plan
          </p>
          <h2 className="mt-1 text-lg font-semibold tracking-tight text-slate-900">
            Planned Actions
          </h2>
        </div>
        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
          {actions.length} actions
        </span>
      </div>

      <div className="space-y-3">
        {actions.length === 0 ? (
          <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-500">
            No planned actions.
          </div>
        ) : null}

        {actions.map((action) => (
          <div key={action.action_id} className="rounded-2xl bg-slate-50 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full bg-white px-2 py-1 text-[11px] font-semibold text-slate-600 shadow-sm">
                    {action.action_id}
                  </span>
                  <span className="text-sm font-semibold text-slate-900">
                    {action.tool_label}
                  </span>
                  <PriorityBadge priority={action.priority} />
                </div>
                <div className="mt-1 break-all text-xs text-slate-500">{action.target}</div>
              </div>

              <div className="rounded-xl bg-white px-3 py-2 text-right shadow-sm">
                <div className="text-[11px] uppercase tracking-wider text-slate-400">Cost</div>
                <div className="text-sm font-semibold text-slate-800">{action.cost}</div>
              </div>
            </div>

            <p className="mt-3 text-sm leading-relaxed text-slate-600">{action.reason}</p>

            <div className="mt-3 flex flex-wrap gap-2">
              {(action.preconditions || []).slice(0, 4).map((item) => (
                <span key={item} className="rounded-full bg-white px-2.5 py-1 text-[11px] text-slate-600 shadow-sm">
                  pre: {item}
                </span>
              ))}
              {(action.capabilities || []).slice(0, 3).map((item) => (
                <span key={item} className="rounded-full bg-sky-50 px-2.5 py-1 text-[11px] text-sky-700">
                  {item}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
