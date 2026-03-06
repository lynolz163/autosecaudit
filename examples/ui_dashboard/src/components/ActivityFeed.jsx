function itemStyle(kind) {
  switch (kind) {
    case "blocked":
      return {
        pill: "bg-rose-50 text-rose-700",
        iconBg: "bg-rose-100",
        icon: "BLK",
        label: "Blocked",
      };
    case "warning":
      return {
        pill: "bg-amber-50 text-amber-700",
        iconBg: "bg-amber-100",
        icon: "WRN",
        label: "Warning",
      };
    case "action":
      return {
        pill: "bg-emerald-50 text-emerald-700",
        iconBg: "bg-emerald-100",
        icon: "ACT",
        label: "Action",
      };
    default:
      return {
        pill: "bg-sky-50 text-sky-700",
        iconBg: "bg-sky-100",
        icon: "INF",
        label: "Info",
      };
  }
}

export default function ActivityFeed({ items }) {
  return (
    <section className="rounded-2xl bg-white p-5 shadow-[0_16px_36px_-22px_rgba(15,23,42,0.16)]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
            Agent Activity
          </p>
          <h2 className="mt-1 text-lg font-semibold tracking-tight text-slate-900">
            Execution and Policy Events
          </h2>
        </div>
        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
          {items.length} events
        </span>
      </div>

      <div className="space-y-3">
        {items.map((item) => {
          const ui = itemStyle(item.kind);
          return (
            <div key={item.id} className="flex gap-3 rounded-2xl bg-slate-50/90 p-3">
              <div className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl text-[10px] font-semibold tracking-wide ${ui.iconBg}`}>
                {ui.icon}
              </div>
              <div className="min-w-0 flex-1">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${ui.pill}`}>
                    {ui.label}
                  </span>
                  <span className="text-xs text-slate-400">{item.time}</span>
                </div>
                <div className="rounded-2xl bg-white px-3 py-2.5 shadow-[0_8px_22px_-18px_rgba(15,23,42,0.2)]">
                  <div className="text-sm font-medium text-slate-900">{item.title}</div>
                  <div className="mt-1 text-sm leading-relaxed text-slate-600">
                    {item.message}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
