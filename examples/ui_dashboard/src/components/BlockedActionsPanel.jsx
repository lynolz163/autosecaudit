function reasonTone(reason) {
  const text = String(reason || "");
  if (text.includes("scope_fail_closed") || text.includes("out_of_scope")) {
    return "bg-rose-50 text-rose-700";
  }
  if (text.includes("budget")) {
    return "bg-amber-50 text-amber-700";
  }
  return "bg-slate-100 text-slate-700";
}

export default function BlockedActionsPanel({ items }) {
  return (
    <section className="rounded-2xl bg-white p-5 shadow-[0_16px_36px_-22px_rgba(15,23,42,0.16)]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
            Policy Blocks
          </p>
          <h2 className="mt-1 text-lg font-semibold tracking-tight text-slate-900">
            Blocked Actions (`blocked_actions.json`)
          </h2>
        </div>
        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
          {items.length} blocked
        </span>
      </div>

      <div className="space-y-3">
        {items.length === 0 ? (
          <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-500">
            No blocked actions.
          </div>
        ) : null}

        {items.map((item, idx) => (
          <div key={`${idx}-${item?.action?.action_id ?? "x"}`} className="rounded-2xl bg-slate-50 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-900">
                  {item?.action?.action_id ?? "N/A"} | {item?.action?.tool_name ?? "unknown_tool"}
                </div>
                <div className="mt-1 break-all text-xs text-slate-500">
                  {item?.action?.target ?? "N/A"}
                </div>
              </div>
              <span className={`rounded-full px-2.5 py-1 text-[11px] font-medium ${reasonTone(item?.reason)}`}>
                {item?.reason ?? "blocked"}
              </span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
