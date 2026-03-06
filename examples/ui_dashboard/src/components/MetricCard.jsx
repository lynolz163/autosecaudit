const TONES = {
  rose: {
    ring: "ring-rose-100",
    badge: "bg-rose-50 text-rose-700",
    dot: "bg-rose-400",
  },
  sky: {
    ring: "ring-sky-100",
    badge: "bg-sky-50 text-sky-700",
    dot: "bg-sky-400",
  },
  emerald: {
    ring: "ring-emerald-100",
    badge: "bg-emerald-50 text-emerald-700",
    dot: "bg-emerald-400",
  },
  amber: {
    ring: "ring-amber-100",
    badge: "bg-amber-50 text-amber-700",
    dot: "bg-amber-400",
  },
};

export default function MetricCard({ label, value, subtext, tone = "sky" }) {
  const ui = TONES[tone] ?? TONES.sky;
  return (
    <div
      className={`rounded-2xl bg-white p-4 ring-1 ${ui.ring} shadow-[0_12px_32px_-20px_rgba(15,23,42,0.15)] transition hover:-translate-y-0.5 hover:shadow-[0_18px_34px_-18px_rgba(15,23,42,0.18)]`}
    >
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-slate-500">{label}</p>
        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-[11px] font-medium ${ui.badge}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${ui.dot}`} />
          Live
        </span>
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight text-slate-900">{value}</div>
      <p className="mt-2 text-xs leading-relaxed text-slate-500">{subtext}</p>
    </div>
  );
}
