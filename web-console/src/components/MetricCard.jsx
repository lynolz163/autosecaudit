export default function MetricCard({ label, value, tone = "neutral", detail }) {
  const toneStyles = {
    neutral: "border-white/80 bg-white/78",
    teal: "border-sky-100 bg-sky-50/85",
    amber: "border-amber-100 bg-amber-50/85",
    red: "border-rose-100 bg-rose-50/85",
  };

  const toneClass = toneStyles[tone] || toneStyles.neutral;

  return (
    <section className={`rounded-[28px] border px-5 py-5 backdrop-blur-2xl shadow-[0_28px_60px_-42px_rgba(15,23,42,0.24)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_32px_64px_-42px_rgba(15,23,42,0.28)] ${toneClass}`}>
      <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">{label}</p>
      <div className="mt-3 text-3xl font-semibold tracking-tight text-slate-950">{value}</div>
      {detail ? <p className="mt-2 text-sm leading-6 text-slate-500">{detail}</p> : null}
    </section>
  );
}
