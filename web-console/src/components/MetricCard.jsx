export default function MetricCard({ label, value, tone = "neutral", detail }) {
  return (
    <section className={`metric-card metric-${tone}`}>
      <p className="metric-label">{label}</p>
      <div className="metric-value">{value}</div>
      {detail ? <p className="metric-detail">{detail}</p> : null}
    </section>
  );
}
