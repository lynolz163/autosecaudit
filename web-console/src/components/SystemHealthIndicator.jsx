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

  return (
    <section className={`system-health-card is-${tone} ${compact ? "is-compact" : ""}`}>
      <div className="system-health-head">
        <div className="system-health-dot" />
        <div>
          <p className="eyebrow">Environment</p>
          <strong>{statusLabel(tone)}</strong>
        </div>
      </div>
      <div className="system-health-metrics">
        <span>Pass {summary.pass || 0}</span>
        <span>Warn {summary.warn || 0}</span>
        <span>Fail {summary.fail || 0}</span>
      </div>
      {!compact && issues.length ? (
        <div className="system-health-issues">
          {issues.map((item) => (
            <div key={item.check_id} className="system-health-issue">
              <strong>{item.message}</strong>
              {item.detail ? <span>{item.detail}</span> : null}
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
