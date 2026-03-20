import { useMemo } from "react";
import StatusBadge from "../components/StatusBadge";
import { useI18n } from "../i18n";
import { formatDateTime, truncateMiddle } from "../lib/formatters";

function getTime(value) {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : null;
}

function withinWindow(value, start, end) {
  const ts = getTime(value);
  if (ts === null) {
    return false;
  }
  return ts >= start && ts < end;
}

function countWindowJobs(jobs, start, end) {
  return jobs.filter((job) => withinWindow(job.last_updated_at || job.updated_at || job.created_at, start, end)).length;
}

function aggregateRecentSeverity(items) {
  const base = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of items || []) {
    const counts = item?.severity_counts;
    if (!counts || typeof counts !== "object") {
      continue;
    }
    for (const key of Object.keys(base)) {
      base[key] += Number(counts[key] || 0);
    }
  }
  return base;
}

function sumSeverity(counts, keys) {
  return keys.reduce((total, key) => total + Number(counts?.[key] || 0), 0);
}

function deltaTone(delta) {
  if (delta > 0) return "text-rose-600";
  if (delta < 0) return "text-emerald-600";
  return "text-slate-500";
}

function deltaPrefix(delta) {
  return delta > 0 ? "+" : "";
}

function statusBucket(jobs, statuses) {
  const normalized = new Set(statuses.map((item) => String(item).toLowerCase()));
  return jobs.filter((job) => normalized.has(String(job.session_status || job.status || "").toLowerCase()));
}

function severityRows(summary, recentJobs) {
  const totalCounts = summary?.severity_counts || {};
  const recentCounts = aggregateRecentSeverity(recentJobs);
  const maxValue = Math.max(1, ...Object.values(totalCounts).map((item) => Number(item || 0)));
  return [
    { key: "critical", label: "Critical", zh: "严重", value: Number(totalCounts.critical || 0), delta: Number(recentCounts.critical || 0) },
    { key: "high", label: "High", zh: "高危", value: Number(totalCounts.high || 0), delta: Number(recentCounts.high || 0) },
    { key: "medium", label: "Medium", zh: "中危", value: Number(totalCounts.medium || 0), delta: Number(recentCounts.medium || 0) },
    { key: "low", label: "Low", zh: "低危", value: Number(totalCounts.low || 0), delta: Number(recentCounts.low || 0) },
  ].map((item) => ({
    ...item,
    width: `${Math.max(10, Math.round((item.value / maxValue) * 100))}%`,
  }));
}

function ActionCard({ title, subtitle, count, tone, children }) {
  return (
    <section className="rounded-3xl border border-slate-200/80 bg-white/92 p-5 shadow-[0_20px_60px_-44px_rgba(15,23,42,0.24)] backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{subtitle}</p>
          <h3 className="mt-2 text-base font-semibold text-slate-950">{title}</h3>
        </div>
        <span className={`inline-flex min-w-12 items-center justify-center rounded-full px-3 py-1 text-sm font-semibold ${tone}`}>
          {count}
        </span>
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

export default function Dashboard({
  summary,
  jobs = [],
  systemHealth,
  onOpenJob,
  onOpenReport,
  onOpenFollowUpMission,
}) {
  const { language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);

  const now = Date.now();
  const last24hStart = now - (24 * 60 * 60 * 1000);
  const prev24hStart = now - (48 * 60 * 60 * 1000);
  const current24hJobs = useMemo(() => countWindowJobs(jobs, last24hStart, now), [jobs, last24hStart, now]);
  const previous24hJobs = useMemo(() => countWindowJobs(jobs, prev24hStart, last24hStart), [jobs, prev24hStart, last24hStart]);
  const throughputDelta = current24hJobs - previous24hJobs;

  const approvalJobs = useMemo(() => statusBucket(jobs, ["waiting_approval"]), [jobs]);
  const blockedJobs = useMemo(() => statusBucket(jobs, ["failed", "error", "environment_blocked", "partial_complete"]), [jobs]);
  const runningJobs = useMemo(() => statusBucket(jobs, ["running", "queued", "active"]), [jobs]);
  const recentJobs = useMemo(() => (summary?.recent_jobs || []).slice(0, 6), [summary]);
  const severity = useMemo(() => severityRows(summary, recentJobs), [summary, recentJobs]);
  const highRiskCount = sumSeverity(summary?.severity_counts, ["critical", "high"]);
  const envSummary = systemHealth?.summary || {};
  const envAlerts = Number(envSummary.fail || 0) + Number(envSummary.warn || 0);
  const activeQueueCount = approvalJobs.length + blockedJobs.length + runningJobs.length;

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-slate-200/80 bg-white/92 p-5 shadow-[0_24px_70px_-44px_rgba(15,23,42,0.22)] backdrop-blur sm:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
              {tt("Today's focus", "今日焦点")}
            </p>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950 sm:text-[2rem]">
              {tt("Keep approvals, blockers, and high-risk changes in view", "优先关注审批、阻断任务和高风险变化")}
            </h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              {tt(
                "This page now keeps only the queue signals you need before drilling into jobs or reports.",
                "这里仅保留进入任务和报告前真正需要看的关键队列信号。",
              )}
            </p>
          </div>
          <div className="rounded-2xl border border-slate-200/80 bg-slate-50/80 px-4 py-3 text-sm text-slate-600">
            {tt("Active queue", "活跃队列")}
            <strong className="ml-2 text-slate-950">{activeQueueCount}</strong>
          </div>
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-4">
        <ActionCard
          title={tt("Approval queue", "待审批队列")}
          subtitle={tt("Approval needed", "待确认")}
          count={approvalJobs.length}
          tone="bg-amber-50 text-amber-700"
        >
          {approvalJobs.length ? (
            <div className="space-y-2">
              {approvalJobs.slice(0, 3).map((job) => (
                <button
                  key={job.job_id}
                  type="button"
                  onClick={() => onOpenJob?.(job.job_id)}
                  className="flex w-full items-center justify-between rounded-2xl border border-amber-100 bg-amber-50/70 px-3 py-2 text-left transition hover:bg-amber-50"
                >
                  <span className="truncate pr-3 text-sm font-medium text-slate-800">{truncateMiddle(job.target || job.job_id, 42)}</span>
                  <StatusBadge status="waiting_approval" />
                </button>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500">{tt("No approvals are waiting right now.", "当前没有待审批任务。")}</p>
          )}
        </ActionCard>

        <ActionCard
          title={tt("Blocked or failed", "失败或阻断")}
          subtitle={tt("Needs intervention", "需要介入")}
          count={blockedJobs.length}
          tone="bg-rose-50 text-rose-700"
        >
          {blockedJobs.length ? (
            <div className="space-y-2">
              {blockedJobs.slice(0, 3).map((job) => (
                <button
                  key={job.job_id}
                  type="button"
                  onClick={() => onOpenJob?.(job.job_id)}
                  className="flex w-full items-center justify-between rounded-2xl border border-rose-100 bg-rose-50/70 px-3 py-2 text-left transition hover:bg-rose-50"
                >
                  <span className="truncate pr-3 text-sm font-medium text-slate-800">{truncateMiddle(job.target || job.job_id, 42)}</span>
                  <StatusBadge status={job.session_status || job.status} />
                </button>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500">{tt("No failed or blocked jobs in the active queue.", "当前队列中没有失败或阻断任务。")}</p>
          )}
        </ActionCard>

        <ActionCard
          title={tt("High-risk findings", "高风险发现")}
          subtitle={tt("Critical + high", "严重 + 高危")}
          count={highRiskCount}
          tone="bg-violet-50 text-violet-700"
        >
          <div className="space-y-3">
            <div className="rounded-2xl bg-slate-50 px-3 py-3 text-sm text-slate-600">
              {tt(
                "Use the report view to inspect remediation priority and evidence correlation for newly surfaced high-risk findings.",
                "用报告视图查看新增高风险的修复优先级与证据关联。",
              )}
            </div>
            <button
              type="button"
              className="ghost-button"
              onClick={() => onOpenReport?.(recentJobs[0]?.job_id || jobs[0]?.job_id || "")}
              disabled={!recentJobs[0]?.job_id && !jobs[0]?.job_id}
            >
              {tt("Open latest report", "打开最新报告")}
            </button>
          </div>
        </ActionCard>

        <ActionCard
          title={tt("Environment health", "环境健康")}
          subtitle={tt("Doctor signals", "体检信号")}
          count={envAlerts}
          tone={envAlerts ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-700"}
        >
          <p className="text-sm text-slate-600">
            {envAlerts
              ? tt("Some dependencies or runtime checks need attention before you launch deeper runs.", "有依赖或运行时检查需要先处理，再启动更深的任务。")
              : tt("Core runtime checks are green. The environment is ready for routine work.", "核心运行检查正常，环境适合日常任务。")}
          </p>
        </ActionCard>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.25fr_0.95fr]">
        <section className="rounded-[28px] border border-slate-200/80 bg-white/92 p-5 shadow-[0_20px_60px_-44px_rgba(15,23,42,0.22)] backdrop-blur sm:p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{tt("24h throughput", "24 小时趋势")}</p>
              <h3 className="mt-2 text-lg font-semibold text-slate-950">{tt("Recent activity and risk mix", "近期活动与风险结构")}</h3>
            </div>
            <div className="text-right">
              <div className="text-2xl font-semibold text-slate-950">{current24hJobs}</div>
              <div className={`text-sm font-medium ${deltaTone(throughputDelta)}`}>
                {deltaPrefix(throughputDelta)}{throughputDelta} {tt("vs previous 24h", "较前 24 小时")}
              </div>
            </div>
          </div>

          <div className="mt-5 grid gap-3">
            {severity.map((item) => (
              <div key={item.key} className="rounded-2xl bg-slate-50/90 px-3 py-3">
                <div className="flex items-center justify-between gap-3 text-sm">
                  <div className="font-medium text-slate-800">{zh ? item.zh : item.label}</div>
                  <div className="flex items-center gap-3">
                    <span className="font-semibold text-slate-900">{item.value}</span>
                    <span className={`text-xs font-semibold ${deltaTone(item.delta)}`}>
                      {deltaPrefix(item.delta)}{item.delta} {tt("recent", "近期")}
                    </span>
                  </div>
                </div>
                <div className="mt-2 h-2 rounded-full bg-slate-200">
                  <div
                    className={`h-2 rounded-full ${item.key === "critical" ? "bg-rose-500" : item.key === "high" ? "bg-orange-500" : item.key === "medium" ? "bg-amber-500" : "bg-sky-500"}`}
                    style={{ width: item.width }}
                  />
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-[28px] border border-slate-200/80 bg-white/92 p-5 shadow-[0_20px_60px_-44px_rgba(15,23,42,0.22)] backdrop-blur sm:p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{tt("Recent jobs", "最近任务")}</p>
              <h3 className="mt-2 text-lg font-semibold text-slate-950">{tt("Fast follow-up actions", "快速跟进动作")}</h3>
            </div>
          </div>

          <div className="mt-5 space-y-3">
            {recentJobs.length ? recentJobs.map((job) => (
              <article key={job.job_id} className="rounded-2xl border border-slate-200/80 bg-slate-50/90 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-slate-900">{truncateMiddle(job.target || job.job_id, 56)}</div>
                    <div className="mt-1 text-xs text-slate-500">{formatDateTime(job.updated_at || job.ended_at || "-", language)}</div>
                  </div>
                  <StatusBadge status={job.status} />
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button type="button" className="ghost-button" onClick={() => onOpenJob?.(job.job_id)}>
                    {tt("Continue investigation", "继续追查")}
                  </button>
                  <button
                    type="button"
                    className="ghost-button"
                    onClick={() => onOpenFollowUpMission?.({
                      composer: `Re-run the latest audit path for ${job.target || job.job_id} and verify drift from the previous run.`,
                      form: {
                        target: job.target || "",
                        mode: "agent",
                        safety_grade: "balanced",
                        approval_mode: "auto",
                        multi_agent: false,
                      },
                    })}
                  >
                    {tt("Rerun", "重跑")}
                  </button>
                  <button type="button" className="ghost-button" onClick={() => onOpenReport?.(job.job_id)}>
                    {tt("Open report", "打开报告")}
                  </button>
                </div>
              </article>
            )) : <div className="empty-state">{tt("No recent jobs available yet.", "暂无最近任务。")}</div>}
          </div>
        </section>
      </div>
    </div>
  );
}
