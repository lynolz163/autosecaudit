import { memo, useEffect, useMemo, useState } from "react";
import ArtifactInspector from "../components/ArtifactInspector";
import AssetGraphPanel from "../components/AssetGraphPanel";
import CVEPanel from "../components/CVEPanel";
import DisclosureSection from "../components/DisclosureSection";
import EvidenceGraphPanel from "../components/EvidenceGraphPanel";
import ExecutionHistoryPanel from "../components/ExecutionHistoryPanel";
import LogViewer from "../components/LogViewer";
import PaginationControls from "../components/PaginationControls";
import ScanForm from "../components/ScanForm";
import StatusBadge from "../components/StatusBadge";
import VerificationRankingPanel from "../components/VerificationRankingPanel";
import WorkflowStateCard from "../components/WorkflowStateCard";
import { useI18n } from "../i18n";
import { apiFetch, buildAuthedUrl } from "../lib/api";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";
import { jobSessionStatusToWorkflowState, workflowTone, WORKFLOW_STATES } from "../lib/workflowState";

const PAGE_SIZE = 8;
const PLACEHOLDER_JOB_LABELS = new Set([
  "string|null",
  "null",
  "undefined",
  "string[]",
  "target",
]);

function normalizeJobLabel(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  const lowered = text.toLowerCase();
  if (PLACEHOLDER_JOB_LABELS.has(lowered)) {
    return "";
  }
  if (/^[a-z0-9_.-]+(?:\|[a-z0-9_.-]+)+\|null$/i.test(lowered)) {
    return "";
  }
  return text;
}

function resolveJobLabel(job, fallback = "") {
  return (
    normalizeJobLabel(job?.target)
    || normalizeJobLabel(job?.scope)
    || normalizeJobLabel(job?.job_id)
    || fallback
  );
}

function DetailStat({ label, value, mono = false, compact = false }) {
  return (
    <div className={`detail-stat ${compact ? "is-compact" : ""}`}>
      <div className="detail-stat-label">{label}</div>
      <div className={`detail-stat-value ${mono ? "is-mono" : ""}`}>{value ?? "-"}</div>
    </div>
  );
}

function ContextCard({ eyebrow, title, tone = "default", children }) {
  return (
    <section className={`jobs-context-card ${tone !== "default" ? `is-${tone}` : ""}`}>
      <p className="eyebrow">{eyebrow}</p>
      <h3>{title}</h3>
      {children}
    </section>
  );
}

const JobQueueItem = memo(function JobQueueItem({
  jobId,
  label,
  status,
  modeLabel,
  safetyLabel,
  updatedAt,
  active,
  onSelect,
}) {
  return (
    <button
      type="button"
      className={`jobs-queue-item ${active ? "is-active" : "is-idle"}`}
      onClick={() => onSelect(jobId)}
    >
      <div className="jobs-queue-item-title">
        <strong className="truncate pr-2 text-sm text-slate-900">{truncateMiddle(label, 40)}</strong>
        <StatusBadge status={status} />
      </div>
      <div className="jobs-queue-item-meta">{modeLabel} 路 {safetyLabel}</div>
      <div className="jobs-queue-item-time">{updatedAt}</div>
    </button>
  );
});

export default function Jobs({
  jobs,
  selectedJob,
  artifacts,
  logLines,
  onSelectJob,
  onSubmitJob,
  onMissionChat,
  submitting,
  canOperate,
  token,
  catalog,
  llmSettings,
  systemHealth,
  jobRealtimeRevision,
  canAccessRag,
  onOpenRag,
  onOpenFollowUpMission,
  followUpMissionSeed,
  onConsumeFollowUpMissionSeed,
  onApproveAndResumeJob,
}) {
  const { t, formatMode, language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const [page, setPage] = useState(1);
  const [cveData, setCveData] = useState(null);
  const [cveLoadedJobId, setCveLoadedJobId] = useState("");
  const [jobAnalysis, setJobAnalysis] = useState(null);
  const [selectedArtifactPath, setSelectedArtifactPath] = useState("");
  const [selectedArtifactPayload, setSelectedArtifactPayload] = useState(null);

  const pagination = useMemo(() => paginateItems(jobs, page, PAGE_SIZE), [jobs, page]);
  const gradeLabels = useMemo(() => ({
    conservative: tt("Discovery", "资产发现"),
    balanced: tt("Standard Audit", "常规审计"),
    aggressive: tt("Deep Validation", "深度验证"),
  }), [zh]);
  const queueItems = useMemo(
    () => pagination.items.map((job) => ({
      jobId: job.job_id,
      label: resolveJobLabel(job, job.job_id),
      status: job.session_status || job.status,
      modeLabel: formatMode(job.mode),
      safetyLabel: gradeLabels[job.safety_grade || "balanced"],
      updatedAt: formatDateTime(job.last_updated_at || job.created_at || "-", language),
      active: selectedJob?.job_id === job.job_id,
    })),
    [pagination.items, formatMode, gradeLabels, language, selectedJob?.job_id],
  );
  const selectedJobStatus = selectedJob?.session_status || selectedJob?.status || "";
  const selectedJobLabel = useMemo(
    () => resolveJobLabel(selectedJob, t("jobs.inspectorTitle")),
    [selectedJob, t],
  );
  const selectedArtifact = useMemo(
    () => (selectedArtifactPath
      ? artifacts.find((item) => item.path === selectedArtifactPath) || { path: selectedArtifactPath }
      : null),
    [artifacts, selectedArtifactPath],
  );

  useEffect(() => {
    setPage((previous) => (previous !== pagination.page ? pagination.page : previous));
  }, [pagination.page]);

  useEffect(() => {
    const jobId = selectedJob?.job_id;
    if (!jobId) {
      setJobAnalysis(null);
      setCveData(null);
      setCveLoadedJobId("");
      setSelectedArtifactPath("");
      setSelectedArtifactPayload(null);
      return undefined;
    }

    const controller = new AbortController();
    apiFetch(`/api/reports/${jobId}/analysis`, { token, signal: controller.signal })
      .then((analysisResult) => {
        setJobAnalysis(analysisResult?.analysis || null);
      })
      .catch((error) => {
        if (error?.name !== "AbortError") {
          console.warn("Failed to fetch report analysis:", error);
          setJobAnalysis(null);
        }
      });

    return () => controller.abort();
  }, [selectedJob?.job_id, token, jobRealtimeRevision]);

  useEffect(() => {
    const jobId = selectedJob?.job_id;
    if (!jobId) {
      setCveData(null);
      setCveLoadedJobId("");
      return undefined;
    }
    if (cveLoadedJobId === jobId && cveData) {
      return undefined;
    }

    const controller = new AbortController();
    apiFetch(`/api/cve/job/${jobId}`, { token, signal: controller.signal })
      .then((payload) => {
        setCveData(payload);
        setCveLoadedJobId(jobId);
      })
      .catch((error) => {
        if (error?.name !== "AbortError") {
          console.warn("Failed to fetch CVE data:", error);
          setCveData(null);
          setCveLoadedJobId("");
        }
      });

    return () => controller.abort();
  }, [selectedJob?.job_id, token, cveLoadedJobId, cveData]);

  useEffect(() => {
    if (!selectedJob || !artifacts.length) {
      setSelectedArtifactPath("");
      setSelectedArtifactPayload(null);
      return;
    }

    const preferred =
      artifacts.find((item) => String(item.path || "").endsWith("ActionPlan.json"))
      || artifacts.find((item) => String(item.path || "").endsWith(".json"))
      || null;

    if (!preferred) {
      setSelectedArtifactPath("");
      setSelectedArtifactPayload(null);
      return;
    }

    setSelectedArtifactPath((current) => {
      if (current && artifacts.some((item) => item.path === current)) {
        return current;
      }
      return preferred.path;
    });
  }, [selectedJob?.job_id, artifacts]);

  useEffect(() => {
    const jobId = selectedJob?.job_id;
    if (!jobId || !selectedArtifactPath || !String(selectedArtifactPath).endsWith(".json")) {
      setSelectedArtifactPayload(null);
      return undefined;
    }

    const controller = new AbortController();
    const filePath = selectedArtifactPath.split("/").map(encodeURIComponent).join("/");

    apiFetch(`/api/jobs/${encodeURIComponent(jobId)}/files/${filePath}`, { token, signal: controller.signal })
      .then((payload) => {
        setSelectedArtifactPayload(payload);
      })
      .catch((error) => {
        if (error?.name !== "AbortError") {
          console.warn("Failed to fetch artifact detail:", error);
          setSelectedArtifactPayload(null);
        }
      });

    return () => controller.abort();
  }, [selectedArtifactPath, selectedJob?.job_id, token]);

  function handleCveRefresh() {
    if (!selectedJob?.job_id) {
      return;
    }
    apiFetch(`/api/cve/job/${selectedJob.job_id}`, { token })
      .then((payload) => {
        setCveData(payload);
        setCveLoadedJobId(selectedJob.job_id);
      })
      .catch(console.warn);
  }

  const pendingApproval = jobAnalysis?.pending_approval && Object.keys(jobAnalysis.pending_approval).length
    ? jobAnalysis.pending_approval
    : selectedJob?.pending_approval && Object.keys(selectedJob.pending_approval).length
      ? selectedJob.pending_approval
      : null;
  const sessionStatus = jobAnalysis?.session_status || selectedJob?.session_status || selectedJob?.status || "";
  const runtimeWorkflowState = jobSessionStatusToWorkflowState(sessionStatus);
  const loopGuard = jobAnalysis?.loop_guard && Object.keys(jobAnalysis.loop_guard).length
    ? jobAnalysis.loop_guard
    : selectedJob?.loop_guard && Object.keys(selectedJob.loop_guard).length
      ? selectedJob.loop_guard
      : null;
  const cveValidation = jobAnalysis?.cve_validation && typeof jobAnalysis.cve_validation === "object"
    ? jobAnalysis.cve_validation
    : null;
  const cveSummary = cveValidation?.summary && typeof cveValidation.summary === "object"
    ? cveValidation.summary
    : null;
  const knowledgeContext = jobAnalysis?.knowledge_context && typeof jobAnalysis.knowledge_context === "object"
    ? jobAnalysis.knowledge_context
    : null;
  const operatorSummary = jobAnalysis?.decision_summary || tt(
    "Use the left queue to switch runs. Keep the center focused on the agent conversation and discoveries.",
    "通过左侧队列切换任务，中间区域只保留 Agent 对话和发现流。",
  );
  const selectedUpdatedAt = selectedJob
    ? formatDateTime(selectedJob.last_updated_at || selectedJob.created_at || "-", language)
    : "-";
  const visibleArtifacts = artifacts.slice(0, 6);
  const rightRailEmptyCopy = tt(
    "The center stays focused on chat and findings. After you select a run, the right rail will show CVE validation, evidence and follow-up actions.",
    "中间区域专注展示对话和发现。选中任务后，右侧会显示 CVE 验证、证据和后续动作。",
  );

  return (
    <div className="jobs-shell">
      <section className="jobs-workbench-shell">
        <header className="jobs-workbench-header">
          <div className="jobs-workbench-copy">
            <p className="eyebrow">{tt("Jobs", "任务")}</p>
            <h2>{tt("Task queue, chat stream, validation rail", "左侧任务队列，中间对话流，右侧验证栏")}</h2>
            <p className="jobs-summary-copy">
              {tt(
                "Keep the center dedicated to the agent stream. Move CVE verification and supporting evidence to the right rail.",
                "让中间区域只承载 Agent 对话与发现，把 CVE 验证和补充证据放到右侧。",
              )}
            </p>
          </div>

          <div className="jobs-header-pills">
            <div className="jobs-header-pill">
              <span>{tt("Recent jobs", "最近任务")}</span>
              <strong>{pagination.totalItems}</strong>
            </div>
            {selectedJob ? (
              <div className="jobs-header-pill is-muted">
                <span>{tt("Active run", "当前任务")}</span>
                <strong>{truncateMiddle(selectedJobLabel, 28)}</strong>
              </div>
            ) : null}
          </div>
        </header>

        <div className="jobs-codex-grid">
          <aside className="jobs-queue-rail">
            <section className="jobs-queue-panel">
              <div className="jobs-side-heading">
                <div>
                  <p className="eyebrow">{tt("Queue", "队列")}</p>
                  <h3>{tt("Recent runs", "最近运行")}</h3>
                </div>
                <span className="jobs-header-pill is-compact">
                  <strong>{pagination.totalItems}</strong>
                </span>
              </div>

              <div className="jobs-queue-list">
                {queueItems.map((job) => (
                  <JobQueueItem key={job.jobId} {...job} onSelect={onSelectJob} />
                ))}
                {!pagination.totalItems ? <div className="empty-state">{t("jobs.noJobs")}</div> : null}
              </div>

              <div className="jobs-queue-footer">
                <PaginationControls {...pagination} onPageChange={setPage} />
              </div>
            </section>
          </aside>

          <main className="jobs-session-column jobs-center-stage">
            <section className="jobs-stage-block">
              <div className="jobs-stage-header">
                <div>
                  <p className="eyebrow">{tt("Launchpad", "启动台")}</p>
                  <h3>{tt("Chat-first mission input", "聊天式任务输入")}</h3>
                </div>
                {canOperate ? <span className="jobs-context-chip">{tt("Chat-first", "聊天优先")}</span> : null}
              </div>

              {canOperate ? (
                <ScanForm
                  onSubmit={onSubmitJob}
                  onMissionChat={onMissionChat}
                  busy={submitting}
                  catalog={catalog}
                  llmSettings={llmSettings}
                  systemHealth={systemHealth}
                  canAccessRag={canAccessRag}
                  onOpenRag={onOpenRag}
                  followUpSeed={followUpMissionSeed}
                  onConsumeFollowUpSeed={onConsumeFollowUpMissionSeed}
                />
              ) : (
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <p className="eyebrow">{t("scanForm.eyebrow")}</p>
                      <h3>{t("jobs.readOnlyTitle")}</h3>
                    </div>
                  </div>
                  <div className="empty-state">{t("jobs.readOnlyDescription")}</div>
                </section>
              )}
            </section>

            {!selectedJob ? (
              <section className="panel jobs-empty-stream">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">{tt("Conversation", "会话")}</p>
                    <h3>{tt("Select a run to inspect", "先选择一个任务查看详情")}</h3>
                  </div>
                </div>
                <div className="empty-state">{t("jobs.selectJob")}</div>
              </section>
            ) : (
              <>
                <section className="jobs-current-run-bar">
                  <div className="jobs-stream-toolbar">
                    <div className="min-w-0">
                      <p className="eyebrow">{tt("Current run", "当前任务")}</p>
                      <h3 className="jobs-current-run-title">{selectedJobLabel}</h3>
                      <p className="jobs-session-copy">{operatorSummary}</p>
                    </div>

                    <div className="jobs-session-badges">
                      <StatusBadge status={selectedJobStatus} />
                      <span className="jobs-context-chip">{formatMode(selectedJob.mode)}</span>
                      <span className="jobs-context-chip">{gradeLabels[selectedJob.safety_grade || "balanced"]}</span>
                    </div>
                  </div>

                  <div className="jobs-run-meta-grid">
                    <DetailStat compact label={tt("Updated", "更新时间")} value={selectedUpdatedAt} />
                    <DetailStat compact label={tt("Logs", "日志")} value={`${selectedJob.log_line_count || 0}`} />
                    <DetailStat compact label={tt("Artifacts", "工件")} value={`${selectedJob.artifact_count || 0}`} />
                    <DetailStat compact label={tt("Job ID", "任务 ID")} value={selectedJob.job_id} mono />
                  </div>
                </section>

                {runtimeWorkflowState === WORKFLOW_STATES.RUNTIME_APPROVAL && pendingApproval ? (
                  <WorkflowStateCard
                    className="jobs-blocking-panel"
                    tone={workflowTone(runtimeWorkflowState)}
                    eyebrow={tt("Approval needed", "等待确认")}
                    title={tt("Agent paused for confirmation", "Agent 已暂停，等待人工确认")}
                    description={pendingApproval.summary || tt(
                      "The agent reached a higher-risk step and paused before going deeper.",
                      "Agent 已进入更高风险的步骤，在继续深入之前先暂停等待确认。",
                    )}
                    badge={{ label: tt("Approval waiting", "等待批准"), className: "status-badge" }}
                    actions={[
                      {
                        label: tt("Approve and continue", "批准并继续"),
                        className: "primary-button",
                        onClick: () => onApproveAndResumeJob?.(selectedJob.job_id),
                      },
                      {
                        label: tt("Stop and summarize", "停止并总结"),
                        className: "ghost-button",
                        onClick: () => onOpenFollowUpMission?.({
                          composer: `Summarize the current evidence for ${selectedJobLabel} and stop at the current report.`,
                          form: {
                            target: selectedJobLabel,
                            mode: "plan",
                            safety_grade: selectedJob.safety_grade || "balanced",
                          },
                        }),
                      },
                    ]}
                  >
                    {Array.isArray(pendingApproval.actions) && pendingApproval.actions.length ? (
                      <div className="workflow-evidence-list">
                        {pendingApproval.actions.map((item) => (
                          <div key={item.action_id || `${item.tool_name}-${item.target}`} className="workflow-evidence-item">
                            <strong>{item.tool_name}</strong>
                            <div className="mt-1 text-xs text-slate-500">{truncateMiddle(item.target || "-", 96)}</div>
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </WorkflowStateCard>
                ) : null}

                {runtimeWorkflowState === WORKFLOW_STATES.ENVIRONMENT_BLOCKED ? (
                  <WorkflowStateCard
                    className="jobs-blocking-panel"
                    tone={workflowTone(runtimeWorkflowState)}
                    eyebrow={tt("Environment blocked", "环境阻塞")}
                    title={tt("The run stopped instead of looping", "本次运行已停止，避免死循环")}
                    description={loopGuard?.last_reason || tt(
                      "Repeated environment-level blockers were detected and the session was safely halted.",
                      "检测到重复的环境级阻塞，会话已安全停止。",
                    )}
                    badge={{ label: tt("Blocked", "已阻塞"), className: "status-badge" }}
                  />
                ) : null}

                <section className="jobs-stream-shell">
                  <div className="jobs-stage-header">
                    <div>
                      <p className="eyebrow">{tt("Conversation stream", "对话流")}</p>
                      <h3>{tt("Agent replies and discoveries", "Agent 回复与发现")}</h3>
                    </div>
                    <div className="jobs-session-badges">
                      <span className="jobs-context-chip">{tt("Live", "实时")}</span>
                      <span className="jobs-context-chip">
                        {tt("Logs", "日志")}: {selectedJob.log_line_count || 0}
                      </span>
                    </div>
                  </div>

                  <LogViewer
                    lines={logLines}
                    status={selectedJob?.status}
                    mode={selectedJob?.mode}
                    analysis={jobAnalysis}
                  />
                </section>
              </>
            )}
          </main>

          <aside className="jobs-context-rail jobs-right-stack">
            {selectedJob ? (
              <>
                <section className="jobs-rail-label">
                  <p className="eyebrow">{tt("Validation rail", "验证栏")}</p>
                  <p className="jobs-weak-copy">
                    {tt(
                      "CVE verification, evidence files and follow-up actions live here.",
                      "这里集中展示 CVE 验证、证据文件和后续动作。",
                    )}
                  </p>
                </section>

                {cveData?.candidates?.length ? (
                  <CVEPanel
                    candidates={cveData.candidates}
                    verifications={cveData.verification || []}
                    target={selectedJobLabel}
                    token={token}
                    onRefresh={handleCveRefresh}
                  />
                ) : (
                  <ContextCard eyebrow={tt("Verification", "验证")} title={tt("CVE validation", "CVE 验证")} tone="muted">
                    <div className="jobs-weak-copy">
                      {tt(
                        "No CVE candidates are available for this run yet.",
                        "这个任务暂时还没有可验证的 CVE 候选项。",
                      )}
                    </div>
                  </ContextCard>
                )}

                <ContextCard eyebrow={tt("Artifacts", "工件")} title={tt("Evidence files", "证据文件")} tone="muted">
                  <div className="jobs-action-list jobs-artifact-list">
                    {visibleArtifacts.map((item) => (
                      <div key={item.path} className="table-row is-static">
                        <div className="table-title">
                          <strong>{truncateMiddle(item.path, 42)}</strong>
                          <span className="table-meta">{item.size} {t("common.bytes")}</span>
                        </div>
                        <div className="inline-actions">
                          {String(item.path || "").endsWith(".json") ? (
                            <button
                              type="button"
                              className={`ghost-button ${selectedArtifactPath === item.path ? "is-active" : ""}`}
                              onClick={() => setSelectedArtifactPath(item.path)}
                            >
                              {tt("Inspect", "查看")}
                            </button>
                          ) : null}
                          <a
                            className="ghost-button"
                            href={buildAuthedUrl(
                              `/api/jobs/${encodeURIComponent(selectedJob.job_id)}/files/${item.path
                                .split("/")
                                .map(encodeURIComponent)
                                .join("/")}`,
                              token,
                            )}
                            target="_blank"
                            rel="noreferrer"
                          >
                            {tt("Open", "打开")}
                          </a>
                        </div>
                      </div>
                    ))}

                    {!artifacts.length ? (
                      <div className="jobs-weak-copy">{tt("No artifacts yet.", "暂时还没有生成工件。")}</div>
                    ) : null}
                  </div>
                </ContextCard>

                {selectedArtifact ? (
                  <ArtifactInspector artifact={selectedArtifact} payload={selectedArtifactPayload} />
                ) : null}

                <ContextCard eyebrow={tt("Signals", "信号")} title={tt("Needs attention", "需要关注")} tone="muted">
                  <div className="jobs-signal-list">
                    {cveSummary ? (
                      <div className="jobs-signal-item">
                        <strong>{tt("CVE pipeline", "CVE 流水线")}</strong>
                        <p>
                          {tt("Candidates", "候选")} {cveSummary.candidate_count || 0}
                          {" 路 "}
                          {tt("Version corroborated", "版本印证")} {cveSummary.version_corroborated_count || 0}
                          {" 路 "}
                          {tt("Template verified", "模板验证")} {cveSummary.template_verified_count || 0}
                        </p>
                      </div>
                    ) : null}

                    {knowledgeContext?.summary ? (
                      <div className="jobs-signal-item">
                        <strong>{tt("Knowledge context", "知识上下文")}</strong>
                        <p>{knowledgeContext.summary}</p>
                      </div>
                    ) : null}

                    {!cveSummary && !knowledgeContext?.summary ? (
                      <div className="jobs-weak-copy">
                        {tt(
                          "The right rail will highlight CVE and evidence context when available.",
                          "当存在可验证内容时，右侧会高亮显示 CVE 和证据上下文。",
                        )}
                      </div>
                    ) : null}
                  </div>
                </ContextCard>

                <ContextCard eyebrow={tt("Actions", "快捷动作")} title={tt("Next steps", "下一步")}>
                  <div className="jobs-action-list">
                    <button
                      type="button"
                      className="ghost-button"
                      onClick={() => onOpenFollowUpMission?.({
                        composer: `Continue the audit from the current findings on ${selectedJobLabel}. Reuse the collected breadcrumbs, go one level deeper, and keep the run non-destructive.`,
                        form: {
                          target: selectedJobLabel,
                          mode: "agent",
                          safety_grade: "aggressive",
                          approval_mode: "granted",
                          multi_agent: true,
                        },
                      })}
                    >
                      {tt("Continue investigation", "继续深挖")}
                    </button>

                    <button
                      type="button"
                      className="ghost-button"
                      onClick={() => onOpenFollowUpMission?.({
                        composer: `Re-validate ${selectedJobLabel} and focus only on previously identified weaknesses and drift from the last run.`,
                        form: {
                          target: selectedJobLabel,
                          mode: "agent",
                          safety_grade: "balanced",
                          approval_mode: "auto",
                          multi_agent: false,
                        },
                      })}
                    >
                      {tt("Re-run validation", "重新验证")}
                    </button>

                    {canAccessRag ? (
                      <button type="button" className="ghost-button" onClick={onOpenRag}>
                        {tt("Open knowledge base", "打开知识库")}
                      </button>
                    ) : null}
                  </div>
                </ContextCard>
              </>
            ) : (
              <ContextCard eyebrow={tt("Context", "上下文")} title={tt("Validation appears here", "验证信息会显示在这里")} tone="muted">
                <div className="jobs-weak-copy">{rightRailEmptyCopy}</div>
              </ContextCard>
            )}
          </aside>
        </div>
      </section>

      {selectedJob && jobAnalysis ? (
        <DisclosureSection
          title={tt("Technical appendix", "技术附录")}
          subtitle={tt("Deep analysis", "深度分析")}
          aside={tt("Hidden by default", "默认折叠")}
        >
          <div className="space-y-4">
            <AssetGraphPanel analysis={jobAnalysis} mode="job" />
            <EvidenceGraphPanel analysis={jobAnalysis} mode="job" />
            <VerificationRankingPanel analysis={jobAnalysis} mode="job" />
            <ExecutionHistoryPanel analysis={jobAnalysis} />
          </div>
        </DisclosureSection>
      ) : null}
    </div>
  );
}
