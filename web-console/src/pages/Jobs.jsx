import { useEffect, useState } from "react";
import LogViewer from "../components/LogViewer";
import PaginationControls from "../components/PaginationControls";
import ScanForm from "../components/ScanForm";
import StatusBadge from "../components/StatusBadge";
import CVEPanel from "../components/CVEPanel";
import AssetGraphPanel from "../components/AssetGraphPanel";
import ArtifactInspector from "../components/ArtifactInspector";
import ExecutionHistoryPanel from "../components/ExecutionHistoryPanel";
import VerificationRankingPanel from "../components/VerificationRankingPanel";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";
import { buildAuthedUrl, apiFetch } from "../lib/api";

const PAGE_SIZE = 8;

export default function Jobs({
  jobs,
  selectedJob,
  artifacts,
  logLines,
  onSelectJob,
  onSubmitJob,
  onParseMission,
  onSubmitMission,
  submitting,
  canOperate,
  token,
  catalog,
  llmSettings,
  systemHealth,
}) {
  const { t, formatMode, language } = useI18n();
  const [page, setPage] = useState(1);
  const [cveData, setCveData] = useState(null);
  const [jobAnalysis, setJobAnalysis] = useState(null);
  const [selectedArtifactPath, setSelectedArtifactPath] = useState("");
  const [selectedArtifactPayload, setSelectedArtifactPayload] = useState(null);

  const pagination = paginateItems(jobs, page, PAGE_SIZE);
  const gradeLabels = {
    conservative: "Conservative",
    balanced: "Balanced",
    aggressive: "Aggressive",
  };

  useEffect(() => {
    setPage((previous) => (previous !== pagination.page ? pagination.page : previous));
  }, [pagination.page]);

  useEffect(() => {
    if (!selectedJob) {
      setCveData(null);
      setJobAnalysis(null);
      setSelectedArtifactPath("");
      setSelectedArtifactPayload(null);
      return undefined;
    }

    let active = true;
    Promise.allSettled([
      apiFetch(`/api/cve/job/${selectedJob.job_id}`, { token }),
      apiFetch(`/api/reports/${selectedJob.job_id}/analysis`, { token }),
    ]).then(([cveResult, analysisResult]) => {
      if (!active) {
        return;
      }
      if (cveResult.status === "fulfilled") {
        setCveData(cveResult.value);
      } else {
        console.warn("Failed to fetch CVE data:", cveResult.reason);
        setCveData(null);
      }
      if (analysisResult.status === "fulfilled") {
        setJobAnalysis(analysisResult.value?.analysis || null);
      } else {
        console.warn("Failed to fetch report analysis:", analysisResult.reason);
        setJobAnalysis(null);
      }
    });

    return () => {
      active = false;
    };
  }, [selectedJob, token]);

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
  }, [selectedJob, artifacts]);

  useEffect(() => {
    if (!selectedJob || !selectedArtifactPath || !String(selectedArtifactPath).endsWith(".json")) {
      setSelectedArtifactPayload(null);
      return undefined;
    }

    let active = true;
    const filePath = selectedArtifactPath
      .split("/")
      .map(encodeURIComponent)
      .join("/");

    apiFetch(`/api/jobs/${encodeURIComponent(selectedJob.job_id)}/files/${filePath}`, { token })
      .then((payload) => {
        if (active) {
          setSelectedArtifactPayload(payload);
        }
      })
      .catch((error) => {
        console.warn("Failed to fetch artifact detail:", error);
        if (active) {
          setSelectedArtifactPayload(null);
        }
      });

    return () => {
      active = false;
    };
  }, [selectedArtifactPath, selectedJob, token]);

  function handleCveRefresh() {
    if (!selectedJob) {
      return;
    }
    apiFetch(`/api/cve/job/${selectedJob.job_id}`, { token })
      .then(setCveData)
      .catch(console.warn);
  }

  return (
    <div className="jobs-layout jobs-workbench">
      {canOperate ? (
        <ScanForm
          onSubmit={onSubmitJob}
          onParseMission={onParseMission}
          onSubmitMission={onSubmitMission}
          busy={submitting}
          catalog={catalog}
          llmSettings={llmSettings}
          systemHealth={systemHealth}
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

      <div className="jobs-workbench-grid">
        <section className="panel jobs-queue-panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{t("jobs.queueEyebrow")}</p>
              <h3>{t("jobs.registryTitle")}</h3>
            </div>
          </div>
          <div className="table-list">
            {pagination.items.map((job) => (
              <button
                key={job.job_id}
                type="button"
                className={selectedJob?.job_id === job.job_id ? "table-row is-active" : "table-row"}
                onClick={() => onSelectJob(job.job_id)}
              >
                <div className="table-title">
                  <strong>{truncateMiddle(job.target, 78)}</strong>
                  <StatusBadge status={job.status} />
                </div>
                <div className="table-meta">
                  {formatMode(job.mode)} | {gradeLabels[job.safety_grade || "balanced"]} |{" "}
                  {t("jobs.logsCount", { count: job.log_line_count })} |{" "}
                  {t("jobs.artifactsCount", { count: job.artifact_count })}
                </div>
                <div className="table-meta">
                  {formatDateTime(job.last_updated_at || job.created_at, language)}
                </div>
              </button>
            ))}
            {!pagination.totalItems ? <div className="empty-state">{t("jobs.noJobs")}</div> : null}
          </div>
          <PaginationControls {...pagination} onPageChange={setPage} />
        </section>

        <div className="jobs-detail-stack">
          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">{t("jobs.detailEyebrow")}</p>
                <h3>{selectedJob ? selectedJob.target : t("jobs.inspectorTitle")}</h3>
              </div>
              {selectedJob ? <StatusBadge status={selectedJob.status} /> : null}
            </div>
            {!selectedJob ? (
              <div className="empty-state">{t("jobs.selectJob")}</div>
            ) : (
              <div className="job-detail-grid">
                <div>
                  <p className="eyebrow">{t("jobs.jobId")}</p>
                  <div>{selectedJob.job_id}</div>
                </div>
                <div>
                  <p className="eyebrow">{t("common.mode")}</p>
                  <div>{formatMode(selectedJob.mode)}</div>
                </div>
                <div>
                  <p className="eyebrow">{t("jobs.pid")}</p>
                  <div>{selectedJob.pid ?? "-"}</div>
                </div>
                <div>
                  <p className="eyebrow">{t("jobs.returnCode")}</p>
                  <div>{selectedJob.return_code ?? "-"}</div>
                </div>
                <div>
                  <p className="eyebrow">{t("common.updated")}</p>
                  <div>{selectedJob.last_updated_at || "-"}</div>
                </div>
                <div>
                  <p className="eyebrow">{t("common.output")}</p>
                  <div>{truncateMiddle(selectedJob.output_dir || "-", 72)}</div>
                </div>
              </div>
            )}
          </section>

          <LogViewer
            lines={logLines}
            status={selectedJob?.status}
            mode={selectedJob?.mode}
            analysis={jobAnalysis}
          />

          {selectedJob && jobAnalysis ? <AssetGraphPanel analysis={jobAnalysis} mode="job" /> : null}
          {selectedJob && jobAnalysis ? <VerificationRankingPanel analysis={jobAnalysis} mode="job" /> : null}
          {selectedJob && jobAnalysis ? <ExecutionHistoryPanel analysis={jobAnalysis} /> : null}

          {cveData?.candidates?.length ? (
            <CVEPanel
              candidates={cveData.candidates}
              verifications={cveData.verification || []}
              target={selectedJob?.target}
              token={token}
              onRefresh={handleCveRefresh}
            />
          ) : null}

          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">{t("jobs.artifactsEyebrow")}</p>
                <h3>{t("jobs.generatedFiles")}</h3>
              </div>
            </div>
            <div className="table-list">
              {artifacts.map((item) => (
                <div key={item.path} className="table-row">
                  <div className="table-title">
                    <strong>{truncateMiddle(item.path, 88)}</strong>
                    <span className="table-meta">{item.size} {t("common.bytes")}</span>
                  </div>
                  <div className="inline-actions">
                    {String(item.path || "").endsWith(".json") ? (
                      <button
                        type="button"
                        className={`ghost-button ${selectedArtifactPath === item.path ? "is-active" : ""}`}
                        onClick={() => setSelectedArtifactPath(item.path)}
                      >
                        Inspect
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
                      Open
                    </a>
                  </div>
                </div>
              ))}
              {!artifacts.length ? <div className="empty-state">{t("jobs.noArtifacts")}</div> : null}
            </div>
          </section>

          {selectedJob && selectedArtifactPath ? (
            <ArtifactInspector
              artifact={artifacts.find((item) => item.path === selectedArtifactPath) || { path: selectedArtifactPath }}
              payload={selectedArtifactPayload}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}
