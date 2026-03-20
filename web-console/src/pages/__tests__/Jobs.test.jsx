import { render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";
import { I18nProvider } from "../../i18n";
import Jobs from "../Jobs";

const apiFetchMock = vi.fn();

vi.mock("../../lib/api", () => ({
  apiFetch: (...args) => apiFetchMock(...args),
  buildAuthedUrl: (path) => path,
}));

vi.mock("../../components/ArtifactInspector", () => ({ default: () => <div data-testid="artifact-inspector" /> }));
vi.mock("../../components/AssetGraphPanel", () => ({ default: () => <div data-testid="asset-graph-panel" /> }));
vi.mock("../../components/CVEPanel", () => ({ default: () => <div data-testid="cve-panel" /> }));
vi.mock("../../components/DisclosureSection", () => ({
  default: ({ children }) => <div>{children}</div>,
}));
vi.mock("../../components/EvidenceGraphPanel", () => ({ default: () => <div data-testid="evidence-graph-panel" /> }));
vi.mock("../../components/ExecutionHistoryPanel", () => ({ default: () => <div data-testid="execution-history-panel" /> }));
vi.mock("../../components/LogViewer", () => ({ default: () => <div data-testid="log-viewer" /> }));
vi.mock("../../components/PaginationControls", () => ({ default: () => <div data-testid="pagination-controls" /> }));
vi.mock("../../components/ScanForm", () => ({ default: () => <div data-testid="scan-form" /> }));
vi.mock("../../components/StatusBadge", () => ({ default: ({ status }) => <span>{status}</span> }));
vi.mock("../../components/VerificationRankingPanel", () => ({ default: () => <div data-testid="verification-ranking-panel" /> }));
vi.mock("../../components/WorkflowStateCard", () => ({ default: ({ children }) => <div>{children}</div> }));

function renderWithI18n(node) {
  window.localStorage.setItem("autosecaudit_console_language", "en");
  return render(<I18nProvider>{node}</I18nProvider>);
}

describe("Jobs page", () => {
  test("loads analysis and CVE data eagerly for the selected job", async () => {
    apiFetchMock.mockImplementation((path) => {
      if (String(path).includes("/analysis")) {
        return Promise.resolve({ analysis: { decision_summary: "summary" } });
      }
      if (String(path).includes("/cve/job/")) {
        return Promise.resolve({
          candidates: [
            {
              cve_id: "CVE-2026-0001",
              severity: "high",
              description: "Example issue",
              has_nuclei_template: true,
              cvss_score: 8.8,
              component: "nginx",
              version: "1.25.0",
            },
          ],
          verification: [],
        });
      }
      return Promise.resolve({});
    });

    renderWithI18n(
      <Jobs
        jobs={[
          {
            job_id: "job-1",
            target: "example.com",
            status: "running",
            session_status: "running",
            mode: "agent",
            safety_grade: "balanced",
            artifact_count: 0,
            log_line_count: 0,
            created_at: "2026-03-19T00:00:00Z",
            last_updated_at: "2026-03-19T00:00:00Z",
          },
        ]}
        selectedJob={{
          job_id: "job-1",
          target: "example.com",
          status: "running",
          session_status: "running",
          mode: "agent",
          safety_grade: "balanced",
          artifact_count: 0,
          log_line_count: 0,
          created_at: "2026-03-19T00:00:00Z",
          last_updated_at: "2026-03-19T00:00:00Z",
        }}
        artifacts={[]}
        logLines={[]}
        onSelectJob={vi.fn()}
        onSubmitJob={vi.fn()}
        onMissionChat={vi.fn()}
        submitting={false}
        canOperate={false}
        token="secret-token"
        catalog={{ tools: [], skills: [] }}
        llmSettings={null}
        systemHealth={null}
        jobRealtimeRevision={0}
        canAccessRag={false}
        onOpenRag={vi.fn()}
        onOpenFollowUpMission={vi.fn()}
        followUpMissionSeed={null}
        onConsumeFollowUpMissionSeed={vi.fn()}
        onApproveAndResumeJob={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(apiFetchMock).toHaveBeenCalledWith(
        "/api/reports/job-1/analysis",
        expect.objectContaining({ token: "secret-token" }),
      );
    });

    await waitFor(() => {
      expect(apiFetchMock.mock.calls.map((call) => call[0])).toContain("/api/cve/job/job-1");
    });

    expect(await screen.findByTestId("cve-panel")).toBeInTheDocument();
  });

  test("falls back to job id when the target is a schema placeholder", async () => {
    apiFetchMock.mockResolvedValue({ analysis: null });

    renderWithI18n(
      <Jobs
        jobs={[
          {
            job_id: "job-1",
            target: "string|null",
            status: "running",
            session_status: "running",
            mode: "agent",
            safety_grade: "balanced",
            artifact_count: 0,
            log_line_count: 0,
            created_at: "2026-03-19T00:00:00Z",
            last_updated_at: "2026-03-19T00:00:00Z",
          },
        ]}
        selectedJob={{
          job_id: "job-1",
          target: "string|null",
          status: "running",
          session_status: "running",
          mode: "agent",
          safety_grade: "balanced",
          artifact_count: 0,
          log_line_count: 0,
          created_at: "2026-03-19T00:00:00Z",
          last_updated_at: "2026-03-19T00:00:00Z",
        }}
        artifacts={[]}
        logLines={[]}
        onSelectJob={vi.fn()}
        onSubmitJob={vi.fn()}
        onMissionChat={vi.fn()}
        submitting={false}
        canOperate={false}
        token="secret-token"
        catalog={{ tools: [], skills: [] }}
        llmSettings={null}
        systemHealth={null}
        jobRealtimeRevision={0}
        canAccessRag={false}
        onOpenRag={vi.fn()}
        onOpenFollowUpMission={vi.fn()}
        followUpMissionSeed={null}
        onConsumeFollowUpMissionSeed={vi.fn()}
        onApproveAndResumeJob={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "job-1" })).toBeInTheDocument();
      expect(screen.queryByText("string|null")).not.toBeInTheDocument();
    });
  });
});
