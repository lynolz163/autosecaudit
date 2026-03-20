import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { I18nProvider } from "../../i18n";
import Reports from "../Reports";

function renderWithI18n(node) {
  return render(<I18nProvider>{node}</I18nProvider>);
}

describe("Reports page", () => {
  test("renders baseline comparison, download entry, and lets users switch baseline", async () => {
    const onSelectBaseline = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();

    renderWithI18n(
      <Reports
        reports={[
          {
            job_id: "job-current",
            target: "https://portal.example.com",
            status: "completed",
            mode: "agent",
            finding_total: 4,
            available_formats: ["html", "json"],
          },
        ]}
        selectedReport={{
          job_id: "job-current",
          target: "https://portal.example.com",
          status: "completed",
          mode: "agent",
          finding_total: 4,
          available_formats: ["html", "json"],
        }}
        selectedBaselineJobId=""
        onSelectReport={() => {}}
        onSelectBaseline={onSelectBaseline}
        reportContent=""
        reportAnalysis={{
          baseline_job_id: "job-baseline",
          history: [
            {
              job_id: "job-baseline",
              ended_at: "2026-03-15T10:00:00Z",
              updated_at: "2026-03-15T10:00:00Z",
              finding_total: 2,
              is_current: false,
            },
            {
              job_id: "job-current",
              ended_at: "2026-03-16T10:00:00Z",
              updated_at: "2026-03-16T10:00:00Z",
              finding_total: 4,
              is_current: true,
            },
          ],
          findings: [
            { fingerprint: "keep-1", title: "Persistent issue", severity: "medium", plugin_name: "agent" },
          ],
          diff: {
            new_count: 2,
            resolved_count: 1,
            persistent_count: 1,
            new_assets_count: 1,
            resolved_assets_count: 0,
            persistent_assets_count: 1,
            new_services_count: 1,
            resolved_services_count: 0,
            persistent_services_count: 1,
            new_findings: [
              { fingerprint: "new-1", title: "New issue", severity: "high", plugin_name: "agent" },
            ],
            resolved_findings: [
              { fingerprint: "resolved-1", title: "Resolved issue", severity: "low", plugin_name: "agent" },
            ],
            persistent_findings: [
              { fingerprint: "keep-1", title: "Persistent issue", severity: "medium", plugin_name: "agent" },
            ],
          },
          available_exports: ["html", "json"],
        }}
        token="secret-token"
        canAccessRag={false}
        onOpenRag={() => {}}
        onOpenFollowUpMission={() => {}}
      />,
    );

    expect(screen.getByText("Baseline comparison and drift")).toBeInTheDocument();
    expect(screen.getByText("Download report")).toBeInTheDocument();
    expect(screen.getByText("New findings since baseline")).toBeInTheDocument();
    expect(screen.getByText("Resolved findings", { selector: "h3" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download HTML" }).href).toContain("/api/reports/job-current/export?format=html");
    expect(screen.getByRole("link", { name: "Download HTML" }).href).toContain("api_token=secret-token");
    expect(screen.getByRole("link", { name: "Download JSON" })).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Baseline run"), "job-baseline");
    expect(onSelectBaseline).toHaveBeenCalledWith("job-baseline");
  });
});
