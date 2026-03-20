import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { I18nProvider } from "../../i18n";
import ScanForm from "../ScanForm";

function buildDraft(overrides = {}) {
  return {
    raw_message: overrides.raw_message || "Audit example.com deeply.",
    target: overrides.target || "example.com",
    scope: overrides.scope || null,
    intent: overrides.intent || "recon",
    depth: overrides.depth || "light",
    mode: overrides.mode || "agent",
    report_lang: overrides.report_lang || "en",
    safety_grade: overrides.safety_grade || "balanced",
    autonomy_mode: overrides.autonomy_mode || "adaptive",
    multi_agent: overrides.multi_agent || false,
    multi_agent_rounds: overrides.multi_agent_rounds || 1,
    authorization_confirmed: overrides.authorization_confirmed || false,
    approval_granted: Object.prototype.hasOwnProperty.call(overrides, "approval_granted")
      ? overrides.approval_granted
      : null,
    selected_tools: overrides.selected_tools || [],
    selected_skills: overrides.selected_skills || [],
    warnings: overrides.warnings || [],
    missing_fields: overrides.missing_fields || [],
    summary: overrides.summary || [],
    payload: overrides.payload || {},
  };
}

function renderScanForm(props = {}) {
  window.localStorage.setItem("autosecaudit_console_language", "en");
  return render(
    <I18nProvider>
      <ScanForm
        onSubmit={vi.fn()}
        onMissionChat={vi.fn()}
        busy={false}
        catalog={{ tools: [], skills: [] }}
        llmSettings={null}
        systemHealth={null}
        canAccessRag={false}
        onOpenRag={vi.fn()}
        onConsumeFollowUpSeed={vi.fn()}
        {...props}
      />
    </I18nProvider>,
  );
}

describe("ScanForm", () => {
  test("sends approval_granted when autonomous execution is selected", async () => {
    const onMissionChat = vi.fn().mockResolvedValue({
      session_id: "session-1",
      action: "executed",
      workflow_state: "launch_executed",
      assistant_message: "Started example.com.",
      messages: [
        { role: "user", message: "Audit example.com.", summary: [] },
        { role: "system", message: "Started example.com.", summary: [] },
      ],
      draft: buildDraft(),
      job: { job_id: "job-1" },
    });
    const user = userEvent.setup();

    renderScanForm({ onMissionChat });

    await user.selectOptions(screen.getByLabelText("Execution"), "autonomous");
    await user.type(screen.getByPlaceholderText(/Audit commu\.fun/i), "Audit example.com.");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(onMissionChat).toHaveBeenCalledTimes(1));
    expect(onMissionChat).toHaveBeenCalledWith(
      "Audit example.com.",
      expect.objectContaining({ approval_granted: true }),
      "",
    );
  });

  test("shows confirm actions and can continue in autonomous mode", async () => {
    const onMissionChat = vi.fn()
      .mockResolvedValueOnce({
        session_id: "session-2",
        action: "confirm",
        workflow_state: "launch_confirm",
        assistant_message: "Approval required.",
        messages: [
          { role: "user", message: "Audit example.com deeply.", summary: [] },
          { role: "system", message: "Approval required.", summary: [] },
        ],
        draft: buildDraft({ safety_grade: "aggressive", depth: "deep" }),
        job: null,
      })
      .mockResolvedValueOnce({
        session_id: "session-2",
        action: "executed",
        workflow_state: "launch_executed",
        assistant_message: "Started example.com.",
        messages: [
          { role: "user", message: "Audit example.com deeply.", summary: [] },
          { role: "system", message: "Approval required.", summary: [] },
          { role: "system", message: "Started example.com.", summary: [] },
        ],
        draft: buildDraft({
          safety_grade: "aggressive",
          depth: "deep",
          approval_granted: true,
        }),
        job: { job_id: "job-2" },
      });
    const user = userEvent.setup();

    renderScanForm({ onMissionChat });

    await user.type(screen.getByPlaceholderText(/Audit commu\.fun/i), "Audit example.com deeply.");
    await user.click(screen.getByRole("button", { name: "Send" }));

    expect(await screen.findByRole("heading", { name: "High-risk action is waiting" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Autonomous and continue" }));

    await waitFor(() => expect(onMissionChat).toHaveBeenCalledTimes(2));
    expect(onMissionChat).toHaveBeenNthCalledWith(
      2,
      "Approval granted. Continue the current mission.",
      expect.objectContaining({ approval_granted: true }),
      "session-2",
    );
  });

  test("shows preview workflow when launch permission is missing", async () => {
    const onMissionChat = vi.fn().mockResolvedValue({
      session_id: "session-preview",
      action: "preview",
      workflow_state: "launch_preview",
      assistant_message: "Preview only.",
      messages: [
        { role: "user", message: "Audit example.com deeply.", summary: [] },
        { role: "system", message: "Preview only.", summary: [] },
      ],
      draft: buildDraft({ safety_grade: "aggressive", depth: "deep" }),
      job: null,
    });
    const user = userEvent.setup();

    renderScanForm({ onMissionChat });

    await user.type(screen.getByPlaceholderText(/Audit commu\.fun/i), "Audit example.com deeply.");
    await user.click(screen.getByRole("button", { name: "Send" }));

    expect(await screen.findByRole("heading", { name: "This account cannot launch jobs" })).toBeInTheDocument();
    expect(screen.getByText("Read only")).toBeInTheDocument();
  });

  test("sends explicit authorization when confirmed", async () => {
    const onMissionChat = vi.fn().mockResolvedValue({
      session_id: "session-auth",
      action: "executed",
      workflow_state: "launch_executed",
      assistant_message: "Started example.com.",
      messages: [
        { role: "user", message: "Audit example.com safely.", summary: [] },
        { role: "system", message: "Started example.com.", summary: [] },
      ],
      draft: buildDraft({ authorization_confirmed: true }),
      job: { job_id: "job-auth" },
    });
    const user = userEvent.setup();

    renderScanForm({ onMissionChat });

    await user.click(screen.getByLabelText(/I confirm I am authorized to test this target/i));
    await user.type(screen.getByPlaceholderText(/Audit commu\.fun/i), "Audit example.com safely.");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(onMissionChat).toHaveBeenCalledTimes(1));
    expect(onMissionChat).toHaveBeenCalledWith(
      "Audit example.com safely.",
      expect.objectContaining({ authorization_confirmed: true }),
      "",
    );
  });

  test("consumes follow-up seed from runtime state", async () => {
    const onConsumeFollowUpSeed = vi.fn();

    renderScanForm({
      followUpSeed: {
        composer: "Continue from the previous run.",
        form: {
          target: "followup.example.com",
          authorization_confirmed: true,
          approval_mode: "granted",
        },
      },
      onConsumeFollowUpSeed,
    });

    expect(await screen.findByDisplayValue("Continue from the previous run.")).toBeInTheDocument();
    expect(screen.getByDisplayValue("followup.example.com")).toBeInTheDocument();
    await waitFor(() => expect(onConsumeFollowUpSeed).toHaveBeenCalledTimes(1));
  });
});
