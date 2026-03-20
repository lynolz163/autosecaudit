export const WORKFLOW_STATES = {
  NEEDS_INPUT: "needs_input",
  LAUNCH_PREVIEW: "launch_preview",
  LAUNCH_CONFIRM: "launch_confirm",
  LAUNCH_EXECUTED: "launch_executed",
  RUNTIME_APPROVAL: "runtime_approval",
  ENVIRONMENT_BLOCKED: "environment_blocked",
};

export function missionChatActionToWorkflowState(action) {
  const normalized = String(action || "").trim().toLowerCase();
  if (normalized === "ask") {
    return WORKFLOW_STATES.NEEDS_INPUT;
  }
  if (normalized === "preview") {
    return WORKFLOW_STATES.LAUNCH_PREVIEW;
  }
  if (normalized === "confirm") {
    return WORKFLOW_STATES.LAUNCH_CONFIRM;
  }
  if (normalized === "executed") {
    return WORKFLOW_STATES.LAUNCH_EXECUTED;
  }
  return null;
}

export function jobSessionStatusToWorkflowState(status) {
  const normalized = String(status || "").trim().toLowerCase();
  if (normalized === "waiting_approval") {
    return WORKFLOW_STATES.RUNTIME_APPROVAL;
  }
  if (normalized === "environment_blocked") {
    return WORKFLOW_STATES.ENVIRONMENT_BLOCKED;
  }
  return null;
}

export function workflowTone(state) {
  if (state === WORKFLOW_STATES.LAUNCH_CONFIRM || state === WORKFLOW_STATES.RUNTIME_APPROVAL) {
    return "warning";
  }
  if (state === WORKFLOW_STATES.ENVIRONMENT_BLOCKED) {
    return "error";
  }
  if (state === WORKFLOW_STATES.LAUNCH_PREVIEW) {
    return "muted";
  }
  if (state === WORKFLOW_STATES.NEEDS_INPUT) {
    return "info";
  }
  return "default";
}
