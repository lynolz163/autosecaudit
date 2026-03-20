import { useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n";
import WorkflowStateCard from "./WorkflowStateCard";
import { missionChatActionToWorkflowState, workflowTone, WORKFLOW_STATES } from "../lib/workflowState";

const INITIAL_FORM = {
  target: "",
  scope: "",
  mode: "agent",
  safety_grade: "balanced",
  autonomy_mode: "adaptive",
  report_lang: "zh-CN",
  plugins: "",
  max_iterations: "5",
  global_timeout: "600",
  llm_source: "system",
  llm_config: "",
  llm_model: "",
  llm_provider: "",
  llm_provider_type: "",
  llm_base_url: "",
  knowledge_summary: "",
  knowledge_tags: "",
  knowledge_refs: "",
  multi_agent: false,
  multi_agent_rounds: "1",
  authorization_confirmed: false,
  approval_mode: "auto",
  surface: "",
};

const TOOL_WARNINGS = new Set([
  "tool_nmap_scan",
  "tool_dynamic_crawl",
  "tool_dirsearch_scan",
  "tool_nuclei_exploit_check",
]);

const MODEL_PRESETS = [
  {
    id: "system",
    label: "System Default",
    zhLabel: "系统默认",
    description: "Use the deployment default model routing.",
    zhDescription: "使用部署环境里的默认模型路由。",
    llm_source: "system",
    llm_model: "",
    llm_provider: "",
    llm_provider_type: "",
    llm_base_url: "",
  },
  {
    id: "openai",
    label: "OpenAI",
    zhLabel: "OpenAI",
    description: "Hosted route for general audit planning.",
    zhDescription: "通用审计规划的托管模型路由。",
    llm_source: "custom",
    llm_model: "gpt-4.1-mini",
    llm_provider: "openai",
    llm_provider_type: "openai_compatible",
    llm_base_url: "https://api.openai.com/v1",
  },
  {
    id: "qwen",
    label: "Qwen",
    zhLabel: "通义千问",
    description: "DashScope compatible route.",
    zhDescription: "DashScope 兼容路由。",
    llm_source: "custom",
    llm_model: "qwen-plus",
    llm_provider: "qwen",
    llm_provider_type: "openai_compatible",
    llm_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    zhLabel: "DeepSeek",
    description: "DeepSeek compatible route for reasoning.",
    zhDescription: "适合推理任务的 DeepSeek 兼容路由。",
    llm_source: "custom",
    llm_model: "deepseek-chat",
    llm_provider: "deepseek",
    llm_provider_type: "openai_compatible",
    llm_base_url: "https://api.deepseek.com/v1",
  },
  {
    id: "local",
    label: "Local LLM",
    zhLabel: "本地模型",
    description: "Route to Ollama or another local gateway.",
    zhDescription: "路由到 Ollama 或其他本地网关。",
    llm_source: "custom",
    llm_model: "qwen2.5:14b",
    llm_provider: "ollama",
    llm_provider_type: "openai_compatible",
    llm_base_url: "http://host.docker.internal:11434/v1",
  },
];

const REASONING_LEVELS = [
  {
    id: "low",
    label: "Low",
    zhLabel: "低",
    description: "Keep the run conservative and low-noise.",
    zhDescription: "尽量保守，保持低噪声执行。",
    safety_grade: "conservative",
    autonomy_mode: "constrained",
    approval_mode: "auto",
    multi_agent: false,
  },
  {
    id: "medium",
    label: "Medium",
    zhLabel: "中",
    description: "Balanced planning and standard validation depth.",
    zhDescription: "平衡规划与标准验证深度。",
    safety_grade: "balanced",
    autonomy_mode: "adaptive",
    approval_mode: "auto",
    multi_agent: false,
  },
  {
    id: "high",
    label: "High",
    zhLabel: "高",
    description: "Give the planner more room and enable multi-agent coordination.",
    zhDescription: "扩大规划空间，并启用多智能体协同。",
    safety_grade: "balanced",
    autonomy_mode: "adaptive",
    approval_mode: "auto",
    multi_agent: true,
  },
  {
    id: "max",
    label: "Max",
    zhLabel: "超高",
    description: "Use the deepest policy-allowed reasoning profile.",
    zhDescription: "使用当前策略允许的最深推理档位。",
    safety_grade: "aggressive",
    autonomy_mode: "supervised",
    approval_mode: "auto",
    multi_agent: true,
  },
];

const EXECUTION_PRIVILEGES = [
  {
    id: "default",
    label: "Default",
    zhLabel: "默认权限",
    description: "High-risk execution pauses for confirmation.",
    zhDescription: "高风险执行会先暂停等待确认。",
    approvalMode: "auto",
  },
  {
    id: "autonomous",
    label: "Autonomous",
    zhLabel: "最高权限",
    description: "Allows autonomous execution of risky steps.",
    zhDescription: "允许自主执行高风险步骤。",
    approvalMode: "granted",
  },
];

const BLOCKED_EXECUTION_PRIVILEGE = {
  id: "blocked",
  label: "Blocked",
  zhLabel: "禁止高风险",
  description: "High-risk execution is blocked even if the plan requests it.",
  zhDescription: "即使任务规划要求高风险步骤，也会被明确阻止。",
  approvalMode: "denied",
};

function parseCsv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function toInt(value, fallback) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toFloat(value, fallback) {
  const parsed = Number.parseFloat(String(value || ""));
  return Number.isFinite(parsed) ? parsed : fallback;
}

function tryParseJson(value) {
  const text = String(value || "").trim();
  if (!text) {
    return { ok: true, value: null };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (error) {
    return { ok: false, error: String(error.message || error) };
  }
}

function approvalModeToValue(mode) {
  if (mode === "granted") {
    return true;
  }
  if (mode === "denied") {
    return false;
  }
  return null;
}

function approvalValueToMode(value) {
  if (value === true) {
    return "granted";
  }
  if (value === false) {
    return "denied";
  }
  return "auto";
}

function latestUserMessage(messages) {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (messages[index]?.role === "user" && messages[index]?.message) {
      return messages[index].message;
    }
  }
  return "";
}

function latestAssistantMessage(messages) {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (messages[index]?.role === "system" && messages[index]?.message) {
      return messages[index].message;
    }
  }
  return "";
}

function healthTone(report) {
  const summary = report?.summary || {};
  if (Number(summary.fail || 0) > 0) {
    return "critical";
  }
  if (Number(summary.warn || 0) > 0) {
    return "warning";
  }
  return "healthy";
}

function buildMissionOverrides(form) {
  const surfaceResult = tryParseJson(form.surface);
  const overrides = {
    mode: form.mode,
    safety_grade: form.safety_grade,
    autonomy_mode: form.autonomy_mode,
    report_lang: form.report_lang,
    max_iterations: toInt(form.max_iterations, 5),
    global_timeout: toFloat(form.global_timeout, 600),
    llm_source: form.llm_source,
    knowledge_tags: parseCsv(form.knowledge_tags),
    knowledge_refs: parseCsv(form.knowledge_refs),
    multi_agent: Boolean(form.multi_agent),
    multi_agent_rounds: toInt(form.multi_agent_rounds, 1),
    authorization_confirmed: Boolean(form.authorization_confirmed),
  };

  if (form.target.trim()) overrides.target = form.target.trim();
  if (form.scope.trim()) overrides.scope = form.scope.trim();
  if (form.plugins.trim()) overrides.plugins = form.plugins.trim();
  if (form.llm_config.trim()) overrides.llm_config = form.llm_config.trim();
  if (form.llm_model.trim()) overrides.llm_model = form.llm_model.trim();
  if (form.llm_provider.trim()) overrides.llm_provider = form.llm_provider.trim();
  if (form.llm_provider_type.trim()) overrides.llm_provider_type = form.llm_provider_type.trim();
  if (form.llm_base_url.trim()) overrides.llm_base_url = form.llm_base_url.trim();
  if (form.knowledge_summary.trim()) overrides.knowledge_summary = form.knowledge_summary.trim();
  if (form.approval_mode !== "auto") {
    overrides.approval_granted = form.approval_mode === "granted";
  }
  if (surfaceResult.ok && surfaceResult.value) {
    overrides.surface = surfaceResult.value;
  }
  return overrides;
}

function buildManualPayload(form) {
  const overrides = buildMissionOverrides(form);
  return {
    target: String(overrides.target || "").trim(),
    mode: overrides.mode || "agent",
    safety_grade: overrides.safety_grade || "balanced",
    autonomy_mode: overrides.autonomy_mode || "adaptive",
    report_lang: overrides.report_lang || "zh-CN",
    scope: overrides.scope || null,
    plugins: overrides.plugins || null,
    max_iterations: overrides.max_iterations || 5,
    global_timeout: overrides.global_timeout || 600,
    llm_source: overrides.llm_source || "system",
    llm_config: overrides.llm_config || null,
    llm_model: overrides.llm_model || null,
    llm_provider: overrides.llm_provider || null,
    llm_provider_type: overrides.llm_provider_type || null,
    llm_base_url: overrides.llm_base_url || null,
    knowledge_summary: overrides.knowledge_summary || null,
    knowledge_tags: overrides.knowledge_tags || [],
    knowledge_refs: overrides.knowledge_refs || [],
    multi_agent: Boolean(overrides.multi_agent),
    multi_agent_rounds: overrides.multi_agent_rounds || 1,
    authorization_confirmed: Boolean(overrides.authorization_confirmed),
    approval_granted: approvalModeToValue(form.approval_mode),
    surface: overrides.surface || null,
  };
}

export default function ScanForm({
  onSubmit,
  onMissionChat,
  busy,
  catalog,
  llmSettings,
  systemHealth,
  canAccessRag = false,
  onOpenRag,
  followUpSeed = null,
  onConsumeFollowUpSeed,
}) {
  const { t, formatMode, language } = useI18n();
  const [form, setForm] = useState(INITIAL_FORM);
  const [composer, setComposer] = useState("");
  const [missionDraft, setMissionDraft] = useState(null);
  const [missionMessages, setMissionMessages] = useState([]);
  const [missionSessionId, setMissionSessionId] = useState("");
  const [lastMissionMessage, setLastMissionMessage] = useState("");
  const [localBusy, setLocalBusy] = useState(false);
  const [localError, setLocalError] = useState("");
  const [chatWorkflowState, setChatWorkflowState] = useState("");
  const [launchGuard, setLaunchGuard] = useState(false);
  const pendingLaunchRef = useRef(null);
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);

  const healthState = useMemo(() => healthTone(systemHealth), [systemHealth]);
  const healthIssues = useMemo(() => {
    if (!Array.isArray(systemHealth?.checks)) {
      return [];
    }
    return systemHealth.checks.filter(
      (item) => TOOL_WARNINGS.has(item?.check_id) && item?.status !== "pass",
    );
  }, [systemHealth]);

  const effectiveTarget = missionDraft?.target || form.target.trim() || "example.com";

  const modelPresets = useMemo(() => {
    if (Array.isArray(llmSettings?.presets) && llmSettings.presets.length) {
      return [
        MODEL_PRESETS[0],
        ...llmSettings.presets.slice(0, 4).map((item) => ({
          id: item.id,
          label: item.label,
          description: item.note || item.default_model,
          llm_source: "custom",
          llm_model: item.default_model,
          llm_provider: item.id,
          llm_provider_type: item.provider_type || "openai_compatible",
          llm_base_url: item.base_url || "",
        })),
      ];
    }
    return MODEL_PRESETS;
  }, [llmSettings]);

  const activeModelPreset = useMemo(() => {
    if (form.llm_source === "system" || !form.llm_model.trim()) {
      return "system";
    }
    const matched = modelPresets.find(
      (item) =>
        item.llm_model === form.llm_model.trim()
        && item.llm_base_url === form.llm_base_url.trim(),
    );
    return matched?.id || "";
  }, [form.llm_base_url, form.llm_model, form.llm_source, modelPresets]);

  const activeReasoning = useMemo(
    () => REASONING_LEVELS.find(
      (item) =>
        item.safety_grade === form.safety_grade
        && item.autonomy_mode === form.autonomy_mode
        && item.multi_agent === Boolean(form.multi_agent),
    )
      || REASONING_LEVELS.find((item) => item.safety_grade === form.safety_grade)
      || REASONING_LEVELS[1],
    [form.autonomy_mode, form.multi_agent, form.safety_grade],
  );
  const executionPrivilegeOptions = useMemo(
    () => (form.approval_mode === "denied"
      ? [...EXECUTION_PRIVILEGES, BLOCKED_EXECUTION_PRIVILEGE]
      : EXECUTION_PRIVILEGES),
    [form.approval_mode],
  );
  const activeExecutionPrivilege = useMemo(
    () => executionPrivilegeOptions.find((item) => item.approvalMode === form.approval_mode) || executionPrivilegeOptions[0],
    [executionPrivilegeOptions, form.approval_mode],
  );
  const renderPresetLabel = (preset) => (zh ? preset.zhLabel || preset.label : preset.label);
  const renderPresetDescription = (preset) => (zh ? preset.zhDescription || preset.description : preset.description);
  const renderReasoningLabel = (scenario) => (zh ? scenario.zhLabel || scenario.label : scenario.label);
  const renderReasoningDescription = (scenario) => (zh ? scenario.zhDescription || scenario.description : scenario.description);
  const renderExecutionLabel = (item) => (zh ? item.zhLabel || item.label : item.label);
  const renderExecutionDescription = (item) => (zh ? item.zhDescription || item.description : item.description);
  const renderMissingFieldLabel = (field) => {
    if (field === "target") {
      return tt("Target", "目标");
    }
    if (field === "scope") {
      return tt("Scope", "范围");
    }
    return String(field || "");
  };
  const quickPrompts = useMemo(() => [
    zh
      ? `审计 ${effectiveTarget} 的对外暴露面，并优先识别 Web 风险。`
      : `Audit the exposed surface of ${effectiveTarget} and prioritize web-facing risk.`,
    zh
      ? `基于现有线索继续深挖 ${effectiveTarget}，但保持非破坏。`
      : `Continue deeper on ${effectiveTarget} using current evidence, but stay non-destructive.`,
  ], [effectiveTarget, zh]);
  const currentAssistantMessage = useMemo(
    () => latestAssistantMessage(missionMessages),
    [missionMessages],
  );
  const launchWorkflowState = useMemo(
    () => String(chatWorkflowState || "").trim().toLowerCase() || null,
    [chatWorkflowState],
  );
  const launchWorkflow = useMemo(() => {
    if (!launchWorkflowState) {
      return null;
    }
    if (launchWorkflowState === WORKFLOW_STATES.NEEDS_INPUT) {
      return {
        tone: workflowTone(launchWorkflowState),
        eyebrow: tt("More details", "补充信息"),
        title: tt("The mission needs one more detail", "任务还需要补充一些信息"),
        description: currentAssistantMessage,
        badge: { label: tt("Need input", "待补充") },
        chips: (missionDraft?.missing_fields || []).map((field) => ({
          label: renderMissingFieldLabel(field),
        })),
      };
    }
    if (launchWorkflowState === WORKFLOW_STATES.LAUNCH_PREVIEW) {
      return {
        tone: workflowTone(launchWorkflowState),
        eyebrow: tt("Preview", "只读预览"),
        title: tt("This account cannot launch jobs", "当前账号不能直接发起任务"),
        description: currentAssistantMessage,
        badge: { label: tt("Read only", "只读") },
      };
    }
    if (launchWorkflowState === WORKFLOW_STATES.LAUNCH_CONFIRM) {
      return {
        tone: workflowTone(launchWorkflowState),
        eyebrow: tt("Confirmation", "确认执行"),
        title: tt("High-risk action is waiting", "高风险动作等待确认"),
        description: tt(
          "This request reached a higher-risk execution path. Approve to continue, or switch to autonomous mode for future requests.",
          "这条请求已经进入更高风险的执行路径。你可以批准继续，或切到最高权限让后续请求自主执行。",
        ),
        badge: {
          label: renderExecutionLabel(activeExecutionPrivilege),
          tone: activeExecutionPrivilege.approvalMode === "denied" ? "warning" : "pending",
        },
        note: !form.authorization_confirmed
          ? tt(
            "If you expect active verification or exploit validation, also confirm that you are authorized below.",
            "如果你希望执行主动验证或更高风险的利用验证，也请先在下方确认你已获授权。",
          )
          : "",
        actions: [
          {
            label: tt("Approve and continue", "批准并继续"),
            className: "primary-button approval-primary-button",
            onClick: () => handleApproveHighRisk(false).catch(() => {}),
            disabled: busy || localBusy,
          },
          {
            label: tt("Autonomous and continue", "切到最高权限并继续"),
            className: "ghost-button approval-secondary-button",
            onClick: () => handleApproveHighRisk(true).catch(() => {}),
            disabled: busy || localBusy,
          },
          {
            label: tt("Not now", "暂不处理"),
            className: "ghost-button approval-dismiss-button",
            onClick: () => setChatWorkflowState(""),
            disabled: busy || localBusy,
          },
        ],
      };
    }
    return null;
  }, [
    activeExecutionPrivilege,
    busy,
    currentAssistantMessage,
    form.authorization_confirmed,
    launchWorkflowState,
    localBusy,
    missionDraft?.missing_fields,
    tt,
  ]);

  useEffect(() => {
    if (missionDraft?.target && !form.target.trim()) {
      setForm((current) => ({ ...current, target: missionDraft.target || "" }));
    }
  }, [form.target, missionDraft?.target]);

  useEffect(() => {
    if (!followUpSeed || typeof followUpSeed !== "object") {
      return;
    }
    if (followUpSeed?.composer) {
      setComposer(String(followUpSeed.composer));
      setLastMissionMessage(String(followUpSeed.composer));
    }
    if (followUpSeed?.form && typeof followUpSeed.form === "object") {
      setForm((current) => ({ ...current, ...followUpSeed.form }));
    }
    if (followUpSeed?.sessionId) {
      setMissionSessionId(String(followUpSeed.sessionId));
    }
    onConsumeFollowUpSeed?.();
  }, [followUpSeed, onConsumeFollowUpSeed]);

  function updateForm(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function applyModelPreset(preset) {
    setForm((current) => ({
      ...current,
      llm_source: preset.llm_source,
      llm_config: "",
      llm_model: preset.llm_model,
      llm_provider: preset.llm_provider,
      llm_provider_type: preset.llm_provider_type,
      llm_base_url: preset.llm_base_url,
    }));
  }

  function applyReasoningLevel(level) {
    setForm((current) => ({
      ...current,
      safety_grade: level.safety_grade,
      autonomy_mode: level.autonomy_mode,
      approval_mode: current.approval_mode,
      multi_agent: level.multi_agent,
      multi_agent_rounds: level.multi_agent ? current.multi_agent_rounds || "2" : "1",
    }));
  }

  function applyExecutionPrivilege(item) {
    setForm((current) => ({
      ...current,
      approval_mode: item.approvalMode,
    }));
  }

  function syncFormFromDraft(draft) {
    if (!draft) {
      return;
    }
    const payload = draft.payload || {};
    const knowledgeContext = payload.surface && typeof payload.surface === "object"
      && payload.surface.knowledge_context && typeof payload.surface.knowledge_context === "object"
      ? payload.surface.knowledge_context
      : {};
    setForm((current) => ({
      ...current,
      target: draft.target || current.target,
      scope: draft.scope || current.scope,
      mode: draft.mode || current.mode,
      safety_grade: draft.safety_grade || current.safety_grade,
      autonomy_mode: draft.autonomy_mode || current.autonomy_mode,
      max_iterations: String(payload.max_iterations ?? current.max_iterations),
      global_timeout: String(payload.global_timeout ?? current.global_timeout),
      llm_source: payload.llm_model ? "custom" : current.llm_source,
      llm_config: payload.llm_config || current.llm_config,
      llm_model: payload.llm_model || current.llm_model,
      llm_provider: payload.llm_provider || current.llm_provider,
      llm_provider_type: payload.llm_provider_type || current.llm_provider_type,
      llm_base_url: payload.llm_base_url || current.llm_base_url,
      knowledge_summary: knowledgeContext.summary || current.knowledge_summary,
      knowledge_tags: Array.isArray(knowledgeContext.tags) ? knowledgeContext.tags.join(",") : current.knowledge_tags,
      knowledge_refs: Array.isArray(knowledgeContext.references) ? knowledgeContext.references.join(",") : current.knowledge_refs,
      multi_agent: Boolean(draft.multi_agent),
      multi_agent_rounds: String(draft.multi_agent_rounds ?? current.multi_agent_rounds),
      authorization_confirmed: Boolean(draft.authorization_confirmed),
      approval_mode: approvalValueToMode(draft.approval_granted),
      surface: payload.surface ? JSON.stringify(payload.surface, null, 2) : current.surface,
    }));
  }

  function queueGuardedLaunch(task) {
    pendingLaunchRef.current = task;
    setLaunchGuard(true);
  }

  function resetConversation() {
    pendingLaunchRef.current = null;
    setLaunchGuard(false);
    setChatWorkflowState("");
    setMissionDraft(null);
    setMissionMessages([]);
    setMissionSessionId("");
    setLastMissionMessage("");
    setComposer("");
    setLocalError("");
  }

  async function confirmLaunchGuard() {
    const task = pendingLaunchRef.current;
    pendingLaunchRef.current = null;
    setLaunchGuard(false);
    if (typeof task === "function") {
      await task();
    }
  }

  async function runMissionChat(message, overrides) {
    setLocalBusy(true);
    setLocalError("");
    try {
      const response = await onMissionChat(message, overrides, missionSessionId);
      if (response?.session_id) {
        setMissionSessionId(response.session_id);
      }
      if (Array.isArray(response?.messages)) {
        setMissionMessages(response.messages);
      }
      if (response?.draft) {
        setMissionDraft(response.draft);
        syncFormFromDraft(response.draft);
      }
      setChatWorkflowState(String(response?.workflow_state || missionChatActionToWorkflowState(response?.action) || ""));
      setComposer("");
      return response;
    } catch (error) {
      setLocalError(String(error.message || error));
      throw error;
    } finally {
      setLocalBusy(false);
    }
  }

  async function handleMissionAction(override = "", bypassGuard = false) {
    const message = String(
      override
      || composer
      || lastMissionMessage
      || latestUserMessage(missionMessages)
      || "",
    ).trim();
    if (!message) {
      setLocalError(tt("Enter a mission first.", "请先输入任务描述。"));
      return;
    }
    if (healthIssues.length && !bypassGuard) {
      queueGuardedLaunch(() => handleMissionAction(override, true));
      return;
    }

    const surfaceResult = tryParseJson(form.surface);
    if (!surfaceResult.ok) {
      setLocalError(`${tt("Surface JSON could not be parsed", "Surface JSON 解析失败")}: ${surfaceResult.error}`);
      return;
    }

    setLastMissionMessage(message);
    if (override) {
      setComposer(message);
    }
    await runMissionChat(message, buildMissionOverrides(form));
  }

  async function handleApproveHighRisk(asAutonomous = false, bypassGuard = false) {
    const approvalMessage = tt(
      "Approval granted. Continue the current mission.",
      "批准高风险并继续当前任务。",
    );
    if (healthIssues.length && !bypassGuard) {
      queueGuardedLaunch(() => handleApproveHighRisk(asAutonomous, true));
      return;
    }
    const overrides = {
      ...buildMissionOverrides(form),
      approval_granted: true,
    };
    if (asAutonomous) {
      setForm((current) => ({ ...current, approval_mode: "granted" }));
    }
    setLastMissionMessage(approvalMessage);
    await runMissionChat(approvalMessage, overrides);
  }

  async function handleManualSubmit(event, bypassGuard = false) {
    if (event) {
      event.preventDefault();
    }
    if (healthIssues.length && !bypassGuard) {
      queueGuardedLaunch(() => handleManualSubmit(null, true));
      return;
    }
    const payload = buildManualPayload(form);
    if (!payload.target) {
      setLocalError(tt("A target is required for manual submit.", "手动提交必须提供目标。"));
      return;
    }
    setLocalBusy(true);
    setLocalError("");
    try {
      await onSubmit(payload);
      setComposer("");
    } catch (error) {
      setLocalError(String(error.message || error));
    } finally {
      setLocalBusy(false);
    }
  }

  function handleComposerKeyDown(event) {
    if (busy || localBusy) {
      return;
    }
    if (event.key !== "Enter" || (!event.ctrlKey && !event.metaKey)) {
      return;
    }
    event.preventDefault();
    handleMissionAction().catch(() => {});
  }

  return (
    <section className="panel scan-studio scan-studio-minimal">
      <div className="scan-studio-head scan-studio-head-minimal">
        <div>
          <p className="eyebrow">{t("scanForm.eyebrow")}</p>
          <h3>{tt("Audit Launchpad", "审计启动台")}</h3>
          <p className="scan-studio-copy">
            {tt(
              "Describe the target and expected outcome in one message. The agent will choose tools automatically under policy and scope constraints.",
              "用一段自然语言描述目标与预期结果。Agent 会在策略和范围约束下自动选择工具。",
            )}
          </p>
        </div>
        {missionSessionId ? <span className="tag-chip mono">{missionSessionId.slice(0, 12)}</span> : null}
      </div>

      {missionMessages.length ? (
        <div className="mission-thread mission-thread-modern mission-thread-chat">
          {missionMessages.map((item, index) => {
            const isUser = item.role === "user";
            return (
              <article key={`${item.role}-${index}`} className={`mission-bubble ${isUser ? "is-user" : "is-system"}`}>
                <header className="mission-bubble-head">
                  <div className="mission-bubble-identity">
                    <span className={`mission-bubble-dot ${isUser ? "is-user" : "is-system"}`} aria-hidden="true" />
                    <strong>{isUser ? tt("You", "你") : tt("Agent", "Agent")}</strong>
                  </div>
                  <span className={`mission-bubble-role ${isUser ? "is-user" : "is-system"}`}>
                    {isUser ? tt("Prompt", "指令") : tt("Reply", "回复")}
                  </span>
                </header>
                <div className="mission-bubble-body">{item.message}</div>
              </article>
            );
          })}
        </div>
      ) : (
        <div className="mission-thread-empty scan-thread-hero">
          <strong>{tt("Start with one instruction.", "从一条指令开始。")}</strong>
          <p>
            {tt(
              "Describe the target, expected outcome, and any constraints. The agent will decide how to plan and which tools to use.",
              "描述目标、期望结果和限制条件。Agent 会自己决定如何规划以及使用哪些工具。",
            )}
          </p>
        </div>
      )}

      {launchWorkflow ? (
        <WorkflowStateCard
          className="approval-panel"
          tone={launchWorkflow.tone}
          eyebrow={launchWorkflow.eyebrow}
          title={launchWorkflow.title}
          description={launchWorkflow.description}
          badge={launchWorkflow.badge}
          chips={launchWorkflow.chips}
          note={launchWorkflow.note}
          actions={launchWorkflow.actions}
        />
      ) : null}

      {missionDraft ? (
        <section className="mission-draft-panel mission-draft-panel-compact">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{tt("Draft", "草案")}</p>
              <h3>{missionDraft.target || tt("Mission draft", "任务草案")}</h3>
            </div>
            <span className={`status-badge ${missionDraft.missing_fields?.length ? "status-amber" : "status-cyan"}`}>
              {missionDraft.missing_fields?.length ? tt("Needs input", "需要补充") : tt("Runnable", "可执行")}
            </span>
          </div>

          <div className="mission-draft-grid mission-draft-grid-compact">
            <div className="mission-stat-card">
              <span className="mission-stat-label">{tt("Mode", "模式")}</span>
              <strong>{formatMode(missionDraft.mode || "agent")}</strong>
            </div>
            <div className="mission-stat-card">
              <span className="mission-stat-label">{tt("Safety", "安全等级")}</span>
              <strong>{missionDraft.safety_grade || "-"}</strong>
            </div>
            <div className="mission-stat-card">
              <span className="mission-stat-label">{tt("Autonomy", "自治级别")}</span>
              <strong>{missionDraft.autonomy_mode || "-"}</strong>
            </div>
          </div>

          {Array.isArray(missionDraft.summary) && missionDraft.summary.length ? (
            <ul className="mission-list mission-list-compact">
              {missionDraft.summary.slice(0, 4).map((item) => <li key={item}>{item}</li>)}
            </ul>
          ) : null}
        </section>
      ) : null}

      <div className="scan-composer-card scan-composer-dock">
        <textarea
          className="scan-composer-input scan-composer-input-minimal"
          rows={4}
          value={composer}
          onChange={(event) => setComposer(event.target.value)}
          onKeyDown={handleComposerKeyDown}
          placeholder={tt(
            "Audit commu.fun and focus on externally exposed web risk. Continue only with safe verification.",
            "例如：审计 commu.fun，优先关注外部 Web 风险，并只做安全验证。",
          )}
        />

        <div className="scan-quick-prompts scan-quick-prompts-minimal">
          {quickPrompts.map((prompt) => (
            <button
              key={prompt}
              type="button"
              className="scan-prompt-chip"
              onClick={() => handleMissionAction(prompt)}
              disabled={busy || localBusy}
            >
              {prompt}
            </button>
          ))}
        </div>

        {localError ? <div className="error-toast">{localError}</div> : null}

        <div className="scan-dock-bar">
          <div className="scan-dock-controls">
            <label className="scan-inline-select">
              <span>{tt("Model", "模型")}</span>
              <select
                value={activeModelPreset || "system"}
                onChange={(event) => {
                  const preset = modelPresets.find((item) => item.id === event.target.value);
                  if (preset) {
                    applyModelPreset(preset);
                  }
                }}
                disabled={busy || localBusy}
              >
                {modelPresets.map((preset) => (
                  <option key={preset.id} value={preset.id}>
                    {renderPresetLabel(preset)}
                  </option>
                ))}
              </select>
            </label>

            <label className="scan-inline-select">
              <span>{tt("Reasoning", "推理强度")}</span>
              <select
                value={activeReasoning.id}
                onChange={(event) => {
                  const preset = REASONING_LEVELS.find((item) => item.id === event.target.value);
                  if (preset) {
                    applyReasoningLevel(preset);
                  }
                }}
                disabled={busy || localBusy}
              >
                {REASONING_LEVELS.map((item) => (
                  <option key={item.id} value={item.id}>
                    {renderReasoningLabel(item)}
                  </option>
                ))}
              </select>
            </label>

            <label className="scan-inline-select">
              <span>{tt("Execution", "执行权限")}</span>
              <select
                value={activeExecutionPrivilege.id}
                onChange={(event) => {
                  const preset = executionPrivilegeOptions.find((item) => item.id === event.target.value);
                  if (preset) {
                    applyExecutionPrivilege(preset);
                  }
                }}
                disabled={busy || localBusy}
              >
                {executionPrivilegeOptions.map((item) => (
                  <option key={item.id} value={item.id}>
                    {renderExecutionLabel(item)}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="checkbox-card scan-authorization-card">
            <input
              type="checkbox"
              checked={Boolean(form.authorization_confirmed)}
              onChange={(event) => updateForm("authorization_confirmed", event.target.checked)}
              disabled={busy || localBusy}
            />
            <span>
              {tt(
                "I confirm I am authorized to test this target",
                "我确认已获得对该目标进行测试的授权",
              )}
            </span>
          </label>

          <div className="scan-dock-meta">
            <span className="scan-dock-pill">{tt("Tool routing: automatic", "工具路由：自动")}</span>
            <span className="scan-dock-pill">{tt("Target", "目标")}: {effectiveTarget}</span>
            <span className="scan-dock-pill">
              {tt("Execution", "执行权限")}: {renderExecutionLabel(activeExecutionPrivilege)}
            </span>
            <span className="scan-dock-pill">
              {tt("Authorization", "授权")}: {form.authorization_confirmed ? tt("Confirmed", "已确认") : tt("Not confirmed", "未确认")}
            </span>
            {systemHealth ? (
              <span className="scan-dock-pill">
                {tt("Environment", "环境")}: {healthState === "healthy" ? tt("Ready", "已就绪") : tt("Needs review", "需检查")}
              </span>
            ) : null}
            {form.knowledge_summary ? <span className="scan-dock-pill">{tt("Knowledge attached", "已附加知识上下文")}</span> : null}
          </div>

          <div className="scan-dock-footer">
            <div className="scan-dock-note-group">
              <div className="table-meta scan-dock-note">
                {renderExecutionDescription(activeExecutionPrivilege)}
              </div>
              <div className="scan-dock-shortcut">
                {tt("Ctrl/Cmd + Enter to send", "Ctrl/Cmd + Enter 发送")}
              </div>
            </div>

            <div className="inline-actions scan-submit-actions">
              <button type="button" className={`primary-button scan-send-button ${(busy || localBusy) ? "is-loading" : ""}`} onClick={() => handleMissionAction()} disabled={busy || localBusy}>
                <span>{busy || localBusy ? t("scanForm.launching") : tt("Send", "发送")}</span>
                <span className="scan-send-icon" aria-hidden="true">↑</span>
              </button>
              <button type="button" className="ghost-button scan-reset-button" onClick={resetConversation} disabled={busy || localBusy}>
                {tt("Reset", "重置")}
              </button>
            </div>
          </div>
        </div>
      </div>

      <details className="manual-controls glass-accordion">
        <summary>{tt("Advanced audit strategy", "高级审计策略")}</summary>
        <form className="scan-form manual-controls-body" onSubmit={handleManualSubmit}>
          <div className="field-grid">
            <label>
              <span>{t("common.target")}</span>
              <input value={form.target} onChange={(event) => updateForm("target", event.target.value)} placeholder={t("scanForm.targetPlaceholder")} />
            </label>
            <label>
              <span>{t("common.scope")}</span>
              <input value={form.scope} onChange={(event) => updateForm("scope", event.target.value)} placeholder={t("scanForm.scopePlaceholder")} />
            </label>
            <label>
              <span>{t("common.mode")}</span>
              <select value={form.mode} onChange={(event) => updateForm("mode", event.target.value)}>
                <option value="agent">{formatMode("agent")}</option>
                <option value="plan">{formatMode("plan")}</option>
                <option value="plugins">{formatMode("plugins")}</option>
              </select>
            </label>
            <label>
              <span>{t("scanForm.iterations")}</span>
              <input value={form.max_iterations} onChange={(event) => updateForm("max_iterations", event.target.value)} inputMode="numeric" />
            </label>
            <label>
              <span>{t("common.timeout")}</span>
              <input value={form.global_timeout} onChange={(event) => updateForm("global_timeout", event.target.value)} inputMode="decimal" />
            </label>
            <label>
              <span>{t("scanForm.plugins")}</span>
              <input value={form.plugins} onChange={(event) => updateForm("plugins", event.target.value)} placeholder={t("scanForm.pluginsPlaceholder")} />
            </label>
            <label>
              <span>{tt("LLM Config", "LLM 配置")}</span>
              <input value={form.llm_config} onChange={(event) => updateForm("llm_config", event.target.value)} placeholder="config/llm_router.json" />
            </label>
            <label>
              <span>{tt("LLM Model", "LLM 模型")}</span>
              <input value={form.llm_model} onChange={(event) => updateForm("llm_model", event.target.value)} placeholder="gpt-4.1-mini" />
            </label>
            <label>
              <span>{tt("Provider", "提供方")}</span>
              <input value={form.llm_provider} onChange={(event) => updateForm("llm_provider", event.target.value)} placeholder="openai" />
            </label>
            <label>
              <span>{tt("Provider Type", "提供方类型")}</span>
              <select value={form.llm_provider_type} onChange={(event) => updateForm("llm_provider_type", event.target.value)}>
                <option value="">{tt("auto", "自动")}</option>
                <option value="openai_sdk">openai_sdk</option>
                <option value="openai_compatible">openai_compatible</option>
                <option value="codex_oauth">codex_oauth</option>
              </select>
            </label>
            <label>
              <span>{tt("Base URL", "基础 URL")}</span>
              <input value={form.llm_base_url} onChange={(event) => updateForm("llm_base_url", event.target.value)} placeholder="http://host.docker.internal:11434/v1" />
            </label>
            <label className="field-span-2">
              <span>{tt("Knowledge Summary", "知识摘要")}</span>
              <textarea
                rows={3}
                value={form.knowledge_summary}
                onChange={(event) => updateForm("knowledge_summary", event.target.value)}
                placeholder={tt(
                  "Optional Swagger / architecture context to guide planning.",
                  "可选：补充 Swagger、架构说明或业务上下文，帮助 Agent 做更合理的规划。",
                )}
              />
            </label>
            <label>
              <span>{tt("Knowledge Tags", "知识标签")}</span>
              <input
                value={form.knowledge_tags}
                onChange={(event) => updateForm("knowledge_tags", event.target.value)}
                placeholder={tt("swagger,api-gateway,admin", "swagger,api-gateway,admin")}
              />
            </label>
            <label>
              <span>{tt("Knowledge References", "知识引用")}</span>
              <input
                value={form.knowledge_refs}
                onChange={(event) => updateForm("knowledge_refs", event.target.value)}
                placeholder={tt("docs/swagger.json, architecture.md", "docs/swagger.json, architecture.md")}
              />
            </label>
            <label>
              <span>{tt("High-risk override", "高风险覆盖策略")}</span>
              <select value={form.approval_mode} onChange={(event) => updateForm("approval_mode", event.target.value)}>
                <option value="auto">{tt("Ask when needed", "按需确认")}</option>
                <option value="granted">{tt("Always allow", "始终放行")}</option>
                <option value="denied">{tt("Always block", "始终阻止")}</option>
              </select>
            </label>
            <label className="checkbox-card">
              <input type="checkbox" checked={form.multi_agent} onChange={(event) => updateForm("multi_agent", event.target.checked)} />
              <span>{t("scanForm.advMultiAgent")}</span>
            </label>
            <label>
              <span>{t("scanForm.advMultiAgentRounds")}</span>
              <input value={form.multi_agent_rounds} onChange={(event) => updateForm("multi_agent_rounds", event.target.value)} inputMode="numeric" />
            </label>
          </div>

          {canAccessRag ? (
            <div className="knowledge-cta-inline">
              <div>
                <strong>{tt("Knowledge-backed audit", "知识增强审计")}</strong>
                <p>{tt("Open the knowledge base only when you need to attach internal docs or architecture context to this run.", "只有在需要为本次任务附加内部文档或架构上下文时，再打开知识库。")}</p>
              </div>
              <button type="button" className="ghost-button" onClick={onOpenRag} disabled={busy || localBusy}>
                {tt("Open knowledge base", "打开知识库")}
              </button>
            </div>
          ) : null}

          <label>
            <span>{t("scanForm.advSurface")}</span>
            <textarea rows={6} value={form.surface} onChange={(event) => updateForm("surface", event.target.value)} placeholder={t("scanForm.advSurfacePlaceholder")} />
          </label>

          <div className="manual-controls-footer">
            <div className="table-meta">{tt("Use this drawer only for explicit overrides such as scope, model routing, high-risk policy, or advanced surface payloads. Authorization stays in the composer dock.", "此抽屉仅用于显式覆盖，例如范围、模型路由、高风险策略或高级 surface 载荷。授权确认仍放在下方输入区。")}</div>
            <button type="submit" className="ghost-button" disabled={busy || localBusy}>
              {tt("Submit manually", "手动提交")}
            </button>
          </div>
        </form>
      </details>

      {launchGuard ? (
        <aside className="floating-toast-card">
          <div className="floating-toast-head">
            <strong>{tt("Pre-flight environment warning", "启动前环境警告")}</strong>
            <button type="button" className="ghost-button" onClick={() => setLaunchGuard(false)}>{tt("Dismiss", "关闭")}</button>
          </div>
          <div className="floating-toast-copy">
            {tt("Missing dependencies will cause the agent to skip tools. Continue only if you accept a partial run.", "缺失依赖会导致 Agent 跳过部分工具。只有在你接受部分覆盖的情况下才继续。")}
          </div>
          <ul className="floating-toast-list">
            {healthIssues.slice(0, 4).map((item) => (
              <li key={item.check_id}>
                <strong>{item.message}</strong>
                {item.detail ? <span>{item.detail}</span> : null}
              </li>
            ))}
          </ul>
          <div className="inline-actions">
            <button type="button" className="ghost-button" onClick={() => setLaunchGuard(false)}>{tt("Fix environment first", "先修复环境")}</button>
            <button type="button" className="primary-button" onClick={() => confirmLaunchGuard().catch(() => {})}>{tt("Continue with degraded coverage", "以降级覆盖继续")}</button>
          </div>
        </aside>
      ) : null}
    </section>
  );
}
