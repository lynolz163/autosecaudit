import { useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n";

const INITIAL_FORM = {
  target: "",
  scope: "",
  mode: "agent",
  safety_grade: "balanced",
  autonomy_mode: "adaptive",
  report_lang: "zh-CN",
  plugins: "",
  budget: "50",
  max_iterations: "5",
  global_timeout: "600",
  llm_source: "system",
  llm_config: "",
  llm_model: "",
  llm_provider: "",
  llm_provider_type: "",
  llm_base_url: "",
  tools: "",
  skills: "",
  multi_agent: false,
  multi_agent_rounds: "1",
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
    label: "System Route",
    description: "Use the deployment default LLM routing",
    llm_source: "system",
    llm_model: "",
    llm_provider: "",
    llm_provider_type: "",
    llm_base_url: "",
  },
  {
    id: "openai",
    label: "GPT-4.1 mini",
    description: "OpenAI hosted route",
    llm_source: "custom",
    llm_model: "gpt-4.1-mini",
    llm_provider: "openai",
    llm_provider_type: "openai_compatible",
    llm_base_url: "https://api.openai.com/v1",
  },
  {
    id: "qwen",
    label: "Qwen Plus",
    description: "DashScope compatible route",
    llm_source: "custom",
    llm_model: "qwen-plus",
    llm_provider: "qwen",
    llm_provider_type: "openai_compatible",
    llm_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    description: "DeepSeek compatible route",
    llm_source: "custom",
    llm_model: "deepseek-chat",
    llm_provider: "deepseek",
    llm_provider_type: "openai_compatible",
    llm_base_url: "https://api.deepseek.com/v1",
  },
  {
    id: "local",
    label: "Local LLM",
    description: "Ollama on the host machine",
    llm_source: "custom",
    llm_model: "qwen2.5:14b",
    llm_provider: "ollama",
    llm_provider_type: "openai_compatible",
    llm_base_url: "http://host.docker.internal:11434/v1",
  },
];

const INTENSITY_OPTIONS = [
  { id: "conservative", label: "Stealth", hint: "Read-only and low-noise." },
  { id: "balanced", label: "Normal", hint: "Default audit workflow." },
  { id: "aggressive", label: "Deep", hint: "Broader verification and retries." },
];

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
    budget: toInt(form.budget, 50),
    max_iterations: toInt(form.max_iterations, 5),
    global_timeout: toFloat(form.global_timeout, 600),
    llm_source: form.llm_source,
    tools: parseCsv(form.tools),
    skills: parseCsv(form.skills),
    multi_agent: Boolean(form.multi_agent),
    multi_agent_rounds: toInt(form.multi_agent_rounds, 1),
  };

  if (form.target.trim()) overrides.target = form.target.trim();
  if (form.scope.trim()) overrides.scope = form.scope.trim();
  if (form.plugins.trim()) overrides.plugins = form.plugins.trim();
  if (form.llm_config.trim()) overrides.llm_config = form.llm_config.trim();
  if (form.llm_model.trim()) overrides.llm_model = form.llm_model.trim();
  if (form.llm_provider.trim()) overrides.llm_provider = form.llm_provider.trim();
  if (form.llm_provider_type.trim()) overrides.llm_provider_type = form.llm_provider_type.trim();
  if (form.llm_base_url.trim()) overrides.llm_base_url = form.llm_base_url.trim();
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
    budget: overrides.budget || 50,
    max_iterations: overrides.max_iterations || 5,
    global_timeout: overrides.global_timeout || 600,
    llm_source: overrides.llm_source || "system",
    llm_config: overrides.llm_config || null,
    llm_model: overrides.llm_model || null,
    llm_provider: overrides.llm_provider || null,
    llm_provider_type: overrides.llm_provider_type || null,
    llm_base_url: overrides.llm_base_url || null,
    tools: overrides.tools || [],
    skills: overrides.skills || [],
    multi_agent: Boolean(overrides.multi_agent),
    multi_agent_rounds: overrides.multi_agent_rounds || 1,
    approval_granted: approvalModeToValue(form.approval_mode),
    surface: overrides.surface || null,
  };
}

export default function ScanForm({
  onSubmit,
  onParseMission,
  onSubmitMission,
  busy,
  catalog,
  llmSettings,
  systemHealth,
}) {
  const { t, formatMode } = useI18n();
  const [form, setForm] = useState(INITIAL_FORM);
  const [composer, setComposer] = useState("");
  const [missionDraft, setMissionDraft] = useState(null);
  const [missionMessages, setMissionMessages] = useState([]);
  const [missionSessionId, setMissionSessionId] = useState("");
  const [lastMissionMessage, setLastMissionMessage] = useState("");
  const [localBusy, setLocalBusy] = useState(false);
  const [localError, setLocalError] = useState("");
  const [launchGuard, setLaunchGuard] = useState(false);
  const pendingLaunchRef = useRef(null);

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
  const toolsCount = Array.isArray(catalog?.tools) ? catalog.tools.length : 0;
  const skillsCount = Array.isArray(catalog?.skills) ? catalog.skills.length : 0;

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

  const quickPrompts = useMemo(() => [
    `Perform reconnaissance against ${effectiveTarget}`,
    `Validate the main exposed services on ${effectiveTarget} with low-risk checks only`,
    `Perform the audit without Playwright or browser automation`,
  ], [effectiveTarget]);

  useEffect(() => {
    if (missionDraft?.target && !form.target.trim()) {
      setForm((current) => ({ ...current, target: missionDraft.target || "" }));
    }
  }, [form.target, missionDraft?.target]);

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

  function syncFormFromDraft(draft) {
    if (!draft) {
      return;
    }
    const payload = draft.payload || {};
    setForm((current) => ({
      ...current,
      target: draft.target || current.target,
      scope: draft.scope || current.scope,
      mode: draft.mode || current.mode,
      safety_grade: draft.safety_grade || current.safety_grade,
      autonomy_mode: draft.autonomy_mode || current.autonomy_mode,
      budget: String(payload.budget ?? current.budget),
      max_iterations: String(payload.max_iterations ?? current.max_iterations),
      global_timeout: String(payload.global_timeout ?? current.global_timeout),
      llm_source: payload.llm_model ? "custom" : current.llm_source,
      llm_config: payload.llm_config || current.llm_config,
      llm_model: payload.llm_model || current.llm_model,
      llm_provider: payload.llm_provider || current.llm_provider,
      llm_provider_type: payload.llm_provider_type || current.llm_provider_type,
      llm_base_url: payload.llm_base_url || current.llm_base_url,
      tools: Array.isArray(draft.selected_tools) ? draft.selected_tools.join(",") : current.tools,
      skills: Array.isArray(draft.selected_skills) ? draft.selected_skills.join(",") : current.skills,
      multi_agent: Boolean(draft.multi_agent),
      multi_agent_rounds: String(draft.multi_agent_rounds ?? current.multi_agent_rounds),
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

  async function handleMissionAction(action, override = "", bypassGuard = false) {
    const message = String(
      override
      || composer
      || lastMissionMessage
      || latestUserMessage(missionMessages)
      || "",
    ).trim();
    if (!message) {
      setLocalError("Enter a mission first.");
      return;
    }
    if (action === "run" && healthIssues.length && !bypassGuard) {
      queueGuardedLaunch(() => handleMissionAction(action, override, true));
      return;
    }

    const surfaceResult = tryParseJson(form.surface);
    if (!surfaceResult.ok) {
      setLocalError(`Surface JSON could not be parsed: ${surfaceResult.error}`);
      return;
    }

    setLastMissionMessage(message);
    if (override) {
      setComposer(message);
    }
    setLocalBusy(true);
    setLocalError("");
    try {
      const runner = action === "run" ? onSubmitMission : onParseMission;
      const response = await runner(message, buildMissionOverrides(form), missionSessionId);
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
      if (action === "run") {
        setComposer("");
      }
    } catch (error) {
      setLocalError(String(error.message || error));
    } finally {
      setLocalBusy(false);
    }
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
      setLocalError("A target is required for manual submit.");
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

  return (
    <section className="panel scan-studio">
      <div className="scan-studio-head">
        <div>
          <p className="eyebrow">{t("scanForm.eyebrow")}</p>
          <h3>Mission Studio</h3>
          <p className="scan-studio-copy">
            Describe the target and the objective in one message. Keep the surface-level
            controls visible and move everything else into the advanced accordion.
          </p>
        </div>
        <div className="scan-studio-meta">
          <span className="tag-chip">{toolsCount} tools</span>
          <span className="tag-chip">{skillsCount} skills</span>
          {missionSessionId ? <span className="tag-chip mono">{missionSessionId.slice(0, 12)}</span> : null}
        </div>
      </div>

      {systemHealth ? (
        <section className={`scan-health-banner is-${healthState}`}>
          <div className="scan-health-summary">
            <div className="scan-health-signal" />
            <div>
              <strong>{healthState === "healthy" ? "Environment healthy" : "Environment needs review"}</strong>
              <p>
                Pass {systemHealth.summary?.pass || 0} / Warn {systemHealth.summary?.warn || 0} / Fail {systemHealth.summary?.fail || 0}
              </p>
            </div>
          </div>
          <div className="scan-health-list">
            {(healthIssues.length ? healthIssues : [{ check_id: "ok", message: "Core tooling is ready for launch." }]).slice(0, 3).map((item) => (
              <span key={item.check_id} className="scan-health-item">{item.message}</span>
            ))}
          </div>
        </section>
      ) : null}

      <div className="scan-studio-shell">
        <div className="scan-composer-card">
          <textarea
            className="scan-composer-input"
            rows={5}
            value={composer}
            onChange={(event) => setComposer(event.target.value)}
            placeholder="Example: Audit https://example.com, keep it low-risk, focus on web exposure first, then continue deeper on 443 if the agent finds anything suspicious."
          />

          <div className="scan-toolbar">
            <div className="scan-toolbar-group">
              <span className="scan-toolbar-label">Model access</span>
              <div className="pill-group">
                {modelPresets.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    className={`pill-button ${activeModelPreset === preset.id ? "is-active" : ""}`}
                    onClick={() => applyModelPreset(preset)}
                    title={preset.description}
                    disabled={busy || localBusy}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="scan-toolbar-group">
              <span className="scan-toolbar-label">Intensity</span>
              <div className="pill-group">
                {INTENSITY_OPTIONS.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`pill-button ${form.safety_grade === item.id ? "is-active" : ""}`}
                    onClick={() => updateForm("safety_grade", item.id)}
                    title={item.hint}
                    disabled={busy || localBusy}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="scan-quick-prompts">
            {quickPrompts.map((prompt) => (
              <button
                key={prompt}
                type="button"
                className="scan-prompt-chip"
                onClick={() => handleMissionAction("preview", prompt)}
                disabled={busy || localBusy}
              >
                {prompt}
              </button>
            ))}
          </div>

          <div className="scan-launch-row">
            <div className="scan-launch-copy">
              <strong>Main path:</strong> write the mission, preview the draft, then launch.
            </div>
            <div className="inline-actions">
              <button type="button" className="ghost-button" onClick={() => handleMissionAction("preview")} disabled={busy || localBusy}>
                Preview Draft
              </button>
              <button type="button" className={`primary-button ${(busy || localBusy) ? "is-loading" : ""}`} onClick={() => handleMissionAction("run")} disabled={busy || localBusy}>
                {busy || localBusy ? t("scanForm.launching") : t("scanForm.startJob")}
              </button>
              <button type="button" className="ghost-button" onClick={resetConversation} disabled={busy || localBusy}>
                Reset
              </button>
            </div>
          </div>

          {localError ? <div className="error-toast">{localError}</div> : null}
        </div>

        <div className="scan-studio-sidecar">
          <div className="scan-sidecard">
            <span className="record-label">Target anchor</span>
            <strong>{effectiveTarget}</strong>
            <p>{activeModelPreset === "system" ? "System-configured routing" : form.llm_model || "No explicit model selected"}</p>
          </div>
          <div className="scan-sidecard">
            <span className="record-label">Intensity</span>
            <strong>{INTENSITY_OPTIONS.find((item) => item.id === form.safety_grade)?.label || "Normal"}</strong>
            <p>{INTENSITY_OPTIONS.find((item) => item.id === form.safety_grade)?.hint || ""}</p>
          </div>
          <div className="scan-sidecard">
            <span className="record-label">Manual budget</span>
            <strong>{form.budget}</strong>
            <p>{form.max_iterations} iterations / {form.global_timeout}s timeout</p>
          </div>
        </div>
      </div>

      {missionMessages.length ? (
        <div className="mission-thread mission-thread-modern">
          {missionMessages.map((item, index) => (
            <article key={`${item.role}-${index}`} className={`mission-bubble ${item.role === "user" ? "is-user" : "is-system"}`}>
              <header className="mission-bubble-head">
                <strong>{item.role === "user" ? "You" : "Agent"}</strong>
                <span className="mission-bubble-role">{item.role}</span>
              </header>
              <div className="mission-bubble-body">{item.message}</div>
            </article>
          ))}
        </div>
      ) : null}

      {missionDraft ? (
        <section className="mission-draft-panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">Draft</p>
              <h3>{missionDraft.target || "Mission draft"}</h3>
            </div>
            <span className={`status-badge ${missionDraft.missing_fields?.length ? "status-amber" : "status-cyan"}`}>
              {missionDraft.missing_fields?.length ? "Needs Input" : "Runnable"}
            </span>
          </div>

          <div className="mission-draft-grid">
            <div className="mission-stat-card">
              <span className="mission-stat-label">Mode</span>
              <strong>{formatMode(missionDraft.mode || "agent")}</strong>
            </div>
            <div className="mission-stat-card">
              <span className="mission-stat-label">Safety</span>
              <strong>{missionDraft.safety_grade || "-"}</strong>
            </div>
            <div className="mission-stat-card">
              <span className="mission-stat-label">Autonomy</span>
              <strong>{missionDraft.autonomy_mode || "-"}</strong>
            </div>
          </div>

          {Array.isArray(missionDraft.summary) && missionDraft.summary.length ? (
            <ul className="mission-list">
              {missionDraft.summary.map((item) => <li key={item}>{item}</li>)}
            </ul>
          ) : null}
        </section>
      ) : null}

      <details className="manual-controls glass-accordion">
        <summary>Advanced settings</summary>
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
              <span>{t("common.budget")}</span>
              <input value={form.budget} onChange={(event) => updateForm("budget", event.target.value)} inputMode="numeric" />
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
              <span>{t("scanForm.advTools")}</span>
              <input value={form.tools} onChange={(event) => updateForm("tools", event.target.value)} placeholder={t("scanForm.advToolsPlaceholder")} />
            </label>
            <label>
              <span>{t("scanForm.advSkills")}</span>
              <input value={form.skills} onChange={(event) => updateForm("skills", event.target.value)} placeholder={t("scanForm.advSkillsPlaceholder")} />
            </label>
            <label>
              <span>LLM Config</span>
              <input value={form.llm_config} onChange={(event) => updateForm("llm_config", event.target.value)} placeholder="config/llm_router.json" />
            </label>
            <label>
              <span>LLM Model</span>
              <input value={form.llm_model} onChange={(event) => updateForm("llm_model", event.target.value)} placeholder="gpt-4.1-mini" />
            </label>
            <label>
              <span>Provider</span>
              <input value={form.llm_provider} onChange={(event) => updateForm("llm_provider", event.target.value)} placeholder="openai" />
            </label>
            <label>
              <span>Provider Type</span>
              <select value={form.llm_provider_type} onChange={(event) => updateForm("llm_provider_type", event.target.value)}>
                <option value="">auto</option>
                <option value="openai_sdk">openai_sdk</option>
                <option value="openai_compatible">openai_compatible</option>
                <option value="codex_oauth">codex_oauth</option>
              </select>
            </label>
            <label>
              <span>Base URL</span>
              <input value={form.llm_base_url} onChange={(event) => updateForm("llm_base_url", event.target.value)} placeholder="http://host.docker.internal:11434/v1" />
            </label>
            <label>
              <span>{t("scanForm.advSysApproval")}</span>
              <select value={form.approval_mode} onChange={(event) => updateForm("approval_mode", event.target.value)}>
                <option value="auto">{t("scanForm.advApprovalAuto")}</option>
                <option value="granted">{t("scanForm.advApprovalGranted")}</option>
                <option value="denied">{t("scanForm.advApprovalDenied")}</option>
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

          <label>
            <span>{t("scanForm.advSurface")}</span>
            <textarea rows={6} value={form.surface} onChange={(event) => updateForm("surface", event.target.value)} placeholder={t("scanForm.advSurfacePlaceholder")} />
          </label>

          <div className="manual-controls-footer">
            <div className="table-meta">Use this panel only for explicit overrides and fallback submission.</div>
            <button type="submit" className="ghost-button" disabled={busy || localBusy}>
              Submit Manually
            </button>
          </div>
        </form>
      </details>

      {launchGuard ? (
        <aside className="floating-toast-card">
          <div className="floating-toast-head">
            <strong>Environment needs attention</strong>
            <button type="button" className="ghost-button" onClick={() => setLaunchGuard(false)}>Dismiss</button>
          </div>
          <div className="floating-toast-copy">
            Missing dependencies will cause the agent to skip tools. Continue only if you accept a partial run.
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
            <button type="button" className="ghost-button" onClick={() => setLaunchGuard(false)}>Review first</button>
            <button type="button" className="primary-button" onClick={() => confirmLaunchGuard().catch(() => { })}>Continue anyway</button>
          </div>
        </aside>
      ) : null}
    </section>
  );
}
