(function () {
  const state = {
    jobs: [],
    selectedJobId: null,
    selectedJob: null,
    timer: null,
    logLines: [],
    logTotal: 0,
    logNextOffset: 0,
    logStream: null,
    apiToken: "",
    codex: {
      config: null,
      sessionId: null,
      loginPollTimer: null,
      models: [],
      connected: false,
    },
    catalog: {
      tools: [],
      skills: [],
    },
  };

  const POLL_MS = 2000;

  const el = {
    serverTs: document.getElementById("serverTs"),
    jobForm: document.getElementById("jobForm"),
    formMessage: document.getElementById("formMessage"),
    refreshJobsBtn: document.getElementById("refreshJobsBtn"),
    jobList: document.getElementById("jobList"),
    jobCount: document.getElementById("jobCount"),
    jobDetails: document.getElementById("jobDetails"),
    cancelJobBtn: document.getElementById("cancelJobBtn"),
    logMeta: document.getElementById("logMeta"),
    logView: document.getElementById("logView"),
    artifactMeta: document.getElementById("artifactMeta"),
    artifactList: document.getElementById("artifactList"),
    modeSelect: document.getElementById("modeSelect"),
    pluginsField: document.getElementById("pluginsField"),
    toolCatalog: document.getElementById("toolCatalog"),
    skillCatalog: document.getElementById("skillCatalog"),
    toolCatalogMeta: document.getElementById("toolCatalogMeta"),
    skillCatalogMeta: document.getElementById("skillCatalogMeta"),
    providerTypeSelect: document.getElementById("providerTypeSelect"),
    oauthSection: document.getElementById("oauthSection"),
    apiTokenInput: document.getElementById("apiTokenInput"),
    codexConnectBtn: document.getElementById("codexConnectBtn"),
    codexRefreshModelsBtn: document.getElementById("codexRefreshModelsBtn"),
    codexModelSelect: document.getElementById("codexModelSelect"),
    useCodexCheckbox: document.getElementById("useCodexCheckbox"),
    codexAuthStatusPill: document.getElementById("codexAuthStatusPill"),
    codexAuthNotice: document.getElementById("codexAuthNotice"),
    codexConfigMeta: document.getElementById("codexConfigMeta"),
  };

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function statusClass(status) {
    if (status === "completed") return "bg-emerald-100 text-emerald-700";
    if (status === "running") return "bg-sky-100 text-sky-700";
    if (status === "failed" || status === "error") return "bg-rose-100 text-rose-700";
    if (status === "canceled") return "bg-amber-100 text-amber-700";
    return "bg-slate-100 text-slate-700";
  }

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (state.apiToken) {
      headers.Authorization = `Bearer ${state.apiToken}`;
    }
    const resp = await fetch(path, {
      headers,
      ...options,
    });
    const text = await resp.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!resp.ok) {
      if (resp.status === 401) {
        throw new Error("Unauthorized: set correct Web API Token.");
      }
      throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
  }

  function showMessage(text, kind = "info") {
    el.formMessage.classList.remove(
      "hidden",
      "bg-rose-50",
      "text-rose-700",
      "bg-emerald-50",
      "text-emerald-700",
      "bg-slate-100",
      "text-slate-700"
    );
    if (kind === "error") {
      el.formMessage.classList.add("bg-rose-50", "text-rose-700");
    } else if (kind === "success") {
      el.formMessage.classList.add("bg-emerald-50", "text-emerald-700");
    } else {
      el.formMessage.classList.add("bg-slate-100", "text-slate-700");
    }
    el.formMessage.textContent = text;
  }

  function clearMessage() {
    el.formMessage.classList.add("hidden");
    el.formMessage.textContent = "";
  }

  function handleApiError(error) {
    const message = error && error.message ? error.message : String(error);
    showMessage(message, "error");
    console.error(error);
  }

  function isTerminalStatus(status) {
    return ["completed", "failed", "error", "canceled"].includes(String(status || ""));
  }

  function closeLogStream() {
    if (state.logStream) {
      state.logStream.close();
      state.logStream = null;
    }
  }

  function syncJobInList(job) {
    if (!job || !job.job_id) return;
    const index = state.jobs.findIndex((item) => item.job_id === job.job_id);
    if (index >= 0) {
      state.jobs[index] = job;
    } else {
      state.jobs.unshift(job);
    }
  }

  function renderLogLines(job) {
    if (!job) {
      el.logMeta.textContent = "No job selected";
      el.logView.textContent = "Select a job to view logs...";
      return;
    }
    const lineCount = Number(state.logTotal || state.logLines.length || 0);
    const liveSuffix = state.logStream ? " | live" : "";
    el.logMeta.textContent = `${job.status} | ${lineCount} lines${liveSuffix}`;
    el.logView.textContent =
      state.logLines.map((item) => `[${item.ts}] ${item.line}`).join("\n") || "(no logs yet)";
    el.logView.scrollTop = el.logView.scrollHeight;
  }

  function openLogStream(jobId, offset) {
    closeLogStream();
    if (!jobId || typeof window.EventSource !== "function") {
      return;
    }

    const params = new URLSearchParams();
    params.set("offset", String(Math.max(0, Number(offset || 0))));
    if (state.apiToken) {
      params.set("api_token", state.apiToken);
    }

    const source = new window.EventSource(
      `/api/jobs/${encodeURIComponent(jobId)}/stream?${params.toString()}`
    );
    state.logStream = source;

    source.addEventListener("log", (event) => {
      let payload = {};
      try {
        payload = JSON.parse(event.data || "{}");
      } catch {
        return;
      }
      if (jobId !== state.selectedJobId) {
        return;
      }
      const item = payload.item;
      if (!item) {
        return;
      }
      state.logLines.push(item);
      if (state.logLines.length > 5000) {
        state.logLines = state.logLines.slice(-5000);
      }
      state.logTotal = Number(payload.total || state.logTotal || state.logLines.length);
      state.logNextOffset = Number(payload.offset || 0) + 1;
      renderLogLines(state.selectedJob);
    });

    source.addEventListener("status", (event) => {
      let payload = {};
      try {
        payload = JSON.parse(event.data || "{}");
      } catch {
        return;
      }
      if (jobId !== state.selectedJobId || !payload.job) {
        return;
      }
      state.selectedJob = payload.job;
      state.logTotal = Number(payload.total || state.logTotal || 0);
      state.logNextOffset = Number(payload.offset || state.logNextOffset || 0);
      syncJobInList(payload.job);
      renderJobs();
      renderJobDetails(payload.job);
      renderLogLines(payload.job);
      if (isTerminalStatus(payload.job.status)) {
        window.setTimeout(() => closeLogStream(), 250);
      }
    });

    source.addEventListener("heartbeat", () => {
      return;
    });

    source.onerror = () => {
      if (state.logStream === source) {
        closeLogStream();
        if (jobId === state.selectedJobId) {
          refreshSelectedJob().catch(console.error);
        }
      }
    };
  }

  function splitCsv(value) {
    return String(value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function renderCatalogList(kind, items) {
    const container = kind === "tools" ? el.toolCatalog : el.skillCatalog;
    const meta = kind === "tools" ? el.toolCatalogMeta : el.skillCatalogMeta;
    if (!container || !meta) return;

    const normalizedItems = Array.isArray(items) ? items : [];
    meta.textContent = `${normalizedItems.length} loaded`;
    if (!normalizedItems.length) {
      container.innerHTML = '<div class="rounded-xl bg-white p-3 text-xs text-slate-500">No catalog entries available.</div>';
      return;
    }

    container.innerHTML = normalizedItems
      .map((item) => {
        const name = String(item.name || "").trim();
        if (!name) return "";
        if (kind === "tools") {
          const availability = item.available ? "ready" : "missing";
          const availabilityCls = item.available ? "bg-emerald-100 text-emerald-700" : "bg-rose-100 text-rose-700";
          const phases = Array.isArray(item.phase_affinity) && item.phase_affinity.length ? item.phase_affinity.join(", ") : "any";
          const targets = Array.isArray(item.target_types) && item.target_types.length ? item.target_types.join(", ") : "-";
          return `
            <label class="block rounded-xl border border-slate-200 bg-white p-3 hover:border-sky-200">
              <div class="flex items-start gap-3">
                <input type="checkbox" name="tools" value="${esc(name)}" class="mt-1 rounded border-slate-300" />
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="text-sm font-medium text-slate-900">${esc(name)}</span>
                    <span class="rounded-full px-2 py-0.5 text-[11px] font-medium ${availabilityCls}">${esc(availability)}</span>
                    <span class="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600">${esc(String(item.category || "generic"))}</span>
                    <span class="rounded-full bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700">${esc(String(item.risk_level || "safe"))}</span>
                  </div>
                  <div class="mt-1 text-xs text-slate-600">${esc(String(item.description || ""))}</div>
                  <div class="mt-2 text-[11px] text-slate-500">phases: ${esc(phases)} | targets: ${esc(targets)}${item.skill ? ` | skill: ${esc(String(item.skill))}` : ""}</div>
                </div>
              </div>
            </label>
          `;
        }

        const phases = Array.isArray(item.phases) && item.phases.length ? item.phases.join(", ") : "any";
        const depends = Array.isArray(item.depends_on_tools) && item.depends_on_tools.length ? item.depends_on_tools.join(", ") : "-";
        return `
          <label class="block rounded-xl border border-slate-200 bg-white p-3 hover:border-sky-200">
            <div class="flex items-start gap-3">
              <input type="checkbox" name="skills" value="${esc(name)}" class="mt-1 rounded border-slate-300" />
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="text-sm font-medium text-slate-900">${esc(name)}</span>
                  <span class="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600">${esc(String(item.category || "generic"))}</span>
                  <span class="rounded-full bg-indigo-50 px-2 py-0.5 text-[11px] font-medium text-indigo-700">tool: ${esc(String(item.tool || ""))}</span>
                  <span class="rounded-full bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700">${esc(String(item.risk_level || "safe"))}</span>
                </div>
                <div class="mt-1 text-xs text-slate-600">${esc(String(item.description || ""))}</div>
                <div class="mt-2 text-[11px] text-slate-500">phases: ${esc(phases)} | target: ${esc(String(item.target_type || "-"))} | depends: ${esc(depends)}</div>
              </div>
            </div>
          </label>
        `;
      })
      .join("");
  }

  function updatePlannerSelectionState() {
    const disabled = String(el.modeSelect?.value || "agent") === "plugins";
    [el.toolCatalog, el.skillCatalog].forEach((container) => {
      if (!container) return;
      container.querySelectorAll('input[type="checkbox"]').forEach((node) => {
        node.disabled = disabled;
      });
    });
  }

  async function loadPlannerCatalog() {
    try {
      const data = await api("/api/jobs/catalog");
      state.catalog.tools = Array.isArray(data.tools) ? data.tools : [];
      state.catalog.skills = Array.isArray(data.skills) ? data.skills : [];
      renderCatalogList("tools", state.catalog.tools);
      renderCatalogList("skills", state.catalog.skills);
      updatePlannerSelectionState();
    } catch (error) {
      if (el.toolCatalog) {
        el.toolCatalog.innerHTML = `<div class="rounded-xl bg-white p-3 text-xs text-rose-700">Failed to load tool catalog: ${esc(error.message || error)}</div>`;
      }
      if (el.skillCatalog) {
        el.skillCatalog.innerHTML = `<div class="rounded-xl bg-white p-3 text-xs text-rose-700">Failed to load skill catalog: ${esc(error.message || error)}</div>`;
      }
      console.error(error);
    }
  }

  function loadApiToken() {
    const key = "autosecaudit_web_api_token";
    const fromStorage = String(window.localStorage.getItem(key) || "").trim();
    state.apiToken = fromStorage;
    if (el.apiTokenInput) {
      el.apiTokenInput.value = fromStorage;
      el.apiTokenInput.addEventListener("input", () => {
        const token = String(el.apiTokenInput.value || "").trim();
        state.apiToken = token;
        if (token) {
          window.localStorage.setItem(key, token);
        } else {
          window.localStorage.removeItem(key);
        }
      });
    }
  }

  function showCodexNotice(text, kind = "info") {
    if (!el.codexAuthNotice) return;
    el.codexAuthNotice.classList.remove(
      "hidden",
      "bg-slate-100",
      "text-slate-700",
      "bg-emerald-50",
      "text-emerald-700",
      "bg-rose-50",
      "text-rose-700",
      "bg-amber-50",
      "text-amber-700"
    );
    if (kind === "success") {
      el.codexAuthNotice.classList.add("bg-emerald-50", "text-emerald-700");
    } else if (kind === "error") {
      el.codexAuthNotice.classList.add("bg-rose-50", "text-rose-700");
    } else if (kind === "warning") {
      el.codexAuthNotice.classList.add("bg-amber-50", "text-amber-700");
    } else {
      el.codexAuthNotice.classList.add("bg-slate-100", "text-slate-700");
    }
    el.codexAuthNotice.textContent = text;
  }

  function clearCodexNotice() {
    if (!el.codexAuthNotice) return;
    el.codexAuthNotice.classList.add("hidden");
    el.codexAuthNotice.textContent = "";
  }

  function renderCodexStatus() {
    if (!el.codexAuthStatusPill) return;
    const cfg = state.codex.config;
    const sessionId = state.codex.sessionId;
    let label = "Not configured";
    let cls = ["bg-slate-100", "text-slate-600"];
    if (cfg && cfg.configured) {
      label = state.codex.connected ? "Connected" : "Ready";
      cls = state.codex.connected ? ["bg-emerald-100", "text-emerald-700"] : ["bg-sky-100", "text-sky-700"];
      if (sessionId) {
        label = "Logging in...";
        cls = ["bg-amber-100", "text-amber-700"];
      }
    }
    el.codexAuthStatusPill.className = `rounded-full px-2 py-1 text-[11px] font-medium ${cls.join(" ")}`;
    el.codexAuthStatusPill.textContent = label;

    if (el.codexConfigMeta) {
      if (!cfg) {
        el.codexConfigMeta.textContent = "";
      } else if (!cfg.configured) {
        el.codexConfigMeta.textContent = "Server Codex OAuth preset is not configured yet.";
      } else {
        const profile = cfg.profile_id || "web";
        const provider = cfg.provider_alias || "codex";
        const preset = cfg.preset_source || "unknown";
        el.codexConfigMeta.textContent = `Provider: ${provider} | Profile: ${profile} | Base URL: ${cfg.base_url || "-"} | Preset: ${preset}`;
      }
    }
  }

  function renderCodexModels(models) {
    if (!el.codexModelSelect) return;
    const current = el.codexModelSelect.value;
    const items = Array.isArray(models) ? models : [];
    const options = ['<option value="">(Select a model)</option>'];
    for (const item of items) {
      const id = String(item.id || "").trim();
      if (!id) continue;
      const label = String(item.label || id);
      options.push(`<option value="${esc(id)}">${esc(label)}</option>`);
    }
    el.codexModelSelect.innerHTML = options.join("");
    if (current && items.some((m) => String(m.id) === current)) {
      el.codexModelSelect.value = current;
    }
  }

  async function loadCodexConfig() {
    try {
      const data = await api("/api/llm/codex/config");
      state.codex.config = data;
      if (!data.configured) {
        showCodexNotice("Codex OAuth preset is not configured on server. Set server env vars first.", "warning");
      } else {
        if (data.preset_source === "builtin_openai_codex") {
          showCodexNotice("Codex zero-config preset is ready. Click Connect Codex to continue.", "info");
        } else {
          clearCodexNotice();
        }
      }
    } catch (error) {
      state.codex.config = null;
      showCodexNotice(`Failed to load Codex config: ${error.message || error}`, "error");
    } finally {
      renderCodexStatus();
    }
  }

  async function refreshCodexModels(options = {}) {
    const silent = Boolean(options.silent);
    if (!state.codex.config || !state.codex.config.configured) {
      if (!silent) {
        showCodexNotice("Codex OAuth preset is not configured on server.", "warning");
      }
      return;
    }
    try {
      const data = await api("/api/llm/codex/models");
      state.codex.models = Array.isArray(data.models) ? data.models : [];
      state.codex.connected = state.codex.models.length > 0 || state.codex.connected;
      renderCodexModels(state.codex.models);
      renderCodexStatus();
      if (!silent) {
        showCodexNotice(`Loaded ${state.codex.models.length} model(s).`, "success");
      }
    } catch (error) {
      state.codex.models = [];
      renderCodexModels([]);
      renderCodexStatus();
      if (!silent) {
        showCodexNotice(`Failed to load models: ${error.message || error}`, "error");
      }
    }
  }

  async function pollCodexLoginStatus(sessionId) {
    if (!sessionId) return;
    try {
      const status = await api(`/api/llm/codex/login/status?session_id=${encodeURIComponent(sessionId)}`);
      if (status.status === "completed") {
        state.codex.sessionId = null;
        state.codex.connected = true;
        if (el.useCodexCheckbox) {
          el.useCodexCheckbox.checked = true;
        }
        renderCodexStatus();
        showCodexNotice("Codex login successful. Fetching models...", "success");
        await refreshCodexModels();
        return;
      }
      if (status.status === "error") {
        state.codex.sessionId = null;
        state.codex.connected = false;
        renderCodexStatus();
        showCodexNotice(`Codex login failed: ${status.error || "unknown error"}`, "error");
        return;
      }
      state.codex.loginPollTimer = window.setTimeout(() => {
        pollCodexLoginStatus(sessionId).catch(console.error);
      }, 1500);
    } catch (error) {
      state.codex.loginPollTimer = window.setTimeout(() => {
        pollCodexLoginStatus(sessionId).catch(console.error);
      }, 2000);
    }
  }

  async function startCodexLogin() {
    clearCodexNotice();
    if (state.codex.loginPollTimer) {
      window.clearTimeout(state.codex.loginPollTimer);
      state.codex.loginPollTimer = null;
    }
    if (!state.codex.config || !state.codex.config.configured) {
      await loadCodexConfig();
      if (!state.codex.config || !state.codex.config.configured) {
        return;
      }
    }
    try {
      const data = await api("/api/llm/codex/login/start", { method: "POST", body: "{}" });
      state.codex.sessionId = String(data.session_id || "");
      state.codex.connected = false;
      renderCodexStatus();

      const url = String(data.authorize_url || "");
      if (!url) {
        throw new Error("server did not return authorize_url");
      }
      const popup = window.open(url, "_blank", "noopener,noreferrer");
      if (!popup) {
        showCodexNotice("Popup blocked. Please allow popups and retry.", "warning");
      } else {
        showCodexNotice("Opened official login page in a new tab/window. Complete login there.", "info");
      }
      pollCodexLoginStatus(state.codex.sessionId).catch(console.error);
    } catch (error) {
      state.codex.sessionId = null;
      state.codex.connected = false;
      renderCodexStatus();
      showCodexNotice(`Failed to start Codex login: ${error.message || error}`, "error");
    }
  }

  function renderJobs() {
    el.jobCount.textContent = String(state.jobs.length);
    if (!state.jobs.length) {
      el.jobList.innerHTML =
        '<div class="rounded-xl bg-slate-50 p-3 text-sm text-slate-500">No jobs yet.</div>';
      return;
    }

    el.jobList.innerHTML = state.jobs
      .map((job) => {
        const active = job.job_id === state.selectedJobId;
        return `
          <button type="button" data-job-id="${job.job_id}" class="w-full rounded-2xl border p-3 text-left transition ${
            active
              ? "border-sky-300 bg-sky-50/60"
              : "border-transparent bg-slate-50 hover:border-slate-200 hover:bg-white"
          }">
            <div class="flex items-start justify-between gap-2">
              <div class="min-w-0">
                <div class="truncate text-sm font-semibold text-slate-900">${esc(job.target)}</div>
                <div class="mt-1 text-xs text-slate-500">${esc(job.mode)} • ${esc(job.job_id)}</div>
              </div>
              <span class="rounded-full px-2 py-1 text-[11px] font-medium ${statusClass(job.status)}">${esc(
                job.status
              )}</span>
            </div>
            <div class="mt-2 grid grid-cols-2 gap-2 text-[11px] text-slate-500">
              <div>logs: ${job.log_line_count}</div>
              <div>artifacts: ${job.artifact_count}</div>
            </div>
          </button>
        `;
      })
      .join("");

    el.jobList.querySelectorAll("[data-job-id]").forEach((node) => {
      node.addEventListener("click", () => selectJob(node.dataset.jobId).catch(console.error));
    });
  }

  function renderJobDetails(job) {
    if (!job) {
      el.jobDetails.textContent =
        "Select a job to inspect status, command line, return code and output directory.";
      el.cancelJobBtn.classList.add("hidden");
      return;
    }

    if (job.status === "running" || job.status === "queued") {
      el.cancelJobBtn.classList.remove("hidden");
    } else {
      el.cancelJobBtn.classList.add("hidden");
    }

    el.jobDetails.innerHTML = `
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div><div class="text-xs text-slate-500">Job ID</div><div class="mt-1 font-medium text-slate-900">${esc(
          job.job_id
        )}</div></div>
        <div><div class="text-xs text-slate-500">Status</div><div class="mt-1"><span class="rounded-full px-2 py-1 text-xs font-medium ${statusClass(
          job.status
        )}">${esc(job.status)}</span></div></div>
        <div><div class="text-xs text-slate-500">PID</div><div class="mt-1 font-medium text-slate-900">${esc(
          job.pid ?? "-"
        )}</div></div>
        <div><div class="text-xs text-slate-500">Return Code</div><div class="mt-1 font-medium text-slate-900">${esc(
          job.return_code ?? "-"
        )}</div></div>
        <div class="sm:col-span-2"><div class="text-xs text-slate-500">Output Dir</div><div class="mt-1 break-all font-medium text-slate-900">${esc(
          job.output_dir
        )}</div></div>
        <div class="sm:col-span-2"><div class="text-xs text-slate-500">Command</div><pre class="mono mt-1 overflow-auto rounded-xl bg-white p-3 text-xs text-slate-700 soft-card">${esc(
          (job.command_preview || []).join(" ")
        )}</pre></div>
        ${
          job.error
            ? `<div class="sm:col-span-2 rounded-xl bg-rose-50 p-3 text-rose-700"><strong>Error:</strong> ${esc(
                job.error
              )}</div>`
            : ""
        }
      </div>
    `;
  }

  function renderArtifacts(jobId, items) {
    el.artifactMeta.textContent = String(items.length);
    if (!items.length) {
      el.artifactList.innerHTML =
        '<div class="rounded-xl bg-slate-50 p-3 text-slate-500">No artifacts yet.</div>';
      return;
    }

    el.artifactList.innerHTML = items
      .map((item) => {
        const href = `/api/jobs/${encodeURIComponent(jobId)}/files/${item.path
          .split("/")
          .map(encodeURIComponent)
          .join("/")}`;
        return `
          <div class="rounded-xl bg-slate-50 p-3">
            <div class="flex items-start justify-between gap-2">
              <div class="min-w-0">
                <div class="truncate text-sm font-medium text-slate-900">${esc(item.path)}</div>
                <div class="mt-1 text-xs text-slate-500">${item.size ?? "-"} bytes</div>
              </div>
              <a class="rounded-lg bg-white px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100" target="_blank" rel="noreferrer" href="${href}">Open</a>
            </div>
          </div>
        `;
      })
      .join("");
  }

  async function refreshJobs() {
    const data = await api("/api/jobs");
    state.jobs = Array.isArray(data.items) ? data.items : [];
    el.serverTs.textContent = new Date().toLocaleTimeString();
    renderJobs();

    if (state.selectedJobId && !state.jobs.some((x) => x.job_id === state.selectedJobId)) {
      closeLogStream();
      state.selectedJobId = null;
      state.selectedJob = null;
      state.logLines = [];
      state.logTotal = 0;
      state.logNextOffset = 0;
      renderJobDetails(null);
      el.logView.textContent = "Select a job to view logs...";
      el.logMeta.textContent = "No job selected";
      renderArtifacts("", []);
    }
  }

  async function refreshSelectedJob() {
    if (!state.selectedJobId) return;

    const [{ job }, logs, artifacts] = await Promise.all([
      api(`/api/jobs/${encodeURIComponent(state.selectedJobId)}`),
      api(`/api/jobs/${encodeURIComponent(state.selectedJobId)}/logs?offset=0&limit=5000`),
      api(`/api/jobs/${encodeURIComponent(state.selectedJobId)}/artifacts`),
    ]);

    state.selectedJob = job;
    state.logLines = Array.isArray(logs.items) ? logs.items : [];
    state.logTotal = Number(logs.total || state.logLines.length);
    state.logNextOffset = Number(logs.next_offset || state.logLines.length);
    syncJobInList(job);
    renderJobs();

    renderJobDetails(job);
    el.logMeta.textContent = `${job.status} • ${logs.total || 0} lines`;
    el.logView.textContent = (logs.items || []).map((item) => `[${item.ts}] ${item.line}`).join("\n") || "(no logs yet)";
    el.logView.scrollTop = el.logView.scrollHeight;
    renderLogLines(job);
    renderArtifacts(state.selectedJobId, artifacts.items || []);
  }

  async function refreshSelectedJobSummary() {
    if (!state.selectedJobId) return;

    const [{ job }, artifacts] = await Promise.all([
      api(`/api/jobs/${encodeURIComponent(state.selectedJobId)}`),
      api(`/api/jobs/${encodeURIComponent(state.selectedJobId)}/artifacts`),
    ]);

    state.selectedJob = job;
    syncJobInList(job);
    renderJobs();
    renderJobDetails(job);
    renderLogLines(job);
    renderArtifacts(state.selectedJobId, artifacts.items || []);
  }

  async function selectJob(jobId) {
    closeLogStream();
    state.selectedJobId = jobId;
    renderJobs();
    el.logView.textContent = "Loading logs...";
    await refreshSelectedJob();
    openLogStream(jobId, state.logNextOffset);
  }

  function updateModeFields() {
    const mode = String(el.modeSelect?.value || "agent");
    if (mode === "plugins") {
      el.pluginsField?.classList.remove("hidden");
    } else {
      el.pluginsField?.classList.add("hidden");
    }
    updatePlannerSelectionState();
  }

  function updateProviderFields() {
    const providerType = String(el.providerTypeSelect?.value || "");
    if (providerType === "codex_oauth") {
      el.oauthSection?.classList.remove("hidden");
    } else {
      el.oauthSection?.classList.add("hidden");
    }
  }

  function buildPayloadFromForm() {
    const fd = new FormData(el.jobForm);
    const payload = {
      target: String(fd.get("target") || "").trim(),
      mode: String(fd.get("mode") || "agent"),
      scope: String(fd.get("scope") || "").trim(),
      plugins: String(fd.get("plugins") || "").trim(),
      tools: fd.getAll("tools").map((item) => String(item).trim()).filter(Boolean),
      skills: fd.getAll("skills").map((item) => String(item).trim()).filter(Boolean),
      budget: Number(fd.get("budget") || 50),
      max_iterations: Number(fd.get("max_iterations") || 3),
      global_timeout: Number(fd.get("global_timeout") || 300),
      resume: String(fd.get("resume") || "").trim(),
      no_llm_hints: fd.get("no_llm_hints") !== null,

      llm_config: String(fd.get("llm_config") || "").trim(),
      llm_model: String(fd.get("llm_model") || "").trim(),
      llm_fallback: splitCsv(fd.get("llm_fallback")),
      llm_provider: String(fd.get("llm_provider") || "").trim(),
      llm_provider_type: String(fd.get("llm_provider_type") || "").trim(),
      llm_base_url: String(fd.get("llm_base_url") || "").trim(),
      llm_api_key_env: String(fd.get("llm_api_key_env") || "").trim(),
      llm_timeout: fd.get("llm_timeout"),
      llm_temperature: fd.get("llm_temperature"),
      llm_max_output_tokens: fd.get("llm_max_output_tokens"),

      llm_oauth_browser_login: fd.get("llm_oauth_browser_login") !== null,
      llm_oauth_profile_id: String(fd.get("llm_oauth_profile_id") || "").trim(),
      llm_oauth_profiles_file: String(fd.get("llm_oauth_profiles_file") || "").trim(),
      llm_oauth_token_env: String(fd.get("llm_oauth_token_env") || "").trim(),
      llm_oauth_token_file: String(fd.get("llm_oauth_token_file") || "").trim(),
      llm_oauth_command_json: String(fd.get("llm_oauth_command_json") || "").trim(),
      llm_oauth_authorize_url: String(fd.get("llm_oauth_authorize_url") || "").trim(),
      llm_oauth_token_url: String(fd.get("llm_oauth_token_url") || "").trim(),
      llm_oauth_client_id: String(fd.get("llm_oauth_client_id") || "").trim(),
      llm_oauth_scopes: splitCsv(fd.get("llm_oauth_scopes")),
      llm_oauth_redirect_host: String(fd.get("llm_oauth_redirect_host") || "").trim(),
      llm_oauth_redirect_port: fd.get("llm_oauth_redirect_port"),
      llm_oauth_redirect_path: String(fd.get("llm_oauth_redirect_path") || "").trim(),
      llm_oauth_cache_file: String(fd.get("llm_oauth_cache_file") || "").trim(),
      llm_oauth_no_auto_refresh: fd.get("llm_oauth_no_auto_refresh") !== null,
      llm_oauth_login_timeout: fd.get("llm_oauth_login_timeout"),
    };
    return payload;
  }

  async function onSubmit(event) {
    event.preventDefault();
    clearMessage();
    const payload = buildPayloadFromForm();

    if (el.useCodexCheckbox?.checked) {
      const cfg = state.codex.config;
      const selectedModel = String(el.codexModelSelect?.value || "").trim();
      if (!cfg || !cfg.configured) {
        showMessage("Codex server preset is not configured. Ask admin to set OAuth env vars.", "error");
        return;
      }
      if (!selectedModel) {
        showMessage("Select a Codex model first (connect and refresh models).", "error");
        return;
      }

      const agentProviderAlias = String(cfg.agent_provider_alias || cfg.provider_alias || "codex");
      const agentProviderType = String(cfg.agent_provider_type || cfg.provider_type || "codex_oauth");
      const agentBaseUrl = String(cfg.agent_base_url || cfg.base_url || "");
      const agentApiKeyEnv = String(cfg.agent_api_key_env || "").trim();

      payload.llm_model = selectedModel.includes("/")
        ? selectedModel
        : `${agentProviderAlias}/${selectedModel}`;
      payload.llm_provider = agentProviderAlias;
      payload.llm_provider_type = agentProviderType;
      payload.llm_base_url = agentBaseUrl;
      if (agentApiKeyEnv) {
        payload.llm_api_key_env = agentApiKeyEnv;
      }

      if (agentProviderType === "codex_oauth") {
        payload.llm_oauth_profile_id = cfg.profile_id || "web";
        payload.llm_oauth_profiles_file = cfg.profiles_file || "";
        payload.llm_oauth_browser_login = false;
      } else {
        payload.llm_oauth_profile_id = "";
        payload.llm_oauth_profiles_file = "";
        payload.llm_oauth_browser_login = false;
      }
      payload.llm_oauth_token_env = "";
      payload.llm_oauth_token_file = "";
      payload.llm_oauth_command_json = "";
      payload.llm_oauth_authorize_url = "";
      payload.llm_oauth_token_url = "";
      payload.llm_oauth_client_id = "";
      payload.llm_oauth_scopes = [];
    }

    try {
      const data = await api("/api/jobs", { method: "POST", body: JSON.stringify(payload) });
      showMessage(`Job created: ${data.job.job_id}`, "success");
      await refreshJobs();
      await selectJob(data.job.job_id);
    } catch (error) {
      showMessage(error.message || String(error), "error");
    }
  }

  async function cancelSelectedJob() {
    if (!state.selectedJobId) return;
    try {
      await api(`/api/jobs/${encodeURIComponent(state.selectedJobId)}/cancel`, {
        method: "POST",
        body: "{}",
      });
      showMessage("Cancel requested");
      await refreshJobs();
      await refreshSelectedJob();
    } catch (error) {
      showMessage(error.message || String(error), "error");
    }
  }

  async function poll() {
    try {
      await refreshJobs();
      if (state.selectedJobId) {
        await refreshSelectedJobSummary();
      }
    } catch (error) {
      handleApiError(error);
    } finally {
      state.timer = window.setTimeout(poll, POLL_MS);
    }
  }

  el.jobForm.addEventListener("submit", onSubmit);
  el.refreshJobsBtn.addEventListener("click", () => refreshJobs().catch(handleApiError));
  el.cancelJobBtn.addEventListener("click", () => cancelSelectedJob().catch(handleApiError));
  el.modeSelect?.addEventListener("change", updateModeFields);
  el.providerTypeSelect?.addEventListener("change", updateProviderFields);
  el.codexConnectBtn?.addEventListener("click", () => startCodexLogin().catch(handleApiError));
  el.codexRefreshModelsBtn?.addEventListener("click", () => refreshCodexModels().catch(handleApiError));

  updateModeFields();
  updateProviderFields();
  renderCodexStatus();
  loadApiToken();

  loadCodexConfig()
    .then(() => refreshCodexModels({ silent: true }))
    .catch(() => {});

  loadPlannerCatalog().catch(console.error);

  refreshJobs()
    .then(() => {
      if (state.jobs.length) {
        return selectJob(state.jobs[0].job_id);
      }
      return null;
    })
    .catch(handleApiError)
    .finally(() => {
      state.timer = window.setTimeout(poll, POLL_MS);
    });
})();
