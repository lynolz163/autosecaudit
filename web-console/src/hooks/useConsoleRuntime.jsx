import { startTransition, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useI18n } from "../i18n";
import { apiFetch, buildAuthedUrl, buildAuthedWebSocketUrl } from "../lib/api";
import { missionChatActionToWorkflowState, jobSessionStatusToWorkflowState, WORKFLOW_STATES } from "../lib/workflowState";
import { activeViewFromPath, viewPath } from "../lib/views";

const TOKEN_KEY = "autosecaudit_console_access_token";
const REFRESH_TOKEN_KEY = "autosecaudit_console_refresh_token";
const MAX_LOG_LINES = 2000;
const LOG_FLUSH_INTERVAL_MS = 120;
const TERMINAL_JOB_STATUSES = new Set(["completed", "failed", "error", "canceled", "waiting_approval", "partial_complete", "environment_blocked"]);

export const EMPTY_PERMISSIONS = {
  role: "",
  can_view: false,
  can_operate: false,
  can_admin: false,
};

export function useConsoleRuntime() {
  const { language, localizeMessage, t } = useI18n();
  const navigate = useNavigate();
  const location = useLocation();
  const activeView = activeViewFromPath(location.pathname);

  const [accessToken, setAccessToken] = useState(() => window.localStorage.getItem(TOKEN_KEY) || "");
  const [refreshToken, setRefreshToken] = useState(() => window.localStorage.getItem(REFRESH_TOKEN_KEY) || "");
  const [authStatus, setAuthStatus] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [permissions, setPermissions] = useState(EMPTY_PERMISSIONS);
  const [summary, setSummary] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState("");
  const [selectedJob, setSelectedJob] = useState(null);
  const [artifacts, setArtifacts] = useState([]);
  const [logLines, setLogLines] = useState([]);
  const [reports, setReports] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [reportContent, setReportContent] = useState("");
  const [reportAnalysis, setReportAnalysis] = useState(null);
  const [assets, setAssets] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [notificationConfig, setNotificationConfig] = useState({});
  const [auditEvents, setAuditEvents] = useState([]);
  const [codexConfig, setCodexConfig] = useState(null);
  const [llmSettings, setLlmSettings] = useState(null);
  const [pluginCatalog, setPluginCatalog] = useState({ items: [], settings: {}, metrics: {} });
  const [jobCatalog, setJobCatalog] = useState({ tools: [], skills: [] });
  const [systemHealth, setSystemHealth] = useState(null);
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [searchResults, setSearchResults] = useState({ query: "", total: 0, groups: {}, items: [] });
  const [searching, setSearching] = useState(false);
  const [selectedReportBaselineId, setSelectedReportBaselineId] = useState("");
  const [selectedJobRealtimeRevision, setSelectedJobRealtimeRevision] = useState(0);
  const [followUpMissionSeed, setFollowUpMissionSeed] = useState(null);
  const refreshPromiseRef = useRef(null);
  const searchRequestRef = useRef(0);
  const selectedJobIdRef = useRef("");
  const pendingLogLinesRef = useRef([]);
  const logFlushTimerRef = useRef(0);

  useEffect(() => {
    selectedJobIdRef.current = selectedJobId;
  }, [selectedJobId]);

  useEffect(() => {
    if (accessToken) {
      window.localStorage.setItem(TOKEN_KEY, accessToken);
    } else {
      window.localStorage.removeItem(TOKEN_KEY);
    }
  }, [accessToken]);

  useEffect(() => {
    if (refreshToken) {
      window.localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    } else {
      window.localStorage.removeItem(REFRESH_TOKEN_KEY);
    }
  }, [refreshToken]);

  async function loadAuthStatus() {
    const data = await apiFetch("/api/auth/status");
    setAuthStatus(data);
    return data;
  }

  async function loadCurrentUser(token = accessToken) {
    const data = await apiFetch("/api/auth/me", { token });
    setCurrentUser(data.user || null);
    setPermissions(data.permissions || EMPTY_PERMISSIONS);
    return data;
  }

  function applySessionTokens(payload) {
    setAccessToken(payload?.access_token || "");
    setRefreshToken(payload?.refresh_token || "");
  }

  function goToView(viewId, options = {}) {
    navigate(viewPath(viewId), options);
  }

  function resetConsoleState() {
    pendingLogLinesRef.current = [];
    if (logFlushTimerRef.current) {
      window.clearTimeout(logFlushTimerRef.current);
      logFlushTimerRef.current = 0;
    }
    setSummary(null);
    setJobs([]);
    setSelectedJobId("");
    setSelectedJob(null);
    setArtifacts([]);
    setLogLines([]);
    setReports([]);
    setSelectedReport(null);
    setReportContent("");
    setReportAnalysis(null);
    setAssets([]);
    setSchedules([]);
    setNotificationConfig({});
    setAuditEvents([]);
    setCodexConfig(null);
    setPluginCatalog({ items: [], settings: {}, metrics: {} });
    setJobCatalog({ tools: [], skills: [] });
    setSystemHealth(null);
    setUsers([]);
    setSearchResults({ query: "", total: 0, groups: {}, items: [] });
    setSearching(false);
    setSelectedReportBaselineId("");
    setSelectedJobRealtimeRevision(0);
    setFollowUpMissionSeed(null);
  }

  function clearPendingLogFlush() {
    if (logFlushTimerRef.current) {
      window.clearTimeout(logFlushTimerRef.current);
      logFlushTimerRef.current = 0;
    }
  }

  function replaceRealtimeLogs(items) {
    pendingLogLinesRef.current = [];
    clearPendingLogFlush();
    startTransition(() => {
      setLogLines(Array.isArray(items) ? items.slice(-MAX_LOG_LINES) : []);
    });
  }

  function flushPendingLogLines() {
    clearPendingLogFlush();
    if (!pendingLogLinesRef.current.length) {
      return;
    }
    const batch = pendingLogLinesRef.current;
    pendingLogLinesRef.current = [];
    startTransition(() => {
      setLogLines((current) => {
        const next = [...current, ...batch];
        return next.length > MAX_LOG_LINES ? next.slice(-MAX_LOG_LINES) : next;
      });
    });
  }

  function queueRealtimeLogLine(item) {
    if (!item) {
      return;
    }
    pendingLogLinesRef.current.push(item);
    if (logFlushTimerRef.current) {
      return;
    }
    logFlushTimerRef.current = window.setTimeout(() => {
      flushPendingLogLines();
    }, LOG_FLUSH_INTERVAL_MS);
  }

  function handleLogout() {
    setAccessToken("");
    setRefreshToken("");
    setCurrentUser(null);
    setPermissions(EMPTY_PERMISSIONS);
    resetConsoleState();
    goToView("dashboard", { replace: true });
  }

  async function refreshAccessToken() {
    if (!refreshToken) {
      handleLogout();
      throw new Error(t("errors.missing_refresh_token"));
    }
    if (!refreshPromiseRef.current) {
      refreshPromiseRef.current = apiFetch("/api/auth/refresh", {
        method: "POST",
        body: JSON.stringify({ refresh_token: refreshToken }),
      })
        .then((data) => {
          applySessionTokens(data);
          return data;
        })
        .catch((error) => {
          handleLogout();
          throw error;
        })
        .finally(() => {
          refreshPromiseRef.current = null;
        });
    }
    return refreshPromiseRef.current;
  }

  async function apiFetchWithAuth(path, options = {}) {
    try {
      return await apiFetch(path, { ...options, token: accessToken });
    } catch (error) {
      const detail = String(error.message || error);
      if (!refreshToken || !["token_expired", "invalid_token"].includes(detail)) {
        throw error;
      }
      const refreshed = await refreshAccessToken();
      return apiFetch(path, { ...options, token: refreshed.access_token || "" });
    }
  }

  async function fetchTextWithAuth(path) {
    async function readOnce(token) {
      const response = await fetch(buildAuthedUrl(path, token));
      if (response.ok) {
        return response.text();
      }
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const payload = await response.json();
        throw new Error(payload?.detail || payload?.error || `HTTP ${response.status}`);
      }
      throw new Error(`HTTP ${response.status}`);
    }

    try {
      return await readOnce(accessToken);
    } catch (error) {
      const detail = String(error.message || error);
      if (!refreshToken || !["token_expired", "invalid_token"].includes(detail)) {
        throw error;
      }
      const refreshed = await refreshAccessToken();
      return readOnce(refreshed.access_token || "");
    }
  }

  async function loadDashboard() {
    const data = await apiFetchWithAuth("/api/dashboard/summary");
    setSummary(data);
  }

  async function loadJobs() {
    const data = await apiFetchWithAuth("/api/jobs");
    const items = Array.isArray(data.items) ? data.items : [];
    setJobs(items);
    if (!selectedJobId && items.length) {
      setSelectedJobId(items[0].job_id);
    }
  }

  async function loadJob(jobId, includeLogs = true) {
    if (!jobId) {
      return { nextStreamOffset: 0 };
    }
    const requests = [
      apiFetchWithAuth(`/api/jobs/${encodeURIComponent(jobId)}`),
      apiFetchWithAuth(`/api/jobs/${encodeURIComponent(jobId)}/artifacts`),
    ];
    if (includeLogs) {
      requests.push(apiFetchWithAuth(`/api/jobs/${encodeURIComponent(jobId)}/logs?offset=0&limit=${MAX_LOG_LINES}`));
    }
    const [jobPayload, artifactPayload, logPayload] = await Promise.all(requests);
    setSelectedJob(jobPayload.job);
    setArtifacts(Array.isArray(artifactPayload.items) ? artifactPayload.items : []);
    if (logPayload) {
      const items = Array.isArray(logPayload.items) ? logPayload.items : [];
      replaceRealtimeLogs(items);
      return { nextStreamOffset: Number(logPayload.next_offset || items.length) };
    }
    return { nextStreamOffset: 0 };
  }

  async function selectReport(report, options = {}) {
    const baselineJobId = Object.prototype.hasOwnProperty.call(options, "baselineJobId")
      ? String(options.baselineJobId || "").trim()
      : "";
    setSelectedReport(report);
    const query = baselineJobId ? `?baseline_job_id=${encodeURIComponent(baselineJobId)}` : "";
    const requests = [apiFetchWithAuth(`/api/reports/${encodeURIComponent(report.job_id)}/analysis${query}`)];
    if (report?.preview_path) {
      const path = report.preview_path.split("/").map(encodeURIComponent).join("/");
      requests.push(fetchTextWithAuth(`/api/jobs/${encodeURIComponent(report.job_id)}/files/${path}`));
    } else {
      requests.push(Promise.resolve(""));
    }
    const [analysisPayload, text] = await Promise.all(requests);
    setReportAnalysis(analysisPayload.analysis || null);
    setSelectedReportBaselineId(baselineJobId || "");
    setReportContent(text);
  }

  async function loadReports() {
    const data = await apiFetchWithAuth("/api/reports");
    const items = Array.isArray(data.items) ? data.items : [];
    setReports(items);
    if (!selectedReport && items.length) {
      await selectReport(items[0]);
    } else if (selectedReport) {
      const refreshed = items.find((item) => item.job_id === selectedReport.job_id);
      if (refreshed) {
        setSelectedReport(refreshed);
      }
    }
  }

  async function selectReportBaseline(baselineJobId = "") {
    if (!selectedReport?.job_id) {
      return;
    }
    return selectReport(selectedReport, { baselineJobId });
  }

  async function loadAssets() {
    const data = await apiFetchWithAuth("/api/assets");
    setAssets(Array.isArray(data.items) ? data.items : []);
  }

  async function loadSchedules() {
    const data = await apiFetchWithAuth("/api/schedules");
    setSchedules(Array.isArray(data.items) ? data.items : []);
  }

  async function loadNotificationSettings() {
    const data = await apiFetchWithAuth("/api/settings/notifications");
    setNotificationConfig(data.item || {});
  }

  async function loadAuditEvents() {
    const data = await apiFetchWithAuth("/api/audit/events?limit=50");
    setAuditEvents(Array.isArray(data.items) ? data.items : []);
  }

  async function loadCodexConfig() {
    const data = await apiFetchWithAuth("/api/llm/codex/config");
    setCodexConfig(data);
  }

  async function loadLlmSettings() {
    try {
      const data = await apiFetchWithAuth("/api/settings/llm");
      setLlmSettings(data);
    } catch { /* noop if endpoint missing */ }
  }

  async function saveLlmSettings(payload) {
    try {
      const data = await apiFetchWithAuth("/api/settings/llm", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      setLlmSettings(data);
      await loadAuditEvents();
      setMessage(t("app.llmSettingsSaved"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function testLlmConnection(payload) {
    try {
      const data = await apiFetchWithAuth("/api/settings/llm/test", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      return data;
    } catch (error) {
      return { ok: false, model: payload.model || "", error: String(error.message || error) };
    }
  }

  async function loadUsers() {
    const data = await apiFetchWithAuth("/api/users");
    setUsers(Array.isArray(data.items) ? data.items : []);
  }

  async function loadPlugins() {
    const data = await apiFetchWithAuth("/api/plugins");
    setPluginCatalog({
      items: Array.isArray(data.items) ? data.items : [],
      settings: data.settings || {},
      metrics: data.metrics || {},
    });
  }

  async function loadJobCatalog() {
    try {
      const data = await apiFetchWithAuth("/api/jobs/catalog");
      setJobCatalog({
        tools: Array.isArray(data.tools) ? data.tools.map(t => typeof t === "string" ? t : t.name).filter(Boolean) : [],
        skills: Array.isArray(data.skills) ? data.skills.map(s => typeof s === "string" ? s : s.name).filter(Boolean) : [],
      });
    } catch {
      // It's optional, fail gracefully
      setJobCatalog({ tools: [], skills: [] });
    }
  }

  async function loadSystemHealth() {
    try {
      const data = await apiFetchWithAuth("/api/system/doctor");
      setSystemHealth(data);
    } catch {
      setSystemHealth(null);
    }
  }

  async function searchGlobal(query, limit = 10) {
    const normalized = String(query || "").trim();
    const requestId = searchRequestRef.current + 1;
    searchRequestRef.current = requestId;
    if (normalized.length < 2) {
      setSearchResults({ query: normalized, total: 0, groups: {}, items: [] });
      setSearching(false);
      return { query: normalized, total: 0, groups: {}, items: [] };
    }
    setSearching(true);
    try {
      const data = await apiFetchWithAuth(`/api/search/global?q=${encodeURIComponent(normalized)}&limit=${encodeURIComponent(limit)}`);
      if (searchRequestRef.current === requestId) {
        setSearchResults(data || { query: normalized, total: 0, groups: {}, items: [] });
      }
      return data;
    } catch (error) {
      if (searchRequestRef.current === requestId) {
        setSearchResults({ query: normalized, total: 0, groups: {}, items: [] });
      }
      throw error;
    } finally {
      if (searchRequestRef.current === requestId) {
        setSearching(false);
      }
    }
  }

  function clearGlobalSearch() {
    searchRequestRef.current += 1;
    setSearching(false);
    setSearchResults({ query: "", total: 0, groups: {}, items: [] });
  }

  function replaceJobsFromRealtime(items) {
    const nextItems = Array.isArray(items) ? items : [];
    setJobs(nextItems);
    const currentSelectedJobId = selectedJobIdRef.current;
    if (!currentSelectedJobId && nextItems.length) {
      setSelectedJobId(nextItems[0].job_id);
      return;
    }
    if (!currentSelectedJobId) {
      return;
    }
    const matched = nextItems.find((item) => item.job_id === currentSelectedJobId) || null;
    if (matched) {
      setSelectedJob((current) => ({ ...(current || {}), ...matched }));
      return;
    }
    if (!nextItems.length) {
      setSelectedJob(null);
      setSelectedJobId("");
      return;
    }
    setSelectedJob(nextItems[0]);
    setSelectedJobId(nextItems[0].job_id);
  }

  function upsertRealtimeJob(job) {
    if (!job?.job_id) {
      return;
    }
    setJobs((current) => {
      const next = Array.isArray(current) ? [...current] : [];
      const index = next.findIndex((item) => item.job_id === job.job_id);
      if (index >= 0) {
        next[index] = { ...next[index], ...job };
      } else {
        next.unshift(job);
      }
      next.sort((left, right) =>
        String(right?.last_updated_at || right?.created_at || "").localeCompare(
          String(left?.last_updated_at || left?.created_at || ""),
        ),
      );
      return next;
    });
    if (selectedJobIdRef.current && job.job_id === selectedJobIdRef.current) {
      setSelectedJob((current) => ({ ...(current || {}), ...job }));
    }
  }

  async function openGlobalSearchResult(item) {
    const route = String(item?.route || "").trim().toLowerCase();
    clearGlobalSearch();
    if (route === "reports" && item?.job_id) {
      await openReportByJobId(String(item.job_id));
      return;
    }
    if (route === "jobs" && item?.job_id) {
      openJob(String(item.job_id));
      return;
    }
    if (route === "assets") {
      goToView("assets");
      return;
    }
    if (route === "schedules") {
      goToView("schedules");
      return;
    }
    if (item?.job_id) {
      openJob(String(item.job_id));
    }
  }

  function activateJob(job, { navigateToJobs = true } = {}) {
    if (!job?.job_id) {
      return;
    }
    setSelectedJobId(job.job_id);
    setSelectedJob(job);
    setArtifacts([]);
    replaceRealtimeLogs([]);
    upsertRealtimeJob(job);
    if (navigateToJobs && activeView !== "jobs") {
      goToView("jobs");
    }
  }

  async function refreshViewState(viewId = activeView, options = {}) {
    if (!currentUser) {
      return;
    }
    const forceHeavy = Boolean(options.forceHeavy);
    try {
      const tasks = [loadJobs()];
      if (viewId === "dashboard") {
        tasks.push(loadDashboard());
      }
      if (viewId === "jobs") {
        if (forceHeavy || !llmSettings) {
          tasks.push(loadLlmSettings());
        }
        if (forceHeavy || (!jobCatalog.tools.length && !jobCatalog.skills.length)) {
          tasks.push(loadJobCatalog());
        }
      }
      if (viewId === "assets") {
        tasks.push(loadAssets());
      }
      if (viewId === "schedules") {
        tasks.push(loadAssets(), loadSchedules());
      }
      if (viewId === "reports") {
        tasks.push(loadReports());
      }
      if (permissions.can_admin && (viewId === "settings" || forceHeavy)) {
        tasks.push(loadNotificationSettings(), loadAuditEvents(), loadCodexConfig(), loadLlmSettings());
      }
      if (permissions.can_admin && (viewId === "plugins" || forceHeavy)) {
        tasks.push(loadPlugins());
      }
      if (permissions.can_admin && (viewId === "users" || forceHeavy)) {
        tasks.push(loadUsers());
      }
      if (!permissions.can_admin && forceHeavy) {
        setNotificationConfig({});
        setAuditEvents([]);
        setCodexConfig(null);
        setPluginCatalog({ items: [], settings: {}, metrics: {} });
        setUsers([]);
      }
      await Promise.all(tasks);
      setMessage("");
    } catch (error) {
      const detail = String(error.message || error);
      setMessage(localizeMessage(detail));
      if (["token_expired", "invalid_token", "user_not_found", "user_disabled"].includes(detail)) {
        handleLogout();
      }
    }
  }

  async function refreshAll(options = {}) {
    return refreshViewState(activeView, { forceHeavy: true, ...options });
  }

  useEffect(() => {
    let cancelled = false;

    async function initializeAuth() {
      try {
        await loadAuthStatus();
        if (!accessToken && !refreshToken) {
          if (!cancelled) {
            setCurrentUser(null);
            setPermissions(EMPTY_PERMISSIONS);
          }
          return;
        }
        let sessionToken = accessToken;
        if (!sessionToken && refreshToken) {
          const refreshed = await refreshAccessToken();
          sessionToken = refreshed.access_token || "";
        }
        try {
          await loadCurrentUser(sessionToken);
        } catch (error) {
          const detail = String(error.message || error);
          if (refreshToken && ["token_expired", "invalid_token"].includes(detail)) {
            const refreshed = await refreshAccessToken();
            sessionToken = refreshed.access_token || "";
            await loadCurrentUser(sessionToken);
          } else {
            throw error;
          }
        }
        if (!cancelled) {
          setMessage("");
        }
      } catch (error) {
        if (cancelled) {
          return;
        }
        setCurrentUser(null);
        setPermissions(EMPTY_PERMISSIONS);
        setAccessToken("");
        setMessage(localizeMessage(String(error.message || error)));
      }
    }

    initializeAuth();
    return () => {
      cancelled = true;
    };
  }, [accessToken]);

  useEffect(() => {
    if (!currentUser) {
      return undefined;
    }
    refreshViewState(activeView, { forceHeavy: true }).catch((error) => setMessage(localizeMessage(String(error.message || error))));
    const timer = window.setInterval(() => {
      refreshViewState(activeView, { forceHeavy: false }).catch((error) => setMessage(localizeMessage(String(error.message || error))));
    }, 15000);
    return () => window.clearInterval(timer);
  }, [
    accessToken,
    refreshToken,
    currentUser?.username,
    permissions.can_admin,
    activeView,
    Boolean(llmSettings),
    jobCatalog.tools.length,
    jobCatalog.skills.length,
  ]);

  useEffect(() => {
    if (!currentUser) {
      return undefined;
    }
    loadSystemHealth().catch(() => { });
    const timer = window.setInterval(() => {
      loadSystemHealth().catch(() => { });
    }, 60000);
    return () => window.clearInterval(timer);
  }, [accessToken, refreshToken, currentUser?.username]);

  useEffect(() => {
    if (!currentUser || !accessToken || typeof window.WebSocket !== "function") {
      return undefined;
    }

    let cancelled = false;
    let socket = null;
    let reconnectTimer = 0;

    const connect = () => {
      if (cancelled) {
        return;
      }
      socket = new window.WebSocket(buildAuthedWebSocketUrl("/api/jobs/ws", accessToken));

      socket.addEventListener("message", (event) => {
        let envelope = null;
        try {
          envelope = JSON.parse(event.data || "{}");
        } catch {
          return;
        }
        const eventName = String(envelope?.event || "").trim();
        const payload = envelope?.payload || {};
        if (eventName === "snapshot" || eventName === "jobs") {
          replaceJobsFromRealtime(payload.items);
        }
      });

      socket.addEventListener("error", () => {
        socket?.close();
      });

      socket.addEventListener("close", () => {
        if (cancelled) {
          return;
        }
        reconnectTimer = window.setTimeout(connect, 2000);
      });
    };

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      socket?.close();
    };
  }, [accessToken, currentUser?.username]);

  useEffect(() => {
    if (!currentUser || !selectedJobId || typeof window.WebSocket !== "function") {
      return undefined;
    }
    let cancelled = false;
    let socket = null;
    let reconnectTimer = 0;
    let streamTerminal = false;
    replaceRealtimeLogs([]);
    setArtifacts([]);

    const connectStream = () => {
      if (cancelled) {
        return;
      }
      socket = new window.WebSocket(
        buildAuthedWebSocketUrl(
          `/api/jobs/${encodeURIComponent(selectedJobId)}/ws?offset=0&limit=${MAX_LOG_LINES}`,
          accessToken,
        ),
      );

      socket.addEventListener("message", (event) => {
        let envelope = null;
        try {
          envelope = JSON.parse(event.data || "{}");
        } catch {
          return;
        }
        const eventName = String(envelope?.event || "").trim();
        const payload = envelope?.payload || {};

        if (eventName === "snapshot") {
          if (payload.job) {
            setSelectedJob(payload.job);
            upsertRealtimeJob(payload.job);
            streamTerminal = TERMINAL_JOB_STATUSES.has(String(payload.job?.status || ""));
          }
          setArtifacts(Array.isArray(payload.artifacts) ? payload.artifacts : []);
          replaceRealtimeLogs(payload.items);
          setSelectedJobRealtimeRevision((current) => current + 1);
          return;
        }

        if (eventName === "status" || eventName === "terminal") {
          if (payload.job) {
            setSelectedJob(payload.job);
            upsertRealtimeJob(payload.job);
            streamTerminal = TERMINAL_JOB_STATUSES.has(String(payload.job?.status || ""));
          }
          if (Array.isArray(payload.artifacts)) {
            setArtifacts(payload.artifacts);
          }
          setSelectedJobRealtimeRevision((current) => current + 1);
          return;
        }

        if (eventName === "analysis") {
          setSelectedJobRealtimeRevision((current) => current + 1);
          return;
        }

        if (eventName !== "log" || !payload.item) {
          return;
        }
        queueRealtimeLogLine(payload.item);
      });

      socket.addEventListener("error", () => {
        socket?.close();
      });

      socket.addEventListener("close", () => {
        if (cancelled || streamTerminal) {
          return;
        }
        reconnectTimer = window.setTimeout(connectStream, 2000);
      });
    };

    connectStream();
    return () => {
      cancelled = true;
      pendingLogLinesRef.current = [];
      clearPendingLogFlush();
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      socket?.close();
    };
  }, [selectedJobId, accessToken, currentUser?.username]);

  useEffect(() => {
    if (!currentUser || !selectedJobId) {
      return undefined;
    }
    if (TERMINAL_JOB_STATUSES.has(String(selectedJob?.status || ""))) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      loadJob(selectedJobId, false).catch((error) => setMessage(localizeMessage(String(error.message || error))));
    }, 12000);
    return () => window.clearInterval(timer);
  }, [selectedJobId, selectedJob?.status, accessToken, currentUser?.username]);

  useEffect(() => {
    if (!selectedJobId) {
      return;
    }
    if (selectedJob && selectedJob.job_id === selectedJobId) {
      return;
    }
    loadJob(selectedJobId, false).catch((error) => setMessage(localizeMessage(String(error.message || error))));
  }, [selectedJobId, accessToken, currentUser?.username]);

  async function handleLogin(form) {
    try {
      const data = await apiFetch("/api/auth/login", { method: "POST", body: JSON.stringify(form) });
      applySessionTokens(data);
      setMessage("");
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function handleBootstrap(form) {
    try {
      const data = await apiFetch("/api/auth/bootstrap", {
        method: "POST",
        token: form.bootstrap_token,
        body: JSON.stringify({
          username: form.username,
          display_name: form.display_name,
          password: form.password,
        }),
      });
      applySessionTokens(data);
      setMessage("");
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function submitJob(payload) {
    setSubmitting(true);
    try {
      const data = await apiFetchWithAuth("/api/jobs", { method: "POST", body: JSON.stringify(payload) });
      activateJob(data.job);
      setMessage(t("app.createdJob", { jobId: data.job.job_id }));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    } finally {
      setSubmitting(false);
    }
  }

  async function approveAndResumeJob(jobId) {
    try {
      const data = await apiFetchWithAuth(`/api/jobs/${encodeURIComponent(jobId)}/approve-resume`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      activateJob(data.job);
      setMessage(`Approval granted. Resumed as ${data.job.job_id}.`);
      return data.job;
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
      throw error;
    }
  }

  async function parseMission(message, overrides = {}, sessionId = "") {
    try {
      const data = await apiFetchWithAuth("/api/mission/parse", {
        method: "POST",
        body: JSON.stringify({ message, overrides, session_id: sessionId || null }),
      });
      return data || null;
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
      throw error;
    }
  }

  async function missionChat(message, overrides = {}, sessionId = "") {
    setSubmitting(true);
    try {
      const data = await apiFetchWithAuth("/api/mission/chat", {
        method: "POST",
        body: JSON.stringify({ message, overrides, session_id: sessionId || null }),
      });
      const workflowState = String(data?.workflow_state || missionChatActionToWorkflowState(data?.action) || "");
      if (workflowState === WORKFLOW_STATES.LAUNCH_EXECUTED && data?.job?.job_id) {
        activateJob(data.job);
        setMessage(t("app.createdJob", { jobId: data.job.job_id }));
      }
      return data || null;
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
      throw error;
    } finally {
      setSubmitting(false);
    }
  }

  async function submitMission(message, overrides = {}, sessionId = "") {
    setSubmitting(true);
    try {
      const data = await apiFetchWithAuth("/api/mission/execute", {
        method: "POST",
        body: JSON.stringify({ message, overrides, session_id: sessionId || null }),
      });
      activateJob(data.job);
      setMessage(t("app.createdJob", { jobId: data.job.job_id }));
      return data;
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
      throw error;
    } finally {
      setSubmitting(false);
    }
  }

  async function createAsset(payload) {
    try {
      await apiFetchWithAuth("/api/assets", { method: "POST", body: JSON.stringify(payload) });
      await loadAssets();
      await loadDashboard();
      setMessage(t("app.assetSaved"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function deleteAsset(assetId) {
    try {
      await apiFetchWithAuth(`/api/assets/${assetId}`, { method: "DELETE" });
      await loadAssets();
      await loadSchedules();
      await loadDashboard();
      if (permissions.can_admin) {
        await loadAuditEvents();
      }
      setMessage(language === "zh-CN" ? `资产已删除：#${assetId}` : `Asset deleted: #${assetId}`);
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function scanAsset(assetId) {
    try {
      const data = await apiFetchWithAuth(`/api/assets/${assetId}/scan`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      activateJob(data.job);
      setMessage(t("app.assetScanCreated", { jobId: data.job.job_id }));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function createSchedule(payload) {
    try {
      await apiFetchWithAuth("/api/schedules", { method: "POST", body: JSON.stringify(payload) });
      await loadSchedules();
      await loadDashboard();
      setMessage(t("app.scheduleSaved"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function deleteSchedule(scheduleId) {
    try {
      await apiFetchWithAuth(`/api/schedules/${scheduleId}`, { method: "DELETE" });
      await loadSchedules();
      await loadDashboard();
      if (permissions.can_admin) {
        await loadAuditEvents();
      }
      setMessage(language === "zh-CN" ? `计划任务已删除：#${scheduleId}` : `Schedule deleted: #${scheduleId}`);
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function saveNotificationConfig(rawConfig) {
    try {
      const payload =
        typeof rawConfig === "string" ? JSON.parse(rawConfig) : rawConfig && typeof rawConfig === "object" ? rawConfig : {};
      await apiFetchWithAuth("/api/settings/notifications", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      await loadNotificationSettings();
      await loadAuditEvents();
      setMessage(t("app.notificationSaved"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function createUser(payload) {
    try {
      await apiFetchWithAuth("/api/users", { method: "POST", body: JSON.stringify(payload) });
      await loadUsers();
      await loadDashboard();
      setMessage(t("app.userCreated"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function updateUser(userId, payload) {
    try {
      await apiFetchWithAuth(`/api/users/${userId}`, { method: "PUT", body: JSON.stringify(payload) });
      await loadUsers();
      await loadAuditEvents();
      setMessage(t("app.userUpdated"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function deleteUser(userId) {
    try {
      await apiFetchWithAuth(`/api/users/${userId}`, { method: "DELETE" });
      await loadUsers();
      await loadAuditEvents();
      await loadDashboard();
      setMessage(t("app.userDeleted"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function savePluginSettings(pluginDirs) {
    try {
      await apiFetchWithAuth("/api/plugins/settings", {
        method: "PUT",
        body: JSON.stringify({ plugin_dirs: pluginDirs }),
      });
      await loadPlugins();
      await loadAuditEvents();
      setMessage(t("app.pluginSettingsSaved"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function reloadPlugins() {
    try {
      await apiFetchWithAuth("/api/plugins/reload", { method: "POST" });
      await loadPlugins();
      await loadAuditEvents();
      setMessage(t("app.pluginsReloaded"));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  async function reloadPlugin(pluginId) {
    try {
      await apiFetchWithAuth(`/api/plugins/${encodeURIComponent(pluginId)}/reload`, {
        method: "POST",
      });
      await loadPlugins();
      await loadAuditEvents();
      setMessage(t("app.pluginReloaded", { pluginId }));
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  function openJob(jobId) {
    if (jobId) {
      setSelectedJobId(jobId);
    }
    goToView("jobs");
  }

  async function openReportByJobId(jobId) {
    try {
      let nextReports = reports;
      if (!nextReports.length) {
        const data = await apiFetchWithAuth("/api/reports");
        nextReports = Array.isArray(data.items) ? data.items : [];
        setReports(nextReports);
      }

      const matched = nextReports.find((item) => item.job_id === jobId);
      goToView("reports");

      if (!matched) {
        setMessage(t("reports.noReports"));
        return;
      }

      await selectReport(matched);
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    }
  }

  function openFollowUpMission(seed) {
    setFollowUpMissionSeed(seed && typeof seed === "object" ? { ...seed } : null);
    goToView("jobs");
  }

  function consumeFollowUpMissionSeed() {
    setFollowUpMissionSeed(null);
  }

  const approvalQueue = jobs.filter(
    (item) => jobSessionStatusToWorkflowState(item?.session_status || item?.status) === WORKFLOW_STATES.RUNTIME_APPROVAL,
  );

  return {
    activeView,
    accessToken,
    authStatus,
    currentUser,
    permissions,
    summary,
    jobs,
    selectedJob,
    artifacts,
    logLines,
    reports,
    selectedReport,
    reportContent,
    reportAnalysis,
    assets,
    schedules,
    notificationConfig,
    auditEvents,
    codexConfig,
    llmSettings,
    pluginCatalog,
    jobCatalog,
    systemHealth,
    users,
    message,
    setMessage,
    submitting,
    searchResults,
    searching,
    selectedReportBaselineId,
    selectedJobRealtimeRevision,
    followUpMissionSeed,
    approvalQueue,
    goToView,
    handleLogin,
    handleBootstrap,
    handleLogout,
    refreshAll,
    setSelectedJobId,
    selectReport,
    selectReportBaseline,
    submitJob,
    parseMission,
    missionChat,
    submitMission,
    createAsset,
    deleteAsset,
    scanAsset,
    createSchedule,
    deleteSchedule,
    saveNotificationConfig,
    createUser,
    updateUser,
    deleteUser,
    savePluginSettings,
    reloadPlugins,
    reloadPlugin,
    saveLlmSettings,
    testLlmConnection,
    searchGlobal,
    clearGlobalSearch,
    openGlobalSearchResult,
    openFollowUpMission,
    consumeFollowUpMissionSeed,
    approveAndResumeJob,
    openJob,
    openReportByJobId,
  };
}
