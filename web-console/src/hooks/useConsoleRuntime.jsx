import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useI18n } from "../i18n";
import { apiFetch, buildAuthedUrl } from "../lib/api";
import { activeViewFromPath, viewPath } from "../lib/views";

const TOKEN_KEY = "autosecaudit_console_access_token";
const REFRESH_TOKEN_KEY = "autosecaudit_console_refresh_token";

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
  const refreshPromiseRef = useRef(null);

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
      requests.push(apiFetchWithAuth(`/api/jobs/${encodeURIComponent(jobId)}/logs?offset=0&limit=5000`));
    }
    const [jobPayload, artifactPayload, logPayload] = await Promise.all(requests);
    setSelectedJob(jobPayload.job);
    setArtifacts(Array.isArray(artifactPayload.items) ? artifactPayload.items : []);
    if (logPayload) {
      const items = Array.isArray(logPayload.items) ? logPayload.items : [];
      setLogLines(items);
      return { nextStreamOffset: Number(logPayload.next_offset || items.length) };
    }
    return { nextStreamOffset: 0 };
  }

  async function selectReport(report) {
    setSelectedReport(report);
    const requests = [apiFetchWithAuth(`/api/reports/${encodeURIComponent(report.job_id)}/analysis`)];
    if (report?.preview_path) {
      const path = report.preview_path.split("/").map(encodeURIComponent).join("/");
      requests.push(fetchTextWithAuth(`/api/jobs/${encodeURIComponent(report.job_id)}/files/${path}`));
    } else {
      requests.push(Promise.resolve(""));
    }
    const [analysisPayload, text] = await Promise.all(requests);
    setReportAnalysis(analysisPayload.analysis || null);
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

  async function refreshAll() {
    if (!currentUser) {
      return;
    }
    try {
      const tasks = [loadDashboard(), loadJobs(), loadReports(), loadAssets(), loadSchedules(), loadJobCatalog()];
      if (permissions.can_admin) {
        tasks.push(loadNotificationSettings(), loadAuditEvents(), loadCodexConfig(), loadLlmSettings(), loadPlugins(), loadUsers());
      } else {
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
    refreshAll().catch((error) => setMessage(localizeMessage(String(error.message || error))));
    const timer = window.setInterval(() => {
      refreshAll().catch((error) => setMessage(localizeMessage(String(error.message || error))));
    }, 10000);
    return () => window.clearInterval(timer);
  }, [accessToken, refreshToken, currentUser?.username, permissions.can_admin]);

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
    if (!currentUser || !selectedJobId) {
      return undefined;
    }
    let cancelled = false;
    let source = null;
    setLogLines([]);

    async function connectStream() {
      try {
        const snapshot = await loadJob(selectedJobId, true);
        if (cancelled) {
          return;
        }
        source = new window.EventSource(
          buildAuthedUrl(`/api/jobs/${encodeURIComponent(selectedJobId)}/stream?offset=${snapshot.nextStreamOffset || 0}`, accessToken)
        );

        source.addEventListener("status", (event) => {
          const payload = JSON.parse(event.data || "{}");
          if (payload.job) {
            setSelectedJob(payload.job);
            setJobs((current) => current.map((item) => (item.job_id === payload.job.job_id ? payload.job : item)));
          }
        });

        source.addEventListener("log", (event) => {
          const payload = JSON.parse(event.data || "{}");
          if (!payload.item) {
            return;
          }
          setLogLines((current) => {
            const next = [...current, payload.item];
            return next.length > 5000 ? next.slice(-5000) : next;
          });
        });

        source.onerror = () => {
          source?.close();
        };
      } catch (error) {
        setMessage(localizeMessage(String(error.message || error)));
      }
    }

    connectStream();
    return () => {
      cancelled = true;
      source?.close();
    };
  }, [selectedJobId, accessToken, currentUser?.username]);

  useEffect(() => {
    if (!currentUser || !selectedJobId) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      loadJob(selectedJobId, false).catch((error) => setMessage(localizeMessage(String(error.message || error))));
    }, 4000);
    return () => window.clearInterval(timer);
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
      setSelectedJobId(data.job.job_id);
      await refreshAll();
      setMessage(t("app.createdJob", { jobId: data.job.job_id }));
      goToView("jobs");
    } catch (error) {
      setMessage(localizeMessage(String(error.message || error)));
    } finally {
      setSubmitting(false);
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

  async function submitMission(message, overrides = {}, sessionId = "") {
    setSubmitting(true);
    try {
      const data = await apiFetchWithAuth("/api/mission/execute", {
        method: "POST",
        body: JSON.stringify({ message, overrides, session_id: sessionId || null }),
      });
      setSelectedJobId(data.job.job_id);
      await refreshAll();
      setMessage(t("app.createdJob", { jobId: data.job.job_id }));
      goToView("jobs");
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
      setSelectedJobId(data.job.job_id);
      goToView("jobs");
      await refreshAll();
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
    goToView,
    handleLogin,
    handleBootstrap,
    handleLogout,
    refreshAll,
    setSelectedJobId,
    selectReport,
    submitJob,
    parseMission,
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
  };
}
