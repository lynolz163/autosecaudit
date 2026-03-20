import { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import GlobalSearchBar from "./components/GlobalSearchBar";
import Shell from "./components/Shell";
import SystemHealthIndicator from "./components/SystemHealthIndicator";
import Login from "./pages/Login";
import { useI18n } from "./i18n";
import { useConsoleRuntime } from "./hooks/useConsoleRuntime";
import { DEFAULT_VIEW, navItemsFor } from "./lib/views";

const NAV_COLLAPSED_KEY = "autosecaudit_console_nav_collapsed";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Jobs = lazy(() => import("./pages/Jobs"));
const Assets = lazy(() => import("./pages/Assets"));
const Schedules = lazy(() => import("./pages/Schedules"));
const Reports = lazy(() => import("./pages/Reports"));
const Settings = lazy(() => import("./pages/Settings"));
const Plugins = lazy(() => import("./pages/Plugins"));
const Users = lazy(() => import("./pages/Users"));
const RagConsole = lazy(() => import("./pages/RagConsole"));

function PageLoader({ children }) {
  return (
    <Suspense
      fallback={
        <section className="panel rounded-[30px] border border-white/80 bg-white/80 shadow-[0_28px_60px_-42px_rgba(15,23,42,0.24)] backdrop-blur-2xl">
          <div className="empty-state border-none bg-transparent px-0 py-8 text-sm text-slate-500">Loading...</div>
        </section>
      }
    >
      {children}
    </Suspense>
  );
}

function ApprovalAlertStrip({ jobs, onOpenJobs, onApprove }) {
  if (!Array.isArray(jobs) || !jobs.length) {
    return null;
  }
  const firstJob = jobs[0];
  return (
    <div className="mb-4 flex flex-col gap-3 rounded-[22px] border border-amber-200 bg-amber-50/92 px-4 py-3 text-amber-800 shadow-[0_18px_32px_-24px_rgba(15,23,42,0.18)] backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-start gap-3">
        <div className="mt-1 h-2.5 w-2.5 rounded-full bg-current" />
        <div>
          <strong className="block text-sm font-semibold">Approval waiting</strong>
          <p className="text-sm text-current/85">
            {jobs.length} job{jobs.length > 1 ? "s" : ""} need approval. Next: {firstJob?.target || firstJob?.job_id}.
          </p>
        </div>
      </div>
      <div className="inline-actions items-center">
        <button className="ghost-button" type="button" onClick={onOpenJobs}>Open queue</button>
        {firstJob?.job_id ? (
          <button className="primary-button" type="button" onClick={() => onApprove(firstJob.job_id)}>
            Approve latest
          </button>
        ) : null}
      </div>
    </div>
  );
}

export default function App() {
  const { t, localizeMessage } = useI18n();
  const runtime = useConsoleRuntime();
  const navItems = navItemsFor(runtime.permissions, t);
  const [navOpen, setNavOpen] = useState(false);
  const [navCollapsed, setNavCollapsed] = useState(() => window.localStorage.getItem(NAV_COLLAPSED_KEY) === "1");

  useEffect(() => {
    if (!navItems.some((item) => item.id === runtime.activeView)) {
      runtime.goToView(DEFAULT_VIEW, { replace: true });
    }
  }, [navItems, runtime.activeView]);

  useEffect(() => {
    setNavOpen(false);
  }, [runtime.activeView]);

  useEffect(() => {
    window.localStorage.setItem(NAV_COLLAPSED_KEY, navCollapsed ? "1" : "0");
  }, [navCollapsed]);

  const rightRail = useMemo(
    () => (
      <div className="flex w-full flex-col gap-3 lg:items-end">
        <GlobalSearchBar
          results={runtime.searchResults}
          searching={runtime.searching}
          onSearch={(query) => runtime.searchGlobal(query).catch(() => {})}
          onClear={runtime.clearGlobalSearch}
          onSelectResult={(item) => runtime.openGlobalSearchResult(item).catch(() => {})}
        />
        <div className="inline-actions items-center lg:justify-end">
          <SystemHealthIndicator report={runtime.systemHealth} compact />
          <button className="ghost-button" type="button" onClick={() => runtime.refreshAll().catch(() => {})}>
            {t("common.refresh")}
          </button>
        </div>
      </div>
    ),
    [
      runtime.searchResults,
      runtime.searching,
      runtime.systemHealth,
      runtime.searchGlobal,
      runtime.clearGlobalSearch,
      runtime.openGlobalSearchResult,
      runtime.refreshAll,
      t,
    ],
  );

  if (!runtime.currentUser) {
    return (
      <Login
        authStatus={runtime.authStatus}
        message={runtime.message}
        onLogin={runtime.handleLogin}
        onBootstrap={runtime.handleBootstrap}
      />
    );
  }

  return (
    <Shell
      activeView={runtime.activeView}
      navItems={navItems}
      onChangeView={runtime.goToView}
      onLogout={runtime.handleLogout}
      title={t("shell.title")}
      subtitle={t("shell.subtitle")}
      currentUser={runtime.currentUser}
      rightRail={rightRail}
      navCollapsed={navCollapsed}
      navOpen={navOpen}
      onToggleNav={() => setNavOpen((current) => !current)}
      onCloseNav={() => setNavOpen(false)}
      onToggleNavCollapsed={() => setNavCollapsed((current) => !current)}
      alertStrip={(
        <ApprovalAlertStrip
          jobs={runtime.approvalQueue}
          onOpenJobs={() => runtime.goToView("jobs")}
          onApprove={(jobId) => runtime.approveAndResumeJob(jobId).catch(() => {})}
        />
      )}
    >
      <Routes>
        <Route path="/" element={<Navigate replace to={`/${DEFAULT_VIEW}`} />} />
        <Route
          path="/dashboard"
          element={
            <PageLoader>
              <Dashboard
                summary={runtime.summary}
                jobs={runtime.jobs}
                systemHealth={runtime.systemHealth}
                onOpenJob={runtime.openJob}
                onOpenReport={runtime.openReportByJobId}
                onOpenFollowUpMission={runtime.openFollowUpMission}
              />
            </PageLoader>
          }
        />
        <Route
          path="/jobs"
          element={
            <PageLoader>
              <Jobs
                jobs={runtime.jobs}
                selectedJob={runtime.selectedJob}
                artifacts={runtime.artifacts}
                logLines={runtime.logLines}
                onSelectJob={runtime.setSelectedJobId}
                onSubmitJob={runtime.submitJob}
                onMissionChat={runtime.missionChat}
                submitting={runtime.submitting}
                canOperate={runtime.permissions.can_operate}
                token={runtime.accessToken}
                catalog={runtime.jobCatalog}
                llmSettings={runtime.llmSettings}
                systemHealth={runtime.systemHealth}
                jobRealtimeRevision={runtime.selectedJobRealtimeRevision}
                canAccessRag={runtime.permissions.can_admin}
                onOpenRag={() => runtime.goToView("rag-console")}
                onOpenFollowUpMission={runtime.openFollowUpMission}
                followUpMissionSeed={runtime.followUpMissionSeed}
                onConsumeFollowUpMissionSeed={runtime.consumeFollowUpMissionSeed}
                onApproveAndResumeJob={runtime.approveAndResumeJob}
              />
            </PageLoader>
          }
        />
        <Route
          path="/assets"
          element={
            <PageLoader>
              <Assets
                assets={runtime.assets}
                onCreate={runtime.permissions.can_operate ? runtime.createAsset : null}
                onScan={runtime.permissions.can_operate ? runtime.scanAsset : null}
                onDelete={runtime.permissions.can_operate ? runtime.deleteAsset : null}
              />
            </PageLoader>
          }
        />
        <Route
          path="/schedules"
          element={
            <PageLoader>
              <Schedules
                assets={runtime.assets}
                schedules={runtime.schedules}
                onCreate={runtime.permissions.can_operate ? runtime.createSchedule : null}
                onDelete={runtime.permissions.can_operate ? runtime.deleteSchedule : null}
              />
            </PageLoader>
          }
        />
        <Route
          path="/reports"
          element={
            <PageLoader>
              <Reports
                reports={runtime.reports}
                selectedReport={runtime.selectedReport}
                selectedBaselineJobId={runtime.selectedReportBaselineId}
                onSelectReport={(report) =>
                  runtime
                    .selectReport(report)
                    .catch((error) => runtime.setMessage(localizeMessage(String(error.message || error))))
                }
                onSelectBaseline={(baselineJobId) =>
                  runtime
                    .selectReportBaseline(baselineJobId)
                    .catch((error) => runtime.setMessage(localizeMessage(String(error.message || error))))
                }
                reportContent={runtime.reportContent}
                reportAnalysis={runtime.reportAnalysis}
                token={runtime.accessToken}
                canAccessRag={runtime.permissions.can_admin}
                onOpenRag={() => runtime.goToView("rag-console")}
                onOpenFollowUpMission={runtime.openFollowUpMission}
              />
            </PageLoader>
          }
        />
        <Route
          path="/rag-console"
          element={
            runtime.permissions.can_admin ? (
              <PageLoader>
                <RagConsole token={runtime.accessToken} />
              </PageLoader>
            ) : (
              <Navigate replace to={`/${DEFAULT_VIEW}`} />
            )
          }
        />
        <Route
          path="/plugins"
          element={
            runtime.permissions.can_admin ? (
              <PageLoader>
                <Plugins
                  pluginCatalog={runtime.pluginCatalog}
                  onSavePluginSettings={runtime.savePluginSettings}
                  onReloadPlugins={runtime.reloadPlugins}
                  onReloadPlugin={runtime.reloadPlugin}
                />
              </PageLoader>
            ) : (
              <Navigate replace to={`/${DEFAULT_VIEW}`} />
            )
          }
        />
        <Route
          path="/users"
          element={
            runtime.permissions.can_admin ? (
              <PageLoader>
                <Users
                  users={runtime.users}
                  currentUser={runtime.currentUser}
                  onCreate={runtime.createUser}
                  onUpdate={runtime.updateUser}
                  onDelete={runtime.deleteUser}
                />
              </PageLoader>
            ) : (
              <Navigate replace to={`/${DEFAULT_VIEW}`} />
            )
          }
        />
        <Route
          path="/settings"
          element={
            runtime.permissions.can_admin ? (
              <PageLoader>
                <Settings
                  authStatus={runtime.authStatus}
                  currentUser={runtime.currentUser}
                  codexConfig={runtime.codexConfig}
                  llmSettings={runtime.llmSettings}
                  message={runtime.message}
                  notificationConfig={runtime.notificationConfig}
                  onSaveNotificationConfig={runtime.saveNotificationConfig}
                  onSaveLlmSettings={runtime.saveLlmSettings}
                  onTestLlmConnection={runtime.testLlmConnection}
                  auditEvents={runtime.auditEvents}
                  onLogout={runtime.handleLogout}
                />
              </PageLoader>
            ) : (
              <Navigate replace to={`/${DEFAULT_VIEW}`} />
            )
          }
        />
      </Routes>
    </Shell>
  );
}
