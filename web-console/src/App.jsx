import { Suspense, lazy, useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Shell from "./components/Shell";
import SystemHealthIndicator from "./components/SystemHealthIndicator";
import Login from "./pages/Login";
import { useI18n } from "./i18n";
import { useConsoleRuntime } from "./hooks/useConsoleRuntime";
import { DEFAULT_VIEW, navItemsFor } from "./lib/views";

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
        <section className="panel">
          <div className="empty-state">Loading...</div>
        </section>
      }
    >
      {children}
    </Suspense>
  );
}

export default function App() {
  const { t, localizeMessage } = useI18n();
  const runtime = useConsoleRuntime();
  const navItems = navItemsFor(runtime.permissions, t);

  useEffect(() => {
    if (!navItems.some((item) => item.id === runtime.activeView)) {
      runtime.goToView(DEFAULT_VIEW, { replace: true });
    }
  }, [navItems, runtime.activeView]);

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

  const rightRail = (
    <>
      <SystemHealthIndicator report={runtime.systemHealth} compact />
      <div className="inline-actions">
        <button className="ghost-button" type="button" onClick={() => runtime.refreshAll().catch(() => { })}>
          {t("common.refresh")}
        </button>
        {runtime.permissions.can_operate ? (
          <button className="primary-button" type="button" onClick={() => runtime.goToView("jobs")}>
            {t("common.launchJob")}
          </button>
        ) : null}
      </div>
    </>
  );

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
    >
      <Routes>
        <Route path="/" element={<Navigate replace to={`/${DEFAULT_VIEW}`} />} />
        <Route path="/dashboard" element={<PageLoader><Dashboard summary={runtime.summary} /></PageLoader>} />
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
                onParseMission={runtime.parseMission}
                onSubmitMission={runtime.submitMission}
                submitting={runtime.submitting}
                canOperate={runtime.permissions.can_operate}
                token={runtime.accessToken}
                catalog={runtime.jobCatalog}
                llmSettings={runtime.llmSettings}
                systemHealth={runtime.systemHealth}
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
                onSelectReport={(report) =>
                  runtime
                    .selectReport(report)
                    .catch((error) => runtime.setMessage(localizeMessage(String(error.message || error))))
                }
                reportContent={runtime.reportContent}
                reportAnalysis={runtime.reportAnalysis}
                token={runtime.accessToken}
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
        <Route path="*" element={<Navigate replace to={`/${DEFAULT_VIEW}`} />} />
      </Routes>
    </Shell>
  );
}
