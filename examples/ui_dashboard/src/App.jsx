import LayoutShell from "./components/LayoutShell";
import HeaderBar from "./components/HeaderBar";
import MetricCard from "./components/MetricCard";
import ActionPlanList from "./components/ActionPlanList";
import ActivityFeed from "./components/ActivityFeed";
import FindingsPanel from "./components/FindingsPanel";
import ScopeSurfacePanel from "./components/ScopeSurfacePanel";
import BlockedActionsPanel from "./components/BlockedActionsPanel";
import { auditReport, agentState, actionPlan, blockedActions } from "./mock/autosecauditMock";
import { selectDashboardViewModel } from "./lib/selectors";

// Replace mock inputs with real JSON fetching:
// - /agent/audit_report.json
// - /agent/agent_state.json
// - /agent/ActionPlan.json
// - /agent/blocked_actions.json
export default function App() {
  const vm = selectDashboardViewModel({
    auditReport,
    agentState,
    actionPlan,
    blockedActions,
  });

  return (
    <LayoutShell
      header={
        <HeaderBar
          appName={vm.meta.appName}
          target={vm.meta.target}
          status={vm.meta.status}
          statusDetail={vm.meta.statusDetail}
          updatedAt={vm.meta.updatedAt}
          resumed={vm.meta.resumed}
          resumedFrom={vm.meta.resumedFrom}
        />
      }
    >
      <section className="space-y-8">
        <div>
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
                Backend-Aligned Overview
              </p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-900 md:text-3xl">
                AutoSecAudit Agent Dashboard
              </h1>
            </div>
            <div className="hidden rounded-full bg-white/80 px-4 py-2 text-xs font-medium text-slate-600 shadow-[0_8px_24px_-16px_rgba(15,23,42,0.25)] backdrop-blur md:block">
              scope / plan / policy / execution / findings
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {vm.metrics.map((metric) => (
              <MetricCard key={metric.key} {...metric} />
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <ActivityFeed items={vm.activityItems} />
          <ActionPlanList actions={vm.plannedActions} />
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.1fr_0.9fr]">
          <FindingsPanel items={vm.findingsItems} />
          <BlockedActionsPanel items={vm.blockedActions} />
        </div>

        <ScopeSurfacePanel data={vm.scopePanel} toolCoverage={vm.toolCoverage} />
      </section>
    </LayoutShell>
  );
}
