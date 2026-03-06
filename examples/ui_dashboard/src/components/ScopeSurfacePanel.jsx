export default function ScopeSurfacePanel({ data, toolCoverage }) {
  const scope = Array.isArray(data.scope) ? data.scope : [];
  const breadcrumbs = Array.isArray(data.breadcrumbs) ? data.breadcrumbs : [];
  const surface = data.surface && typeof data.surface === "object" ? data.surface : {};
  const discoveredUrls = Array.isArray(surface.discovered_urls) ? surface.discovered_urls : [];
  const apiEndpoints = Array.isArray(surface.api_endpoints) ? surface.api_endpoints : [];
  const dirsearchResults = Array.isArray(surface.dirsearch_results) ? surface.dirsearch_results : [];

  return (
    <section className="rounded-2xl bg-white p-5 shadow-[0_16px_36px_-22px_rgba(15,23,42,0.16)]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
            Scope and Surface
          </p>
          <h2 className="mt-1 text-lg font-semibold tracking-tight text-slate-900">
            Scope, Breadcrumbs, and Surface Map
          </h2>
        </div>
        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
          {scope.length} scope / {discoveredUrls.length} urls
        </span>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Scope
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {scope.map((item) => (
                <span key={item} className="rounded-full bg-white px-3 py-1 text-xs font-medium text-slate-700 shadow-sm">
                  {item}
                </span>
              ))}
            </div>
          </div>

          <div className="rounded-2xl bg-slate-50 p-4">
            <div className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">
              Breadcrumbs
            </div>
            <div className="max-h-48 space-y-1 overflow-auto text-xs">
              {breadcrumbs.map((item, idx) => (
                <div key={`${idx}-${item.type}-${item.data}`} className="flex gap-2 rounded-xl bg-white px-2 py-1.5 shadow-sm">
                  <span className="w-16 shrink-0 text-slate-500">{item.type}</span>
                  <span className="break-all text-slate-700">{item.data}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Surface Summary
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              <div className="rounded-xl bg-white p-2 shadow-sm">
                <div className="text-lg font-semibold text-slate-900">{discoveredUrls.length}</div>
                <div className="text-[11px] text-slate-500">URLs</div>
              </div>
              <div className="rounded-xl bg-white p-2 shadow-sm">
                <div className="text-lg font-semibold text-slate-900">{apiEndpoints.length}</div>
                <div className="text-[11px] text-slate-500">API</div>
              </div>
              <div className="rounded-xl bg-white p-2 shadow-sm">
                <div className="text-lg font-semibold text-slate-900">{dirsearchResults.length}</div>
                <div className="text-[11px] text-slate-500">Dirsearch</div>
              </div>
            </div>
          </div>

          <div className="rounded-2xl bg-slate-50 p-4">
            <div className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">
              Tool Coverage (Plan / Exec / Block)
            </div>
            <div className="space-y-2">
              {toolCoverage.map((tool) => (
                <div key={tool.tool} className="rounded-xl bg-white px-3 py-2 shadow-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="truncate text-sm font-medium text-slate-800">{tool.label}</span>
                    <div className="flex items-center gap-2 text-[11px] text-slate-500">
                      <span>plan {tool.planned}</span>
                      <span>exec {tool.executed}</span>
                      <span>block {tool.blocked}</span>
                    </div>
                  </div>
                </div>
              ))}
              {toolCoverage.length === 0 ? (
                <div className="text-sm text-slate-500">No tool activity yet.</div>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
