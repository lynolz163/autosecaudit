export default function LayoutShell({ header, children }) {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-slate-50 text-slate-900">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-24 -top-16 h-72 w-72 rounded-full bg-sky-200/40 blur-3xl" />
        <div className="absolute right-0 top-6 h-80 w-80 rounded-full bg-indigo-200/25 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-emerald-200/30 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 pb-10 pt-4 sm:px-6 lg:px-8">
        <div className="sticky top-4 z-30 mb-6">{header}</div>
        <main>{children}</main>
      </div>
    </div>
  );
}
