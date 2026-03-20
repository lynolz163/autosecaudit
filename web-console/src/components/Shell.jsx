import LanguageSwitcher from "./LanguageSwitcher";
import { useI18n } from "../i18n";

function NavContent({ activeView, navItems, onChangeView, collapsed }) {
  return (
    <nav className="nav mt-2">
      {navItems.map((item) => (
        <button
          key={item.id}
          type="button"
          className={item.id === activeView ? "nav-item is-active" : "nav-item"}
          onClick={() => onChangeView(item.id)}
          title={collapsed ? item.label : undefined}
        >
          {collapsed ? item.label.slice(0, 2) : item.label}
        </button>
      ))}
    </nav>
  );
}

export default function Shell({
  activeView,
  navItems,
  onChangeView,
  onLogout,
  title,
  subtitle,
  currentUser,
  children,
  rightRail,
  navCollapsed = false,
  navOpen = false,
  onToggleNav,
  onCloseNav,
  onToggleNavCollapsed,
  alertStrip,
}) {
  const { t, formatRole } = useI18n();
  const sidebarWidth = navCollapsed ? "lg:grid-cols-[88px_minmax(0,1fr)]" : "lg:grid-cols-[268px_minmax(0,1fr)]";
  const sidebarPadding = navCollapsed ? "px-3 py-5" : "px-5 py-6";

  return (
    <div className={`shell ${sidebarWidth}`}>
      <div className="pointer-events-none fixed inset-0 -z-10">
        <div className="absolute left-[-8rem] top-[-8rem] h-72 w-72 rounded-full bg-sky-200/65 blur-3xl" />
        <div className="absolute right-[-10rem] top-24 h-96 w-96 rounded-full bg-blue-100/70 blur-3xl" />
        <div className="absolute bottom-[-10rem] left-1/3 h-96 w-96 rounded-full bg-slate-200/60 blur-3xl" />
      </div>

      <aside className={`sidebar hidden lg:flex ${sidebarPadding}`}>
        <div className="brand items-center justify-between">
          <div className={`flex items-center gap-4 ${navCollapsed ? "justify-center w-full" : ""}`}>
            <div className="brand-mark">AS</div>
            {!navCollapsed ? (
              <div className="min-w-0">
                <p className="eyebrow">{t("shell.blueTeamConsole")}</p>
                <h1>AutoSecAudit</h1>
              </div>
            ) : null}
          </div>
          <button className="ghost-button hidden lg:inline-flex" type="button" onClick={onToggleNavCollapsed}>
            {navCollapsed ? "→" : "←"}
          </button>
        </div>

        {!navCollapsed ? <LanguageSwitcher compact /> : null}

        <NavContent activeView={activeView} navItems={navItems} onChangeView={onChangeView} collapsed={navCollapsed} />

        <div className="sidebar-note mt-auto">
          {!navCollapsed ? (
            <>
              <p className="eyebrow">{t("shell.session")}</p>
              <p>{currentUser?.display_name || currentUser?.username || t("shell.unknownUser")}</p>
              <p>{currentUser?.role ? formatRole(currentUser.role) : "-"}</p>
              <button className="ghost-button sidebar-button" type="button" onClick={onLogout}>
                {t("common.signOut")}
              </button>
            </>
          ) : (
            <button className="ghost-button sidebar-button" type="button" onClick={onLogout} title={t("common.signOut")}>
              ⎋
            </button>
          )}
        </div>
      </aside>

      <div className={`fixed inset-0 z-40 bg-slate-950/18 backdrop-blur-sm transition lg:hidden ${navOpen ? "opacity-100" : "pointer-events-none opacity-0"}`} onClick={onCloseNav}>
        <aside
          className={`h-full w-[280px] border-r border-white/80 bg-white/82 px-5 py-6 shadow-[24px_0_60px_-36px_rgba(15,23,42,0.28)] backdrop-blur-2xl transition-transform ${navOpen ? "translate-x-0" : "-translate-x-full"}`}
          onClick={(event) => event.stopPropagation()}
        >
          <div className="brand items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="brand-mark">AS</div>
              <div className="min-w-0">
                <p className="eyebrow">{t("shell.blueTeamConsole")}</p>
                <h1>AutoSecAudit</h1>
              </div>
            </div>
            <button className="ghost-button" type="button" onClick={onCloseNav}>×</button>
          </div>

          <LanguageSwitcher compact />
          <NavContent activeView={activeView} navItems={navItems} onChangeView={(viewId) => { onChangeView(viewId); onCloseNav?.(); }} collapsed={false} />

          <div className="sidebar-note mt-auto">
            <p className="eyebrow">{t("shell.session")}</p>
            <p>{currentUser?.display_name || currentUser?.username || t("shell.unknownUser")}</p>
            <p>{currentUser?.role ? formatRole(currentUser.role) : "-"}</p>
            <button className="ghost-button sidebar-button" type="button" onClick={onLogout}>
              {t("common.signOut")}
            </button>
          </div>
        </aside>
      </div>

      <div className="content">
        <header className="hero hero-compact">
          <div className="flex min-w-0 items-start gap-3">
            <button className="ghost-button lg:hidden" type="button" onClick={onToggleNav}>☰</button>
            <div className="min-w-0">
              <p className="eyebrow">{t("shell.securityOperations")}</p>
              <h2>{title}</h2>
              {subtitle ? <p className="hero-copy mt-2">{subtitle}</p> : null}
            </div>
          </div>
          {rightRail ? <div className="hero-rail w-full lg:w-auto">{rightRail}</div> : null}
        </header>

        {alertStrip}

        <main className="page-grid mx-auto w-full max-w-[1680px]">{children}</main>
      </div>
    </div>
  );
}
