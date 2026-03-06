import LanguageSwitcher from "./LanguageSwitcher";
import { useI18n } from "../i18n";

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
}) {
  const { t, formatRole } = useI18n();

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">AS</div>
          <div>
            <p className="eyebrow">{t("shell.blueTeamConsole")}</p>
            <h1>AutoSecAudit</h1>
          </div>
        </div>

        <LanguageSwitcher compact />

        <nav className="nav">
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              className={item.id === activeView ? "nav-item is-active" : "nav-item"}
              onClick={() => onChangeView(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-note">
          <p className="eyebrow">{t("shell.session")}</p>
          <p>{currentUser?.display_name || currentUser?.username || t("shell.unknownUser")}</p>
          <p>{currentUser?.role ? formatRole(currentUser.role) : "-"}</p>
          <button className="ghost-button sidebar-button" type="button" onClick={onLogout}>
            {t("common.signOut")}
          </button>
        </div>
      </aside>

      <div className="content">
        <header className="hero">
          <div>
            <p className="eyebrow">{t("shell.securityOperations")}</p>
            <h2>{title}</h2>
            <p className="hero-copy">{subtitle}</p>
          </div>
          {rightRail ? <div className="hero-rail">{rightRail}</div> : null}
        </header>
        <main className="page-grid">{children}</main>
      </div>
    </div>
  );
}
