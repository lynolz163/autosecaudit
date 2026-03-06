export const DEFAULT_VIEW = "dashboard";

export function activeViewFromPath(pathname) {
  const normalized = String(pathname || "")
    .replace(/^\/+/, "")
    .trim()
    .toLowerCase();
  return normalized || DEFAULT_VIEW;
}

export function viewPath(viewId) {
  const normalized = String(viewId || DEFAULT_VIEW)
    .trim()
    .toLowerCase();
  return `/${normalized || DEFAULT_VIEW}`;
}

export function navItemsFor(permissions, t) {
  const items = [
    { id: "dashboard", label: t("nav.dashboard") },
    { id: "jobs", label: t("nav.jobs") },
    { id: "assets", label: t("nav.assets") },
    { id: "schedules", label: t("nav.schedules") },
    { id: "reports", label: t("nav.reports") },
  ];
  if (permissions?.can_admin) {
    items.push({ id: "rag-console", label: t("nav.ragConsole") || "RAG" });
    items.push({ id: "plugins", label: t("nav.plugins") });
    items.push({ id: "users", label: t("nav.users") });
    items.push({ id: "settings", label: t("nav.settings") });
  }
  return items;
}
