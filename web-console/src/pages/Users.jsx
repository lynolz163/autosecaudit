import { useEffect, useState } from "react";

import PaginationControls from "../components/PaginationControls";
import StatusBadge from "../components/StatusBadge";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems } from "../lib/formatters";

const CREATE_FORM = {
  username: "",
  display_name: "",
  password: "",
  role: "viewer",
};
const PAGE_SIZE = 6;

export default function Users({ users, currentUser, onCreate, onUpdate, onDelete }) {
  const { t, formatBoolean, formatRole, language } = useI18n();
  const [form, setForm] = useState(CREATE_FORM);
  const [drafts, setDrafts] = useState({});
  const [page, setPage] = useState(1);
  const pagination = paginateItems(users, page, PAGE_SIZE);

  useEffect(() => {
    setPage((prev) => prev !== pagination.page ? pagination.page : prev);
  }, [pagination.page]);

  function updateCreateField(event) {
    const { name, value } = event.target;
    setForm((current) => ({ ...current, [name]: value }));
  }

  function updateDraft(userId, field, value) {
    setDrafts((current) => ({
      ...current,
      [userId]: {
        username: current[userId]?.username ?? "",
        display_name: current[userId]?.display_name ?? "",
        password: current[userId]?.password ?? "",
        role: current[userId]?.role ?? "",
        enabled: current[userId]?.enabled,
        [field]: value,
      },
    }));
  }

  async function handleCreate(event) {
    event.preventDefault();
    await onCreate(form);
    setForm(CREATE_FORM);
  }

  async function handleUpdate(user) {
    const draft = drafts[user.user_id] || {};
    await onUpdate(user.user_id, {
      username: draft.username || user.username,
      display_name: draft.display_name !== undefined ? draft.display_name : user.display_name || "",
      password: draft.password || "",
      role: draft.role || user.role,
      enabled: draft.enabled !== undefined ? draft.enabled : user.enabled,
    });
    setDrafts((current) => ({
      ...current,
      [user.user_id]: { ...current[user.user_id], password: "" },
    }));
  }

  async function handleToggleFreeze(user) {
    const targetEnabled = !(drafts[user.user_id]?.enabled !== undefined ? drafts[user.user_id]?.enabled : user.enabled);
    await onUpdate(user.user_id, {
      username: user.username,
      display_name: drafts[user.user_id]?.display_name !== undefined ? drafts[user.user_id].display_name : user.display_name || "",
      password: drafts[user.user_id]?.password || "",
      role: drafts[user.user_id]?.role || user.role,
      enabled: targetEnabled,
    });
  }

  async function handleDelete(user) {
    if (!window.confirm(t("users.deleteConfirm", { username: user.username }))) {
      return;
    }
    await onDelete(user.user_id);
  }

  return (
    <div className="jobs-layout">
      <form className="panel scan-form" onSubmit={handleCreate}>
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("users.identityEyebrow")}</p>
            <h3>{t("users.createUserTitle")}</h3>
          </div>
        </div>
        <label>
          <span>{t("common.username")}</span>
          <input
            name="username"
            value={form.username}
            onChange={updateCreateField}
            placeholder={t("users.analystPlaceholder")}
            required
          />
        </label>
        <label>
          <span>{t("common.displayName")}</span>
          <input
            name="display_name"
            value={form.display_name}
            onChange={updateCreateField}
            placeholder={t("users.displayNamePlaceholder")}
          />
        </label>
        <label>
          <span>{t("common.password")}</span>
          <input
            name="password"
            type="password"
            value={form.password}
            onChange={updateCreateField}
            placeholder={t("users.minimumPassword")}
            required
          />
        </label>
        <label>
          <span>{t("common.role")}</span>
          <select name="role" value={form.role} onChange={updateCreateField}>
            <option value="admin">{formatRole("admin")}</option>
            <option value="operator">{formatRole("operator")}</option>
            <option value="viewer">{formatRole("viewer")}</option>
          </select>
        </label>
        <button className="primary-button" type="submit">
          {t("users.createUser")}
        </button>
      </form>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("users.directoryEyebrow")}</p>
            <h3>{t("users.platformUsers")}</h3>
          </div>
        </div>
        <div className="table-list">
          {pagination.items.map((user) => {
            const draft = drafts[user.user_id] || {};
            const isSelf = Number(currentUser?.user_id || 0) === Number(user.user_id);
            const effectiveEnabled = draft.enabled !== undefined ? draft.enabled : user.enabled;
            return (
              <div key={user.user_id} className="table-row">
                <div className="table-title">
                  <strong>{user.username}</strong>
                  <div className="inline-actions">
                    <span className="panel-chip">{formatRole(user.role)}</span>
                    <StatusBadge status={effectiveEnabled ? "active" : "frozen"} />
                  </div>
                </div>
                <div className="field-grid">
                  <label>
                    <span>{t("common.displayName")}</span>
                    <input
                      value={draft.display_name !== undefined ? draft.display_name : user.display_name || ""}
                      onChange={(event) => updateDraft(user.user_id, "display_name", event.target.value)}
                      placeholder={t("common.displayName")}
                    />
                  </label>
                  <label>
                    <span>{t("common.role")}</span>
                    <select
                      value={draft.role || user.role}
                      disabled={isSelf}
                      onChange={(event) => updateDraft(user.user_id, "role", event.target.value)}
                    >
                      <option value="admin">{formatRole("admin")}</option>
                      <option value="operator">{formatRole("operator")}</option>
                      <option value="viewer">{formatRole("viewer")}</option>
                    </select>
                  </label>
                  <label>
                    <span>{t("users.enabledLabel")}</span>
                    <select
                      value={String(effectiveEnabled)}
                      disabled={isSelf}
                      onChange={(event) => updateDraft(user.user_id, "enabled", event.target.value === "true")}
                    >
                      <option value="true">{formatBoolean(true)}</option>
                      <option value="false">{formatBoolean(false)}</option>
                    </select>
                  </label>
                </div>
                <label>
                  <span>{t("users.resetPassword")}</span>
                  <input
                    type="password"
                    value={draft.password || ""}
                    onChange={(event) => updateDraft(user.user_id, "password", event.target.value)}
                    placeholder={t("users.resetPasswordPlaceholder")}
                  />
                </label>
                <div className="table-meta">
                  {t("users.createdMeta", { createdAt: formatDateTime(user.created_at, language), lastLogin: formatDateTime(user.last_login_at || "-", language) })}
                </div>
                <div className="inline-actions">
                  <button className="ghost-button" type="button" onClick={() => handleUpdate(user)}>
                    {t("common.saveChanges")}
                  </button>
                  <button className="ghost-button" type="button" onClick={() => handleToggleFreeze(user)} disabled={isSelf}>
                    {effectiveEnabled ? t("users.freeze") : t("users.unfreeze")}
                  </button>
                  <button className="ghost-button" type="button" onClick={() => handleDelete(user)} disabled={isSelf}>
                    {t("users.delete")}
                  </button>
                </div>
                {isSelf ? <div className="table-meta">{t("users.selfProtected")}</div> : null}
              </div>
            );
          })}
          {!pagination.totalItems ? <div className="empty-state">{t("users.noUsers")}</div> : null}
        </div>
        <PaginationControls {...pagination} onPageChange={setPage} />
      </section>
    </div>
  );
}
