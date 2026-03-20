import { useEffect, useState } from "react";
import LlmConfigPanel from "../components/LlmConfigPanel";
import NotificationSettingsForm from "../components/NotificationSettingsForm";
import PaginationControls from "../components/PaginationControls";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";

const PAGE_SIZE = 8;

export default function Settings({
  authStatus,
  currentUser,
  codexConfig,
  llmSettings,
  message,
  notificationConfig,
  onSaveNotificationConfig,
  onSaveLlmSettings,
  onTestLlmConnection,
  auditEvents,
  onLogout,
}) {
  const { t, formatBoolean, formatRole, localizeMessage, language } = useI18n();
  const [page, setPage] = useState(1);
  const pagination = paginateItems(auditEvents || [], page, PAGE_SIZE);

  useEffect(() => {
    setPage((prev) => (prev !== pagination.page ? pagination.page : prev));
  }, [pagination.page]);

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("settings.accessEyebrow")}</p>
            <h3>{t("settings.sessionTitle")}</h3>
          </div>
          <button className="ghost-button" type="button" onClick={onLogout}>
            {t("common.signOut")}
          </button>
        </div>

        <div className="record-grid">
          <div>
            <span className="record-label">{t("common.user")}</span>
            <div className="record-value">{currentUser?.display_name || currentUser?.username || "-"}</div>
          </div>
          <div>
            <span className="record-label">{t("common.role")}</span>
            <div className="record-value">{currentUser?.role ? formatRole(currentUser.role) : "-"}</div>
          </div>
          <div>
            <span className="record-label">{t("settings.bootstrapEnabled")}</span>
            <div className="record-value">{formatBoolean(Boolean(authStatus?.bootstrap_enabled))}</div>
          </div>
          <div>
            <span className="record-label">{t("settings.defaultAdminEnv")}</span>
            <div className="record-value">{formatBoolean(Boolean(authStatus?.default_admin_env_configured))}</div>
          </div>
          <div>
            <span className="record-label">{t("settings.tokenTtl")}</span>
            <div className="record-value">{authStatus?.token_ttl_seconds || "-"}s</div>
          </div>
          <div>
            <span className="record-label">{t("settings.refreshTtl")}</span>
            <div className="record-value">{authStatus?.refresh_token_ttl_seconds || "-"}s</div>
          </div>
        </div>
        {message ? <div className="empty-state">{localizeMessage(message)}</div> : null}
      </section>

      <LlmConfigPanel llmSettings={llmSettings} onSave={onSaveLlmSettings} onTest={onTestLlmConnection} />

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("settings.llmEyebrow")}</p>
            <h3>{t("settings.codexTitle")}</h3>
          </div>
        </div>

        <div className="record-grid">
          <div>
            <span className="record-label">{t("common.configured")}</span>
            <div className="record-value">{formatBoolean(Boolean(codexConfig?.configured))}</div>
          </div>
          <div>
            <span className="record-label">{t("common.provider")}</span>
            <div className="record-value">{codexConfig?.provider_alias || "-"}</div>
          </div>
          <div>
            <span className="record-label">{t("settings.baseUrl")}</span>
            <div className="record-value mono">{truncateMiddle(codexConfig?.base_url || "-", 68)}</div>
          </div>
          <div>
            <span className="record-label">{t("common.profile")}</span>
            <div className="record-value">{codexConfig?.profile_id || "-"}</div>
          </div>
        </div>
      </section>

      <NotificationSettingsForm notificationConfig={notificationConfig} onSave={onSaveNotificationConfig} />

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("settings.auditEyebrow")}</p>
            <h3>{t("settings.recentAuditEvents")}</h3>
          </div>
          <span className="panel-chip">{pagination.totalItems}</span>
        </div>
        <div className="table-list">
          {pagination.items.map((item) => (
            <article key={item.event_id} className="table-row is-static">
              <div className="table-title">
                <strong>{item.event_type}</strong>
                <span className="panel-chip">{item.actor}</span>
              </div>
              <div className="record-grid">
                <div>
                  <span className="record-label">{language === "zh-CN" ? "资源类型" : "Resource"}</span>
                  <div className="record-value">{item.resource_type}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "资源 ID" : "Resource ID"}</span>
                  <div className="record-value">{item.resource_id || "-"}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "时间" : "Created"}</span>
                  <div className="record-value">{formatDateTime(item.created_at, language)}</div>
                </div>
              </div>
            </article>
          ))}
          {!pagination.totalItems ? <div className="empty-state">{t("settings.noAuditEvents")}</div> : null}
        </div>
        <PaginationControls {...pagination} onPageChange={setPage} />
      </section>
    </div>
  );
}

