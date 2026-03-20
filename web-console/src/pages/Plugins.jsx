import { useEffect, useState } from "react";

import StatusBadge from "../components/StatusBadge";
import { useI18n } from "../i18n";

export default function Plugins({
  pluginCatalog,
  onSavePluginSettings,
  onReloadPlugins,
  onReloadPlugin,
}) {
  const { t, formatBoolean, formatPluginCategory } = useI18n();
  const [rawDirs, setRawDirs] = useState("");

  useEffect(() => {
    setRawDirs((pluginCatalog?.settings?.plugin_dirs || []).join("\n"));
  }, [pluginCatalog]);

  async function handleSubmit(event) {
    event.preventDefault();
    const pluginDirs = rawDirs
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);
    await onSavePluginSettings(pluginDirs);
  }

  const items = Array.isArray(pluginCatalog?.items) ? pluginCatalog.items : [];
  const settings = pluginCatalog?.settings || {};
  const runtime = settings.runtime || {};
  const resolvedDirs = Array.isArray(settings.resolved_dirs) ? settings.resolved_dirs : [];
  const errors = Array.isArray(runtime.errors) ? runtime.errors : [];
  const metrics = pluginCatalog?.metrics || {};

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("plugins.runtimeEyebrow")}</p>
            <h3>{t("plugins.directoriesTitle")}</h3>
          </div>
          <div className="inline-actions">
            <button className="ghost-button" type="button" onClick={onReloadPlugins}>
              {t("plugins.reloadAll")}
            </button>
          </div>
        </div>

        <form className="scan-form" onSubmit={handleSubmit}>
          <label>
            <span>{t("plugins.directories")}</span>
            <textarea
              value={rawDirs}
              onChange={(event) => setRawDirs(event.target.value)}
              rows={6}
              placeholder={t("plugins.directoriesPlaceholder")}
            />
          </label>
          <div className="inline-actions">
            <button className="primary-button" type="submit">
              {t("plugins.saveDirectories")}
            </button>
          </div>
        </form>

        <div className="job-detail-grid mt-5">
          <div>
            <p className="eyebrow">{t("plugins.totalPlugins")}</p>
            <div>{metrics.total_plugins || 0}</div>
          </div>
          <div>
            <p className="eyebrow">{t("plugins.builtin")}</p>
            <div>{metrics.builtin_plugins || 0}</div>
          </div>
          <div>
            <p className="eyebrow">{t("plugins.external")}</p>
            <div>{metrics.external_plugins || 0}</div>
          </div>
          <div>
            <p className="eyebrow">{t("plugins.lastReload")}</p>
            <div>{runtime.last_loaded_at || "-"}</div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("plugins.resolutionEyebrow")}</p>
            <h3>{t("plugins.resolutionStatus")}</h3>
          </div>
        </div>

        <div className="table-list">
          {resolvedDirs.map((item) => (
            <div key={`${item.configured_path}-${item.resolved_path}`} className="table-row">
              <div className="table-title">
                <strong>{item.configured_path}</strong>
                <StatusBadge status={item.exists && item.is_dir ? "active" : "error"} />
              </div>
              <div className="table-meta">{item.resolved_path}</div>
              <div className="table-meta">
                {t("plugins.existsDirectory", {
                  exists: formatBoolean(Boolean(item.exists)),
                  isDir: formatBoolean(Boolean(item.is_dir)),
                })}
              </div>
            </div>
          ))}
          {!resolvedDirs.length ? <div className="empty-state">{t("plugins.noDirectories")}</div> : null}
        </div>

        <div className="table-list mt-5">
          {errors.map((item, index) => (
            <div key={`${item.path}-${index}`} className="table-row">
              <div className="table-title">
                <strong>{t("plugins.loadError")}</strong>
                <StatusBadge status="error" />
              </div>
              <div className="table-meta">{item.path}</div>
              <div className="table-meta">{item.error}</div>
            </div>
          ))}
          {!errors.length ? <div className="empty-state">{t("plugins.noLoadErrors")}</div> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("plugins.catalogEyebrow")}</p>
            <h3>{t("plugins.registeredPlugins")}</h3>
          </div>
        </div>

        <div className="table-list">
          {items.map((item) => (
            <div key={item.plugin_id} className="table-row">
              <div className="table-title">
                <strong>{item.name}</strong>
                <div className="inline-actions">
                  <StatusBadge status={item.source_type} />
                  <StatusBadge status={item.risk_level} />
                </div>
              </div>
              <div className="table-meta">
                {t("plugins.pluginMeta", {
                  pluginId: item.plugin_id,
                  category: formatPluginCategory(item.category),
                  version: item.version,
                })}
              </div>
              {item.description ? <div className="table-meta">{item.description}</div> : null}
              <div className="table-meta">{item.module_path || item.module_name}</div>
              {item.reloadable ? (
                <div className="inline-actions">
                  <button className="ghost-button" type="button" onClick={() => onReloadPlugin(item.plugin_id)}>
                    {t("plugins.reloadOne")}
                  </button>
                </div>
              ) : null}
            </div>
          ))}
          {!items.length ? <div className="empty-state">{t("plugins.noPlugins")}</div> : null}
        </div>
      </section>
    </div>
  );
}

