import { useEffect, useState } from "react";
import PaginationControls from "../components/PaginationControls";
import StatusBadge from "../components/StatusBadge";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";

const EMPTY_FORM = {
  name: "",
  target: "",
  scope: "",
  default_mode: "agent",
  tags: "",
  notes: "",
};

const PAGE_SIZE = 6;

export default function Assets({ assets, onCreate, onScan, onDelete }) {
  const { t, formatMode, language } = useI18n();
  const [form, setForm] = useState(EMPTY_FORM);
  const [page, setPage] = useState(1);
  const pagination = paginateItems(assets, page, PAGE_SIZE);

  useEffect(() => {
    setPage((prev) => prev !== pagination.page ? pagination.page : prev);
  }, [pagination.page]);

  function updateField(event) {
    const { name, value } = event.target;
    setForm((current) => ({ ...current, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    await onCreate({
      ...form,
      tags: form.tags
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    });
    setForm(EMPTY_FORM);
  }

  async function handleDelete(asset) {
    if (!onDelete) {
      return;
    }
    const confirmText =
      language === "zh-CN"
        ? `确认删除资产“${asset.name}”吗？关联计划任务也会一并删除。`
        : `Delete asset "${asset.name}"? Linked schedules will also be removed.`;
    if (!window.confirm(confirmText)) {
      return;
    }
    await onDelete(asset.asset_id);
  }

  return (
    <div className="jobs-layout">
      {onCreate ? (
        <form className="panel scan-form" onSubmit={handleSubmit}>
          <div className="panel-head">
            <div>
              <p className="eyebrow">{t("assets.inventoryEyebrow")}</p>
              <h3>{t("assets.addAssetTitle")}</h3>
            </div>
          </div>

          <label>
            <span>{t("common.displayName")}</span>
            <input name="name" value={form.name} onChange={updateField} placeholder={t("assets.namePlaceholder")} required />
          </label>
          <label>
            <span>{t("common.target")}</span>
            <input name="target" value={form.target} onChange={updateField} placeholder={t("assets.targetPlaceholder")} required />
          </label>
          <label>
            <span>{t("common.scope")}</span>
            <input name="scope" value={form.scope} onChange={updateField} placeholder={t("assets.scopePlaceholder")} />
          </label>
          <div className="field-grid">
            <label>
              <span>{t("assets.defaultMode")}</span>
              <select name="default_mode" value={form.default_mode} onChange={updateField}>
                <option value="agent">{formatMode("agent")}</option>
                <option value="plan">{formatMode("plan")}</option>
                <option value="plugins">{formatMode("plugins")}</option>
              </select>
            </label>
            <label>
              <span>{t("assets.tags")}</span>
              <input name="tags" value={form.tags} onChange={updateField} placeholder={t("assets.tagsPlaceholder")} />
            </label>
            <label>
              <span>{language === "zh-CN" ? "备注" : "Notes"}</span>
              <input
                name="notes"
                value={form.notes}
                onChange={updateField}
                placeholder={language === "zh-CN" ? "资产说明、归属团队、场景" : "Owner, criticality, notes"}
              />
            </label>
          </div>
          <button className="primary-button" type="submit">
            {t("assets.saveAsset")}
          </button>
        </form>
      ) : (
        <section className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{t("assets.inventoryEyebrow")}</p>
              <h3>{t("assets.readOnlyTitle")}</h3>
            </div>
          </div>
          <div className="empty-state">{t("assets.readOnlyDescription")}</div>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("assets.catalogEyebrow")}</p>
            <h3>{t("assets.managedAssets")}</h3>
          </div>
          <span className="panel-chip">{pagination.totalItems}</span>
        </div>
        <div className="table-list">
          {pagination.items.map((asset) => (
            <article key={asset.asset_id} className="table-row is-static">
              <div className="table-title">
                <strong>{asset.name}</strong>
                <StatusBadge status={asset.enabled ? "active" : "disabled"} />
              </div>
              <div className="record-grid">
                <div>
                  <span className="record-label">{language === "zh-CN" ? "目标" : "Target"}</span>
                  <div className="record-value mono">{truncateMiddle(asset.target, 88)}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "模式" : "Mode"}</span>
                  <div className="record-value">{formatMode(asset.default_mode)}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "范围" : "Scope"}</span>
                  <div className="record-value">{asset.scope || t("assets.noScope")}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "更新时间" : "Updated"}</span>
                  <div className="record-value">{formatDateTime(asset.updated_at, language)}</div>
                </div>
              </div>
              <div className="tag-list">
                {(asset.tags || []).length ? (asset.tags || []).map((tag) => <span key={tag} className="tag-chip">{tag}</span>) : <span className="table-meta">{t("assets.noTags")}</span>}
              </div>
              {asset.notes ? <div className="table-meta clamp-2">{asset.notes}</div> : null}
              {(onScan || onDelete) ? (
                <div className="inline-actions">
                  {onScan ? (
                    <button className="ghost-button" type="button" onClick={() => onScan(asset.asset_id)}>
                      {t("assets.scanNow")}
                    </button>
                  ) : null}
                  {onDelete ? (
                    <button className="ghost-button danger-button" type="button" onClick={() => handleDelete(asset)}>
                      {language === "zh-CN" ? "删除" : "Delete"}
                    </button>
                  ) : null}
                </div>
              ) : null}
            </article>
          ))}
          {!pagination.totalItems ? <div className="empty-state">{t("assets.noAssets")}</div> : null}
        </div>
        <PaginationControls {...pagination} onPageChange={setPage} />
      </section>
    </div>
  );
}
