import { useEffect, useState } from "react";
import PaginationControls from "../components/PaginationControls";
import StatusBadge from "../components/StatusBadge";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";

const EMPTY_FORM = {
  name: "",
  asset_id: "",
  cron_expr: "0 2 * * 1",
  mode: "agent",
  safety_grade: "balanced",
  budget: 50,
  notify_on: "completed,finding_high",
};

const PAGE_SIZE = 6;

export default function Schedules({ assets, schedules, onCreate, onDelete }) {
  const { t, formatMode, language } = useI18n();
  const [form, setForm] = useState(EMPTY_FORM);
  const [page, setPage] = useState(1);
  const pagination = paginateItems(schedules, page, PAGE_SIZE);
  const gradeLabels =
    language === "zh-CN"
      ? {
        conservative: "保守",
        balanced: "平衡",
        aggressive: "激进",
      }
      : {
        conservative: "Conservative",
        balanced: "Balanced",
        aggressive: "Aggressive",
      };

  useEffect(() => {
    setPage((prev) => prev !== pagination.page ? pagination.page : prev);
  }, [pagination.page]);

  function updateField(event) {
    const { name, value } = event.target;
    setForm((current) => ({ ...current, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const payload = {
      name: form.name,
      asset_id: form.asset_id ? Number(form.asset_id) : null,
      cron_expr: form.cron_expr,
      payload: {
        mode: form.mode,
        safety_grade: form.safety_grade,
        budget: Number(form.budget || 50),
      },
      notify_on: form.notify_on
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    };
    await onCreate(payload);
    setForm(EMPTY_FORM);
  }

  async function handleDelete(item) {
    if (!onDelete) {
      return;
    }
    const confirmText =
      language === "zh-CN"
        ? `确认删除计划任务“${item.name}”吗？`
        : `Delete schedule "${item.name}"?`;
    if (!window.confirm(confirmText)) {
      return;
    }
    await onDelete(item.schedule_id);
  }

  function assetName(assetId) {
    const matched = assets.find((asset) => Number(asset.asset_id) === Number(assetId));
    return matched?.name || "-";
  }

  function gradeLabel(value) {
    return gradeLabels[value] || gradeLabels.balanced;
  }

  return (
    <div className="jobs-layout">
      {onCreate ? (
        <form className="panel scan-form" onSubmit={handleSubmit}>
          <div className="panel-head">
            <div>
              <p className="eyebrow">{t("schedules.automationEyebrow")}</p>
              <h3>{t("schedules.newScheduleTitle")}</h3>
            </div>
          </div>

          <label>
            <span>{t("common.displayName")}</span>
            <input
              name="name"
              value={form.name}
              onChange={updateField}
              placeholder={t("schedules.namePlaceholder")}
              required
            />
          </label>
          <label>
            <span>{t("schedules.asset")}</span>
            <select name="asset_id" value={form.asset_id} onChange={updateField}>
              <option value="">{t("schedules.selectAsset")}</option>
              {assets.map((asset) => (
                <option key={asset.asset_id} value={asset.asset_id}>
                  {asset.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>{t("schedules.cron")}</span>
            <input
              name="cron_expr"
              value={form.cron_expr}
              onChange={updateField}
              placeholder="0 2 * * 1"
              required
            />
          </label>
          <div className="field-grid">
            <label>
              <span>{t("common.mode")}</span>
              <select name="mode" value={form.mode} onChange={updateField}>
                <option value="agent">{formatMode("agent")}</option>
                <option value="plan">{formatMode("plan")}</option>
                <option value="plugins">{formatMode("plugins")}</option>
              </select>
            </label>
            <label>
              <span>{language === "zh-CN" ? "安全等级" : "Safety grade"}</span>
              <select name="safety_grade" value={form.safety_grade} onChange={updateField}>
                <option value="conservative">{gradeLabels.conservative}</option>
                <option value="balanced">{gradeLabels.balanced}</option>
                <option value="aggressive">{gradeLabels.aggressive}</option>
              </select>
            </label>
            <label>
              <span>{t("common.budget")}</span>
              <input name="budget" type="number" min="1" value={form.budget} onChange={updateField} />
            </label>
            <label>
              <span>{t("schedules.notifyOn")}</span>
              <input
                name="notify_on"
                value={form.notify_on}
                onChange={updateField}
                placeholder={t("schedules.notifyOnPlaceholder")}
              />
            </label>
          </div>
          <button className="primary-button" type="submit">
            {t("schedules.saveSchedule")}
          </button>
        </form>
      ) : (
        <section className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">{t("schedules.automationEyebrow")}</p>
              <h3>{t("schedules.readOnlyTitle")}</h3>
            </div>
          </div>
          <div className="empty-state">{t("schedules.readOnlyDescription")}</div>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("schedules.plannerEyebrow")}</p>
            <h3>{t("schedules.scheduledJobs")}</h3>
          </div>
          <span className="panel-chip">{pagination.totalItems}</span>
        </div>
        <div className="table-list">
          {pagination.items.map((item) => (
            <article key={item.schedule_id} className="table-row is-static">
              <div className="table-title">
                <strong>{item.name}</strong>
                <StatusBadge status={item.enabled ? "active" : "disabled"} />
              </div>
              <div className="record-grid">
                <div>
                  <span className="record-label">{language === "zh-CN" ? "资产" : "Asset"}</span>
                  <div className="record-value">{assetName(item.asset_id)}</div>
                </div>
                <div>
                  <span className="record-label">{t("schedules.cron")}</span>
                  <div className="record-value mono">{item.cron_expr}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "运行模式" : "Mode"}</span>
                  <div className="record-value">{formatMode(item.payload?.mode || "agent")}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "安全等级" : "Safety grade"}</span>
                  <div className="record-value">{gradeLabel(item.payload?.safety_grade || "balanced")}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "预算" : "Budget"}</span>
                  <div className="record-value">{item.payload?.budget ?? "-"}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "下一次执行" : "Next run"}</span>
                  <div className="record-value">{formatDateTime(item.next_run_at, language)}</div>
                </div>
                <div>
                  <span className="record-label">{language === "zh-CN" ? "上次执行" : "Last run"}</span>
                  <div className="record-value">{formatDateTime(item.last_run_at, language)}</div>
                </div>
              </div>
              <div className="tag-list">
                {(item.notify_on || []).length ? (
                  item.notify_on.map((rule) => (
                    <span key={rule} className="tag-chip">
                      {rule}
                    </span>
                  ))
                ) : (
                  <span className="table-meta">{t("common.noData")}</span>
                )}
              </div>
              <div className="table-meta">
                {language === "zh-CN" ? "最近任务" : "Last job"}: {truncateMiddle(item.last_job_id || "-", 60)}
              </div>
              {item.last_error ? (
                <div className="table-meta clamp-2">{truncateMiddle(item.last_error, 160)}</div>
              ) : null}
              {onDelete ? (
                <div className="inline-actions">
                  <button className="ghost-button danger-button" type="button" onClick={() => handleDelete(item)}>
                    {language === "zh-CN" ? "删除" : "Delete"}
                  </button>
                </div>
              ) : null}
            </article>
          ))}
          {!pagination.totalItems ? <div className="empty-state">{t("schedules.noSchedules")}</div> : null}
        </div>
        <PaginationControls {...pagination} onPageChange={setPage} />
      </section>
    </div>
  );
}
