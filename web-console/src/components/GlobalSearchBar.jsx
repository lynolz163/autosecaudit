import { useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n";

function kindLabel(kind, zh) {
  const key = String(kind || "").toLowerCase();
  if (key === "finding") return zh ? "发现" : "Finding";
  if (key === "report") return zh ? "报告" : "Report";
  if (key === "job") return zh ? "任务" : "Job";
  if (key === "asset") return zh ? "资产" : "Asset";
  if (key === "schedule") return zh ? "计划" : "Schedule";
  return zh ? "结果" : "Result";
}

export default function GlobalSearchBar({
  results,
  searching,
  onSearch,
  onSelectResult,
  onClear,
}) {
  const { language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef(null);

  useEffect(() => {
    function handlePointerDown(event) {
      if (!wrapperRef.current?.contains(event.target)) {
        setOpen(false);
      }
    }
    window.addEventListener("pointerdown", handlePointerDown);
    return () => window.removeEventListener("pointerdown", handlePointerDown);
  }, []);

  useEffect(() => {
    const normalized = String(query || "").trim();
    if (normalized.length < 2) {
      onClear?.();
      return undefined;
    }
    const timer = window.setTimeout(() => {
      Promise.resolve(onSearch?.(normalized)).catch(() => { });
    }, 220);
    return () => window.clearTimeout(timer);
  }, [query, onSearch, onClear]);

  const groupSummary = useMemo(() => {
    const groups = Object.entries(results?.groups || {});
    if (!groups.length) {
      return "";
    }
    return groups
      .map(([kind, count]) => `${kindLabel(kind, zh)} ${count}`)
      .join(" · ");
  }, [results?.groups, zh]);

  const items = Array.isArray(results?.items) ? results.items : [];
  const showPopover = open && String(query || "").trim().length > 0;

  function handleClear() {
    setQuery("");
    setOpen(false);
    onClear?.();
  }

  async function handleSelect(item) {
    setQuery("");
    setOpen(false);
    onClear?.();
    await onSelectResult?.(item);
  }

  return (
    <div className="global-search-shell" ref={wrapperRef}>
      <div className="global-search-field">
        <input
          type="search"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          placeholder={tt("Search targets, CVEs, findings, jobs…", "搜索目标、CVE、发现、任务…")}
          aria-label={tt("Global search", "全局搜索")}
        />
        {query ? (
          <button type="button" className="ghost-button" onClick={handleClear}>
            {tt("Clear", "清空")}
          </button>
        ) : null}
      </div>

      {showPopover ? (
        <div className="global-search-popover">
          {String(query || "").trim().length < 2 ? (
            <div className="empty-state global-search-empty">
              {tt("Type at least 2 characters to search.", "至少输入 2 个字符后开始搜索。")}
            </div>
          ) : searching ? (
            <div className="empty-state global-search-empty">
              {tt("Searching…", "搜索中…")}
            </div>
          ) : items.length ? (
            <>
              <div className="global-search-meta">
                <strong>{tt("Quick results", "快速结果")}</strong>
                <span>{groupSummary || `${results?.total || items.length}`}</span>
              </div>
              <div className="table-list">
                {items.map((item, index) => (
                  <button
                    key={`${item.kind || "result"}:${item.job_id || item.asset_id || item.schedule_id || index}`}
                    type="button"
                    className="table-row"
                    onClick={() => handleSelect(item)}
                  >
                    <div className="table-title">
                      <strong>{item.title}</strong>
                      <span className="panel-chip">{kindLabel(item.kind, zh)}</span>
                    </div>
                    {item.subtitle ? <div className="table-meta">{item.subtitle}</div> : null}
                    {item.summary ? <div className="table-meta clamp-2">{item.summary}</div> : null}
                  </button>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state global-search-empty">
              {tt("No matches found in jobs, reports, assets, or schedules.", "任务、报告、资产和计划中都没有匹配项。")}
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
