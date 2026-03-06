import { useI18n } from "../i18n";

const COPY = {
  "zh-CN": {
    previous: "上一页",
    next: "下一页",
    page: "第 {page} / {total} 页",
    range: "显示 {start}-{end} / {total}",
  },
  en: {
    previous: "Previous",
    next: "Next",
    page: "Page {page} / {total}",
    range: "Showing {start}-{end} of {total}",
  },
};

function translate(template, vars) {
  return String(template).replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? ""));
}

export default function PaginationControls({ page, totalPages, totalItems, startIndex, endIndex, onPageChange }) {
  const { language } = useI18n();
  const copy = COPY[language] || COPY.en;

  if (totalItems <= 0 || totalPages <= 1) {
    return null;
  }

  return (
    <div className="pagination-bar">
      <div className="pagination-meta">
        <strong>{translate(copy.page, { page, total: totalPages })}</strong>
        <span>{translate(copy.range, { start: startIndex, end: endIndex, total: totalItems })}</span>
      </div>
      <div className="inline-actions">
        <button className="ghost-button" type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          {copy.previous}
        </button>
        <button className="ghost-button" type="button" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>
          {copy.next}
        </button>
      </div>
    </div>
  );
}
