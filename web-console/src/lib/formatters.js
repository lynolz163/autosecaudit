export function formatDateTime(value, language = "en") {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) {
    return raw;
  }
  return new Intl.DateTimeFormat(language === "zh-CN" ? "zh-CN" : "en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function truncateMiddle(value, maxLength = 72) {
  const text = String(value || "");
  if (!text || text.length <= maxLength) {
    return text || "-";
  }
  const headLength = Math.max(12, Math.floor((maxLength - 3) / 2));
  const tailLength = Math.max(8, maxLength - headLength - 3);
  return `${text.slice(0, headLength)}...${text.slice(-tailLength)}`;
}

export function paginateItems(items, page, pageSize) {
  const safeItems = Array.isArray(items) ? items : [];
  const safePageSize = Math.max(1, Number(pageSize || 1));
  const totalPages = Math.max(1, Math.ceil(safeItems.length / safePageSize));
  const safePage = Math.min(Math.max(1, Number(page || 1)), totalPages);
  const start = (safePage - 1) * safePageSize;
  return {
    page: safePage,
    pageSize: safePageSize,
    totalPages,
    totalItems: safeItems.length,
    items: safeItems.slice(start, start + safePageSize),
    startIndex: safeItems.length ? start + 1 : 0,
    endIndex: Math.min(start + safePageSize, safeItems.length),
  };
}
