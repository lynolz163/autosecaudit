import { useMemo } from "react";
import { useI18n } from "../../i18n";
import { buildReportExportUrl, normalizeAvailableReportExports } from "../../lib/reporting";

function downloadLabel(format, tt, formatExportFormat) {
  if (format === "html") return tt("Download HTML", "下载 HTML");
  if (format === "markdown") return tt("Download Markdown", "下载 Markdown");
  if (format === "json") return tt("Download JSON", "下载 JSON");
  return `${tt("Download", "下载")} ${formatExportFormat(format)}`;
}

function extensionForFormat(format) {
  return format === "markdown" ? "md" : format;
}

export default function ReportExportButtons({
  report,
  analysis,
  availableExports,
  token,
  className = "inline-actions",
  linkClassName = "ghost-button",
}) {
  const { formatExportFormat, language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const formats = useMemo(
    () => normalizeAvailableReportExports(analysis, report, availableExports),
    [analysis, availableExports, report],
  );

  if (!report || !formats.length) {
    return null;
  }

  return (
    <div className={className} role="group" aria-label={tt("Report downloads", "报告下载")}>
      {formats.map((format) => (
        <a
          key={format}
          className={linkClassName}
          href={buildReportExportUrl(report, token, format)}
          download={`${report.job_id}.${extensionForFormat(format)}`}
        >
          {downloadLabel(format, tt, formatExportFormat)}
        </a>
      ))}
    </div>
  );
}
