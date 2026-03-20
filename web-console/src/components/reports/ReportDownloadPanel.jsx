import { useMemo } from "react";
import { useI18n } from "../../i18n";
import { normalizeAvailableReportExports } from "../../lib/reporting";
import ReportExportButtons from "./ReportExportButtons";

export default function ReportDownloadPanel({ report, analysis, token }) {
  const { formatExportFormat, language } = useI18n();
  const zh = language === "zh-CN";
  const tt = (enText, zhText) => (zh ? zhText : enText);
  const availableExports = useMemo(
    () => normalizeAvailableReportExports(analysis, report),
    [analysis, report],
  );

  if (!report || !availableExports.length) {
    return null;
  }

  return (
    <section className="panel report-download-panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{tt("Download", "下载")}</p>
          <h3>{tt("Download report", "下载报告")}</h3>
          <p className="report-summary-copy">
            {tt(
              "Grab the generated report directly here without scrolling to the raw preview.",
              "可以直接在这里下载生成好的报告，不用滚动到原始预览区。",
            )}
          </p>
        </div>
      </div>
      <ReportExportButtons
        report={report}
        analysis={analysis}
        token={token}
        className="report-download-links"
      />
      <div className="report-download-note">
        {tt("Available formats", "可下载格式")}：{availableExports.map((item) => formatExportFormat(item)).join(", ")}
      </div>
    </section>
  );
}
