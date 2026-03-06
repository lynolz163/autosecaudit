import { useEffect, useState } from "react";
import PaginationControls from "../components/PaginationControls";
import ReportPreview from "../components/ReportPreview";
import StatusBadge from "../components/StatusBadge";
import { useI18n } from "../i18n";
import { formatDateTime, paginateItems, truncateMiddle } from "../lib/formatters";

const PAGE_SIZE = 8;

export default function Reports({ reports, selectedReport, onSelectReport, reportContent, reportAnalysis, token }) {
  const { t, formatExportFormat, language } = useI18n();
  const [page, setPage] = useState(1);
  const pagination = paginateItems(reports, page, PAGE_SIZE);

  useEffect(() => {
    setPage((prev) => prev !== pagination.page ? pagination.page : prev);
  }, [pagination.page]);

  return (
    <div className="reports-layout">
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">{t("reports.archiveEyebrow")}</p>
            <h3>{t("reports.centerTitle")}</h3>
          </div>
        </div>

        <div className="table-list">
          {pagination.items.map((report) => (
            <button
              key={report.job_id}
              type="button"
              className={selectedReport?.job_id === report.job_id ? "table-row is-active" : "table-row"}
              onClick={() => onSelectReport(report)}
            >
              <div className="table-title">
                <strong>{truncateMiddle(report.target || report.job_id, 82)}</strong>
                <StatusBadge status={report.status} />
              </div>
              <div className="table-meta">
                {t("reports.findingsMeta", {
                  count: report.finding_total,
                  formats: report.available_formats.map((item) => formatExportFormat(item)).join(", "),
                })}
              </div>
              <div className="table-meta">{t("reports.updatedMeta", { value: formatDateTime(report.ended_at || report.updated_at || "-", language) })}</div>
              {report.decision_summary ? <div className="table-meta clamp-2">{report.decision_summary}</div> : null}
            </button>
          ))}
          {!pagination.totalItems ? <div className="empty-state">{t("reports.noReports")}</div> : null}
        </div>
        <PaginationControls {...pagination} onPageChange={setPage} />
      </section>

      <ReportPreview report={selectedReport} content={reportContent} analysis={reportAnalysis} token={token} />
    </div>
  );
}
