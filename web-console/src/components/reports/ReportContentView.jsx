import ReactMarkdown from "react-markdown";

export default function ReportContentView({ report, content, emptyLabel, missingContentLabel }) {
  if (!report) {
    return <div className="empty-state">{emptyLabel}</div>;
  }

  if (!content) {
    return <div className="empty-state">{missingContentLabel}</div>;
  }

  if (report.preview_path?.endsWith(".html")) {
    return <iframe className="report-frame" title={report.job_id} srcDoc={content} />;
  }

  if (report.preview_path?.endsWith(".json")) {
    return <pre className="report-code">{content}</pre>;
  }

  return (
    <div className="report-markdown">
      <ReactMarkdown>{content}</ReactMarkdown>
    </div>
  );
}
