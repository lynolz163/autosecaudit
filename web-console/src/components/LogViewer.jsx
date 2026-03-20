import { memo, useDeferredValue, useMemo, useState } from "react";
import { useI18n } from "../i18n";
import AgentTimeline from "./AgentTimeline";

const STRUCTURED_HINT_PATTERN = /\[[^\]]+\]\s+[^|]+\|\s+[^|]+\|\s+/;
const STRUCTURED_DETECTION_WINDOW = 400;

function LogViewer({ lines, status, mode, analysis = null }) {
  const { t, formatStatus } = useI18n();
  const deferredLines = useDeferredValue(Array.isArray(lines) ? lines : []);

  // default to timeline when agent mode or structured agent logs are detected
  const [viewOverride, setViewOverride] = useState(null);
  const recentLines = useMemo(
    () => (Array.isArray(deferredLines) ? deferredLines.slice(-STRUCTURED_DETECTION_WINDOW) : []),
    [deferredLines],
  );
  const hasStructuredSignals = useMemo(
    () => recentLines.some((item) => STRUCTURED_HINT_PATTERN.test(String(item?.line || ""))),
    [recentLines],
  );
  const currentView = useMemo(() => {
    if (viewOverride) return viewOverride;
    return mode === "agent" || hasStructuredSignals ? "timeline" : "raw";
  }, [mode, viewOverride, hasStructuredSignals]);
  const rawText = useMemo(() => {
    if (currentView !== "raw") {
      return "";
    }
    return deferredLines.length
      ? deferredLines.map((item) => `[${item.ts}] ${item.line}`).join("\n")
      : t("logViewer.empty");
  }, [currentView, deferredLines, t]);

  return (
    <section className="panel timeline-panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{t("logViewer.eyebrow")}</p>
          <h3>{t("logViewer.title")}</h3>
        </div>

        <div className="inline-actions">
          {(mode === "agent" || hasStructuredSignals) && (
            <div className="view-toggle">
              <button
                type="button"
                className={`ghost-button ${currentView === "timeline" ? "is-active" : ""}`}
                onClick={() => setViewOverride("timeline")}
              >
                {t("logViewer.viewTimeline")}
              </button>
              <button
                type="button"
                className={`ghost-button ${currentView === "raw" ? "is-active" : ""}`}
                onClick={() => setViewOverride("raw")}
              >
                {t("logViewer.viewRaw")}
              </button>
            </div>
          )}
          <div className="panel-chip">{formatStatus(status || "idle")}</div>
        </div>
      </div>

      {currentView === "timeline" ? (
        <AgentTimeline lines={deferredLines} totalLineCount={Array.isArray(lines) ? lines.length : 0} analysis={analysis} />
      ) : (
        <pre className="log-viewer">{rawText}</pre>
      )}
    </section>
  );
}

export default memo(LogViewer);
