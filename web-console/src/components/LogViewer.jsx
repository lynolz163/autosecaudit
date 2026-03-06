import { useState, useMemo } from "react";
import { useI18n } from "../i18n";
import AgentTimeline from "./AgentTimeline";

const STRUCTURED_HINT_PATTERN = /\[[^\]]+\]\s+[^|]+\|\s+[^|]+\|\s+/;

export default function LogViewer({ lines, status, mode, analysis = null }) {
  const { t, formatStatus } = useI18n();

  // default to timeline when agent mode or structured agent logs are detected
  const [viewOverride, setViewOverride] = useState(null);
  const hasStructuredSignals = useMemo(
    () => Array.isArray(lines) && lines.some((item) => STRUCTURED_HINT_PATTERN.test(String(item?.line || ""))),
    [lines]
  );

  const currentView = useMemo(() => {
    if (viewOverride) return viewOverride;
    return mode === "agent" || hasStructuredSignals ? "timeline" : "raw";
  }, [mode, viewOverride, hasStructuredSignals]);

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
        <AgentTimeline lines={lines} analysis={analysis} />
      ) : (
        <pre className="log-viewer">
          {lines.length
            ? lines.map((item) => `[${item.ts}] ${item.line}`).join("\n")
            : t("logViewer.empty")}
        </pre>
      )}
    </section>
  );
}
