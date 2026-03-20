import { useMemo, useState } from "react";
import { useI18n } from "../i18n";
import AnimatedCollapse from "./AnimatedCollapse";

const STRUCTURED_EVENT_PATTERN = /(?:^|-\s+)\[([^\]]+)\]\s+([^|]+?)\s+\|\s+([^|]+?)\s+\|\s*(.*)$/;
const TIMELINE_LINE_LIMIT = 1200;

function safeJsonParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function normalizeLower(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeComparableTarget(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    if (text.includes("://")) {
      const parsed = new URL(text);
      const fallbackPort = parsed.protocol === "https:" ? "443" : parsed.protocol === "http:" ? "80" : "";
      const port = String(parsed.port || fallbackPort || "").trim();
      const pathname = String(parsed.pathname || "/").replace(/\/+$/, "") || "/";
      return `${parsed.protocol}//${parsed.hostname.toLowerCase()}:${port}${pathname}`;
    }
  } catch {
    // fall back to string normalization below
  }
  return text.replace(/\/+$/, "").toLowerCase();
}

function sameComparableTarget(left, right) {
  const leftValue = normalizeComparableTarget(left);
  const rightValue = normalizeComparableTarget(right);
  if (!leftValue || !rightValue) return false;
  return leftValue === rightValue;
}

function shortText(value, maxLen = 220) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen)}...`;
}

function normalizeStatus(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return "info";
  if (["completed", "success", "passed", "ok"].includes(raw)) return "completed";
  if (["start", "running", "in_progress"].includes(raw)) return "running";
  if (["error", "failed", "warning", "warn", "blocked"].includes(raw)) return "error";
  return raw;
}

function tt(language, english, chinese) {
  return language === "zh-CN" ? chinese : english;
}

function parseStructuredEvent(rawLine) {
  const line = String(rawLine || "").trim();
  if (!line) return null;
  const match = line.match(STRUCTURED_EVENT_PATTERN);
  if (!match) return null;
  const pluginId = String(match[1] || "").trim();
  const action = String(match[2] || "").trim().toLowerCase();
  const rawStatus = String(match[3] || "").trim();
  const detail = String(match[4] || "").trim();
  if (!pluginId || !action) return null;
  return {
    pluginId,
    action,
    status: normalizeStatus(rawStatus),
    rawStatus,
    detail,
  };
}

function parseActionDetail(detail) {
  const output = {
    reasoning: "",
    target: "",
    cmdArgs: "",
    actionRef: "",
    options: {},
  };
  const payload = safeJsonParse(detail);
  if (payload && typeof payload === "object") {
    if (typeof payload.reason === "string") output.reasoning = payload.reason;
    if (typeof payload.target === "string") output.target = payload.target;
    if (payload.options && typeof payload.options === "object" && !Array.isArray(payload.options)) {
      output.options = payload.options;
      output.cmdArgs = Object.entries(payload.options)
        .slice(0, 12)
        .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
        .join(" ");
    }
    if (typeof payload.action_id === "string") {
      output.actionRef = payload.action_id;
    }
  }
  if (!output.actionRef) {
    const actionRefMatch = String(detail || "").match(/^(A\d+)\b/i);
    if (actionRefMatch) output.actionRef = String(actionRefMatch[1] || "").trim();
  }
  if (!output.target) {
    const targetMatch = String(detail || "").match(/(?:^|[\s,])target[:=]\s*([^\s,]+)/i);
    if (targetMatch) output.target = String(targetMatch[1] || "").trim();
  }
  return output;
}

function parseSignalPayload(detail) {
  const payload = safeJsonParse(detail);
  if (payload && typeof payload === "object") {
    return payload;
  }
  return { summary: String(detail || "").trim() };
}

function selectRankingCandidate(block) {
  const items = Array.isArray(block?.items) ? block.items : [];
  if (!items.length) return null;
  return items.find((item) => item?.selected) || items[0];
}

function matchRankingBlock(event, rankingBlocks) {
  const safeBlocks = Array.isArray(rankingBlocks) ? rankingBlocks : [];
  if (!safeBlocks.length || event?.type !== "action") {
    return null;
  }

  const eventTool = normalizeLower(event.pluginId);
  const eventTarget = normalizeComparableTarget(event.target);
  const eventOptions = event.options && typeof event.options === "object" ? event.options : {};
  const eventComponent = normalizeLower(eventOptions.component);
  const eventService = normalizeLower(eventOptions.service);
  const eventVersion = String(eventOptions.version || "").trim();
  const eventSelectedCandidate = normalizeUpper(
    eventOptions.cve_id || (Array.isArray(eventOptions.cve_ids) ? eventOptions.cve_ids[0] : "")
  );

  let bestBlock = null;
  let bestScore = -1;

  for (const block of safeBlocks) {
    if (!block || typeof block !== "object") continue;
    if (normalizeLower(block.tool) !== eventTool) continue;

    let score = 1;
    if (eventTarget && sameComparableTarget(eventTarget, block.target)) {
      score += 6;
    } else if (eventTarget && block.target) {
      score -= 3;
    }

    if (eventComponent && normalizeLower(block.component) === eventComponent) score += 3;
    if (eventService && normalizeLower(block.service) === eventService) score += 2;
    if (eventVersion && String(block.version || "").trim() === eventVersion) score += 1;

    const selectedCandidate = normalizeUpper(block.selected_candidate);
    const candidate = selectRankingCandidate(block);
    if (eventSelectedCandidate && selectedCandidate && eventSelectedCandidate === selectedCandidate) {
      score += 4;
    }
    if (eventSelectedCandidate && candidate && normalizeUpper(candidate.cve_id) === eventSelectedCandidate) {
      score += 2;
    }

    if (score > bestScore) {
      bestBlock = block;
      bestScore = score;
    }
  }

  return bestScore > 0 ? bestBlock : null;
}

function normalizeUpper(value) {
  return String(value || "").trim().toUpperCase();
}

function attachRankingContext(events, rankingBlocks) {
  return events.map((event) => {
    if (event?.type !== "action") return event;
    const rankingBlock = matchRankingBlock(event, rankingBlocks);
    if (!rankingBlock) return event;
    return {
      ...event,
      rankingBlock,
    };
  });
}

function parseLogToEvents(lines, rankingBlocks = []) {
  const events = [];
  const openActionByPlugin = new Map();

  const getLatestOpenAction = () => {
    for (let i = events.length - 1; i >= 0; i -= 1) {
      const node = events[i];
      if (node?.type === "action" && node.status === "running") {
        return node;
      }
    }
    return null;
  };

  const attachRawLineToAction = (item) => {
    const actionNode = getLatestOpenAction();
    if (!actionNode) return false;
    actionNode.logs.push(item);
    return true;
  };

  for (let idx = 0; idx < (Array.isArray(lines) ? lines.length : 0); idx += 1) {
    const item = lines[idx];
    const raw = String(item?.line || "").trim();
    if (!raw) continue;

    const structured = parseStructuredEvent(raw);
    if (structured) {
      const { pluginId, action, status, rawStatus, detail } = structured;
      const source = pluginId.toLowerCase();

      if (action === "action_start") {
        const parsedDetail = parseActionDetail(detail);
        const actionNode = {
          id: `${item.ts}-${idx}-action-start`,
          type: "action",
          pluginId,
          startTs: item.ts,
          endTs: null,
          status: "running",
          rawStatus,
          detail,
          reasoning: parsedDetail.reasoning,
          target: parsedDetail.target,
          cmdArgs: parsedDetail.cmdArgs,
          actionRef: parsedDetail.actionRef,
          options: parsedDetail.options,
          resultSummary: "",
          logs: [],
        };
        openActionByPlugin.set(source, actionNode);
        events.push(actionNode);
        continue;
      }

      if (action === "action_end") {
        const actionNode = openActionByPlugin.get(source) || getLatestOpenAction();
        if (actionNode) {
          actionNode.status = status === "running" ? "completed" : status;
          actionNode.rawStatus = rawStatus;
          actionNode.endTs = item.ts;
          actionNode.resultSummary = detail;
          openActionByPlugin.delete(source);
        } else {
          events.push({
            id: `${item.ts}-${idx}-signal-action-end`,
            type: "signal",
            ts: item.ts,
            pluginId,
            action,
            status,
            rawStatus,
            detail,
          });
        }
        continue;
      }

      if ((source === "agent" || source === "orchestrator") && action === "run_start") {
        events.push({
          id: `${item.ts}-${idx}-run-start`,
          type: "run_start",
          ts: item.ts,
          pluginId,
          status,
          rawStatus,
          detail,
        });
        continue;
      }

      if ((source === "agent" || source === "orchestrator") && action === "phase_transition") {
        events.push({
          id: `${item.ts}-${idx}-phase`,
          type: "phase_transition",
          ts: item.ts,
          pluginId,
          status,
          rawStatus,
          phaseName: detail,
          detail,
        });
        continue;
      }

      if ((source === "agent" || source === "orchestrator") && ["thought", "observation", "strategy_shift", "approval_pending", "loop_break"].includes(action)) {
        events.push({
          id: `${item.ts}-${idx}-${action}`,
          type: action,
          ts: item.ts,
          pluginId,
          status,
          rawStatus,
          detail,
          payload: parseSignalPayload(detail),
        });
        continue;
      }

      if ((source === "agent" || source === "orchestrator") && ["run_end", "run_stop", "iteration_stop"].includes(action)) {
        events.push({
          id: `${item.ts}-${idx}-run-end`,
          type: "run_end",
          ts: item.ts,
          pluginId,
          status,
          rawStatus,
          action,
          detail,
        });
        continue;
      }

      const activeAction = openActionByPlugin.get(source);
      if (activeAction) {
        activeAction.logs.push(item);
      } else {
        events.push({
          id: `${item.ts}-${idx}-signal`,
          type: "signal",
          ts: item.ts,
          pluginId,
          action,
          status,
          rawStatus,
          detail,
        });
      }
      continue;
    }

    if (raw.startsWith("$ ")) {
      events.push({
        id: `${item.ts}-${idx}-command`,
        type: "command",
        ts: item.ts,
        command: raw.slice(2),
      });
      continue;
    }

    if (raw.includes("[web] starting process")) {
      events.push({
        id: `${item.ts}-${idx}-web-start`,
        type: "run_start",
        ts: item.ts,
        pluginId: "web",
        status: "running",
        rawStatus: "start",
        detail: "web process started",
      });
      continue;
    }

    if (raw.includes("[web] process exited")) {
      events.push({
        id: `${item.ts}-${idx}-web-exit`,
        type: "run_end",
        ts: item.ts,
        pluginId: "web",
        status: "completed",
        rawStatus: "exit",
        action: "process_exit",
        detail: raw,
      });
      continue;
    }

    if (!attachRawLineToAction(item)) {
      if (
        raw.includes("LLM request") ||
        raw.includes("LLM router enabled") ||
        raw.includes("Agent decision summary") ||
        raw.includes("Action plan:") ||
        raw.includes("History:") ||
        raw.includes("State:") ||
        raw.includes("Findings:")
      ) {
        events.push({
          id: `${item.ts}-${idx}-note`,
          type: "note",
          ts: item.ts,
          text: raw,
        });
      }
    }
  }

  if (events.length === 0) {
    return (Array.isArray(lines) ? lines : []).slice(-60).map((item, idx) => ({
      id: `${item.ts}-${idx}-raw`,
      type: "note",
      ts: item.ts,
      text: String(item?.line || ""),
    }));
  }

  return attachRankingContext(events, rankingBlocks);
}

function statusText(status, t) {
  if (status === "running") return t("agentTimeline.actionRunning");
  if (status === "completed") return t("agentTimeline.actionCompleted");
  if (status === "error") return t("agentTimeline.actionError");
  return status || "info";
}

function RankingExplanation({ block, t }) {
  const selectedCandidate = selectRankingCandidate(block);
  const selectedTemplates = Array.isArray(block?.selected_templates) ? block.selected_templates : [];
  const reasons = Array.isArray(selectedCandidate?.reasons) ? selectedCandidate.reasons : [];
  const protocolTags = Array.isArray(selectedCandidate?.template_capability?.protocol_tags)
    ? selectedCandidate.template_capability.protocol_tags
    : [];

  return (
    <div className="timeline-ranking-card">
      <div className="timeline-ranking-title">{t("agentTimeline.whySelected")}</div>
      <div className="timeline-ranking-meta">
        <span>
          {t("agentTimeline.selectedCandidate")}: <strong>{block?.selected_candidate || selectedCandidate?.cve_id || "-"}</strong>
        </span>
        {block?.component ? (
          <span>
            {t("agentTimeline.component")}: <strong>{block.component}</strong>
          </span>
        ) : null}
        {block?.service ? (
          <span>
            {t("agentTimeline.service")}: <strong>{block.service}</strong>
          </span>
        ) : null}
      </div>
      {selectedTemplates.length ? (
        <div className="timeline-ranking-templates">
          <span className="timeline-ranking-label">{t("agentTimeline.selectedTemplates")}</span>
          {selectedTemplates.slice(0, 6).map((item) => (
            <span key={`${block?.tool || "tool"}-${item}`} className="timeline-ranking-chip">
              {item}
            </span>
          ))}
        </div>
      ) : null}
      {protocolTags.length ? (
        <div className="timeline-ranking-templates">
          <span className="timeline-ranking-label">{t("agentTimeline.protocolTags")}</span>
          {protocolTags.slice(0, 6).map((item) => (
            <span key={`${selectedCandidate?.cve_id || "candidate"}-${item}`} className="timeline-ranking-chip is-muted">
              {item}
            </span>
          ))}
        </div>
      ) : null}
      <div className="timeline-ranking-reasons">
        {reasons.length ? (
          reasons.slice(0, 4).map((reason) => (
            <div key={`${block?.tool || "tool"}-${reason}`} className="timeline-ranking-reason">
              {reason}
            </div>
          ))
        ) : (
          <div className="timeline-ranking-reason is-empty">{t("agentTimeline.noRankingReason")}</div>
        )}
      </div>
    </div>
  );
}

function ActionNode({ event, t, language }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetails = Boolean(event.cmdArgs || event.logs.length > 0);
  const detailPanelId = `${event.id}-details`;
  const statusClass =
    event.status === "running" ? "is-running" : event.status === "completed" ? "is-completed" : "is-error";
  const HeaderTag = hasDetails ? "button" : "div";
  const toggleLabel = expanded ? tt(language, "Hide details", "\u6536\u8d77\u8be6\u60c5") : t("agentTimeline.toggleDetails");

  return (
    <div className={`timeline-node action-node ${statusClass}`}>
      <div className="node-icon">
        {event.status === "running" ? <div className="timeline-pulse" /> : event.status === "completed" ? "OK" : "ERR"}
      </div>
      <div className="node-content">
        <HeaderTag
          {...(hasDetails
            ? {
              type: "button",
              className: "node-header node-header-button",
              onClick: () => setExpanded((current) => !current),
              "aria-expanded": expanded,
              "aria-controls": detailPanelId,
            }
            : { className: "node-header" })}
        >
          <span className="node-title">
            <span className="plugin-tag">[{event.pluginId}]</span>
            <span className="node-kind">{tt(language, "tool", "\u5de5\u5177")}</span>
            {event.target ? <span className="target-tag">{event.target}</span> : null}
          </span>
          <span className="node-meta">
            <span className="status-label">{statusText(event.status, t)}</span>
            <span className="ts-label">{event.startTs}</span>
            {hasDetails ? (
              <span className={`collapse-indicator ${expanded ? "is-open" : ""}`} aria-hidden="true">
                ⌄
              </span>
            ) : null}
          </span>
        </HeaderTag>

        {event.reasoning ? <div className="node-reasoning">{shortText(event.reasoning, 320)}</div> : null}

        {event.rankingBlock ? <RankingExplanation block={event.rankingBlock} t={t} /> : null}

        {event.resultSummary ? <div className="node-summary">{shortText(event.resultSummary, 400)}</div> : null}

        {hasDetails ? (
          <button type="button" className={`toggle-logs-btn ${expanded ? "is-active" : ""}`} onClick={() => setExpanded((current) => !current)}>
            {toggleLabel}
            {event.logs.length > 0 ? ` (${event.logs.length} ${tt(language, "lines", "\u884c")})` : ""}
          </button>
        ) : null}

        {hasDetails ? (
          <AnimatedCollapse id={detailPanelId} open={expanded} className="timeline-detail-collapse">
            <>
              {event.cmdArgs ? (
                <div className="node-cmd">
                  <span className="cmd-prompt">{t("agentTimeline.terminalCommand")}</span>
                  <code>
                    {event.pluginId} {event.cmdArgs}
                  </code>
                </div>
              ) : null}

              {event.logs.length > 0 ? (
                <pre className="node-logs">
                  {event.logs.map((line, idx) => (
                    <div key={`${line.ts}-${idx}`} className="log-line">
                      <span className="log-ts">{line.ts}</span> {line.line}
                    </div>
                  ))}
                </pre>
              ) : null}
            </>
          </AnimatedCollapse>
        ) : null}
      </div>
    </div>
  );
}

function GenericNode({ icon, title, detail, ts, className = "" }) {
  return (
    <div className={`timeline-node ${className}`.trim()}>
      <div className="node-icon">{icon}</div>
      <div className="node-content">
        <div className="node-header">
          <div className="node-title">
            <span className="plugin-tag">{title}</span>
          </div>
          <div className="node-meta">
            <span className="ts-label">{ts}</span>
          </div>
        </div>
        {detail ? <div className="node-detail">{detail}</div> : null}
      </div>
    </div>
  );
}

function ReasoningNode({ event, language }) {
  const payload = event.payload || {};
  const summary = shortText(payload.summary || event.detail || "", 320);
  const meta = [
    payload.phase ? `${tt(language, "phase", "\u9636\u6bb5")}: ${payload.phase}` : "",
    payload.tool_name ? `${tt(language, "tool", "\u5de5\u5177")}: ${payload.tool_name}` : "",
    payload.target ? shortText(payload.target, 80) : "",
  ]
    .filter(Boolean)
    .join(" | ");

  const config = {
    thought: { icon: "TH", title: tt(language, "Thought", "\u601d\u8003"), className: "thought-node" },
    observation: { icon: "OB", title: tt(language, "Observation", "\u89c2\u5bdf"), className: "observation-node" },
    strategy_shift: { icon: "SW", title: tt(language, "Strategy shift", "\u7b56\u7565\u8c03\u6574"), className: "strategy-node" },
    approval_pending: { icon: "AP", title: tt(language, "Approval required", "\u7b49\u5f85\u5ba1\u6279"), className: "approval-node" },
    loop_break: { icon: "LB", title: tt(language, "Loop break", "\u5faa\u73af\u8df3\u51fa"), className: "loop-break-node" },
  }[event.type] || { icon: "*", title: event.type, className: "signal-node" };

  return (
    <div className={`timeline-node ${config.className}`.trim()}>
      <div className="node-icon">{config.icon}</div>
      <div className="node-content">
        <div className="node-header">
          <div className="node-title">
            <span className="plugin-tag">{config.title}</span>
          </div>
          <div className="node-meta">
            <span className="status-label">{event.rawStatus || event.status || tt(language, "info", "\u4fe1\u606f")}</span>
            <span className="ts-label">{event.ts}</span>
          </div>
        </div>
        {summary ? <div className="node-detail">{summary}</div> : null}
        {meta ? <div className="table-meta">{meta}</div> : null}
      </div>
    </div>
  );
}

export default function AgentTimeline({ lines, totalLineCount = 0, analysis = null }) {
  const { t, language } = useI18n();
  const rankingBlocks = useMemo(
    () => (Array.isArray(analysis?.verification_ranking) ? analysis.verification_ranking : []),
    [analysis]
  );
  const visibleLines = useMemo(
    () => (Array.isArray(lines) && lines.length > TIMELINE_LINE_LIMIT ? lines.slice(-TIMELINE_LINE_LIMIT) : Array.isArray(lines) ? lines : []),
    [lines],
  );
  const hiddenLineCount = Math.max(0, (Number(totalLineCount) || visibleLines.length) - visibleLines.length);
  const events = useMemo(() => parseLogToEvents(visibleLines, rankingBlocks), [visibleLines, rankingBlocks]);

  if (!Array.isArray(lines) || lines.length === 0) {
    return <div className="empty-state">{t("agentTimeline.noEvents")}</div>;
  }

  return (
    <div className="agent-timeline-wrapper">
      {hiddenLineCount > 0 ? (
        <div className="mb-3 text-xs font-medium text-slate-500">
          {language === "zh-CN"
            ? `为保证流畅度，时间线仅渲染最近 ${visibleLines.length} / ${totalLineCount} 条日志；完整内容可切到原始日志视图。`
            : `Timeline is rendering the latest ${visibleLines.length} of ${totalLineCount} log lines for performance. Use raw view for the full log.`}
        </div>
      ) : null}
      <div className="timeline-track" />
      <div className="timeline-events">
        {events.map((event, idx) => {
          if (event.type === "action") {
            return <ActionNode key={event.id || idx} event={event} t={t} language={language} />;
          }

          if (["thought", "observation", "strategy_shift", "approval_pending", "loop_break"].includes(event.type)) {
            return <ReasoningNode key={event.id || idx} event={event} language={language} />;
          }

          if (event.type === "run_start") {
            return (
              <GenericNode
                key={event.id || idx}
                icon="RUN"
                className="run-node"
                title={`[${event.pluginId}] ${tt(language, "run start", "\u8fd0\u884c\u5f00\u59cb")}`}
                detail={shortText(event.detail, 320)}
                ts={event.ts}
              />
            );
          }

          if (event.type === "phase_transition") {
            return (
              <GenericNode
                key={event.id || idx}
                icon="#"
                className="phase-node"
                title={t("agentTimeline.phaseTransition")}
                detail={event.phaseName || event.detail || "-"}
                ts={event.ts}
              />
            );
          }

          if (event.type === "run_end") {
            return (
              <GenericNode
                key={event.id || idx}
                icon="END"
                className="end-node"
                title={`[${event.pluginId}] ${event.action || tt(language, "run end", "\u8fd0\u884c\u7ed3\u675f")}`}
                detail={shortText(event.detail, 320)}
                ts={event.ts}
              />
            );
          }

          if (event.type === "command") {
            return (
              <GenericNode
                key={event.id || idx}
                icon="$"
                className="command-node"
                title={tt(language, "command", "\u547d\u4ee4")}
                detail={shortText(event.command, 320)}
                ts={event.ts}
              />
            );
          }

          if (event.type === "signal") {
            return (
              <GenericNode
                key={event.id || idx}
                icon="*"
                className="signal-node"
                title={`[${event.pluginId}] ${event.action} (${event.rawStatus || event.status})`}
                detail={shortText(event.detail, 260)}
                ts={event.ts}
              />
            );
          }

          return (
              <GenericNode
                key={event.id || idx}
                icon="i"
                className="note-node"
                title={tt(language, "note", "\u5907\u6ce8")}
                detail={shortText(event.text || event.detail || "", 260)}
                ts={event.ts}
              />
          );
        })}
      </div>
    </div>
  );
}
