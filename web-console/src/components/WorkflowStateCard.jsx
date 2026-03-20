function normalizeItems(items) {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.filter(Boolean);
}

export default function WorkflowStateCard({
  className = "",
  tone = "default",
  eyebrow,
  title,
  description,
  badge = null,
  chips = [],
  note = "",
  actions = [],
  children = null,
}) {
  const chipItems = normalizeItems(chips);
  const actionItems = normalizeItems(actions);
  const rootClassName = ["workflow-state-card", className, tone !== "default" ? `is-${tone}` : ""]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={rootClassName}>
      <div className="workflow-state-head">
        <div>
          {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
          {title ? <h4>{title}</h4> : null}
          {description ? <p className="workflow-state-copy">{description}</p> : null}
        </div>
        {badge?.label ? (
          <span className={["panel-chip", badge.tone ? `is-${badge.tone}` : "", badge.className || ""].filter(Boolean).join(" ")}>
            {badge.label}
          </span>
        ) : null}
      </div>

      {chipItems.length ? (
        <div className="workflow-state-chip-list">
          {chipItems.map((item, index) => {
            const normalized = typeof item === "string" ? { label: item } : item;
            return (
              <span
                key={`${normalized.label}-${index}`}
                className={["panel-chip", normalized.tone ? `is-${normalized.tone}` : "", normalized.className || ""].filter(Boolean).join(" ")}
              >
                {normalized.label}
              </span>
            );
          })}
        </div>
      ) : null}

      {note ? <div className="workflow-state-note">{note}</div> : null}
      {children}

      {actionItems.length ? (
        <div className="workflow-state-actions">
          {actionItems.map((item, index) => (
            <button
              key={`${item.label}-${index}`}
              type={item.type || "button"}
              className={item.className || "ghost-button"}
              onClick={item.onClick}
              disabled={item.disabled}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
    </section>
  );
}
