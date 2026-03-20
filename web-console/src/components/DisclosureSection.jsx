import { useId, useState } from "react";
import AnimatedCollapse from "./AnimatedCollapse";

export default function DisclosureSection({
  title,
  subtitle,
  children,
  defaultOpen = false,
  aside = null,
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();

  return (
    <section className={`panel disclosure-panel ${open ? "is-open" : "is-collapsed"}`}>
      <button
        type="button"
        className="disclosure-summary"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        aria-controls={panelId}
      >
        <span className="disclosure-summary-copy">
          <span className="eyebrow">{subtitle}</span>
          <strong>{title}</strong>
        </span>
        <span className="disclosure-summary-meta">
          {aside ? <span className="text-xs font-medium text-slate-400">{aside}</span> : null}
          <span className={`disclosure-chevron ${open ? "is-open" : ""}`} aria-hidden="true">
            ⌄
          </span>
        </span>
      </button>
      <AnimatedCollapse id={panelId} open={open} className="disclosure-collapse">
        <div className="disclosure-body">{children}</div>
      </AnimatedCollapse>
    </section>
  );
}
