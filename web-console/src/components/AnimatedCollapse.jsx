export default function AnimatedCollapse({
  open,
  children,
  className = "",
  innerClassName = "",
  id,
}) {
  return (
    <div
      id={id}
      className={`animated-collapse ${open ? "is-open" : "is-closed"} ${className}`.trim()}
      aria-hidden={!open}
    >
      <div className={`animated-collapse-inner ${innerClassName}`.trim()}>{children}</div>
    </div>
  );
}
