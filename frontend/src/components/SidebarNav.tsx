import { Link } from "react-router-dom";

const links = [
  ["Main Page", "/"],
  ["New Preflight Check", "/preflight"],
  ["Safety Rules", "/rules"],
  ["Unsafe Patterns", "/unsafe-patterns"],
  ["Safe Patterns", "/safe-patterns"],
  ["Observed Violations", "/violations"],
  ["Regression Tests", "/regression-tests"],
  ["Recently Added", "/recently-added"],
  ["Recent Changes", "/recent-changes"],
  ["About Redline", "/about"]
];

export function SidebarNav() {
  return (
    <aside className="left-sidebar" aria-label="Wiki navigation">
      <nav>
        {links.map(([label, path], index) => (
          <Link className={index === links.length - 1 ? "after-divider" : undefined} key={path} to={path}>
            {label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}
