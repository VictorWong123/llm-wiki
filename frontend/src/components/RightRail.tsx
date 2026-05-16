import { Link } from "react-router-dom";
import { WikiBox } from "./WikiBox";

export function RightRail() {
  return (
    <aside className="right-rail" aria-label="Related navigation">
      <WikiBox title="Quick Links">
        <ul className="plain-list">
          <li><Link to="/preflight">New Preflight Check</Link></li>
          <li><Link to="/rules">All Safety Rules</Link></li>
          <li><Link to="/unsafe-patterns">All Unsafe Patterns</Link></li>
          <li><Link to="/safe-patterns">All Safe Patterns</Link></li>
          <li><Link to="/preflight?mode=evidence">Upload Evidence</Link></li>
          <li><Link to="/regression-tests?run=true">Run Regression Tests</Link></li>
        </ul>
      </WikiBox>
      <WikiBox title="Featured Rule">
        <p><strong>SQLI-001</strong></p>
        <p>Avoid string-concatenated SQL with untrusted input.</p>
        <ul className="plain-list">
          <li><Link to="/rules/SQLI-001">View Rule</Link></li>
          <li><Link to="/rules/SQLI-001#examples">Examples</Link></li>
          <li><Link to="/rules/SQLI-001#tests">Tests</Link></li>
        </ul>
      </WikiBox>
      <WikiBox title="About Redline">
        <p>Redline is an open safety layer for AI coding agents.</p>
        <ul className="plain-list">
          <li><Link to="/docs">Docs</Link></li>
          <li><Link to="/contribute">Contribute</Link></li>
          <li><Link to="/changelog">Changelog</Link></li>
        </ul>
        <p>License: Apache-2.0</p>
      </WikiBox>
    </aside>
  );
}
