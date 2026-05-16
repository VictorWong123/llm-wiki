import { Link } from "react-router-dom";
import { PreflightResultPanel } from "../components/PreflightResultPanel";
import { RecentViolations } from "../components/RecentViolations";
import { findViolation, featuredViolationId } from "../data";

export function MainPage() {
  const featured = findViolation(featuredViolationId);

  return (
    <>
      <h1>Redline Main Page</h1>
      <p>
        Redline helps agents write safer code by making <Link to="/rules">safety rules</Link> executable, observable, and fixable.
      </p>
      <p>
        Run a <Link to="/preflight">preflight check</Link> on your changes to catch issues before they reach production.
      </p>
      {featured ? <PreflightResultPanel report={featured} allowDownloads /> : null}
      <RecentViolations />
    </>
  );
}
