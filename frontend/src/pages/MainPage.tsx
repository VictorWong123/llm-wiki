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
        <strong>Redline</strong> is a living safety wiki and preflight layer for AI coding agents.
        It sits between the agent and the codebase, enforcing <Link to="/rules">security rules</Link> in
        real time so unsafe changes never reach production.
      </p>
      <p>
        Run a <Link to="/preflight">preflight check</Link> on your changes to catch SQL injection, XSS,
        command injection, secrets exposure, and other vulnerabilities before they ship. Every blocked
        result includes a safe rewrite suggestion and links to the matched rule.
      </p>
      <p>
        The backend uses deterministic detectors, Redis-backed reflex memory, and a knowledge graph to
        continuously learn from past violations. Read more on the <Link to="/about">About Redline</Link> page.
      </p>
      {featured ? <PreflightResultPanel report={featured} allowDownloads /> : null}
      <RecentViolations />
    </>
  );
}
