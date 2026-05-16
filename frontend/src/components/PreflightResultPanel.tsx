import { Link, useNavigate } from "react-router-dom";
import { featuredViolationId, type Violation } from "../data";
import { type PreflightReport, sqlDemo } from "../preflight";
import { CodeBlock } from "./CodeBlock";

type PanelData = Violation | PreflightReport;

interface PreflightResultPanelProps {
  title?: string;
  report: PanelData;
  allowDownloads?: boolean;
  onAcceptRewrite?: (report: PreflightReport) => void;
}

function isViolation(report: PanelData): report is Violation {
  return "ruleId" in report;
}

function downloadFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function PreflightResultPanel({ title = "Preflight Check Result", report, allowDownloads = false, onAcceptRewrite }: PreflightResultPanelProps) {
  const navigate = useNavigate();
  const id = report.id;
  const statusText = isViolation(report) ? "REDLINE TRIGGERED" : report.status;
  const ruleId = isViolation(report) ? report.ruleId : report.matchedRuleId;
  const ruleTitle = isViolation(report) ? report.ruleTitle : report.matchedRuleTitle;
  const unsafeCode = isViolation(report) ? report.unsafeCode : report.unsafeCode;
  const safeRewrite = isViolation(report) ? report.safeRewrite : report.safeRewrite;

  function handleJson() {
    downloadFile(`${id}.json`, JSON.stringify(report, null, 2), "application/json");
  }

  function handleHtml() {
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>${id}</title></head><body><h1>${statusText}</h1><p>${ruleId ?? "No matched rule"}</p><pre>${unsafeCode.replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char] ?? char)}</pre></body></html>`;
    downloadFile(`${id}.html`, html, "text/html");
  }

  function handleRerun() {
    navigate(`/preflight?demo=sql&content=${encodeURIComponent(sqlDemo)}`);
  }

  function formatTelemetry(value: unknown): string {
    if (typeof value === "string") {
      return value;
    }

    return JSON.stringify(value, null, 2);
  }

  const hasBackendTelemetry =
    !isViolation(report) &&
    Boolean(report.preflight_id || report.session_id || report.fast_path !== undefined || report.fingerprint || report.similar_memories?.length || report.memory_trace || report.recent_events?.length);

  return (
    <section className="result-panel">
      <h2>{title}</h2>
      <div className={`alert-banner ${statusText === "PASS" ? "pass" : "blocked"}`}>{statusText}</div>
      <dl className="metadata-grid">
        <div><dt>Check ID</dt><dd>{id}</dd></div>
        <div><dt>Project</dt><dd>{report.project}</dd></div>
        <div><dt>Branch</dt><dd>{report.branch}</dd></div>
        <div><dt>Triggered</dt><dd>{report.triggered}</dd></div>
        <div><dt>Duration</dt><dd>{report.duration}</dd></div>
        <div><dt>Status</dt><dd>{isViolation(report) ? report.status : report.status}</dd></div>
        <div><dt>Matched Rule</dt><dd>{ruleId ? <Link to={`/rules/${ruleId}`}>{ruleId}</Link> : "None"}</dd></div>
        <div><dt>Rule title</dt><dd>{ruleTitle ?? "No matching Redline rule"}</dd></div>
        <div><dt>Severity</dt><dd>{report.severity ?? "None"}</dd></div>
        <div><dt>Confidence</dt><dd>{report.confidence ?? "None"}</dd></div>
        <div><dt>Category</dt><dd>{report.category ?? "None"}</dd></div>
        <div><dt>Evidence file</dt><dd>{report.evidenceFile}</dd></div>
        <div><dt>Lines</dt><dd>{report.evidenceLines}</dd></div>
        {!isViolation(report) ? <div><dt>Source</dt><dd>{report.source === "backend" ? "Backend" : "Local fallback"}</dd></div> : null}
        {!isViolation(report) && report.preflight_id ? <div><dt>Preflight ID</dt><dd>{report.preflight_id}</dd></div> : null}
        {!isViolation(report) && report.session_id ? <div><dt>Session ID</dt><dd>{report.session_id}</dd></div> : null}
        {!isViolation(report) && report.fast_path !== undefined ? <div><dt>Fast path</dt><dd>{report.fast_path ? "true" : "false"}</dd></div> : null}
      </dl>
      {!isViolation(report) && report.fallbackReason ? <p className="status-note">Backend unavailable, using local preflight: {report.fallbackReason}</p> : null}
      {!isViolation(report) && <p>{report.evidence}</p>}
      {hasBackendTelemetry && !isViolation(report) ? (
        <section className="telemetry-panel" aria-label="Backend trace and memory">
          <h3>Backend Trace</h3>
          {report.fingerprint ? (
            <>
              <h4>Fingerprint</h4>
              <pre>{formatTelemetry(report.fingerprint)}</pre>
            </>
          ) : null}
          {report.similar_memories?.length ? (
            <>
              <h4>Similar memories</h4>
              <pre>{formatTelemetry(report.similar_memories)}</pre>
            </>
          ) : null}
          {report.memory_trace ? (
            <>
              <h4>Memory trace</h4>
              <pre>{formatTelemetry(report.memory_trace)}</pre>
            </>
          ) : null}
          {report.recent_events?.length ? (
            <>
              <h4>Recent session events</h4>
              <pre>{formatTelemetry(report.recent_events)}</pre>
            </>
          ) : null}
        </section>
      ) : null}
      <h3>Unsafe code</h3>
      <CodeBlock code={unsafeCode || "No unsafe code detected."} language="python" />
      <h3>Safe rewrite</h3>
      <CodeBlock code={safeRewrite || "No rewrite required."} language="python" />
      {!isViolation(report) && report.source === "backend" && report.matchedRuleId ? (
        <div className="action-row">
          <button type="button" onClick={() => onAcceptRewrite?.(report)} disabled={!onAcceptRewrite}>Accept Rewrite</button>
        </div>
      ) : null}
      {allowDownloads ? (
        <div className="action-row">
          <button type="button" onClick={handleJson}>Download JSON</button>
          <button type="button" onClick={handleHtml}>Download HTML</button>
          <Link to={`/violations/${featuredViolationId}`}>View Full Report</Link>
          <button type="button" onClick={handleRerun}>Re-run Check</button>
        </div>
      ) : null}
    </section>
  );
}
