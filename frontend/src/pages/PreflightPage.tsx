import { FormEvent, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { PreflightResultPanel } from "../components/PreflightResultPanel";
import { type InputType } from "../data";
import { acceptRewrite, promptDemo, runPreflight, sqlDemo, type PreflightReport } from "../preflight";

const emptyReport = "";

export function PreflightPage() {
  const [params] = useSearchParams();
  const [inputType, setInputType] = useState<InputType>((params.get("mode") === "evidence" ? "untrusted_content" : "code") as InputType);
  const [content, setContent] = useState(params.get("content") ?? emptyReport);
  const [report, setReport] = useState<PreflightReport | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [acceptStatus, setAcceptStatus] = useState<string | null>(null);

  useEffect(() => {
    let isActive = true;

    if (params.get("demo") === "sql") {
      setInputType("code");
      setContent(sqlDemo);
      setIsRunning(true);
      setAcceptStatus(null);
      runPreflight(sqlDemo, "code")
        .then((nextReport) => {
          if (isActive) {
            setReport(nextReport);
          }
        })
        .finally(() => {
          if (isActive) {
            setIsRunning(false);
          }
        });
    }

    return () => {
      isActive = false;
    };
  }, [params]);

  async function runCheck(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    setIsRunning(true);
    setAcceptStatus(null);

    try {
      setReport(await runPreflight(content, inputType));
    } finally {
      setIsRunning(false);
    }
  }

  async function handleAcceptRewrite(reportToAccept: PreflightReport) {
    setAcceptStatus("Accepting rewrite...");

    try {
      await acceptRewrite(reportToAccept);
      setAcceptStatus("Rewrite accepted.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Backend unavailable";
      setAcceptStatus(`Accept failed: ${message}`);
    }
  }

  function loadSqlDemo() {
    setInputType("code");
    setContent(sqlDemo);
    setReport(null);
  }

  function loadPromptDemo() {
    setInputType("untrusted_content");
    setContent(promptDemo);
    setReport(null);
  }

  return (
    <>
      <h1>New Preflight Check</h1>
      <form className="preflight-form" onSubmit={runCheck}>
        <fieldset>
          <legend>Input type</legend>
          <label><input checked={inputType === "code"} name="inputType" onChange={() => setInputType("code")} type="radio" /> code</label>
          <label><input checked={inputType === "untrusted_content"} name="inputType" onChange={() => setInputType("untrusted_content")} type="radio" /> untrusted content</label>
          <label><input checked={inputType === "tool_plan"} name="inputType" onChange={() => setInputType("tool_plan")} type="radio" /> tool plan</label>
        </fieldset>
        <label className="textarea-label" htmlFor="preflight-content">Content</label>
        <textarea id="preflight-content" value={content} onChange={(event) => setContent(event.target.value)} rows={14} />
        <div className="action-row">
          <button type="submit" disabled={isRunning}>{isRunning ? "Running..." : "Run Preflight"}</button>
          <button type="button" onClick={loadSqlDemo}>Load SQL Injection Demo</button>
          <button type="button" onClick={loadPromptDemo}>Load Prompt Injection Demo</button>
        </div>
      </form>
      {acceptStatus ? <p className="status-note">{acceptStatus}</p> : null}
      {report ? <PreflightResultPanel report={report} onAcceptRewrite={handleAcceptRewrite} /> : null}
    </>
  );
}
