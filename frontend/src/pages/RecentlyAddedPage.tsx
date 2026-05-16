import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { regressionTests, rules, violations } from "../data";
import { fetchRecentWikiEntries, type RecentWikiEntry } from "../wiki";

const fallbackEntries: RecentWikiEntry[] = [
  ...violations.map((violation) => ({
    id: violation.id,
    kind: "observed_violation" as const,
    title: `Observed violation: ${violation.ruleId}`,
    summary: violation.summary,
    created_at: violation.triggered,
    severity: violation.severity.toLowerCase(),
    status: "REDLINE TRIGGERED",
    matched_rule_id: violation.ruleId,
    source_path: `wiki/observed_violations/${violation.id}.json`,
    app_path: `/violations/${violation.id}`
  })),
  ...regressionTests.slice(0, 3).map((test) => ({
    id: test.id,
    kind: "regression_test" as const,
    title: `Regression test: ${test.ruleId}`,
    summary: test.sample,
    created_at: "May 25, 2025 15:41 UTC",
    status: test.expectedStatus,
    matched_rule_id: test.ruleId,
    source_path: `wiki/regression_tests/${test.id}.json`,
    app_path: "/regression-tests"
  })),
  ...rules.slice(0, 3).map((rule) => ({
    id: rule.id,
    kind: "safety_rule" as const,
    title: rule.title,
    summary: rule.ruleText,
    created_at: "May 25, 2025 09:00 UTC",
    severity: rule.severity.toLowerCase(),
    matched_rule_id: rule.id,
    source_path: `wiki/safety_rules/${rule.id}.json`,
    app_path: `/rules/${rule.id}`
  }))
];

function kindLabel(kind: RecentWikiEntry["kind"]) {
  return kind.replace(/_/g, " ");
}

function dateLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return value;
  }
  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  });
}

function ruleLink(ruleId: string) {
  return <Link to={`/rules/${ruleId}`}>{ruleId}</Link>;
}

export function RecentlyAddedPage() {
  const [entries, setEntries] = useState<RecentWikiEntry[]>(fallbackEntries);
  const [source, setSource] = useState<"live" | "fallback">("fallback");
  const [loading, setLoading] = useState(false);

  function loadLiveEntries() {
    setLoading(true);
    return fetchRecentWikiEntries()
      .then((nextEntries) => {
        if (nextEntries.length) {
          setEntries(nextEntries);
          setSource("live");
        }
      })
      .catch(() => {
        setSource("fallback");
      })
      .finally(() => {
        setLoading(false);
      });
  }

  useEffect(() => {
    let cancelled = false;

    setLoading(true);
    fetchRecentWikiEntries()
      .then((nextEntries) => {
        if (!cancelled && nextEntries.length) {
          setEntries(nextEntries);
          setSource("live");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSource("fallback");
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <h1>Recently Added</h1>
      <p>
        New wiki knowledge appears here after an agent logs a novel security finding or accepts a safe rewrite that creates violation and regression memory.
      </p>
      <p>
        <button type="button" onClick={loadLiveEntries} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh live wiki"}
        </button>
      </p>
      {source === "fallback" ? (
        <p className="page-note">Showing local demo entries until the Redline API is available.</p>
      ) : null}
      <table className="recently-added-table">
        <thead>
          <tr>
            <th>Added</th>
            <th>Type</th>
            <th>Knowledge</th>
            <th>Rule</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr id={entry.id} key={`${entry.kind}:${entry.id}`}>
              <td>{dateLabel(entry.created_at)}</td>
              <td>{kindLabel(entry.kind)}</td>
              <td>
                <Link to={entry.app_path}>{entry.title}</Link>
                <p className="table-summary">{entry.summary}</p>
                {entry.severity || entry.status ? (
                  <p className="table-meta">{[entry.severity, entry.status].filter(Boolean).join(" / ")}</p>
                ) : null}
              </td>
              <td>{entry.matched_rule_id ? ruleLink(entry.matched_rule_id) : "n/a"}</td>
              <td><code>{entry.source_path}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
