import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { regressionTests } from "../data";
import { runLocalPreflight } from "../preflight";

interface TestRun {
  id: string;
  status: "PASS" | "FAIL";
  actual: string;
}

export function RegressionTestsPage() {
  const [params] = useSearchParams();
  const [runs, setRuns] = useState<TestRun[]>([]);

  function runTests() {
    setRuns(
      regressionTests.map((test) => {
        const report = runLocalPreflight(test.sample, test.inputType);
        return {
          id: test.id,
          status: report.status === test.expectedStatus ? "PASS" : "FAIL",
          actual: report.status
        };
      })
    );
  }

  useEffect(() => {
    if (params.get("run") === "true") {
      runTests();
    }
  }, [params]);

  return (
    <>
      <h1>Regression Tests</h1>
      <p>Generated tests prove the local detector keeps blocking known unsafe patterns.</p>
      <button type="button" onClick={runTests}>Run Regression Tests</button>
      <table>
        <thead>
          <tr>
            <th>Test</th>
            <th>Rule</th>
            <th>Expected</th>
            <th>Last run</th>
          </tr>
        </thead>
        <tbody>
          {regressionTests.map((test) => {
            const run = runs.find((item) => item.id === test.id);
            return (
              <tr key={test.id}>
                <td>{test.title}</td>
                <td><Link to={`/rules/${test.ruleId}`}>{test.ruleId}</Link></td>
                <td>{test.expectedStatus}</td>
                <td>{run ? `${run.status} (${run.actual})` : "Not run"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}
