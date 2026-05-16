import { Link } from "react-router-dom";
import { violations } from "../data";

export function ViolationsPage() {
  return (
    <>
      <h1>Observed Violations</h1>
      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th>Rule</th>
            <th>Project</th>
            <th>Severity</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody>
          {violations.map((violation) => (
            <tr key={violation.id}>
              <td><Link to={`/violations/${violation.id}`}>{violation.id}</Link></td>
              <td><Link to={`/rules/${violation.ruleId}`}>{violation.ruleId}</Link></td>
              <td>{violation.project}</td>
              <td>{violation.severity}</td>
              <td>{violation.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
