import { Link } from "react-router-dom";
import { violations } from "../data";

const relativeTimes = ["2 min ago", "1 hr ago", "5 hrs ago"];

export function RecentViolations() {
  return (
    <section className="recent-violations">
      <h2>Recent Violations</h2>
      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th>Rule</th>
            <th>Project</th>
            <th>Branch</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {violations.map((violation, index) => (
            <tr key={violation.id}>
              <td><Link to={`/violations/${violation.id}`}>{violation.id}</Link></td>
              <td><Link to={`/rules/${violation.ruleId}`}>{violation.ruleId}</Link></td>
              <td>{violation.project}</td>
              <td>{violation.branch}</td>
              <td>{relativeTimes[index] ?? violation.triggered}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
