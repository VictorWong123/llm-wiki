import { Link } from "react-router-dom";
import { rules } from "../data";

export function RuleListPage() {
  return (
    <>
      <h1>Safety Rules</h1>
      <table>
        <thead>
          <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => (
            <tr key={rule.id}>
              <td><Link to={`/rules/${rule.id}`}>{rule.id}</Link></td>
              <td>{rule.severity}</td>
              <td>{rule.category}</td>
              <td>{rule.title}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
