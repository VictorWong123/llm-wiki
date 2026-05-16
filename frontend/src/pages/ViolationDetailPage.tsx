import { Link, useParams } from "react-router-dom";
import { PreflightResultPanel } from "../components/PreflightResultPanel";
import { findViolation } from "../data";

export function ViolationDetailPage() {
  const { id } = useParams();
  const violation = findViolation(id);

  if (!violation) {
    return (
      <>
        <h1>Violation not found</h1>
        <p><Link to="/violations">Return to Observed Violations</Link></p>
      </>
    );
  }

  return <PreflightResultPanel title="Violation Report" report={violation} />;
}
