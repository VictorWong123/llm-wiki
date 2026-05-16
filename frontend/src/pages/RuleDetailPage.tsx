import { Link, useParams } from "react-router-dom";
import { CodeBlock } from "../components/CodeBlock";
import { findRule } from "../data";

export function RuleDetailPage() {
  const { id } = useParams();
  const rule = findRule(id);

  if (!rule) {
    return (
      <>
        <h1>Rule not found</h1>
        <p><Link to="/rules">Return to Safety Rules</Link></p>
      </>
    );
  }

  return (
    <>
      <h1>{rule.id}: {rule.title}</h1>
      <dl className="metadata-grid">
        <div><dt>Severity</dt><dd>{rule.severity}</dd></div>
        <div><dt>Category</dt><dd>{rule.category}</dd></div>
        <div><dt>Source</dt><dd>{rule.source}</dd></div>
      </dl>
      <p>{rule.description}</p>
      <h2>Rule text</h2>
      <p>{rule.ruleText}</p>
      <h2>Unsafe patterns</h2>
      <ul>
        {rule.unsafePatterns.map((pattern) => <li key={pattern}>{pattern}</li>)}
      </ul>
      <h2>Safe patterns</h2>
      <ul>
        {rule.safePatterns.map((pattern) => <li key={pattern}>{pattern}</li>)}
      </ul>
      {rule.example ? (
        <section id="examples">
          <h2>Examples</h2>
          <h3>Unsafe</h3>
          <CodeBlock code={rule.example.unsafeCode} language="python" />
          <h3>Safe</h3>
          <CodeBlock code={rule.example.safeCode} language="python" />
        </section>
      ) : null}
      <section id="tests">
        <h2>Related tests</h2>
        <ul>
          {rule.testIds.map((testId) => <li key={testId}><Link to="/regression-tests">{testId}</Link></li>)}
        </ul>
      </section>
    </>
  );
}
