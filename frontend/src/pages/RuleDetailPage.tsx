import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { CodeBlock } from "../components/CodeBlock";
import { findRule, type SafetyRule } from "../data";
import { fetchWikiRules, type WikiSafetyRule } from "../wiki";

function severityLabel(value: WikiSafetyRule["severity"]): SafetyRule["severity"] {
  if (value === "critical") return "Critical";
  if (value === "high") return "High";
  if (value === "medium") return "Medium";
  return "Low";
}

function liveRuleToSafetyRule(rule: WikiSafetyRule): SafetyRule {
  return {
    id: rule.id,
    title: rule.title,
    severity: severityLabel(rule.severity),
    category: rule.category,
    source: rule.source_url || rule.source,
    description: rule.rule_text,
    ruleText: rule.rule_text,
    unsafePatterns: rule.unsafe_patterns,
    safePatterns: rule.safe_patterns,
    testIds: []
  };
}

export function RuleDetailPage() {
  const { id } = useParams();
  const staticRule = findRule(id);
  const [liveRule, setLiveRule] = useState<SafetyRule | null>(null);
  const [loading, setLoading] = useState(Boolean(id && !staticRule));

  useEffect(() => {
    let cancelled = false;

    if (!id || staticRule) {
      setLoading(false);
      setLiveRule(null);
      return () => {
        cancelled = true;
      };
    }

    setLoading(true);
    fetchWikiRules()
      .then((rules) => {
        if (cancelled) {
          return;
        }
        const found = rules.find((rule) => rule.id === id);
        setLiveRule(found ? liveRuleToSafetyRule(found) : null);
      })
      .catch(() => {
        if (!cancelled) {
          setLiveRule(null);
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
  }, [id, staticRule]);

  const rule = staticRule ?? liveRule;

  if (loading) {
    return (
      <>
        <h1>Loading rule...</h1>
        <p>Retrieving live wiki rule data.</p>
      </>
    );
  }

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
        <div>
          <dt>Source</dt>
          <dd>
            {rule.source.startsWith("http") ? <a href={rule.source}>{rule.source}</a> : rule.source}
          </dd>
        </div>
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
        {rule.testIds.length ? (
          <ul>
            {rule.testIds.map((testId) => <li key={testId}><Link to="/regression-tests">{testId}</Link></li>)}
          </ul>
        ) : (
          <p>No regression tests have been generated for this learned rule yet.</p>
        )}
      </section>
    </>
  );
}
