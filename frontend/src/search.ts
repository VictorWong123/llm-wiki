import { regressionTests, rules, safePatterns, simplePages, unsafePatterns, violations } from "./data";

export interface SearchResult {
  id: string;
  title: string;
  path: string;
  snippet: string;
  haystack: string;
}

function normalize(value: string) {
  return value.toLowerCase();
}

function makeSnippet(text: string, query: string) {
  const clean = text.replace(/\s+/g, " ").trim();
  const index = normalize(clean).indexOf(normalize(query));
  if (index < 0) {
    return clean.slice(0, 160);
  }
  const start = Math.max(0, index - 45);
  return `${start > 0 ? "..." : ""}${clean.slice(start, start + 160)}`;
}

export const searchableItems: SearchResult[] = [
  ...rules.map((rule) => ({
    id: rule.id,
    title: `${rule.id}: ${rule.title}`,
    path: `/rules/${rule.id}`,
    snippet: rule.description,
    haystack: [rule.id, rule.title, rule.category, rule.severity, rule.description, rule.ruleText, ...rule.unsafePatterns, ...rule.safePatterns, rule.example?.unsafeCode, rule.example?.safeCode].filter(Boolean).join(" ")
  })),
  ...unsafePatterns.map((pattern) => ({
    id: pattern.id,
    title: pattern.title,
    path: "/unsafe-patterns",
    snippet: `Unsafe pattern for ${pattern.ruleId}: ${pattern.description}`,
    haystack: [pattern.id, pattern.title, pattern.category, pattern.description, pattern.ruleId].join(" ")
  })),
  ...safePatterns.map((pattern) => ({
    id: pattern.id,
    title: pattern.title,
    path: "/safe-patterns",
    snippet: `Safe pattern for ${pattern.ruleId}: ${pattern.description}`,
    haystack: [pattern.id, pattern.title, pattern.category, pattern.description, pattern.ruleId].join(" ")
  })),
  ...violations.map((violation) => ({
    id: violation.id,
    title: `${violation.id}: ${violation.ruleId}`,
    path: `/violations/${violation.id}`,
    snippet: violation.summary,
    haystack: [violation.id, violation.ruleId, violation.ruleTitle, violation.category, violation.severity, violation.summary, violation.evidenceFile, violation.unsafeCode, violation.safeRewrite].join(" ")
  })),
  ...regressionTests.map((test) => ({
    id: test.id,
    title: test.title,
    path: "/regression-tests",
    snippet: `${test.ruleId} expects ${test.expectedStatus}.`,
    haystack: [test.id, test.title, test.ruleId, test.sample, test.expectedStatus].join(" ")
  })),
  ...simplePages.map((page) => ({
    id: page.id,
    title: page.title,
    path: page.path,
    snippet: page.description,
    haystack: [page.id, page.title, page.description, ...page.sections.flatMap((section) => [section.heading, section.body])].join(" ")
  }))
];

export function searchRedline(query: string) {
  const terms = normalize(query).split(/\s+/).filter(Boolean);
  if (terms.length === 0) {
    return [];
  }
  return searchableItems
    .filter((item) => {
      const text = normalize(item.haystack);
      return terms.every((term) => text.includes(term));
    })
    .map((item) => ({
      ...item,
      snippet: makeSnippet(item.haystack, query)
    }));
}
