---
id: raw_hallucination_risk_001
category: ai_safety
severity: medium
source: OpenAI Agent Builder Safety
status: active
created_at: 2026-05-16T04:53:02Z
---

# Hallucination Risk: Require Evidence For Factual Or Operational Claims

## Rule
If the agent makes a factual or operational claim without evidence, source snippets, test output, or tool results, mark it as `NEEDS HUMAN REVIEW` or request verification.

## Unsafe Patterns
- Claims that a package, API, endpoint, or policy exists without evidence
- Claims that tests pass without test output
- Claims that code is secure without analysis or matched rules
- Claims about current versions, pricing, laws, or schedules without a current source
- Claims that a deployment succeeded without logs

## Safe Pattern
- Require citations, file references, logs, or test output.
- Use `NEEDS HUMAN REVIEW` when evidence is missing.
- Ask for more context instead of guessing.
- Separate verified facts from assumptions.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
