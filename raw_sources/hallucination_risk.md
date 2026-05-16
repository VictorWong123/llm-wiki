---
id: raw_hallucination_risk_001
title: "Hallucination Risk: Require Evidence For Factual Or Operational Claims"
category: ai_safety
severity: medium
source_name: "OpenAI Agent Builder Safety"
source_url: "https://platform.openai.com/docs/guides/agent-builder-safety"
redline_status: active
---

# Hallucination Risk: Require Evidence For Factual Or Operational Claims

## Summary
Agent workflows can fail when the model confidently states unsupported claims about code behavior, dependencies, policies, recent facts, or system state.

## Redline Rule
If the agent makes a factual or operational claim without evidence, source snippets, test output, or tool results, mark it as `NEEDS HUMAN REVIEW` or request verification.

## Unsafe Patterns To Flag
- Claims that a package, API, endpoint, or policy exists without evidence
- Claims that tests pass without test output
- Claims that code is secure without analysis or matched rules
- Claims about current versions, pricing, laws, or schedules without a current source
- Claims that a deployment succeeded without logs

## Safe Patterns
- Require citations, file references, logs, or test output.
- Use `NEEDS HUMAN REVIEW` when evidence is missing.
- Ask for more context instead of guessing.
- Separate verified facts from assumptions.

## Detector Notes
This rule is usually semantic. Do not block every unsupported sentence. Focus on operational claims that could cause a bad action if wrong.

## Safe Rewrite Prompt
Rewrite the claim to state what is known, what evidence supports it, and what still needs verification.
