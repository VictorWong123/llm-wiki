---
id: raw_unsafe_output_handling_001
category: ai_safety
severity: high
source: OWASP Top 10 for LLM Applications
status: active
created_at: 2026-05-16T04:53:02Z
---

# Unsafe Output Handling: Do Not Execute Or Trust Model Output Blindly

## Rule
Inspect generated code and tool arguments before they reach interpreters, shells, browsers, databases, external APIs, or production systems.

## Unsafe Patterns
- Executing model output with `eval`, `exec`, or shell commands
- Running generated SQL without review
- Rendering generated HTML without sanitization
- Following model-generated links that trigger side effects
- Passing model output directly into production APIs

## Safe Pattern
- Treat model output as untrusted until checked.
- Validate and sanitize output before use.
- Use sandboxed execution for generated code.
- Require review for high-risk actions.
- Apply allowlists for tools, commands, URLs, and APIs.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
