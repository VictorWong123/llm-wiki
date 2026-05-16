---
id: raw_unsafe_output_handling_001
title: "Unsafe Output Handling: Do Not Execute Or Trust Model Output Blindly"
category: ai_safety
severity: high
source_name: "OWASP Top 10 for LLM Applications"
source_url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
redline_status: active
---

# Unsafe Output Handling: Do Not Execute Or Trust Model Output Blindly

## Summary
LLM output can contain unsafe code, shell commands, links, SQL, HTML, or instructions that downstream systems might execute.

## Redline Rule
Inspect generated code and tool arguments before they reach interpreters, shells, browsers, databases, external APIs, or production systems.

## Unsafe Patterns To Flag
- Executing model output with `eval`, `exec`, or shell commands
- Running generated SQL without review
- Rendering generated HTML without sanitization
- Following model-generated links that trigger side effects
- Passing model output directly into production APIs

## Safe Patterns
- Treat model output as untrusted until checked.
- Validate and sanitize output before use.
- Use sandboxed execution for generated code.
- Require review for high-risk actions.
- Apply allowlists for tools, commands, URLs, and APIs.

## Detector Notes
Flag paths where model output flows into an interpreter, shell, browser sink, database, or production API. Return `REDLINE TRIGGERED` for direct execution and `NEEDS HUMAN REVIEW` for ambiguous flows.

## Safe Rewrite Prompt
Rewrite the action to validate, sandbox, or review the model output before execution. Remove direct execution of generated content.
