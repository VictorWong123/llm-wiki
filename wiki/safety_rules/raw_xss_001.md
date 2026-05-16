---
id: raw_xss_001
category: secure_code
severity: high
source: OWASP XSS Prevention Cheat Sheet
status: active
created_at: 2026-05-16T04:53:02Z
---

# Cross-Site Scripting: Encode Output Based On Context

## Rule
Do not insert untrusted data into dangerous browser sinks or raw HTML contexts unless it is properly sanitized and encoded for that context.

## Unsafe Patterns
- React `dangerouslySetInnerHTML` with untrusted content
- DOM `innerHTML` or `outerHTML` with user content
- `document.write` with user content
- Event handler attributes built from untrusted data
- Untrusted data inside `<script>`, `<style>`, or URLs
- Markdown or rich HTML rendering without sanitization

## Safe Pattern
- Use framework escaping by default.
- Prefer `textContent` over `innerHTML`.
- Sanitize rich HTML with a trusted sanitizer.
- Use context-specific output encoding.
- Avoid dangerous rendering contexts.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
