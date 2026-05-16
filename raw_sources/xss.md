---
id: raw_xss_001
title: "Cross-Site Scripting: Encode Output Based On Context"
category: secure_code
severity: high
source_name: "OWASP XSS Prevention Cheat Sheet"
source_url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
redline_status: active
---

# Cross-Site Scripting: Encode Output Based On Context

## Summary
XSS occurs when untrusted content is interpreted as executable browser code instead of being displayed as text.

## Redline Rule
Do not insert untrusted data into dangerous browser sinks or raw HTML contexts unless it is properly sanitized and encoded for that context.

## Unsafe Patterns To Flag
- React `dangerouslySetInnerHTML` with untrusted content
- DOM `innerHTML` or `outerHTML` with user content
- `document.write` with user content
- Event handler attributes built from untrusted data
- Untrusted data inside `<script>`, `<style>`, or URLs
- Markdown or rich HTML rendering without sanitization

## Safe Patterns
- Use framework escaping by default.
- Prefer `textContent` over `innerHTML`.
- Sanitize rich HTML with a trusted sanitizer.
- Use context-specific output encoding.
- Avoid dangerous rendering contexts.

## Detector Notes
Flag dangerous sinks when they are near variables from props, request data, user content, markdown, database content, or tool output.

## Safe Rewrite Prompt
Rewrite the code to render untrusted content as text or sanitize it before rendering. Avoid raw HTML unless there is a clear trusted sanitizer.
