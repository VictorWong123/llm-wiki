---
id: learned_open_redirect_001
category: open_redirect
severity: medium
source: OWASP Unvalidated Redirects and Forwards Cheat Sheet
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
status: active
created_at: 2026-05-16T22:37:06Z
---

# Open Redirect: Validate Redirect Targets

## Rule
Do not redirect to user-controlled URLs unless the target is constrained to a safe same-origin path or explicit allowlist.

## Source
https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

## Unsafe Patterns
- Login, logout, invite, or completion route redirects directly to a next, returnUrl, redirect, or url parameter.
- Redirect target accepts absolute external URLs without validation.
- Redirect validation checks string prefixes instead of parsing and enforcing origin or allowlisted paths.

## Safe Pattern
- Prefer fixed server-side redirect destinations for sensitive flows.
- Allow only relative same-origin paths when a return destination is required.
- Validate external redirect targets against an explicit allowlist.
- Fall back to a safe default route when validation fails.

## Detector Notes
Learned from an agent finding. Add deterministic detectors or regression tests when implementation evidence is available.
