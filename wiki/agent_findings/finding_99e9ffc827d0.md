---
id: finding_99e9ffc827d0
severity: medium
status: NEEDS HUMAN REVIEW
created_at: 2026-05-16T22:30:57Z
---

# Agent Security Finding: Open redirect risk in post-login redirect helper

## Description
The login completion route redirects to a user-controlled next URL without same-origin validation or an allowlist. Attackers could use the trusted app domain in phishing or auth-flow exploit chains.

## Evidence
Demo unknown issue: /api/login/complete reads next from the query string and redirects directly to that value.
