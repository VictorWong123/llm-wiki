---
id: finding_bf46236b0ca7
severity: critical
status: NEEDS HUMAN REVIEW
created_at: 2026-05-16T21:28:20Z
---

# Agent Security Finding: Local env contains exposed API key

## Description
A real provider API key is present in backend/.env. Local env files should not contain shared or committed secrets, and exposed keys should be rotated.

## Evidence
backend/.env contains a provider API key value; exact value intentionally omitted.
