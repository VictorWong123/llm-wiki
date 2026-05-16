---
id: raw_least_privilege_001
title: "Least Privilege: Give Agents And Tools Only The Access They Need"
category: secure_code
severity: medium
source_name: "OWASP Least Privilege Principle"
source_url: "https://owasp.org/www-community/controls/Least_Privilege_Principle"
redline_status: active
---

# Least Privilege: Give Agents And Tools Only The Access They Need

## Summary
Least privilege limits damage when an agent, tool, dependency, account, or service behaves unexpectedly.

## Redline Rule
Flag tool plans, credentials, or code changes that request broader access than needed for the task.

## Unsafe Patterns To Flag
- Admin credentials when read-only access is enough
- Production access for local development tasks
- Broad OAuth scopes such as full mailbox, full drive, or all repositories when narrower scopes exist
- Long-lived unrestricted tokens
- Unnecessary filesystem or network permissions
- Agents allowed to modify unrelated resources

## Safe Patterns
- Use scoped credentials.
- Prefer read-only defaults.
- Separate dev, staging, and production credentials.
- Use short-lived tokens.
- Add approval steps for elevated access.
- Allowlist tools and destinations.

## Detector Notes
This detector often returns `WARNING` or `NEEDS HUMAN REVIEW` because context matters. Use `REDLINE TRIGGERED` for obviously unnecessary admin or production access.

## Safe Rewrite Prompt
Rewrite the plan to use the minimum permissions needed. Prefer read-only or scoped access and ask for approval before elevation.
