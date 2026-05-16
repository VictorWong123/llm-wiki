---
id: raw_least_privilege_001
category: secure_code
severity: medium
source: OWASP Least Privilege Principle
status: active
created_at: 2026-05-16T04:53:02Z
---

# Least Privilege: Give Agents And Tools Only The Access They Need

## Rule
Flag tool plans, credentials, or code changes that request broader access than needed for the task.

## Unsafe Patterns
- Admin credentials when read-only access is enough
- Production access for local development tasks
- Broad OAuth scopes such as full mailbox, full drive, or all repositories when narrower scopes exist
- Long-lived unrestricted tokens
- Unnecessary filesystem or network permissions
- Agents allowed to modify unrelated resources

## Safe Pattern
- Use scoped credentials.
- Prefer read-only defaults.
- Separate dev, staging, and production credentials.
- Use short-lived tokens.
- Add approval steps for elevated access.
- Allowlist tools and destinations.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
