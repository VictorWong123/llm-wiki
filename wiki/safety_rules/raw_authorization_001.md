---
id: raw_authorization_001
category: secure_code
severity: high
source: OWASP Authorization Cheat Sheet
status: active
created_at: 2026-05-16T04:53:02Z
---

# Authorization: Deny By Default And Check Permissions Server-Side

## Rule
Endpoints that read, update, or delete user-owned resources must enforce authorization on the server side. Deny access by default when permission is missing or unclear.

## Unsafe Patterns
- API route reads `user_id`, `owner_id`, `account_id`, or `project_id` from the client and directly queries data
- Update/delete endpoints without permission checks
- Admin actions without role checks
- Client-side-only authorization logic
- Object access without verifying ownership

## Safe Pattern
- Enforce authorization server-side.
- Check object-level permissions.
- Deny by default.
- Use middleware or helper functions like `requireUser`, `requireRole`, or `canAccessResource`.
- Test allowed and forbidden paths.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
