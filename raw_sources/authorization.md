---
id: raw_authorization_001
title: "Authorization: Deny By Default And Check Permissions Server-Side"
category: secure_code
severity: high
source_name: "OWASP Authorization Cheat Sheet"
source_url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
redline_status: active
---

# Authorization: Deny By Default And Check Permissions Server-Side

## Summary
Authorization bugs happen when code trusts the client or forgets to verify whether the current user is allowed to access, update, or delete a resource.

## Redline Rule
Endpoints that read, update, or delete user-owned resources must enforce authorization on the server side. Deny access by default when permission is missing or unclear.

## Unsafe Patterns To Flag
- API route reads `user_id`, `owner_id`, `account_id`, or `project_id` from the client and directly queries data
- Update/delete endpoints without permission checks
- Admin actions without role checks
- Client-side-only authorization logic
- Object access without verifying ownership

## Safe Patterns
- Enforce authorization server-side.
- Check object-level permissions.
- Deny by default.
- Use middleware or helper functions like `requireUser`, `requireRole`, or `canAccessResource`.
- Test allowed and forbidden paths.

## Detector Notes
This detector should usually return `WARNING` or `NEEDS HUMAN REVIEW`, because missing authorization is harder to prove from a snippet. Return `REDLINE TRIGGERED` only for very obvious cases.

## Safe Rewrite Prompt
Add an explicit server-side authorization check before reading, updating, or deleting the resource. Keep the original functionality but deny access when the current user is not allowed.
