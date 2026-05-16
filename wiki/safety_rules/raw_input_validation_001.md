---
id: raw_input_validation_001
category: secure_code
severity: medium
source: OWASP Input Validation Cheat Sheet
status: active
created_at: 2026-05-16T04:53:02Z
---

# Input Validation: Validate Data Shape, Type, Range, And Format

## Rule
Do not trust request bodies, query parameters, uploaded files, headers, cookies, model outputs, or tool inputs without validation.

## Unsafe Patterns
- Directly using `req.body`, `request.json`, `request.args`, or `params` without validation
- Accepting uploaded files without checking type, size, or extension
- Passing unvalidated input into database queries, shell commands, file paths, or model prompts
- Missing schema validation for create/update endpoints

## Safe Pattern
- Use allowlist validation.
- Use schema validation with tools such as Zod, Pydantic, Joi, Yup, or similar.
- Validate type, length, range, format, and required fields.
- Enforce server-side validation even if the frontend validates too.
- Reject invalid input with clear errors.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
