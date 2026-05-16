---
id: raw_input_validation_001
title: "Input Validation: Validate Data Shape, Type, Range, And Format"
category: secure_code
severity: medium
source_name: "OWASP Input Validation Cheat Sheet"
source_url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
redline_status: active
---

# Input Validation: Validate Data Shape, Type, Range, And Format

## Summary
Input validation reduces unexpected behavior by ensuring incoming data matches the expected type, length, range, format, and structure before it reaches business logic.

## Redline Rule
Do not trust request bodies, query parameters, uploaded files, headers, cookies, model outputs, or tool inputs without validation.

## Unsafe Patterns To Flag
- Directly using `req.body`, `request.json`, `request.args`, or `params` without validation
- Accepting uploaded files without checking type, size, or extension
- Passing unvalidated input into database queries, shell commands, file paths, or model prompts
- Missing schema validation for create/update endpoints

## Safe Patterns
- Use allowlist validation.
- Use schema validation with tools such as Zod, Pydantic, Joi, Yup, or similar.
- Validate type, length, range, format, and required fields.
- Enforce server-side validation even if the frontend validates too.
- Reject invalid input with clear errors.

## Detector Notes
This detector should return `WARNING` when input appears trusted without validation. Combine with stronger rules such as SQL injection, XSS, or shell execution when unsafe input reaches a dangerous sink.

## Safe Rewrite Prompt
Add schema or allowlist validation before the input is used. Keep error handling simple and explicit.
