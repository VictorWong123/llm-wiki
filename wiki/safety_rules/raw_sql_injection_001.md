---
id: raw_sql_injection_001
category: secure_code
severity: critical
source: OWASP SQL Injection Prevention Cheat Sheet
status: active
created_at: 2026-05-16T04:53:02Z
---

# SQL Injection: Use Parameterized Queries For User-Controlled Input

## Rule
Never place user-controlled input directly inside SQL strings. Use prepared statements or parameterized queries.

## Unsafe Patterns
- Python f-string SQL: `f"SELECT * FROM users WHERE email = '{email}'"`
- Python string concatenation into SQL: `"SELECT ..." + user_input`
- Python `.format()` inserting variables into SQL
- JavaScript template literal SQL with `${userInput}`
- SQL generated from request body, query params, cookies, or tool output without parameters

## Safe Pattern
- Use prepared statements.
- Use parameterized queries.
- Avoid dynamic SQL when possible.
- Validate input shape and type before database access.
- Use least-privilege database accounts.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
