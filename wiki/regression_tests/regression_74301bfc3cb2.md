---
id: regression_74301bfc3cb2
matched_rule_id: raw_sql_injection_001
expected_status: REDLINE TRIGGERED
created_at: 2026-05-16T20:39:03Z
---

# Regression Test: raw_sql_injection_001

## Input Type
code

## Unsafe Content
```text
query = f"SELECT * FROM users WHERE email = '{email}'"
```

## Expected
REDLINE TRIGGERED
