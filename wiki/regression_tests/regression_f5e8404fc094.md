---
id: regression_f5e8404fc094
matched_rule_id: raw_sql_injection_001
expected_status: REDLINE TRIGGERED
created_at: 2026-05-16T05:07:10Z
---

# Regression Test: raw_sql_injection_001

## Input Type
code

## Unsafe Content
```text
def get_user_by_email(conn, email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return conn.execute(query).fetchone()

```

## Expected
REDLINE TRIGGERED
