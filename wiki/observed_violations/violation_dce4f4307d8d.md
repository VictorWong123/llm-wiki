---
id: violation_dce4f4307d8d
severity: critical
status: REDLINE TRIGGERED
matched_rule_id: raw_sql_injection_001
created_at: 2026-05-16T05:06:31Z
---

# Observed Violation: raw_sql_injection_001

## Evidence


## Original Content
```text
def get_user_by_email(conn, email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return conn.execute(query).fetchone()

```

## Safe Rewrite
```text
Use a parameterized query and pass user-controlled values separately from the SQL string.

```python
def get_user_by_email(conn, email):
    query = "SELECT * FROM users WHERE email = ?"
    return conn.execute(query, (email,)).fetchone()
```
```

## Notes
Accepted from Redline demo UI.
