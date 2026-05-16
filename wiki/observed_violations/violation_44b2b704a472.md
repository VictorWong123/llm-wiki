---
id: violation_44b2b704a472
severity: critical
status: REDLINE TRIGGERED
matched_rule_id: raw_sql_injection_001
created_at: 2026-05-16T05:06:48Z
---

# Observed Violation: raw_sql_injection_001

## Evidence


## Original Content
```text
query = f"SELECT * FROM users WHERE email = '{email}'"
```

## Safe Rewrite
```text
query = "SELECT * FROM users WHERE email = ?"
```

## Notes
Saved from accepted Redline rewrite.
