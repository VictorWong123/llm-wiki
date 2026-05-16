---
id: violation_6f26c10047a6
severity: critical
status: REDLINE TRIGGERED
matched_rule_id: raw_sql_injection_001
created_at: 2026-05-16T04:53:02Z
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
