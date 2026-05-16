---
id: raw_sql_injection_001
title: "SQL Injection: Use Parameterized Queries For User-Controlled Input"
category: secure_code
severity: critical
source_name: "OWASP SQL Injection Prevention Cheat Sheet"
source_url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
redline_status: active
---

# SQL Injection: Use Parameterized Queries For User-Controlled Input

## Summary
SQL injection occurs when user-controlled input is inserted into a SQL query as executable SQL instead of being passed as data.

## Redline Rule
Never place user-controlled input directly inside SQL strings. Use prepared statements or parameterized queries.

## Unsafe Patterns To Flag
- Python f-string SQL: `f"SELECT * FROM users WHERE email = '{email}'"`
- Python string concatenation into SQL: `"SELECT ..." + user_input`
- Python `.format()` inserting variables into SQL
- JavaScript template literal SQL with `${userInput}`
- SQL generated from request body, query params, cookies, or tool output without parameters

## Safe Patterns
- Use prepared statements.
- Use parameterized queries.
- Avoid dynamic SQL when possible.
- Validate input shape and type before database access.
- Use least-privilege database accounts.

## Detector Notes
For the MVP, match SQL keywords such as `SELECT`, `INSERT`, `UPDATE`, `DELETE`, or `DROP` near interpolation patterns such as f-strings, `+`, `.format`, `%`, or `${...}`.

## Safe Rewrite Prompt
Rewrite the query using the language's parameterized query syntax. Keep the same business logic but move user-controlled values into parameters.

## Demo Unsafe Example
```python
def get_user_by_email(conn, email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return conn.execute(query).fetchone()
```

## Demo Safe Example
```python
def get_user_by_email(conn, email):
    query = "SELECT * FROM users WHERE email = ?"
    return conn.execute(query, (email,)).fetchone()
```
