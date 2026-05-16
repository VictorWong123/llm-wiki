---
id: raw_secrets_management_001
title: "Secrets Management: Do Not Hardcode API Keys, Tokens, Or Passwords"
category: secure_code
severity: critical
source_name: "OWASP Secrets Management Cheat Sheet"
source_url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
redline_status: active
---

# Secrets Management: Do Not Hardcode API Keys, Tokens, Or Passwords

## Summary
Secrets should not be placed in source code, prompts, logs, screenshots, generated examples, or committed configuration files.

## Redline Rule
Block hardcoded credentials and prevent the agent from pasting secrets into generated code, logs, markdown, prompts, or responses.

## Unsafe Patterns To Flag
- `api_key = "..."`
- `password = "..."`
- `Authorization: Bearer ...`
- Private key blocks
- Database URLs with usernames and passwords
- `.env` contents pasted into code or chat
- Tokens in logs, screenshots, or generated docs

## Safe Patterns
- Read secrets from environment variables.
- Use a secrets manager for production.
- Redact secrets in logs and UI.
- Rotate exposed credentials.
- Keep `.env` files out of version control.

## Detector Notes
Use regexes for obvious secret formats and keyword proximity checks for `api_key`, `token`, `password`, `secret`, `private_key`, `connection_string`, and `DATABASE_URL`.

## Safe Rewrite Prompt
Replace hardcoded secrets with environment variable reads. Add a comment or note that exposed credentials should be rotated.

## Demo Unsafe Example
```python
OPENAI_API_KEY = "sk-proj-hardcoded-demo-key"
client = OpenAI(api_key=OPENAI_API_KEY)
```

## Demo Safe Example
```python
import os
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
```
