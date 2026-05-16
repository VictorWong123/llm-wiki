---
id: raw_secrets_management_001
category: secure_code
severity: critical
source: OWASP Secrets Management Cheat Sheet
status: active
created_at: 2026-05-16T04:53:02Z
---

# Secrets Management: Do Not Hardcode API Keys, Tokens, Or Passwords

## Rule
Block hardcoded credentials and prevent the agent from pasting secrets into generated code, logs, markdown, prompts, or responses.

## Unsafe Patterns
- `api_key = "..."`
- `password = "..."`
- `Authorization: Bearer ...`
- Private key blocks
- Database URLs with usernames and passwords
- `.env` contents pasted into code or chat
- Tokens in logs, screenshots, or generated docs

## Safe Pattern
- Read secrets from environment variables.
- Use a secrets manager for production.
- Redact secrets in logs and UI.
- Rotate exposed credentials.
- Keep `.env` files out of version control.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
