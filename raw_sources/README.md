# Redline Raw Sources

These markdown files are starter source notes for Redline's LLM wiki. Each file is written so Codex can turn it into:

- a safety rule
- unsafe pattern detectors
- safe rewrite prompts
- observed violation templates
- regression test seeds

Use these files as local, trusted source material. Codex should not invent security rules beyond these sources unless the user ingests new rules through the app.

## Recommended MVP Demo Rules

Start with these for the hackathon demo:

1. `sql_injection.md`
2. `prompt_injection.md`
3. `secrets_management.md`
4. `unsafe_shell_commands.md`
5. `authorization.md`

The fastest demo path is SQL injection + prompt injection + observed violation writeback.
