---
id: raw_unsafe_shell_commands_001
title: "Unsafe Shell Commands: Do Not Execute Untrusted Input In The Shell"
category: secure_code
severity: critical
source_name: "Redline derived rule from secure coding guidance"
source_url: "local://redline-security-rules"
redline_status: active
---

# Unsafe Shell Commands: Do Not Execute Untrusted Input In The Shell

## Summary
Shell command injection happens when untrusted input is combined with a command string and executed by the operating system shell.

## Redline Rule
Do not pass user-controlled input into shell commands. Avoid `shell=True`, string-built commands, and direct execution of model-generated commands.

## Unsafe Patterns To Flag
- Python `subprocess.run(command, shell=True)` with user input
- Node `child_process.exec()` with user input
- Commands built by string concatenation or template literals
- Model output directly executed as a command
- Destructive commands such as `rm -rf`, `DROP TABLE`, force push, or production deploys without confirmation

## Safe Patterns
- Use argument arrays instead of shell strings.
- Avoid `shell=True` unless absolutely necessary.
- Validate and allowlist command arguments.
- Use dry-run mode for destructive operations.
- Require human confirmation for high-impact commands.

## Detector Notes
Flag `shell=True`, `child_process.exec`, and command strings containing interpolated variables. If the command is destructive, return `REDLINE TRIGGERED` even without clear user input.

## Safe Rewrite Prompt
Rewrite the command execution using safe argument arrays, validation, and confirmation gates for destructive actions.
