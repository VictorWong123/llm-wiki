---
id: raw_excessive_agency_001
title: "Excessive Agency: Limit What The Agent Can Do Without Confirmation"
category: ai_safety
severity: high
source_name: "OpenAI Agent Builder Safety"
source_url: "https://platform.openai.com/docs/guides/agent-builder-safety"
redline_status: active
---

# Excessive Agency: Limit What The Agent Can Do Without Confirmation

## Summary
Agents can cause harm when they have too much autonomy, too many permissions, or the ability to perform high-impact actions without review.

## Redline Rule
The agent must require human confirmation before irreversible or high-impact actions such as deleting data, sending external messages, changing billing, publishing code, modifying production systems, or using broad credentials.

## Unsafe Patterns To Flag
- Delete database records without confirmation
- Send emails or messages without confirmation
- Change billing, permissions, or production settings
- Deploy to production without review
- Use admin credentials when read-only access is enough
- Run destructive shell commands like `rm -rf`, `DROP TABLE`, or force pushes

## Safe Patterns
- Use dry-run mode first.
- Ask for confirmation before irreversible actions.
- Use scoped credentials and least-privilege tools.
- Prefer read-only access by default.
- Add allowlists for permitted tools and destinations.

## Detector Notes
Classify destructive file operations, database mutations, external communication, and production changes as high-impact. Return `NEEDS HUMAN REVIEW` when intent is unclear.

## Safe Rewrite Prompt
Rewrite the tool plan into a dry-run or review-first version. The rewrite should ask for confirmation before any irreversible side effect.
