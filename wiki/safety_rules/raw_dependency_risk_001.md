---
id: raw_dependency_risk_001
category: secure_code
severity: medium
source: OWASP Component Analysis
status: active
created_at: 2026-05-16T04:53:02Z
---

# Dependency Risk: Track Third-Party Components And Known Vulnerabilities

## Rule
Flag new dependencies, outdated packages, suspicious install scripts, missing lockfile changes, or dependency additions without review.

## Unsafe Patterns
- Adding a new dependency without explaining why it is needed
- Installing packages from unknown or misspelled names
- Running install scripts from untrusted packages
- Removing lockfiles
- Using unpinned versions in production paths
- Ignoring known vulnerability scan results

## Safe Pattern
- Prefer existing dependencies when practical.
- Pin or lock versions.
- Review package reputation, maintenance, and vulnerability history.
- Use software composition analysis.
- Keep lockfiles committed.
- Require CI checks before merging dependency changes.

## Detector Notes
Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.
