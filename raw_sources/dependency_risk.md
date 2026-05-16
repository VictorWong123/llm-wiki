---
id: raw_dependency_risk_001
title: "Dependency Risk: Track Third-Party Components And Known Vulnerabilities"
category: secure_code
severity: medium
source_name: "OWASP Component Analysis"
source_url: "https://owasp.org/www-community/Component_Analysis"
redline_status: active
---

# Dependency Risk: Track Third-Party Components And Known Vulnerabilities

## Summary
Modern applications depend on many open-source packages. Vulnerable, outdated, malicious, or unnecessary dependencies can become part of the application through generated code.

## Redline Rule
Flag new dependencies, outdated packages, suspicious install scripts, missing lockfile changes, or dependency additions without review.

## Unsafe Patterns To Flag
- Adding a new dependency without explaining why it is needed
- Installing packages from unknown or misspelled names
- Running install scripts from untrusted packages
- Removing lockfiles
- Using unpinned versions in production paths
- Ignoring known vulnerability scan results

## Safe Patterns
- Prefer existing dependencies when practical.
- Pin or lock versions.
- Review package reputation, maintenance, and vulnerability history.
- Use software composition analysis.
- Keep lockfiles committed.
- Require CI checks before merging dependency changes.

## Detector Notes
Return `WARNING` for most new dependency additions. Return `NEEDS HUMAN REVIEW` for suspicious package names, broad install commands, or changes that affect production dependencies.

## Safe Rewrite Prompt
Rewrite the plan to avoid unnecessary dependencies or require review before adding them. Include why the dependency is needed and how it will be checked.
