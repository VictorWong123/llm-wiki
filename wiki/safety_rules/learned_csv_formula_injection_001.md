---
id: learned_csv_formula_injection_001
category: csv_formula_injection
severity: medium
source: OWASP CSV Injection
source_url: https://owasp.org/www-community/attacks/CSV_Injection
status: active
created_at: 2026-05-16T22:36:13Z
---

# CSV Formula Injection: Escape Spreadsheet Formula Cells

## Rule
Do not export untrusted spreadsheet cells that can be interpreted as formulas without neutralizing formula control characters.

## Source
https://owasp.org/www-community/attacks/CSV_Injection

## Unsafe Patterns
- CSV export writes untrusted values beginning with =, +, -, or @ directly into cells.
- Spreadsheet export assumes normal CSV quoting is enough to prevent formula execution.
- Customer notes, names, or imported fields are exported exactly as stored for Excel or Sheets.

## Safe Pattern
- Prefix formula-like cells with a tab or other reviewed neutralization pattern before CSV export.
- Quote CSV fields and escape embedded quotes correctly.
- Apply formula-cell protection to every untrusted exported field.
- Document export behavior for downstream spreadsheet users.

## Detector Notes
Learned from an agent finding. Add deterministic detectors or regression tests when implementation evidence is available.
