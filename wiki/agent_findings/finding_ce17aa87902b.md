---
id: finding_ce17aa87902b
severity: medium
status: NEEDS HUMAN REVIEW
created_at: 2026-05-16T22:36:13Z
---

# Agent Security Finding: CSV formula injection risk in customer export

## Description
Customer CSV export writes untrusted notes exactly as stored. Spreadsheet apps may interpret cells beginning with formula control characters as formulas.

## Evidence
Demo verification: /api/customers/export.csv exports a note beginning with =HYPERLINK(...) without neutralization.
