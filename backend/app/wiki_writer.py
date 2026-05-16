from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import RegressionTestEntry, SafetyRule, ViolationEntry


REPO_ROOT = Path(__file__).resolve().parents[2]
WIKI_ROOT = REPO_ROOT / "wiki"
RAW_SOURCES_ROOT = REPO_ROOT / "raw_sources"


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return slug or "entry"


def ensure_wiki_dirs() -> None:
    for name in [
        "safety_rules",
        "unsafe_patterns",
        "safe_patterns",
        "observed_violations",
        "regression_tests",
    ]:
        (WIKI_ROOT / name).mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_rule(rule: SafetyRule) -> None:
    ensure_wiki_dirs()
    base = WIKI_ROOT / "safety_rules" / rule.id
    markdown = [
        "---",
        f"id: {rule.id}",
        f"category: {rule.category}",
        f"severity: {rule.severity}",
        f"source: {rule.source}",
        "status: active",
        f"created_at: {rule.created_at}",
        "---",
        "",
        f"# {rule.title}",
        "",
        "## Rule",
        rule.rule_text,
        "",
        "## Unsafe Patterns",
        *[f"- {pattern}" for pattern in rule.unsafe_patterns],
        "",
        "## Safe Pattern",
        *[f"- {pattern}" for pattern in rule.safe_patterns],
        "",
        "## Detector Notes",
        "Use deterministic matching where available. Return NEEDS HUMAN REVIEW when the evidence is unclear.",
        "",
    ]
    (base.with_suffix(".md")).write_text("\n".join(markdown), encoding="utf-8")
    write_json(base.with_suffix(".json"), rule.model_dump())


def write_violation(entry: ViolationEntry) -> None:
    ensure_wiki_dirs()
    base = WIKI_ROOT / "observed_violations" / entry.id
    evidence = "\n".join(
        f"- {item.detector}: {item.message} (line {item.line or 'unknown'})"
        for item in entry.evidence
    )
    markdown = f"""---
id: {entry.id}
severity: {entry.severity}
status: {entry.status}
matched_rule_id: {entry.matched_rule_id}
created_at: {entry.created_at}
---

# Observed Violation: {entry.matched_rule_id}

## Evidence
{evidence}

## Original Content
```text
{entry.original_content}
```

## Safe Rewrite
```text
{entry.safe_rewrite}
```

## Notes
{entry.notes or "Saved from accepted Redline rewrite."}
"""
    base.with_suffix(".md").write_text(markdown, encoding="utf-8")
    write_json(base.with_suffix(".json"), entry.model_dump())


def write_regression_test(entry: RegressionTestEntry) -> None:
    ensure_wiki_dirs()
    base = WIKI_ROOT / "regression_tests" / entry.id
    markdown = f"""---
id: {entry.id}
matched_rule_id: {entry.matched_rule_id}
expected_status: {entry.expected_status}
created_at: {entry.created_at}
---

# Regression Test: {entry.matched_rule_id}

## Input Type
{entry.input_type}

## Unsafe Content
```text
{entry.unsafe_content}
```

## Expected
{entry.expected_status}
"""
    base.with_suffix(".md").write_text(markdown, encoding="utf-8")
    write_json(base.with_suffix(".json"), entry.model_dump())
