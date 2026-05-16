from __future__ import annotations

import json
import re
from pathlib import Path

from .models import SafetyRule, utc_now
from .models import Severity
from .wiki_writer import RAW_SOURCES_ROOT, WIKI_ROOT, slugify, write_rule


SEED_RULES = {
    "sql_injection.md",
    "prompt_injection.md",
    "secrets_management.md",
    "authorization.md",
    "input_validation.md",
    "xss.md",
    "unsafe_output_handling.md",
    "least_privilege.md",
    "dependency_risk.md",
    "hallucination_risk.md",
}


def _frontmatter(markdown: str) -> tuple[dict[str, str], str]:
    if not markdown.startswith("---"):
        return {}, markdown
    _, raw_meta, body = markdown.split("---", 2)
    metadata: dict[str, str] = {}
    for line in raw_meta.strip().splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    return metadata, body.strip()


def _section(body: str, heading: str) -> str:
    pattern = rf"## {re.escape(heading)}\n(.*?)(?=\n## |\Z)"
    match = re.search(pattern, body, re.S)
    return match.group(1).strip() if match else ""


def _bullets(text: str) -> list[str]:
    return [line[2:].strip() for line in text.splitlines() if line.strip().startswith("- ")]


def rule_from_raw_file(path: Path) -> SafetyRule:
    markdown = path.read_text(encoding="utf-8")
    meta, body = _frontmatter(markdown)
    title = meta.get("title") or path.stem.replace("_", " ").title()
    return SafetyRule(
        id=meta.get("id") or f"rule_{slugify(title)}",
        title=title,
        source=meta.get("source_name") or meta.get("source") or "Redline source notes",
        source_url=meta.get("source_url"),
        category=meta.get("category", "secure_code"),
        severity=meta.get("severity", "medium"),
        rule_text=_section(body, "Redline Rule") or _section(body, "Summary") or title,
        unsafe_patterns=_bullets(_section(body, "Unsafe Patterns To Flag")),
        safe_patterns=_bullets(_section(body, "Safe Patterns")),
        created_at=utc_now(),
    )


def extract_rule_from_ingest(title: str, source: str, text: str) -> SafetyRule:
    lowered = text.lower()
    severity: Severity = "medium"
    if any(term in lowered for term in ["critical", "sql injection", "secret", "token", "password"]):
        severity = "critical"
    elif any(term in lowered for term in ["authorization", "xss", "permission"]):
        severity = "high"
    category = "ai_safety" if any(term in lowered for term in ["prompt", "agent", "instruction"]) else "secure_code"
    unsafe_patterns = _bullets(_section(text, "Unsafe Patterns To Flag")) or _bullets(_section(text, "Unsafe Patterns"))
    safe_patterns = _bullets(_section(text, "Safe Patterns")) or _bullets(_section(text, "Safe Pattern"))
    rule_text = _section(text, "Redline Rule") or _section(text, "Rule") or text.strip().splitlines()[0]
    return SafetyRule(
        id=f"rule_{slugify(title)}",
        title=title.strip(),
        source=source.strip(),
        category=category,
        severity=severity,
        rule_text=rule_text,
        unsafe_patterns=unsafe_patterns,
        safe_patterns=safe_patterns,
        created_at=utc_now(),
    )


def seed_rules() -> list[SafetyRule]:
    existing = list((WIKI_ROOT / "safety_rules").glob("*.json"))
    if existing:
        return load_rules()
    rules: list[SafetyRule] = []
    for filename in sorted(SEED_RULES):
        path = RAW_SOURCES_ROOT / filename
        if path.exists():
            rule = rule_from_raw_file(path)
            write_rule(rule)
            rules.append(rule)
    return rules


def load_rules() -> list[SafetyRule]:
    rules: list[SafetyRule] = []
    for path in sorted((WIKI_ROOT / "safety_rules").glob("*.json")):
        rules.append(SafetyRule(**json.loads(path.read_text(encoding="utf-8"))))
    return rules


def save_rule(rule: SafetyRule) -> SafetyRule:
    write_rule(rule)
    return rule


def get_rule(rule_id: str) -> SafetyRule | None:
    for rule in load_rules():
        if rule.id == rule_id:
            return rule
    return None
