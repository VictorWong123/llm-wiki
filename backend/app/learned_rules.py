from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import SafetyRule, Severity


@dataclass(frozen=True)
class LearnedRuleTemplate:
    id: str
    title: str
    source: str
    source_url: str
    category: str
    severity: Severity
    rule_text: str
    unsafe_patterns: list[str]
    safe_patterns: list[str]
    keywords: tuple[str, ...]


LEARNED_RULE_TEMPLATES: tuple[LearnedRuleTemplate, ...] = (
    LearnedRuleTemplate(
        id="learned_ssrf_001",
        title="Server-Side Request Forgery: Restrict Server-Side URL Fetches",
        source="OWASP Server-Side Request Forgery Prevention Cheat Sheet",
        source_url="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        category="server_side_request_forgery",
        severity="high",
        rule_text="Do not fetch user-controlled URLs from the server unless the destination is strictly validated and constrained.",
        unsafe_patterns=[
            "Server route calls fetch(url), httpx.get(url), requests.get(url), or similar with request-controlled URL input.",
            "URL preview, webhook, import, callback, or metadata fetch accepts arbitrary schemes or hosts.",
            "HTTP client follows redirects after validating only the original URL.",
            "Server-side fetch allows loopback, link-local, private network, cloud metadata, or file-style destinations.",
        ],
        safe_patterns=[
            "Allow only required schemes, usually https.",
            "Validate hostnames against an explicit allowlist for the feature.",
            "Resolve DNS and reject loopback, link-local, multicast, and private IP ranges before connecting.",
            "Disable redirects or re-validate every redirect target.",
            "Use short timeouts, response size limits, and network egress controls.",
        ],
        keywords=("ssrf", "server-side request forgery", "fetches a user-controlled url", "fetch(url)", "url preview", "metadata endpoint"),
    ),
    LearnedRuleTemplate(
        id="learned_open_redirect_001",
        title="Open Redirect: Validate Redirect Targets",
        source="OWASP Unvalidated Redirects and Forwards Cheat Sheet",
        source_url="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        category="open_redirect",
        severity="medium",
        rule_text="Do not redirect to user-controlled URLs unless the target is constrained to a safe same-origin path or explicit allowlist.",
        unsafe_patterns=[
            "Login, logout, invite, or completion route redirects directly to a next, returnUrl, redirect, or url parameter.",
            "Redirect target accepts absolute external URLs without validation.",
            "Redirect validation checks string prefixes instead of parsing and enforcing origin or allowlisted paths.",
        ],
        safe_patterns=[
            "Prefer fixed server-side redirect destinations for sensitive flows.",
            "Allow only relative same-origin paths when a return destination is required.",
            "Validate external redirect targets against an explicit allowlist.",
            "Fall back to a safe default route when validation fails.",
        ],
        keywords=("open redirect", "unvalidated redirect", "returnurl", "redirects to a user-controlled", "next query param"),
    ),
    LearnedRuleTemplate(
        id="learned_mass_assignment_001",
        title="Mass Assignment: Allowlist Bindable Fields",
        source="OWASP Mass Assignment Cheat Sheet",
        source_url="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        category="mass_assignment",
        severity="high",
        rule_text="Do not bind or merge arbitrary request fields into persisted objects. Only update explicitly allowlisted, non-sensitive fields.",
        unsafe_patterns=[
            "PATCH or update route spreads, merges, or assigns the entire request body into a user, customer, account, or settings object.",
            "Request body can set sensitive fields such as role, isAdmin, owner_id, plan, balance, approval, or security status.",
            "ORM update call receives unchecked request body data.",
        ],
        safe_patterns=[
            "Define an allowlist of bindable fields per route.",
            "Ignore or reject sensitive and unexpected fields.",
            "Use DTO/schema validation separate from persistence models.",
            "Add tests that sensitive fields cannot be changed through generic update routes.",
        ],
        keywords=("mass assignment", "merge every provided field", "request body", "isadmin", "bindable fields"),
    ),
    LearnedRuleTemplate(
        id="learned_csv_formula_injection_001",
        title="CSV Formula Injection: Escape Spreadsheet Formula Cells",
        source="OWASP CSV Injection",
        source_url="https://owasp.org/www-community/attacks/CSV_Injection",
        category="csv_formula_injection",
        severity="medium",
        rule_text="Do not export untrusted spreadsheet cells that can be interpreted as formulas without neutralizing formula control characters.",
        unsafe_patterns=[
            "CSV export writes untrusted values beginning with =, +, -, or @ directly into cells.",
            "Spreadsheet export assumes normal CSV quoting is enough to prevent formula execution.",
            "Customer notes, names, or imported fields are exported exactly as stored for Excel or Sheets.",
        ],
        safe_patterns=[
            "Prefix formula-like cells with a tab or other reviewed neutralization pattern before CSV export.",
            "Quote CSV fields and escape embedded quotes correctly.",
            "Apply formula-cell protection to every untrusted exported field.",
            "Document export behavior for downstream spreadsheet users.",
        ],
        keywords=("csv injection", "formula injection", "spreadsheet formula", "export.csv", "hyperlink("),
    ),
)


def infer_learned_rule_template(category: str | None, *parts: str | None) -> LearnedRuleTemplate | None:
    normalized_category = (category or "").strip().lower()
    haystack = " ".join(part for part in parts if part).lower()
    for template in LEARNED_RULE_TEMPLATES:
        if normalized_category == template.category:
            return template
        if any(keyword in haystack for keyword in template.keywords):
            return template
    return None


def build_learned_rule(template: LearnedRuleTemplate, created_at: str | Callable[[], str]) -> SafetyRule:
    timestamp = created_at() if callable(created_at) else created_at
    return SafetyRule(
        id=template.id,
        title=template.title,
        source=template.source,
        source_url=template.source_url,
        category=template.category,
        severity=template.severity,
        rule_text=template.rule_text,
        unsafe_patterns=template.unsafe_patterns,
        safe_patterns=template.safe_patterns,
        created_at=timestamp,
    )
