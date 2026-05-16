#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_API_BASE_URL = "http://localhost:8000"
DISABLED_VALUES = {"0", "false", "no", "off", "without"}

LEARNED_RULE_TEMPLATES: dict[str, dict[str, Any]] = {
    "server_side_request_forgery": {
        "id": "learned_ssrf_001",
        "title": "Server-Side Request Forgery: Restrict Server-Side URL Fetches",
        "source": "OWASP Server-Side Request Forgery Prevention Cheat Sheet",
        "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "severity": "high",
        "rule_text": "Do not fetch user-controlled URLs from the server unless the destination is strictly validated and constrained.",
        "unsafe_patterns": [
            "Server route calls fetch(url), httpx.get(url), requests.get(url), or similar with request-controlled URL input.",
            "URL preview, webhook, import, callback, or metadata fetch accepts arbitrary schemes or hosts.",
            "HTTP client follows redirects after validating only the original URL.",
            "Server-side fetch allows loopback, link-local, private network, cloud metadata, or file-style destinations.",
        ],
        "safe_patterns": [
            "Allow only required schemes, usually https.",
            "Validate hostnames against an explicit allowlist for the feature.",
            "Resolve DNS and reject loopback, link-local, multicast, and private IP ranges before connecting.",
            "Disable redirects or re-validate every redirect target.",
            "Use short timeouts, response size limits, and network egress controls.",
        ],
        "keywords": ("ssrf", "server-side request forgery", "fetches a user-controlled url", "fetch(url)", "url preview", "metadata endpoint"),
    },
    "open_redirect": {
        "id": "learned_open_redirect_001",
        "title": "Open Redirect: Validate Redirect Targets",
        "source": "OWASP Unvalidated Redirects and Forwards Cheat Sheet",
        "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "severity": "medium",
        "rule_text": "Do not redirect to user-controlled URLs unless the target is constrained to a safe same-origin path or explicit allowlist.",
        "unsafe_patterns": [
            "Login, logout, invite, or completion route redirects directly to a next, returnUrl, redirect, or url parameter.",
            "Redirect target accepts absolute external URLs without validation.",
            "Redirect validation checks string prefixes instead of parsing and enforcing origin or allowlisted paths.",
        ],
        "safe_patterns": [
            "Prefer fixed server-side redirect destinations for sensitive flows.",
            "Allow only relative same-origin paths when a return destination is required.",
            "Validate external redirect targets against an explicit allowlist.",
            "Fall back to a safe default route when validation fails.",
        ],
        "keywords": ("open redirect", "unvalidated redirect", "returnurl", "redirects to a user-controlled", "next query param"),
    },
    "mass_assignment": {
        "id": "learned_mass_assignment_001",
        "title": "Mass Assignment: Allowlist Bindable Fields",
        "source": "OWASP Mass Assignment Cheat Sheet",
        "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        "severity": "high",
        "rule_text": "Do not bind or merge arbitrary request fields into persisted objects. Only update explicitly allowlisted, non-sensitive fields.",
        "unsafe_patterns": [
            "PATCH or update route spreads, merges, or assigns the entire request body into a user, customer, account, or settings object.",
            "Request body can set sensitive fields such as role, isAdmin, owner_id, plan, balance, approval, or security status.",
            "ORM update call receives unchecked request body data.",
        ],
        "safe_patterns": [
            "Define an allowlist of bindable fields per route.",
            "Ignore or reject sensitive and unexpected fields.",
            "Use DTO/schema validation separate from persistence models.",
            "Add tests that sensitive fields cannot be changed through generic update routes.",
        ],
        "keywords": ("mass assignment", "merge every provided field", "request body", "isadmin", "bindable fields"),
    },
    "csv_formula_injection": {
        "id": "learned_csv_formula_injection_001",
        "title": "CSV Formula Injection: Escape Spreadsheet Formula Cells",
        "source": "OWASP CSV Injection",
        "source_url": "https://owasp.org/www-community/attacks/CSV_Injection",
        "severity": "medium",
        "rule_text": "Do not export untrusted spreadsheet cells that can be interpreted as formulas without neutralizing formula control characters.",
        "unsafe_patterns": [
            "CSV export writes untrusted values beginning with =, +, -, or @ directly into cells.",
            "Spreadsheet export assumes normal CSV quoting is enough to prevent formula execution.",
            "Customer notes, names, or imported fields are exported exactly as stored for Excel or Sheets.",
        ],
        "safe_patterns": [
            "Prefix formula-like cells with a tab or other reviewed neutralization pattern before CSV export.",
            "Quote CSV fields and escape embedded quotes correctly.",
            "Apply formula-cell protection to every untrusted exported field.",
            "Document export behavior for downstream spreadsheet users.",
        ],
        "keywords": ("csv injection", "formula injection", "spreadsheet formula", "export.csv", "hyperlink("),
    },
}


def _guard_disabled() -> bool:
    return os.getenv("REDLINE_AGENT_GUARD", "on").strip().lower() in DISABLED_VALUES


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _digest(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def _post_json(api_base_url: str, path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{api_base_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _query(payload: dict[str, Any]) -> str:
    return " ".join(
        part
        for part in [
            payload["title"],
            payload["description"],
            payload.get("evidence") or "",
            payload.get("affected_content") or "",
        ]
        if part
    ).strip()


def _token_score(query: str, payload: dict[str, Any]) -> float:
    terms = {term for term in re.findall(r"[a-zA-Z0-9_]{4,}", query.lower())}
    if not terms:
        return 0
    haystack = json.dumps(payload, sort_keys=True, default=str).lower()
    return round(sum(1 for term in terms if term in haystack) / len(terms), 4)


def _local_matches(query: str, top_k: int) -> list[dict[str, Any]]:
    matches: list[tuple[float, dict[str, Any]]] = []
    for path in sorted((REPO_ROOT / "wiki" / "agent_findings").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        score = _token_score(query, payload)
        if score <= 0:
            continue
        summary = " ".join([payload.get("title", ""), payload.get("description", "")]).strip()
        matches.append(
            (
                score,
                {
                    "id": payload.get("id", path.stem),
                    "kind": "agent_finding",
                    "risk_type": payload.get("category"),
                    "title": payload.get("title"),
                    "severity": payload.get("severity"),
                    "score": score,
                    "source": payload.get("source", "agent"),
                    "summary": summary[:220],
                },
            )
        )
    matches.sort(key=lambda item: item[0], reverse=True)
    return [match for _, match in matches[:top_k]]


def _write_local_finding(payload: dict[str, Any], query: str) -> dict[str, Any]:
    now = _utc_now()
    session_id = payload.get("session_id") or "session:local-redline-finding"
    matched_rule_id = payload.get("matched_rule_id")
    if not matched_rule_id:
        template = _infer_learned_rule_template(payload)
        if template:
            _write_local_rule(template, now)
            matched_rule_id = template["id"]
    finding = {
        "id": f"finding_{_digest(f'{session_id}:{query}:{now}')}",
        "title": payload["title"].strip(),
        "description": payload["description"].strip(),
        "status": "NEEDS HUMAN REVIEW",
        "severity": payload["severity"],
        "category": payload["category"],
        "matched_rule_id": matched_rule_id,
        "evidence": payload.get("evidence"),
        "affected_content": payload.get("affected_content"),
        "safe_rewrite": payload.get("safe_rewrite"),
        "source": "agent",
        "session_id": session_id,
        "created_at": now,
    }
    root = REPO_ROOT / "wiki" / "agent_findings"
    root.mkdir(parents=True, exist_ok=True)
    base = root / finding["id"]
    base.with_suffix(".json").write_text(json.dumps(finding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    base.with_suffix(".md").write_text(
        "\n".join(
            [
                "---",
                f"id: {finding['id']}",
                f"severity: {finding['severity']}",
                f"status: {finding['status']}",
                f"created_at: {finding['created_at']}",
                "---",
                "",
                f"# Agent Security Finding: {finding['title']}",
                "",
                "## Description",
                finding["description"],
                "",
                "## Evidence",
                finding.get("evidence") or "No evidence supplied.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return finding


def _infer_learned_rule_template(payload: dict[str, Any]) -> dict[str, Any] | None:
    category = str(payload.get("category") or "").strip().lower()
    if category in LEARNED_RULE_TEMPLATES:
        return LEARNED_RULE_TEMPLATES[category]
    haystack = " ".join(
        str(payload.get(key) or "")
        for key in ["title", "description", "evidence", "affected_content"]
    ).lower()
    for template in LEARNED_RULE_TEMPLATES.values():
        if any(keyword in haystack for keyword in template["keywords"]):
            return template
    return None


def _write_local_rule(template: dict[str, Any], created_at: str) -> None:
    root = REPO_ROOT / "wiki" / "safety_rules"
    root.mkdir(parents=True, exist_ok=True)
    base = root / str(template["id"])
    if base.with_suffix(".json").exists():
        return
    rule = {
        "id": template["id"],
        "title": template["title"],
        "source": template["source"],
        "source_url": template["source_url"],
        "category": next(category for category, candidate in LEARNED_RULE_TEMPLATES.items() if candidate["id"] == template["id"]),
        "severity": template["severity"],
        "rule_text": template["rule_text"],
        "unsafe_patterns": template["unsafe_patterns"],
        "safe_patterns": template["safe_patterns"],
        "created_at": created_at,
    }
    write_json = json.dumps(rule, indent=2, sort_keys=True) + "\n"
    base.with_suffix(".json").write_text(write_json, encoding="utf-8")
    base.with_suffix(".md").write_text(
        "\n".join(
            [
                "---",
                f"id: {rule['id']}",
                f"category: {rule['category']}",
                f"severity: {rule['severity']}",
                f"source: {rule['source']}",
                f"source_url: {rule['source_url']}",
                "status: active",
                f"created_at: {rule['created_at']}",
                "---",
                "",
                f"# {rule['title']}",
                "",
                "## Rule",
                rule["rule_text"],
                "",
                "## Source",
                rule["source_url"],
                "",
                "## Unsafe Patterns",
                *[f"- {pattern}" for pattern in rule["unsafe_patterns"]],
                "",
                "## Safe Pattern",
                *[f"- {pattern}" for pattern in rule["safe_patterns"]],
                "",
                "## Detector Notes",
                "Learned from an agent finding. Add deterministic detectors or regression tests when implementation evidence is available.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _local_finding(payload: dict[str, Any]) -> dict[str, Any]:
    query = _query(payload)
    matches = _local_matches(query, payload["top_k"])
    prior = next((match for match in matches if (match.get("score") or 0) >= payload["similarity_threshold"]), None)
    if prior or not payload["log_if_new"]:
        if prior:
            _backfill_existing_finding_rule(str(prior.get("id")), payload)
        return {
            "status": "EXISTING_MATCH_FOUND" if prior else "NOT_LOGGED",
            "session_id": payload.get("session_id") or "session:local-redline-finding",
            "query": query,
            "existing_matches": matches,
            "finding": None,
            "memory_trace": ["Searched local wiki/agent_findings.", "Skipped logging because a matching finding exists." if prior else "Skipped logging because log_if_new was false."],
            "guard_enabled": True,
        }
    finding = _write_local_finding(payload, query)
    return {
        "status": "LOGGED_NEW_FINDING",
        "session_id": finding["session_id"],
        "query": query,
        "existing_matches": matches,
        "finding": finding,
        "memory_trace": ["Searched local wiki/agent_findings.", f"Logged {finding['id']} locally because the backend API was unavailable."],
        "guard_enabled": True,
    }


def _backfill_existing_finding_rule(finding_id: str, payload: dict[str, Any]) -> None:
    path = REPO_ROOT / "wiki" / "agent_findings" / f"{finding_id}.json"
    if not path.exists():
        return
    try:
        finding = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    if finding.get("matched_rule_id"):
        return
    template = _infer_learned_rule_template({**finding, **payload})
    if not template:
        return
    _write_local_rule(template, _utc_now())
    finding["matched_rule_id"] = template["id"]
    path.write_text(json.dumps(finding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path = path.with_suffix(".md")
    if md_path.exists():
        markdown = md_path.read_text(encoding="utf-8")
        markdown = re.sub(r"matched_rule_id:\s*.*", f"matched_rule_id: {template['id']}", markdown, count=1)
        md_path.write_text(markdown, encoding="utf-8")


def _print_text(result: dict[str, Any]) -> None:
    print(f"REDLINE FINDING: {result.get('status')}")
    print(f"session_id: {result.get('session_id')}")
    matches = result.get("existing_matches") or []
    if matches:
        print("existing_matches:")
        for match in matches:
            print(f"- {match.get('id')} ({match.get('kind')}, score={match.get('score')}): {match.get('title')}")
    finding = result.get("finding")
    if finding:
        print(f"logged: {finding.get('id')} - {finding.get('title')}")
    for item in result.get("memory_trace") or []:
        print(f"- {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Search Redline memory and log a new agent security finding if it is novel.")
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--evidence")
    parser.add_argument("--affected-content")
    parser.add_argument("--affected-content-file")
    parser.add_argument("--safe-rewrite")
    parser.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--category", default="secure_code")
    parser.add_argument("--matched-rule-id")
    parser.add_argument("--input-type", default="code", choices=["code", "untrusted_content", "tool_plan"])
    parser.add_argument("--language")
    parser.add_argument("--session-id")
    parser.add_argument("--no-log", action="store_true")
    parser.add_argument("--similarity-threshold", type=float, default=0.74)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--api-base-url", default=os.getenv("REDLINE_API_BASE_URL", DEFAULT_API_BASE_URL))
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if _guard_disabled():
        result = {"guard_enabled": False, "status": "DISABLED", "reason": "REDLINE_AGENT_GUARD is disabled"}
        print(json.dumps(result, indent=2) if args.json else "REDLINE FINDING: disabled by REDLINE_AGENT_GUARD")
        return 0

    affected_content = args.affected_content
    if args.affected_content_file:
        affected_content = Path(args.affected_content_file).read_text(encoding="utf-8")
    payload = {
        "title": args.title,
        "description": args.description,
        "evidence": args.evidence,
        "affected_content": affected_content,
        "safe_rewrite": args.safe_rewrite,
        "severity": args.severity,
        "category": args.category,
        "matched_rule_id": args.matched_rule_id,
        "input_type": args.input_type,
        "language": args.language,
        "session_id": args.session_id,
        "log_if_new": not args.no_log,
        "similarity_threshold": args.similarity_threshold,
        "top_k": args.top_k,
    }
    try:
        result = _post_json(args.api_base_url, "/agent/finding", payload, args.timeout)
    except (OSError, urllib.error.URLError, TimeoutError):
        result = _local_finding(payload)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
