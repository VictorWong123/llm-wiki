#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_API_BASE_URL = "http://localhost:8000"
DISABLED_VALUES = {"0", "false", "no", "off", "without"}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _guard_disabled() -> bool:
    return os.getenv("REDLINE_AGENT_GUARD", "on").strip().lower() in DISABLED_VALUES


def _post_json(api_base_url: str, path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{api_base_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _guess_risk_type(query: str, input_type: str) -> str | None:
    lowered = query.lower()
    if any(term in lowered for term in ["select", "insert", "update", "delete", "drop", "sql", "query"]):
        return "sql_injection"
    if input_type == "untrusted_content" and any(term in lowered for term in ["ignore previous instructions", "system prompt", "hidden instructions"]):
        return "prompt_injection"
    if any(term in lowered for term in ["api_key", "api key", "token", "password", "secret", "private key"]):
        return "secrets_management"
    if any(term in lowered for term in ["eval(", "exec(", "shell=true", "shell = true", "rm -rf", "child_process.exec"]):
        return "unsafe_shell_commands"
    if any(term in lowered for term in ["authorization", "permission", "owner_id", "account_id", "project_id", "user_id", "current user"]):
        return "authorization"
    return None


def _risk_type_for_rule_id(rule_id: str) -> str:
    for hint in ["sql_injection", "prompt_injection", "secrets_management", "unsafe_shell_commands", "authorization"]:
        if hint in rule_id:
            return hint
    return rule_id.replace("raw_", "").replace("_001", "")


def _load_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted((REPO_ROOT / "wiki" / "safety_rules").glob("*.json")):
        rules.append(json.loads(path.read_text(encoding="utf-8")))
    return rules


def _score_rule(rule: dict[str, Any], query: str, input_type: str) -> tuple[int, str]:
    risk = _guess_risk_type(query, input_type)
    rule_risk = _risk_type_for_rule_id(rule["id"])
    haystack = " ".join(
        [
            rule.get("id", ""),
            rule.get("title", ""),
            rule.get("category", ""),
            rule.get("rule_text", ""),
            " ".join(rule.get("unsafe_patterns", [])),
            " ".join(rule.get("safe_patterns", [])),
        ]
    ).lower()
    terms = {term.strip(".,:;()[]{}\"'").lower() for term in query.split() if len(term.strip(".,:;()[]{}\"'")) >= 4}
    score = sum(1 for term in terms if term in haystack)
    reasons: list[str] = []
    if risk and risk == rule_risk:
        score += 8
        reasons.append(f"risk hint matched {risk}")
    if score and not reasons:
        reasons.append("task terms matched this wiki rule")
    if not reasons:
        reasons.append("baseline secure-coding rule")
    return score, "; ".join(reasons)


def _local_context(payload: dict[str, Any]) -> dict[str, Any]:
    query = " ".join(part for part in [payload["task"], payload.get("content") or ""] if part).strip()
    ranked = []
    for rule in _load_rules():
        score, reason = _score_rule(rule, query, payload["input_type"])
        ranked.append((score, SEVERITY_ORDER.get(rule.get("severity", "low"), 0), rule.get("title", ""), reason, rule))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    selected = [item for item in ranked if item[0] > 0][: payload["top_k"]]
    if len(selected) < min(payload["top_k"], 3):
        selected_ids = {item[4]["id"] for item in selected}
        selected.extend(item for item in ranked if item[4]["id"] not in selected_ids and item[1] >= 3)
        selected = selected[: payload["top_k"]]
    rules = []
    for _, _, _, reason, rule in selected[: payload["top_k"]]:
        rules.append(
            {
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "category": rule["category"],
                "source": rule["source"],
                "rule_text": rule["rule_text"],
                "unsafe_patterns": rule.get("unsafe_patterns", [])[:5],
                "safe_patterns": rule.get("safe_patterns", [])[:5],
                "why_relevant": reason,
            }
        )
    return {
        "session_id": payload.get("session_id") or "session:local-redline-context",
        "query": query,
        "rules": rules,
        "similar_memories": [],
        "memory_trace": [
            f"Retrieved {len(rules)} wiki safety rules locally.",
            "Backend API was unavailable, so no demo event was recorded.",
        ],
        "degraded": True,
        "guard_enabled": True,
    }


def _print_text(result: dict[str, Any]) -> None:
    print("REDLINE AGENT CONTEXT: enabled")
    print(f"session_id: {result.get('session_id')}")
    for index, rule in enumerate(result.get("rules", []), start=1):
        print(f"\n{index}. {rule['rule_id']} - {rule['title']} [{rule['severity']}]")
        print(f"   why: {rule['why_relevant']}")
        print(f"   rule: {rule['rule_text']}")
        safe_patterns = rule.get("safe_patterns") or []
        if safe_patterns:
            print(f"   safe: {safe_patterns[0]}")
    trace = result.get("memory_trace") or []
    if trace:
        print("\ntrace:")
        for item in trace:
            print(f"- {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrieve Redline wiki context for a coding agent.")
    parser.add_argument("task", nargs="*", help="Task description for the coding agent.")
    parser.add_argument("--content-file", help="Optional file whose content should influence rule retrieval.")
    parser.add_argument("--input-type", default="code", choices=["code", "untrusted_content", "tool_plan"])
    parser.add_argument("--language")
    parser.add_argument("--session-id")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--api-base-url", default=os.getenv("REDLINE_API_BASE_URL", DEFAULT_API_BASE_URL))
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--json", action="store_true", help="Print raw JSON.")
    args = parser.parse_args()

    if _guard_disabled():
        message = {"guard_enabled": False, "reason": "REDLINE_AGENT_GUARD is disabled"}
        print(json.dumps(message, indent=2) if args.json else "REDLINE AGENT CONTEXT: disabled by REDLINE_AGENT_GUARD")
        return 0

    content = None
    if args.content_file:
        content = Path(args.content_file).read_text(encoding="utf-8")
    task = " ".join(args.task).strip() or "coding task"
    payload = {
        "task": task,
        "content": content,
        "input_type": args.input_type,
        "language": args.language,
        "session_id": args.session_id,
        "top_k": args.top_k,
    }
    try:
        result = _post_json(args.api_base_url, "/agent/context", payload, args.timeout)
    except (OSError, urllib.error.URLError, TimeoutError):
        result = _local_context(payload)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
