from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Evidence, InputType, PreflightResult, SafetyRule, Severity, Status
from .rewrite import rewrite_for


@dataclass
class DetectorMatch:
    rule_hint: str
    status: Status
    severity: Severity
    evidence: Evidence
    explanation: str


SQL_KEYWORDS = r"(SELECT|INSERT|UPDATE|DELETE|DROP)"
PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all above",
    "reveal your system prompt",
    "show hidden instructions",
    "developer message",
    "hidden instructions",
    "bypass safety",
    "disable guardrails",
    "act as unconstrained",
]
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*=\s*[\"'][^\"']{8,}[\"']"),
    re.compile(r"(?i)\b(?:postgres|mysql|mongodb)://[^:\s]+:[^@\s]+@"),
    re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{12,}"),
]


def _line_for(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def _snippet(content: str, start: int, end: int) -> str:
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end].strip()


def _evidence(name: str, message: str, content: str, start: int, end: int) -> Evidence:
    return Evidence(
        detector=name,
        message=message,
        snippet=_snippet(content, start, end),
        line=_line_for(content, start),
    )


def detect_sql_injection(content: str) -> DetectorMatch | None:
    patterns = [
        (re.compile(rf"f([\"'])(?=[^\n]*{SQL_KEYWORDS})[^\n]*\{{[^}}\n]+\}}[^\n]*\1", re.I), "SQL f-string interpolates a value"),
        (re.compile(rf"{SQL_KEYWORDS}[^;\n]*(?:\+|%)[^;\n]*", re.I), "SQL string is built with concatenation or formatting"),
        (re.compile(rf"{SQL_KEYWORDS}[^;\n]*\.format\(", re.I), "SQL string uses .format interpolation"),
        (re.compile(rf"`[^`]*{SQL_KEYWORDS}[^`]*\$\{{[^}}]+\}}[^`]*`", re.I | re.S), "SQL template literal interpolates a value"),
    ]
    for pattern, message in patterns:
        match = pattern.search(content)
        if match:
            return DetectorMatch(
                "sql_injection",
                "REDLINE TRIGGERED",
                "critical",
                _evidence("sql_injection", message, content, match.start(), match.end()),
                "User-controlled values appear to be inserted into executable SQL. Use parameterized queries.",
            )
    return None


def detect_prompt_injection(content: str, input_type: InputType) -> DetectorMatch | None:
    if input_type != "untrusted_content":
        return None
    lowered = content.lower()
    for phrase in PROMPT_INJECTION_PHRASES:
        index = lowered.find(phrase)
        if index >= 0:
            return DetectorMatch(
                "prompt_injection",
                "REDLINE TRIGGERED",
                "critical",
                _evidence("prompt_injection", f"Untrusted content contains instruction override phrase: {phrase}", content, index, index + len(phrase)),
                "Untrusted content is attempting to override higher-priority instructions. Treat it as data only.",
            )
    return None


def detect_secrets(content: str) -> DetectorMatch | None:
    for pattern in SECRET_PATTERNS:
        match = pattern.search(content)
        if match:
            return DetectorMatch(
                "secrets_management",
                "REDLINE TRIGGERED",
                "critical",
                _evidence("secrets", "Likely hardcoded credential or secret-like value", content, match.start(), match.end()),
                "Secrets should not be hardcoded, logged, or pasted into generated code. Use environment variables or a secrets manager.",
            )
    return None


def detect_unsafe_execution(content: str) -> DetectorMatch | None:
    patterns = [
        (re.compile(r"\beval\s*\("), "eval() executes dynamic code"),
        (re.compile(r"\bexec\s*\("), "exec() executes dynamic code"),
        (re.compile(r"shell\s*=\s*True"), "subprocess shell=True expands command injection risk"),
        (re.compile(r"child_process\.exec\s*\("), "child_process.exec runs a shell command string"),
        (re.compile(r"\brm\s+-rf\b|\bDROP\s+TABLE\b|git\s+push\s+--force", re.I), "destructive command requires confirmation"),
    ]
    for pattern, message in patterns:
        match = pattern.search(content)
        if match:
            return DetectorMatch(
                "unsafe_shell_commands",
                "REDLINE TRIGGERED",
                "critical",
                _evidence("unsafe_execution", message, content, match.start(), match.end()),
                "Dynamic execution or shell command strings can execute untrusted input. Use safe APIs and confirmation gates.",
            )
    return None


def detect_missing_authorization(content: str) -> DetectorMatch | None:
    route_terms = re.search(r"(@app\.(get|post|put|patch|delete)|router\.(get|post|put|patch|delete)|app\.(get|post|put|patch|delete)\()", content)
    resource_terms = re.search(r"(user_id|owner_id|account_id|project_id|delete|update|fetchone|find_unique|findUnique)", content, re.I)
    auth_terms = re.search(r"(auth|authorize|permission|session|current_user|requireUser|middleware|canAccess|role)", content, re.I)
    if route_terms and resource_terms and not auth_terms:
        match = resource_terms
        return DetectorMatch(
            "authorization",
            "WARNING",
            "high",
            _evidence("authorization", "Route touches user-owned resources without an obvious server-side authorization check", content, match.start(), match.end()),
            "The snippet may be missing object-level authorization. This requires review unless an auth layer exists outside the snippet.",
        )
    return None


def _rule_for(rules: list[SafetyRule], hint: str) -> SafetyRule | None:
    for rule in rules:
        if hint in rule.id:
            return rule
    return None


def run_preflight(content: str, input_type: InputType, rules: list[SafetyRule]) -> PreflightResult:
    matches = [
        detect_sql_injection(content),
        detect_prompt_injection(content, input_type),
        detect_secrets(content),
        detect_unsafe_execution(content),
        detect_missing_authorization(content),
    ]
    found = [match for match in matches if match]
    if not found:
        return PreflightResult(
            status="PASS",
            severity="low",
            explanation="No deterministic Redline rule matched this proposal.",
            safe_rewrite="No rewrite needed.",
        )
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    status_order = {"PASS": 0, "WARNING": 1, "NEEDS HUMAN REVIEW": 2, "REDLINE TRIGGERED": 3}
    primary = max(found, key=lambda item: (status_order[item.status], severity_order[item.severity]))
    matched_rules = [rule for match in found if (rule := _rule_for(rules, match.rule_hint))]
    return PreflightResult(
        status=primary.status,
        severity=primary.severity,
        matched_rules=matched_rules,
        evidence=[match.evidence for match in found],
        explanation=primary.explanation,
        safe_rewrite=rewrite_for(primary.rule_hint, content, input_type),
    )
