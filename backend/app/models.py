from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Status = Literal["PASS", "WARNING", "REDLINE TRIGGERED", "NEEDS HUMAN REVIEW"]
Severity = Literal["low", "medium", "high", "critical"]
InputType = Literal["code", "untrusted_content", "tool_plan"]


class SafetyRule(BaseModel):
    id: str
    title: str
    source: str
    category: str
    severity: Severity
    rule_text: str
    unsafe_patterns: list[str] = Field(default_factory=list)
    safe_patterns: list[str] = Field(default_factory=list)
    created_at: str
    source_url: str | None = None


class IngestRequest(BaseModel):
    title: str
    source: str
    text: str


class PreflightRequest(BaseModel):
    input_type: InputType
    content: str
    language: str | None = None
    session_id: str | None = None


class Evidence(BaseModel):
    detector: str
    message: str
    snippet: str
    line: int | None = None


class ViolationEntry(BaseModel):
    id: str
    status: Status
    severity: Severity
    matched_rule_id: str
    evidence: list[Evidence]
    original_content: str
    safe_rewrite: str
    notes: str | None = None
    created_at: str


class RegressionTestEntry(BaseModel):
    id: str
    matched_rule_id: str
    input_type: InputType
    unsafe_content: str
    expected_status: Status
    created_at: str


class MemoryMatch(BaseModel):
    id: str
    kind: str
    risk_type: str | None = None
    title: str | None = None
    severity: Severity | None = None
    score: float | None = None
    source: str | None = None
    summary: str


class FingerprintEntry(BaseModel):
    fingerprint: str
    hash: str
    risk_type: str
    language: str | None = None
    pattern: str
    first_seen: str
    last_seen: str
    count: int = 1
    matched_rule_id: str | None = None
    last_preflight_id: str | None = None
    last_violation_id: str | None = None


class TraceEvent(BaseModel):
    id: str | None = None
    event_type: str
    session_id: str | None = None
    preflight_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class PreflightResult(BaseModel):
    preflight_id: str | None = None
    session_id: str | None = None
    status: Status
    matched_rules: list[SafetyRule] = Field(default_factory=list)
    severity: Severity = "low"
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str
    safe_rewrite: str
    fast_path: bool = False
    similar_memories: list[MemoryMatch] = Field(default_factory=list)
    memory_trace: list[str] = Field(default_factory=list)
    fingerprint: FingerprintEntry | None = None
    created_violation: ViolationEntry | None = None
    created_regression_test: RegressionTestEntry | None = None


class AcceptRewriteRequest(BaseModel):
    original_content: str
    safe_rewrite: str
    matched_rule_id: str
    notes: str | None = None
    input_type: InputType = "code"
    language: str | None = None
    session_id: str | None = None
    preflight_id: str | None = None


class AcceptRewriteResponse(BaseModel):
    observed_violation: ViolationEntry
    regression_test: RegressionTestEntry
    rewrite_id: str | None = None


class MemoryRecallRequest(BaseModel):
    query: str
    session_id: str | None = None
    top_k: int = 5


class MemoryRecallResponse(BaseModel):
    session_id: str | None = None
    redis_matches: list[MemoryMatch] = Field(default_factory=list)
    cognee_results: list[Any] = Field(default_factory=list)
    degraded: bool = False


class AgentContextRequest(BaseModel):
    task: str
    content: str | None = None
    input_type: InputType = "code"
    language: str | None = None
    session_id: str | None = None
    top_k: int = Field(default=5, ge=1, le=20)


class AgentRuleContext(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: str
    source: str
    rule_text: str
    unsafe_patterns: list[str] = Field(default_factory=list)
    safe_patterns: list[str] = Field(default_factory=list)
    why_relevant: str


class AgentContextResponse(BaseModel):
    session_id: str
    query: str
    rules: list[AgentRuleContext] = Field(default_factory=list)
    similar_memories: list[MemoryMatch] = Field(default_factory=list)
    memory_trace: list[str] = Field(default_factory=list)
    degraded: bool = False
    guard_enabled: bool = True


class SecurityFindingEntry(BaseModel):
    id: str
    title: str
    description: str
    status: Status = "NEEDS HUMAN REVIEW"
    severity: Severity
    category: str = "secure_code"
    matched_rule_id: str | None = None
    evidence: str | None = None
    affected_content: str | None = None
    safe_rewrite: str | None = None
    source: str = "agent"
    session_id: str | None = None
    created_at: str


class AgentFindingRequest(BaseModel):
    title: str
    description: str
    evidence: str | None = None
    affected_content: str | None = None
    safe_rewrite: str | None = None
    severity: Severity = "medium"
    category: str = "secure_code"
    matched_rule_id: str | None = None
    input_type: InputType = "code"
    language: str | None = None
    session_id: str | None = None
    log_if_new: bool = True
    similarity_threshold: float = Field(default=0.74, ge=0, le=1)
    top_k: int = Field(default=5, ge=1, le=20)


class AgentFindingResponse(BaseModel):
    status: Literal["EXISTING_MATCH_FOUND", "LOGGED_NEW_FINDING", "NOT_LOGGED"]
    session_id: str
    query: str
    existing_matches: list[MemoryMatch] = Field(default_factory=list)
    finding: SecurityFindingEntry | None = None
    memory_trace: list[str] = Field(default_factory=list)
    guard_enabled: bool = True


class FeedbackRequest(BaseModel):
    session_id: str | None = None
    preflight_id: str | None = None
    matched_rule_id: str | None = None
    success_score: float = Field(default=0, ge=0, le=1)
    score: float | None = Field(default=None, ge=0, le=1)
    feedback: str
    skill_name: str = "redline-preflight"
    accepted: bool | None = None
    result_snapshot: dict[str, Any] = Field(default_factory=dict)


class FeedbackEntry(BaseModel):
    id: str
    session_id: str | None = None
    preflight_id: str | None = None
    success_score: float
    feedback: str
    skill_name: str
    result_snapshot: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ImprovementProposal(BaseModel):
    id: str
    feedback_id: str
    skill_name: str
    apply: bool = False
    proposal: str
    created_at: str
    applied_at: str | None = None


class LintRequest(BaseModel):
    session_id: str | None = None
    apply: bool = False
    dry_run: bool | None = None
    checks: list[str] = Field(default_factory=lambda: ["duplicates", "conflicts", "stale"])
    max_session_age_hours: int = 24


class LintIssue(BaseModel):
    id: str
    kind: str
    severity: Severity
    message: str
    references: list[str] = Field(default_factory=list)
    applied: bool = False


class LintResponse(BaseModel):
    applied: bool = False
    issues: list[LintIssue] = Field(default_factory=list)


class EventListResponse(BaseModel):
    events: list[TraceEvent] = Field(default_factory=list)


class RecentWikiEntry(BaseModel):
    id: str
    kind: Literal["agent_finding", "observed_violation", "regression_test", "safety_rule"]
    title: str
    summary: str
    created_at: str
    severity: Severity | None = None
    status: Status | None = None
    matched_rule_id: str | None = None
    source_path: str
    app_path: str


class RecentWikiResponse(BaseModel):
    entries: list[RecentWikiEntry] = Field(default_factory=list)


def utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
