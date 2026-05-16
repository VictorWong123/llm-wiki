from __future__ import annotations

import hashlib
import json
import os
import re
import time
from array import array
from importlib import import_module
from typing import Any

from .embeddings import EMBEDDING_DIMENSIONS, HashEmbeddingProvider, cosine_similarity
from .models import (
    FingerprintEntry,
    InputType,
    MemoryMatch,
    PreflightResult,
    RegressionTestEntry,
    SafetyRule,
    SecurityFindingEntry,
    TraceEvent,
    ViolationEntry,
    utc_now,
)


STREAM_KEY = "stream:redline_events"
INDEX_NAME = "idx:safety_memories"
SESSION_TTL_SECONDS = 60 * 60 * 24


RISK_BY_RULE_HINT = {
    "sql_injection": "sql_injection",
    "prompt_injection": "prompt_injection",
    "secrets": "secrets_management",
    "secrets_management": "secrets_management",
    "unsafe_shell_commands": "unsafe_shell_commands",
    "authorization": "authorization",
}


def risk_type_for_rule_id(rule_id: str | None) -> str | None:
    if not rule_id:
        return None
    for hint, risk_type in RISK_BY_RULE_HINT.items():
        if hint in rule_id:
            return risk_type
    return rule_id.replace("raw_", "").replace("_001", "")


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _json_safe(payload: Any) -> Any:
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    if isinstance(payload, dict):
        return {key: _json_safe(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_json_safe(value) for value in payload]
    return payload


def _short_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def build_rule_memory(rule: SafetyRule, embedder: HashEmbeddingProvider) -> dict[str, Any]:
    risk_type = risk_type_for_rule_id(rule.id) or rule.category
    content = " ".join(
        [
            rule.title,
            rule.category,
            rule.severity,
            rule.rule_text,
            " ".join(rule.unsafe_patterns),
            " ".join(rule.safe_patterns),
        ]
    )
    return {
        "id": rule.id,
        "kind": "rule",
        "risk_type": risk_type,
        "severity": rule.severity,
        "language": None,
        "title": rule.title,
        "source": rule.source,
        "content": content,
        "unsafe_patterns": rule.unsafe_patterns,
        "safe_patterns": rule.safe_patterns,
        "active": True,
        "created_at": rule.created_at,
        "embedding": embedder.embed(content),
    }


def build_violation_memory(
    violation: ViolationEntry,
    safe_rewrite_id: str | None,
    regression_id: str | None,
    input_type: InputType,
    language: str | None,
    embedder: HashEmbeddingProvider,
) -> dict[str, Any]:
    risk_type = risk_type_for_rule_id(violation.matched_rule_id)
    content = " ".join([violation.matched_rule_id, violation.original_content, violation.safe_rewrite, violation.notes or ""])
    return {
        "id": violation.id,
        "kind": "violation",
        "risk_type": risk_type,
        "severity": violation.severity,
        "language": language,
        "title": f"Observed violation for {violation.matched_rule_id}",
        "source": "redline-observed-violation",
        "content": content,
        "proposal_type": input_type,
        "matched_rule_ids": [violation.matched_rule_id],
        "safe_rewrite_id": safe_rewrite_id,
        "regression_test_id": regression_id,
        "created_at": violation.created_at,
        "embedding": embedder.embed(content),
    }


def build_regression_memory(
    regression: RegressionTestEntry,
    violation_id: str | None,
    embedder: HashEmbeddingProvider,
) -> dict[str, Any]:
    risk_type = risk_type_for_rule_id(regression.matched_rule_id)
    content = " ".join([regression.matched_rule_id, regression.input_type, regression.unsafe_content, regression.expected_status])
    return {
        "id": regression.id,
        "kind": "regression",
        "risk_type": risk_type,
        "severity": "medium",
        "language": None,
        "title": f"Regression test for {regression.matched_rule_id}",
        "source": "redline-regression-test",
        "content": content,
        "violation_id": violation_id,
        "expected_status": regression.expected_status,
        "created_at": regression.created_at,
        "embedding": embedder.embed(content),
    }


def build_security_finding_memory(
    finding: SecurityFindingEntry,
    input_type: InputType,
    language: str | None,
    embedder: HashEmbeddingProvider,
) -> dict[str, Any]:
    risk_type = risk_type_for_rule_id(finding.matched_rule_id) or finding.category
    content = " ".join(
        [
            finding.title,
            finding.description,
            finding.evidence or "",
            finding.affected_content or "",
            finding.safe_rewrite or "",
        ]
    )
    return {
        "id": finding.id,
        "kind": "agent_finding",
        "risk_type": risk_type,
        "severity": finding.severity,
        "language": language,
        "title": finding.title,
        "source": finding.source,
        "content": content,
        "proposal_type": input_type,
        "matched_rule_ids": [finding.matched_rule_id] if finding.matched_rule_id else [],
        "created_at": finding.created_at,
        "embedding": embedder.embed(content),
    }


def guess_risk_type(content: str, input_type: InputType) -> str | None:
    lowered = content.lower()
    if re.search(r"\b(select|insert|update|delete|drop)\b", lowered):
        return "sql_injection"
    if input_type == "untrusted_content" and any(phrase in lowered for phrase in ["ignore previous instructions", "reveal your system prompt", "hidden instructions"]):
        return "prompt_injection"
    if re.search(r"api[_-]?key|token|password|secret|sk-|ghp_|private key", lowered):
        return "secrets_management"
    if re.search(r"\beval\s*\(|\bexec\s*\(|shell\s*=\s*true|rm\s+-rf|child_process\.exec", lowered):
        return "unsafe_shell_commands"
    if "project_id" in lowered or "user_id" in lowered or "owner_id" in lowered:
        return "authorization"
    return None


def generate_fingerprint(content: str, input_type: InputType, language: str | None, risk_type: str | None = None) -> tuple[str, str, str] | None:
    normalized = normalize_text(content)
    risk = risk_type or guess_risk_type(content, input_type)
    lang = (language or "unknown").lower()
    if risk == "sql_injection" and re.search(r"\b(select|insert|update|delete|drop)\b", normalized) and (
        "f\"" in content or "f'" in content or "${" in content or re.search(r"['\"`]\s*\+", content) or re.search(r"\+\s*['\"`]", content)
    ):
        return ("sql_injection", f"sql_injection:{lang}:string_interpolated_sql", "string-interpolated SQL query")
    if risk == "prompt_injection" and "ignore previous instructions" in normalized:
        return ("prompt_injection", "prompt_injection:ignore_previous_instructions", "instruction override phrase")
    if risk == "secrets_management" and re.search(r"api[_-]?key|token|password|secret|sk-|ghp_|private key", normalized):
        return ("secrets_management", f"secrets_management:{lang}:hardcoded_secret", "hardcoded secret-like value")
    if risk == "unsafe_shell_commands" and re.search(r"\beval\s*\(|\bexec\s*\(|shell\s*=\s*true|rm\s+-rf|child_process\.exec", normalized):
        return ("unsafe_shell_commands", f"unsafe_shell_commands:{lang}:dynamic_or_destructive_execution", "dynamic or destructive execution")
    return None


class RedisMemoryAdapter:
    def __init__(self) -> None:
        self._client: Any | None = None
        self.embedder = HashEmbeddingProvider()
        self.available = False
        self.json_available = False
        self.search_available = False
        self.vector_available = False
        self.streams_available = False
        self._local_events: list[TraceEvent] = []
        self._local_memories: dict[str, dict[str, Any]] = {}
        url = os.getenv("REDIS_URL")
        if not url:
            return
        try:
            redis = import_module("redis")
            self._client = redis.from_url(url, decode_responses=True)
            self._client.ping()
            self.available = True
        except Exception:
            self._client = None
            return
        self._detect_capabilities()
        self.ensure_search_index()

    @property
    def configured(self) -> bool:
        return bool(os.getenv("REDIS_URL"))

    @property
    def degraded(self) -> bool:
        return self.configured and not self.available

    @property
    def status(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "available": self.available,
            "degraded": self.degraded,
            "redis_json": self.json_available,
            "redis_search": self.search_available,
            "redis_vector": self.vector_available,
            "redis_streams": self.streams_available,
            "url_env": "REDIS_URL" if self.configured else None,
            "role": "hot session memory, vector recall, streams, and unsafe-pattern fingerprints",
        }

    def _detect_capabilities(self) -> None:
        if not self._client:
            return
        try:
            self._client.xadd(STREAM_KEY, {"event_type": "capability.check", "payload": "{}", "created_at": utc_now()}, maxlen=50, approximate=True)
            self.streams_available = True
        except Exception:
            self.streams_available = False
        try:
            json_api = self._client.json()
            json_api.set("capability:json", "$", {"ok": True})
            json_api.get("capability:json")
            self.json_available = True
        except Exception:
            self.json_available = False
        try:
            self._client.ft(INDEX_NAME)
            self.search_available = True
            self.vector_available = True
        except Exception:
            self.search_available = False
            self.vector_available = False

    def ensure_search_index(self) -> None:
        if not self._client or not self.json_available:
            return
        try:
            self._client.ft(INDEX_NAME).info()
            self.search_available = True
            self.vector_available = True
            return
        except Exception:
            pass
        try:
            self._client.execute_command(
                "FT.CREATE",
                INDEX_NAME,
                "ON",
                "JSON",
                "PREFIX",
                "1",
                "memory:",
                "SCHEMA",
                "$.id",
                "AS",
                "id",
                "TAG",
                "$.kind",
                "AS",
                "kind",
                "TAG",
                "$.risk_type",
                "AS",
                "risk_type",
                "TAG",
                "$.severity",
                "AS",
                "severity",
                "TAG",
                "$.language",
                "AS",
                "language",
                "TAG",
                "$.title",
                "AS",
                "title",
                "TEXT",
                "WEIGHT",
                "3.0",
                "$.content",
                "AS",
                "content",
                "TEXT",
                "$.unsafe_patterns[*]",
                "AS",
                "unsafe_patterns",
                "TEXT",
                "$.safe_patterns[*]",
                "AS",
                "safe_patterns",
                "TEXT",
                "$.active",
                "AS",
                "active",
                "TAG",
                "$.embedding",
                "AS",
                "embedding",
                "VECTOR",
                "HNSW",
                "6",
                "TYPE",
                "FLOAT32",
                "DIM",
                str(EMBEDDING_DIMENSIONS),
                "DISTANCE_METRIC",
                "COSINE",
            )
            self.search_available = True
            self.vector_available = True
        except Exception:
            self.search_available = False
            self.vector_available = False

    def _set_plain_json(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        if not self._client:
            return
        encoded = json.dumps(_json_safe(value))
        if ttl_seconds:
            self._client.setex(key, ttl_seconds, encoded)
        else:
            self._client.set(key, encoded)

    def set_json(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        try:
            safe_value = _json_safe(value)
            if self._client and self.json_available:
                self._client.json().set(key, "$", safe_value)
                if ttl_seconds:
                    self._client.expire(key, ttl_seconds)
                return
            self._set_plain_json(key, safe_value, ttl_seconds=ttl_seconds)
        except Exception:
            return

    def get_json(self, key: str) -> Any | None:
        if not self._client:
            return None
        try:
            if self.json_available:
                return self._client.json().get(key)
            raw = self._client.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def store_document(self, key: str, value: dict[str, Any], ttl_seconds: int | None = None) -> None:
        safe_value = _json_safe(value)
        self._local_memories[key] = safe_value
        if not self._client:
            return
        try:
            if self.json_available:
                self._client.json().set(key, "$", safe_value)
                if ttl_seconds:
                    self._client.expire(key, ttl_seconds)
            else:
                self._set_plain_json(key, safe_value, ttl_seconds=ttl_seconds)
        except Exception:
            return

    def get_document(self, key: str) -> dict[str, Any] | None:
        if key in self._local_memories:
            return self._local_memories[key]
        if not self._client:
            return None
        try:
            if self.json_available:
                return self._client.json().get(key)
            raw = self._client.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def remember_rule(self, rule: SafetyRule) -> None:
        self.store_document(f"rule:{rule.id}", {**rule.model_dump(), "active": True, "risk_type": risk_type_for_rule_id(rule.id)})
        memory = build_rule_memory(rule, self.embedder)
        self.store_document(f"memory:rule:{rule.id}", memory)

    def remember_violation(
        self,
        violation: ViolationEntry,
        safe_rewrite_id: str | None,
        regression_id: str | None,
        input_type: InputType,
        language: str | None,
    ) -> None:
        doc = {
            **violation.model_dump(),
            "risk_type": risk_type_for_rule_id(violation.matched_rule_id),
            "proposal_type": input_type,
            "language": language,
            "matched_rule_ids": [violation.matched_rule_id],
            "safe_rewrite_id": safe_rewrite_id,
            "regression_test_id": regression_id,
        }
        self.store_document(f"violation:{violation.id}", doc)
        self.store_document(f"memory:violation:{violation.id}", build_violation_memory(violation, safe_rewrite_id, regression_id, input_type, language, self.embedder))

    def remember_rewrite(self, rewrite_id: str, violation_id: str, before: str, after: str, why_safe: str) -> None:
        self.store_document(
            f"rewrite:{rewrite_id}",
            {
                "id": rewrite_id,
                "violation_id": violation_id,
                "before": before,
                "after": after,
                "why_safe": why_safe,
                "created_at": utc_now(),
            },
        )

    def remember_regression(self, regression: RegressionTestEntry, violation_id: str | None) -> None:
        self.store_document(f"regression:{regression.id}", {**regression.model_dump(), "violation_id": violation_id, "risk_type": risk_type_for_rule_id(regression.matched_rule_id)})
        self.store_document(f"memory:regression:{regression.id}", build_regression_memory(regression, violation_id, self.embedder))

    def remember_security_finding(self, finding: SecurityFindingEntry, input_type: InputType, language: str | None) -> None:
        doc = {
            **finding.model_dump(),
            "risk_type": risk_type_for_rule_id(finding.matched_rule_id) or finding.category,
            "proposal_type": input_type,
            "language": language,
        }
        self.store_document(f"finding:{finding.id}", doc)
        self.store_document(f"memory:finding:{finding.id}", build_security_finding_memory(finding, input_type, language, self.embedder))

    def remember_preflight(self, result: PreflightResult, content_hash: str, input_type: InputType, language: str | None) -> None:
        if not result.preflight_id:
            return
        self.store_document(
            f"preflight:{result.preflight_id}",
            {
                "id": result.preflight_id,
                "session_id": result.session_id,
                "input_type": input_type,
                "language": language,
                "content_hash": content_hash,
                "status": result.status,
                "severity": result.severity,
                "matched_rule_ids": [rule.id for rule in result.matched_rules],
                "evidence": [item.model_dump() for item in result.evidence],
                "explanation": result.explanation,
                "safe_rewrite": result.safe_rewrite,
                "fast_path": result.fast_path,
                "created_at": utc_now(),
            },
        )

    def remember_session_event(self, session_id: str | None, event: dict[str, Any]) -> None:
        if not session_id:
            return
        key = f"session:{session_id}"
        existing = self.get_document(key) or {"id": session_id, "started_at": utc_now(), "events": []}
        existing["last_seen_at"] = utc_now()
        existing.setdefault("events", []).append(event)
        existing["events"] = existing["events"][-50:]
        self.store_document(key, existing, ttl_seconds=SESSION_TTL_SECONDS)

    def search_similar(self, query: str, input_type: InputType, top_k: int = 5) -> list[MemoryMatch]:
        risk_type = guess_risk_type(query, input_type)
        query_vector = self.embedder.embed(query)
        if self._client and self.search_available and self.vector_available:
            try:
                vector_bytes = array("f", query_vector).tobytes()
                base = f"@risk_type:{{{risk_type}}}" if risk_type else "*"
                redis_query = f"({base})=>[KNN {top_k} @embedding $vec AS vector_score]"
                result = self._client.ft(INDEX_NAME).search(
                    redis_query,
                    query_params={"vec": vector_bytes},
                    sort_by="vector_score",
                    dialect=2,
                )
                matches: list[MemoryMatch] = []
                for doc in getattr(result, "docs", []):
                    payload = getattr(doc, "json", None) or getattr(doc, "__dict__", {})
                    if isinstance(payload, str):
                        payload = json.loads(payload)
                    matches.append(_memory_match_from_doc(payload, score=_score_from_doc(doc)))
                return matches[:top_k]
            except Exception:
                pass
        candidates = [value for key, value in self._local_memories.items() if key.startswith("memory:")]
        scored: list[tuple[float, dict[str, Any]]] = []
        for doc in candidates:
            if risk_type and doc.get("risk_type") != risk_type:
                continue
            score = cosine_similarity(query_vector, doc.get("embedding", []))
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [_memory_match_from_doc(doc, score=round(score, 4)) for score, doc in scored[:top_k]]

    def check_fingerprint(self, content: str, input_type: InputType, language: str | None) -> FingerprintEntry | None:
        generated = generate_fingerprint(content, input_type, language)
        if not generated:
            return None
        _, fingerprint, _ = generated
        key = f"fingerprint:{_short_hash(fingerprint, 32)}"
        doc = self.get_document(key)
        return FingerprintEntry(**doc) if doc else None

    def save_fingerprint(
        self,
        content: str,
        input_type: InputType,
        language: str | None,
        result: PreflightResult,
        violation_id: str | None = None,
    ) -> FingerprintEntry | None:
        risk_type = risk_type_for_rule_id(result.matched_rules[0].id if result.matched_rules else None)
        generated = generate_fingerprint(content, input_type, language, risk_type=risk_type)
        if not generated:
            return None
        fp_risk, fingerprint, pattern = generated
        fp_hash = _short_hash(fingerprint, 32)
        key = f"fingerprint:{fp_hash}"
        now = utc_now()
        existing = self.get_document(key)
        if existing:
            existing["last_seen"] = now
            existing["count"] = int(existing.get("count", 0)) + 1
            existing["last_preflight_id"] = result.preflight_id
            if violation_id:
                existing["last_violation_id"] = violation_id
            doc = existing
        else:
            doc = {
                "fingerprint": fingerprint,
                "hash": fp_hash,
                "risk_type": fp_risk,
                "language": language,
                "pattern": pattern,
                "first_seen": now,
                "last_seen": now,
                "count": 1,
                "matched_rule_id": result.matched_rules[0].id if result.matched_rules else None,
                "last_preflight_id": result.preflight_id,
                "last_violation_id": violation_id,
            }
        self.store_document(key, doc)
        if self._client:
            try:
                self._client.zadd("fingerprints:recent", {fp_hash: time.time()})
                self._client.sadd(f"fingerprints:risk:{fp_risk}", fp_hash)
            except Exception:
                pass
        return FingerprintEntry(**doc)

    def emit_event(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        session_id: str | None = None,
        preflight_id: str | None = None,
    ) -> TraceEvent:
        event = TraceEvent(
            event_type=event_type,
            session_id=session_id,
            preflight_id=preflight_id,
            payload=payload or {},
            created_at=utc_now(),
        )
        if self._client and self.streams_available:
            try:
                event_id = self._client.xadd(
                    STREAM_KEY,
                    {
                        "event_type": event.event_type,
                        "session_id": event.session_id or "",
                        "preflight_id": event.preflight_id or "",
                        "payload": json.dumps(event.payload),
                        "created_at": event.created_at,
                    },
                    maxlen=500,
                    approximate=True,
                )
                event.id = event_id
            except Exception:
                pass
        self._local_events.append(event)
        self._local_events = self._local_events[-500:]
        return event

    def recent_events(self, session_id: str | None = None, limit: int = 50) -> list[TraceEvent]:
        events: list[TraceEvent] = []
        if self._client and self.streams_available:
            try:
                rows = self._client.xrevrange(STREAM_KEY, count=limit)
                for event_id, values in reversed(rows):
                    payload_raw = values.get("payload") or "{}"
                    event = TraceEvent(
                        id=event_id,
                        event_type=values.get("event_type", "unknown"),
                        session_id=values.get("session_id") or None,
                        preflight_id=values.get("preflight_id") or None,
                        payload=json.loads(payload_raw),
                        created_at=values.get("created_at", utc_now()),
                    )
                    if not session_id or event.session_id == session_id:
                        events.append(event)
                return events
            except Exception:
                pass
        for event in self._local_events[-limit:]:
            if not session_id or event.session_id == session_id:
                events.append(event)
        return events


def _score_from_doc(doc: Any) -> float | None:
    raw = getattr(doc, "vector_score", None)
    if raw is None:
        return None
    try:
        return round(1.0 - float(raw), 4)
    except Exception:
        return None


def _memory_match_from_doc(doc: dict[str, Any], score: float | None = None) -> MemoryMatch:
    summary = doc.get("content") or doc.get("title") or doc.get("id", "")
    if len(summary) > 220:
        summary = summary[:217] + "..."
    return MemoryMatch(
        id=doc.get("id", "unknown"),
        kind=doc.get("kind", "memory"),
        risk_type=doc.get("risk_type"),
        title=doc.get("title"),
        severity=doc.get("severity"),
        score=score,
        source=doc.get("source"),
        summary=summary,
    )
