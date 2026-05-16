from __future__ import annotations

import asyncio
import inspect
import json
import os
import threading
from datetime import datetime, timezone
from importlib import import_module
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def _text_for(label: str, payload: Any, metadata: dict[str, Any] | None = None) -> str:
    body = {"label": label, "payload": _json_safe(payload)}
    if metadata:
        body["metadata"] = _json_safe(metadata)
    return json.dumps(body, sort_keys=True, default=str)


class MemoryAdapter:
    """Cognee-compatible memory adapter with a deterministic local fallback."""

    def __init__(self, dataset_name: str | None = None) -> None:
        self.dataset_name = dataset_name or os.getenv("COGNEE_DATASET", "redline_memory")
        self._cognee: Any | None = None
        self._search_type: Any | None = None
        self._last_error: str | None = None
        self._events: list[dict[str, Any]] = []
        self._memories: list[dict[str, Any]] = []
        self._session_memories: dict[str, list[dict[str, Any]]] = {}
        self._feedback: list[dict[str, Any]] = []
        self._proposals: list[dict[str, Any]] = []
        if os.getenv("COGNEE_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
            self._last_error = "Cognee disabled by COGNEE_ENABLED"
            return
        try:
            self._cognee = import_module("cognee")
            self._search_type = getattr(self._cognee, "SearchType", None)
            if self._search_type is None:
                search_module = import_module("cognee.api.v1.search")
                self._search_type = getattr(search_module, "SearchType", None)
        except Exception as exc:
            self._last_error = f"Cognee unavailable: {exc}"
            self._cognee = None

    @property
    def available(self) -> bool:
        return self._cognee is not None

    @property
    def degraded(self) -> bool:
        return not self.available or self._last_error is not None

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def log(self) -> list[dict[str, Any]]:
        return list(self._events)

    def remember(self, label: str, payload: Any) -> dict[str, Any]:
        return self.remember_durable(label, payload)

    def remember_durable(
        self,
        label: str,
        payload: Any,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry = self._append_memory("durable", label, payload, metadata)
        if self._cognee:
            text = _text_for(label, payload, metadata)
            if self._try_cognee_add(text, dataset_name=self.dataset_name):
                self._try_cognee_cognify()
        return entry

    def remember_session(
        self,
        session_id: str,
        label: str,
        payload: Any,
    ) -> dict[str, Any]:
        entry = self._append_memory("session", label, payload, {"session_id": session_id})
        self._session_memories.setdefault(session_id, []).append(entry)
        if self._cognee:
            text = _text_for(label, payload, {"session_id": session_id})
            if hasattr(self._cognee, "remember"):
                self._call_cognee("remember", text, session_id=session_id)
            else:
                self._try_cognee_add(text, dataset_name=self.dataset_name)
        return entry

    def recall(
        self,
        query: str,
        session_id: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        limit = max(1, top_k)
        results: list[dict[str, Any]] = []
        if self._cognee:
            cognee_results = self._recall_from_cognee(query, session_id)
            results.extend(self._normalize_results(cognee_results, "cognee"))

        seen = {self._result_key(result) for result in results}
        for result in self._recall_from_local(query, session_id, limit):
            key = self._result_key(result)
            if key not in seen:
                results.append(result)
                seen.add(key)
            if len(results) >= limit:
                break
        return results[:limit]

    def record_feedback(self, feedback_entry: dict[str, Any]) -> dict[str, Any]:
        entry = self._entry("feedback", "feedback", feedback_entry)
        self._feedback.append(entry)
        self._events.append({"event": "record_feedback", "entry": entry, "created_at": _utc_now()})
        if self._cognee:
            self._try_cognee_add(_text_for("feedback", feedback_entry), dataset_name=self.dataset_name)
        return entry

    def propose_improvement(self, feedback_entry: dict[str, Any]) -> dict[str, Any]:
        safe_feedback = _json_safe(feedback_entry)
        proposal = {
            "id": f"proposal-{len(self._proposals) + 1}",
            "status": "proposed",
            "label": safe_feedback.get("label", "feedback") if isinstance(safe_feedback, dict) else "feedback",
            "feedback": safe_feedback,
            "proposal": self._proposal_text(safe_feedback),
            "created_at": _utc_now(),
        }
        self._proposals.append(proposal)
        self._events.append({"event": "propose_improvement", "entry": proposal, "created_at": _utc_now()})
        if self._cognee and hasattr(self._cognee, "improve"):
            self._call_cognee("improve", dataset=self.dataset_name)
        return proposal

    def apply_improvement(self, proposal: dict[str, Any]) -> dict[str, Any]:
        applied = dict(_json_safe(proposal))
        applied["status"] = "applied"
        applied["applied_at"] = _utc_now()
        self._events.append({"event": "apply_improvement", "entry": applied, "created_at": _utc_now()})
        if self._cognee:
            self._try_cognee_add(_text_for("applied_improvement", applied), dataset_name=self.dataset_name)
            self._try_cognee_cognify()
        return applied

    def lint(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "degraded": self.degraded,
            "last_error": self._last_error,
            "dataset_name": self.dataset_name,
            "memory_count": len(self._memories),
            "session_count": len(self._session_memories),
            "feedback_count": len(self._feedback),
            "proposal_count": len(self._proposals),
        }

    def _entry(
        self,
        scope: str,
        label: str,
        payload: Any,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": f"memory-{len(self._memories) + len(self._feedback) + len(self._proposals) + 1}",
            "scope": scope,
            "label": label,
            "payload": _json_safe(payload),
            "metadata": _json_safe(metadata or {}),
            "created_at": _utc_now(),
        }

    def _append_memory(
        self,
        scope: str,
        label: str,
        payload: Any,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry = self._entry(scope, label, payload, metadata)
        self._memories.append(entry)
        self._events.append({"event": f"remember_{scope}", "entry": entry, "created_at": _utc_now()})
        return entry

    def _recall_from_cognee(self, query: str, session_id: str | None) -> Any:
        if not self._cognee:
            return None
        if session_id and hasattr(self._cognee, "recall"):
            return self._call_cognee(
                "recall",
                query,
                datasets=[self.dataset_name],
                session_id=session_id,
            )
        kwargs: dict[str, Any] = {"query_text": query, "datasets": [self.dataset_name]}
        query_type = getattr(self._search_type, "GRAPH_COMPLETION", None) if self._search_type else None
        if query_type is not None:
            kwargs["query_type"] = query_type
        result = self._call_cognee("search", **kwargs)
        if result is None:
            result = self._call_cognee("search", query, datasets=[self.dataset_name])
        return result

    def _recall_from_local(
        self,
        query: str,
        session_id: str | None,
        top_k: int,
    ) -> list[dict[str, Any]]:
        terms = {term for term in query.lower().split() if term}
        if session_id:
            candidates = [entry for entry in self._memories if entry.get("scope") != "session"]
            candidates.extend(self._session_memories.get(session_id, []))
        else:
            candidates = list(self._memories)
        candidates.extend(self._feedback)
        candidates.extend(self._proposals)
        ranked: list[tuple[int, dict[str, Any]]] = []
        for entry in candidates:
            haystack = json.dumps(entry, sort_keys=True, default=str).lower()
            score = sum(1 for term in terms if term in haystack)
            if score or not terms:
                result = dict(entry)
                result["source"] = "local"
                result["score"] = score
                ranked.append((score, result))
        ranked.sort(key=lambda item: (item[0], item[1].get("created_at", "")), reverse=True)
        return [entry for _, entry in ranked[:top_k]]

    def _try_cognee_add(self, text: str, dataset_name: str) -> bool:
        result = self._call_cognee("add", text, dataset_name=dataset_name)
        if result is not None or self._last_error is None:
            return True
        self._last_error = None
        return self._call_cognee("add", text) is not None or self._last_error is None

    def _try_cognee_cognify(self) -> None:
        if self._cognee:
            self._call_cognee("cognify", datasets=[self.dataset_name])

    def _call_cognee(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        if not self._cognee:
            return None
        method = getattr(self._cognee, method_name, None)
        if not method:
            self._last_error = f"Cognee method unavailable: {method_name}"
            return None
        try:
            result = method(*args, **kwargs)
            if inspect.isawaitable(result):
                return self._run_awaitable(result)
            self._last_error = None
            return result
        except Exception as exc:
            self._last_error = f"Cognee {method_name} failed: {exc}"
            return None

    def _run_awaitable(self, awaitable: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            try:
                result = asyncio.run(awaitable)
                self._last_error = None
                return result
            except Exception as exc:
                self._last_error = f"Cognee async call failed: {exc}"
                return None

        container: dict[str, Any] = {}

        def runner() -> None:
            try:
                container["result"] = asyncio.run(awaitable)
            except Exception as exc:
                container["error"] = exc

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join()
        if "error" in container:
            self._last_error = f"Cognee async call failed: {container['error']}"
            return None
        self._last_error = None
        return container.get("result")

    def _normalize_results(self, results: Any, source: str) -> list[dict[str, Any]]:
        if results is None:
            return []
        if isinstance(results, dict):
            values = results.get("results", results.get("data", [results]))
        elif isinstance(results, list):
            values = results
        else:
            values = [results]
        normalized: list[dict[str, Any]] = []
        for index, value in enumerate(values):
            item = _json_safe(value)
            if isinstance(item, dict):
                result = dict(item)
            else:
                result = {"content": item}
            result.setdefault("id", f"{source}-{index + 1}")
            result["source"] = source
            normalized.append(result)
        return normalized

    def _result_key(self, result: dict[str, Any]) -> str:
        return str(result.get("id") or result.get("content") or json.dumps(result, sort_keys=True, default=str))

    def _proposal_text(self, feedback: Any) -> str:
        if isinstance(feedback, dict):
            message = feedback.get("message") or feedback.get("notes") or feedback.get("reason")
            if message:
                return f"Review memory behavior for feedback: {message}"
        return "Review memory behavior for recorded feedback."
