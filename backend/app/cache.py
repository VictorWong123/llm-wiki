from __future__ import annotations

import json
import os
from importlib import import_module
from typing import Any


class CacheAdapter:
    def __init__(self) -> None:
        self._client: Any | None = None
        url = os.getenv("REDIS_URL")
        if not url:
            return
        try:
            redis = import_module("redis")
            self._client = redis.from_url(url, decode_responses=True)
            self._client.ping()
        except Exception:
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    def set_json(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        if not self._client:
            return
        self._client.setex(key, ttl_seconds, json.dumps(value))

    def get_json(self, key: str) -> Any | None:
        if not self._client:
            return None
        raw = self._client.get(key)
        return json.loads(raw) if raw else None
