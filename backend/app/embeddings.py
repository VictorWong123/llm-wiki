from __future__ import annotations

import hashlib
import math
import re


EMBEDDING_DIMENSIONS = 384
TOKEN_RE = re.compile(r"[a-zA-Z0-9_.$:-]+")


class HashEmbeddingProvider:
    """Small deterministic embedder for offline demo and tests.

    It is intentionally dependency-free. Redis vector search gets stable vectors
    without requiring network calls or model downloads.
    """

    dimensions = EMBEDDING_DIMENSIONS

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in TOKEN_RE.findall(text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if not norm:
            return vector
        return [value / norm for value in vector]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    return sum(a * b for a, b in zip(left, right))
