"""
Episodic memory: stores embeddings of confirmed attack payloads
indexed by OWASP category and target model family.

Uses an in-memory store by default; swap _backend for ChromaDB or Qdrant
in production deployments.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class MemoryEntry:
    payload_text: str
    owasp_category: str
    surface: str
    strategy: str
    model_family: str
    cvss_score: float
    embedding: list[float]
    session_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


class EpisodicMemory:
    """
    Lightweight in-process vector store for confirmed attack payloads.

    Production note: replace _store with a ChromaDB or Qdrant collection
    for persistence and approximate nearest-neighbour search at scale.
    """

    def __init__(self, persist_path: str | None = None) -> None:
        self._store: list[MemoryEntry] = []
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path and self._persist_path.exists():
            self._load()

    def add(self, entry: MemoryEntry) -> None:
        self._store.append(entry)
        if self._persist_path:
            self._save()

    def query_relevant(
        self,
        model_family: str,
        owasp_category: str | None = None,
        top_k: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Return top_k entries most relevant to the given model family
        and optional OWASP category filter, sorted by CVSS score descending.
        """
        candidates = [
            e for e in self._store
            if e.model_family == model_family
            and (owasp_category is None or e.owasp_category == owasp_category)
        ]
        candidates.sort(key=lambda e: e.cvss_score, reverse=True)
        return [
            {
                "owasp_category": e.owasp_category,
                "surface": e.surface,
                "strategy": e.strategy,
                "cvss_score": e.cvss_score,
                "payload_preview": e.payload_text[:80] + "..."
                    if len(e.payload_text) > 80 else e.payload_text,
            }
            for e in candidates[:top_k]
        ]

    def similarity_search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
    ) -> list[MemoryEntry]:
        """Return top_k entries by cosine similarity to query_embedding."""
        scored = [
            (e, _cosine_similarity(query_embedding, e.embedding))
            for e in self._store
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [e for e, _ in scored[:top_k]]

    def __len__(self) -> int:
        return len(self._store)

    def _save(self) -> None:
        assert self._persist_path
        data = [vars(e) for e in self._store]
        self._persist_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        assert self._persist_path
        data = json.loads(self._persist_path.read_text(encoding="utf-8"))
        self._store = [MemoryEntry(**d) for d in data]
