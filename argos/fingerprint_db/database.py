"""The ARGOS Fingerprint Database — the project's core differentiator.

Where existing MCP/guardrail tools ask *"is this string malicious?"*, ARGOS asks
*"is this the same underlying threat we've seen before, even reworded?"*.

The database stores :class:`~argos.core.models.Threat` objects, each carrying a
semantic :class:`~argos.core.models.Fingerprint`. Given a new attack, it:

1. Embeds it into the same semantic space.
2. Compares it against every stored fingerprint via **cosine similarity**.
3. If the best match exceeds a threshold, it reports a *mutation* of a known
   threat (and bumps that threat's reputation) instead of a brand-new one.

This module is implemented for real. The in-memory store is intentionally simple;
swapping in a vector database (FAISS/Qdrant/pgvector) is a Phase-2 task tracked in
ROADMAP.md and does not change this public API.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from argos.core.models import Fingerprint, Severity, Threat, ThreatCategory
from argos.fingerprint_db.embeddings import Embedder, get_default_embedder

# Default cosine-similarity threshold above which two texts are considered the
# same underlying threat. Tuned informally on the sample dataset; calibrating
# this against a labeled corpus is a roadmap item.
DEFAULT_MUTATION_THRESHOLD = 0.72


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity between two equal-length vectors, in ``[-1, 1]``.

    Raises:
        ValueError: if the vectors have different dimensions.
    """
    if len(a) != len(b):
        raise ValueError(
            f"Cannot compare vectors of different dimensions: {len(a)} vs {len(b)}"
        )
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


@dataclass
class MatchResult:
    """Outcome of comparing a query against the database."""

    is_known: bool
    similarity: float
    threat: Optional[Threat] = None

    @property
    def is_mutation(self) -> bool:
        """True when we matched a known threat below a perfect (exact) score."""
        return self.is_known and self.similarity < 0.999


class FingerprintDB:
    """In-memory semantic threat database with mutation detection.

    Args:
        embedder: Embedding backend. Defaults to the real semantic backend.
        threshold: Cosine-similarity cutoff for treating a query as a known
            threat. Higher = stricter.
    """

    def __init__(
        self,
        embedder: Optional[Embedder] = None,
        threshold: float = DEFAULT_MUTATION_THRESHOLD,
    ) -> None:
        self.embedder: Embedder = embedder or get_default_embedder()
        self.threshold = threshold
        self._threats: list[Threat] = []

    # ------------------------------------------------------------------ #
    # Core operations
    # ------------------------------------------------------------------ #
    def fingerprint_text(self, text: str) -> Fingerprint:
        """Compute a semantic fingerprint for ``text`` using the active embedder."""
        vector = self.embedder.embed(text)
        return Fingerprint(vector=vector, model=self.embedder.model_name)

    def query(self, text: str) -> MatchResult:
        """Look up ``text`` against the database without modifying it.

        Returns the best matching known threat if similarity clears the
        threshold, otherwise an ``is_known=False`` result.
        """
        fp = self.fingerprint_text(text)
        best_threat: Optional[Threat] = None
        best_sim = -1.0
        for threat in self._threats:
            if threat.fingerprint is None:
                continue
            if threat.fingerprint.model != fp.model:
                # Never compare across incompatible embedding spaces.
                continue
            sim = cosine_similarity(fp.vector, threat.fingerprint.vector)
            if sim > best_sim:
                best_sim = sim
                best_threat = threat

        if best_threat is not None and best_sim >= self.threshold:
            return MatchResult(is_known=True, similarity=best_sim, threat=best_threat)
        return MatchResult(is_known=False, similarity=max(best_sim, 0.0), threat=best_threat)

    def add_or_merge(
        self,
        text: str,
        *,
        category: ThreatCategory = ThreatCategory.OTHER,
        severity: Severity = Severity.MEDIUM,
        source: str = "unknown",
    ) -> tuple[Threat, MatchResult]:
        """Add a threat, or merge it into an existing one if it's a mutation.

        This is the write path that makes the database *collaborative*: reworded
        resubmissions of a known attack increase that threat's reputation instead
        of polluting the store with near-duplicates.

        Returns:
            A tuple of (the resulting stored threat, the match result that
            produced the decision).
        """
        match = self.query(text)
        if match.is_known and match.threat is not None:
            existing = match.threat
            existing.times_reported += 1
            existing.last_seen = datetime.now(timezone.utc)
            if text.strip() and text not in existing.aliases and text != existing.text:
                existing.aliases.append(text)
            return existing, match

        threat = Threat(
            text=text,
            category=category,
            severity=severity,
            source=source,
            fingerprint=self.fingerprint_text(text),
        )
        self._threats.append(threat)
        return threat, match

    # ------------------------------------------------------------------ #
    # Introspection & persistence
    # ------------------------------------------------------------------ #
    def all_threats(self) -> list[Threat]:
        """Return all stored threats (live references, not copies)."""
        return list(self._threats)

    def __len__(self) -> int:
        return len(self._threats)

    def save(self, path: str | Path) -> None:
        """Persist the database to a JSON file (fingerprints included)."""
        path = Path(path)
        payload = {
            "model": self.embedder.model_name,
            "threshold": self.threshold,
            "threats": [t.model_dump(mode="json") for t in self._threats],
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def load(self, path: str | Path) -> None:
        """Load threats from a JSON file produced by :meth:`save`.

        Note: this replaces the current in-memory threats. It does not re-embed;
        it trusts the stored vectors, so ensure the embedder matches the model
        recorded in the file.
        """
        path = Path(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self._threats = [Threat.model_validate(t) for t in payload.get("threats", [])]
