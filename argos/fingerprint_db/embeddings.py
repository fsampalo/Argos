"""Semantic embedding backends for threat fingerprints.

This module turns attack text into dense vectors whose geometry captures
*meaning*, not surface form. That is what lets ARGOS recognize two reworded
attacks as the same threat.

Two backends are provided:

* :class:`SentenceTransformerEmbedder` — the real, semantic backend (default).
  Uses a small open-source sentence-transformer model. Requires the optional
  ``sentence-transformers`` dependency and downloads the model on first use.

* :class:`HashingEmbedder` — a deterministic, dependency-free fallback that is
  **NOT semantic**. It exists only so the codebase and tests can run in fully
  offline CI. It will *not* recognize reworded attacks; the demo intentionally
  refuses to use it. This is called out honestly rather than pretending it works.
"""

from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from typing import Sequence

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class Embedder(ABC):
    """Abstract embedding backend: maps text to a fixed-dimension vector."""

    #: Human-readable identifier of the underlying model. Stored on every
    #: fingerprint so vectors from different spaces are never compared.
    model_name: str

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Return the embedding vector for a single string."""

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed many strings. Backends may override for efficiency."""
        return [self.embed(t) for t in texts]


class SentenceTransformerEmbedder(Embedder):
    """Real semantic backend built on ``sentence-transformers``.

    The model is loaded lazily on first use so importing this module stays cheap.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self.model_name = model_name
        self._model = None  # lazily initialized

    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ImportError(
                "SentenceTransformerEmbedder requires the 'sentence-transformers' "
                "package. Install it with `pip install sentence-transformers`, or "
                "use HashingEmbedder for offline (non-semantic) smoke tests."
            ) from exc
        self._model = SentenceTransformer(self.model_name)

    def embed(self, text: str) -> list[float]:
        self._ensure_model()
        vector = self._model.encode(text, normalize_embeddings=True)
        return [float(x) for x in vector]

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        self._ensure_model()
        vectors = self._model.encode(list(texts), normalize_embeddings=True)
        return [[float(x) for x in row] for row in vectors]


class HashingEmbedder(Embedder):
    """Deterministic, offline, **non-semantic** fallback embedder.

    Produces a normalized bag-of-hashed-tokens vector. Useful only to exercise
    the plumbing (storage, cosine math, API wiring) without any model download.
    It cannot detect rewording — do not use it for the mutation-detection demo.
    """

    def __init__(self, dim: int = 256) -> None:
        self.model_name = f"hashing-{dim}d-NONSEMANTIC"
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        for token in text.lower().split():
            digest = hashlib.md5(token.encode("utf-8")).hexdigest()
            index = int(digest, 16) % self.dim
            vector[index] += 1.0
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]
        return vector


def get_default_embedder() -> Embedder:
    """Return the default (real, semantic) embedder."""
    return SentenceTransformerEmbedder()
