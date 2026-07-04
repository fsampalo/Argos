"""Huellas semánticas de amenazas y detección de mutaciones — el diferenciador."""

from argos.fingerprint_db.database import (
    DEFAULT_MUTATION_THRESHOLD,
    FingerprintDB,
    MatchResult,
    cosine_similarity,
)
from argos.fingerprint_db.embeddings import (
    Embedder,
    HashingEmbedder,
    SentenceTransformerEmbedder,
    get_default_embedder,
)

__all__ = [
    "FingerprintDB",
    "MatchResult",
    "cosine_similarity",
    "DEFAULT_MUTATION_THRESHOLD",
    "Embedder",
    "SentenceTransformerEmbedder",
    "HashingEmbedder",
    "get_default_embedder",
]
