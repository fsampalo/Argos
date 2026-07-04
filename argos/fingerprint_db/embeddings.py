"""Backends de embeddings semánticos para las huellas de amenazas.

Convierten el texto de un ataque en vectores densos cuya geometría captura el
*significado*, no la forma superficial. Eso es lo que permite a ARGOS reconocer
dos ataques reformulados como la misma amenaza.

Dos backends:

* :class:`SentenceTransformerEmbedder` — el backend real y semántico (por
  defecto). Usa un modelo sentence-transformer open source. Requiere la
  dependencia opcional ``sentence-transformers`` y descarga el modelo la primera
  vez.
* :class:`HashingEmbedder` — fallback determinista y sin dependencias, **NO
  semántico**. Existe solo para poder correr código y tests totalmente offline.
  No reconoce reformulaciones; la demo se niega a usarlo a propósito.
"""

from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from typing import Sequence

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class Embedder(ABC):
    """Backend de embeddings: mapea texto a un vector de dimensión fija."""

    #: Identificador del modelo. Se guarda en cada huella para no comparar
    #: nunca vectores de espacios distintos.
    model_name: str

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Devuelve el vector de embedding de una cadena."""

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        """Embebe varias cadenas. Los backends pueden sobreescribir por eficiencia."""
        return [self.embed(t) for t in texts]


class SentenceTransformerEmbedder(Embedder):
    """Backend semántico real sobre ``sentence-transformers``.

    El modelo se carga de forma perezosa en el primer uso.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self.model_name = model_name
        self._model = None  # carga perezosa

    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - depende del entorno
            raise ImportError(
                "SentenceTransformerEmbedder requiere el paquete "
                "'sentence-transformers'. Instálalo con `pip install "
                "sentence-transformers`, o usa HashingEmbedder para pruebas "
                "offline (no semánticas)."
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
    """Fallback offline, determinista y **no semántico**.

    Produce un vector normalizado de tokens hasheados. Sirve solo para ejercitar
    la fontanería (almacenamiento, coseno, API) sin descargar ningún modelo. No
    detecta reformulaciones: no usar para la demo de mutaciones.
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
    """Devuelve el embedder por defecto (real, semántico)."""
    return SentenceTransformerEmbedder()
