"""Base de huellas de ARGOS — el diferenciador del proyecto.

Donde las herramientas MCP/guardrail existentes preguntan *"¿es maliciosa esta
cadena?"*, ARGOS pregunta *"¿es la misma amenaza subyacente que ya vimos, aunque
esté reformulada?"*.

La base almacena :class:`~argos.core.models.Threat`, cada uno con su
:class:`~argos.core.models.Fingerprint` semántica. Dado un ataque nuevo:

1. Lo embebe en el mismo espacio semántico.
2. Lo compara con cada huella almacenada por **similitud de coseno**.
3. Si el mejor match supera el umbral, lo reporta como *mutación* de una amenaza
   conocida (y sube su reputación) en vez de como algo nuevo.

Implementado de verdad. El almacén en memoria es intencionadamente simple;
cambiarlo por una vector DB (FAISS/Qdrant/pgvector) es tarea de Fase 2 y no
altera esta API pública.
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

# Umbral de coseno por encima del cual dos textos se consideran la misma amenaza.
# Calibrado sobre el dataset de ejemplo con el modelo multilingüe por defecto: las
# paráfrasis reales quedan en ~0.39-0.86 y los textos benignos en ~0.09-0.21, así
# que 0.35 separa ambas clases con margen. Recalibrarlo contra un corpus etiquetado
# mayor es tarea del roadmap (el valor óptimo depende del modelo de embeddings).
DEFAULT_MUTATION_THRESHOLD = 0.35


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Similitud de coseno entre dos vectores de igual longitud, en ``[-1, 1]``.

    Raises:
        ValueError: si los vectores tienen dimensiones distintas.
    """
    if len(a) != len(b):
        raise ValueError(
            f"No se pueden comparar vectores de distinta dimensión: {len(a)} vs {len(b)}"
        )
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


@dataclass
class MatchResult:
    """Resultado de comparar una consulta con la base."""

    is_known: bool
    similarity: float
    threat: Optional[Threat] = None

    @property
    def is_mutation(self) -> bool:
        """True cuando hubo match conocido por debajo de una coincidencia exacta."""
        return self.is_known and self.similarity < 0.999


class FingerprintDB:
    """Base semántica de amenazas en memoria, con detección de mutaciones.

    Args:
        embedder: backend de embeddings. Por defecto el real semántico.
        threshold: corte de coseno para tratar una consulta como amenaza conocida.
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
    # Operaciones principales
    # ------------------------------------------------------------------ #
    def fingerprint_text(self, text: str) -> Fingerprint:
        """Calcula la huella semántica de ``text`` con el embedder activo."""
        vector = self.embedder.embed(text)
        return Fingerprint(vector=vector, model=self.embedder.model_name)

    def query(self, text: str) -> MatchResult:
        """Busca ``text`` en la base sin modificarla.

        Devuelve la mejor amenaza conocida si la similitud supera el umbral.
        """
        fp = self.fingerprint_text(text)
        best_threat: Optional[Threat] = None
        best_sim = -1.0
        for threat in self._threats:
            if threat.fingerprint is None:
                continue
            if threat.fingerprint.model != fp.model:
                # Nunca comparar entre espacios de embedding incompatibles.
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
        """Añade una amenaza, o la fusiona en una existente si es una mutación.

        Es la ruta de escritura que hace la base *colaborativa*: reenvíos
        reformulados de un ataque conocido suben su reputación en vez de generar
        casi-duplicados.

        Returns:
            (amenaza resultante almacenada, match que motivó la decisión).
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
    # Introspección y persistencia
    # ------------------------------------------------------------------ #
    def all_threats(self) -> list[Threat]:
        """Devuelve todas las amenazas almacenadas (referencias, no copias)."""
        return list(self._threats)

    def __len__(self) -> int:
        return len(self._threats)

    def save(self, path: str | Path) -> None:
        """Persiste la base en un fichero JSON (con las huellas incluidas)."""
        path = Path(path)
        payload = {
            "model": self.embedder.model_name,
            "threshold": self.threshold,
            "threats": [t.model_dump(mode="json") for t in self._threats],
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def load(self, path: str | Path) -> None:
        """Carga amenazas desde un JSON de :meth:`save`.

        Reemplaza las amenazas en memoria y no re-embebe: confía en los vectores
        guardados, así que el embedder debe coincidir con el modelo del fichero.
        """
        path = Path(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self._threats = [Threat.model_validate(t) for t in payload.get("threats", [])]
