"""Detección de inyección de prompt / jailbreak con un modelo guardián open source.

ARGOS delega la pregunta *¿es un ataque esta interacción?* a un clasificador open
source dedicado. Por defecto, un detector de inyección basado en DeBERTa de
Hugging Face (p.ej. ``protectai/deberta-v3-base-prompt-injection-v2``).

* :class:`GuardianDetector` envuelve el modelo HF tras una API estable
  (:meth:`classify`) que devuelve un :class:`DetectionResult`.
* :class:`HeuristicDetector` es un fallback ligero sin dependencias, de baja
  fidelidad, marcado como tal. No confundir con el modelo guardián.

Nada aquí fabrica un veredicto: si el modelo no carga, quien llama recibe un error
claro o el fallback heurístico etiquetado — nunca un falso "limpio".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from argos.core.models import Severity, ThreatCategory

DEFAULT_GUARDIAN_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


@dataclass
class DetectionResult:
    """Veredicto para una interacción."""

    is_attack: bool
    confidence: float  # confianza en la etiqueta "ataque", en [0, 1]
    category: ThreatCategory
    severity: Severity
    detector: str  # qué backend produjo el veredicto
    raw: dict  # salida cruda del backend, por transparencia


class GuardianDetector:
    """Envoltorio del clasificador de inyección de prompt de Hugging Face.

    El modelo se carga de forma perezosa en el primer :meth:`classify`.
    """

    def __init__(self, model_name: str = DEFAULT_GUARDIAN_MODEL) -> None:
        self.model_name = model_name
        self._pipeline = None  # pipeline HF con carga perezosa

    def _ensure_pipeline(self) -> None:
        if self._pipeline is not None:
            return
        try:
            from transformers import pipeline
        except ImportError as exc:  # pragma: no cover - depende del entorno
            raise ImportError(
                "GuardianDetector requiere 'transformers' (y un backend como "
                "torch). Instálalo con `pip install transformers torch`, o usa "
                "HeuristicDetector como fallback offline de baja fidelidad."
            ) from exc
        self._pipeline = pipeline(
            "text-classification",
            model=self.model_name,
            truncation=True,
        )

    def classify(self, text: str) -> DetectionResult:
        """Clasifica ``text`` como benigno o intento de inyección/jailbreak.

        Raises:
            ImportError: si el backend transformers no está disponible.
        """
        self._ensure_pipeline()
        output = self._pipeline(text)[0]  # p.ej. {"label": "INJECTION", "score": 0.99}
        label = str(output.get("label", "")).upper()
        score = float(output.get("score", 0.0))
        is_attack = label in {"INJECTION", "JAILBREAK", "LABEL_1", "UNSAFE"}
        confidence = score if is_attack else 1.0 - score
        severity = Severity.HIGH if is_attack and confidence >= 0.9 else (
            Severity.MEDIUM if is_attack else Severity.INFO
        )
        return DetectionResult(
            is_attack=is_attack,
            confidence=round(confidence, 4),
            category=ThreatCategory.PROMPT_INJECTION,
            severity=severity,
            detector=self.model_name,
            raw=dict(output),
        )


class HeuristicDetector:
    """Fallback sin dependencias, de BAJA FIDELIDAD, para inyección de prompt.

    Basado en regex/palabras clave. Solo para pruebas offline y demos donde el
    modelo guardián no se pueda descargar. Se le escaparán ataques parafraseados
    y novedosos: no confiar en él para protección real.
    """

    _PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I),
        re.compile(r"disregard\s+(the\s+)?(above|prior|previous|system)", re.I),
        re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.I),
        re.compile(r"you\s+are\s+now\s+(dan|in\s+developer\s+mode)", re.I),
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I),
        re.compile(r"jailbreak", re.I),
    ]

    def __init__(self) -> None:
        self.model_name = "heuristic-regex-LOWFIDELITY"

    def classify(self, text: str) -> DetectionResult:
        matches = [p.pattern for p in self._PATTERNS if p.search(text or "")]
        is_attack = bool(matches)
        # Confianza cruda: más patrones distintos -> más confianza.
        confidence = min(0.5 + 0.15 * len(matches), 0.95) if is_attack else 0.6
        return DetectionResult(
            is_attack=is_attack,
            confidence=round(confidence, 4),
            category=ThreatCategory.PROMPT_INJECTION if is_attack else ThreatCategory.OTHER,
            severity=Severity.MEDIUM if is_attack else Severity.INFO,
            detector=self.model_name,
            raw={"matched_patterns": matches},
        )


def get_detector(prefer_model: bool = True) -> "GuardianDetector | HeuristicDetector":
    """Devuelve un detector.

    Args:
        prefer_model: si True, el guardián real (que lanzará en ``classify`` si
            falta la dependencia). Si False, el fallback heurístico.
    """
    return GuardianDetector() if prefer_model else HeuristicDetector()


def analyze_interaction(
    text: str,
    detector: Optional["GuardianDetector | HeuristicDetector"] = None,
) -> DetectionResult:
    """Atajo: clasifica una interacción. Usa el guardián real por defecto."""
    detector = detector or get_detector(prefer_model=True)
    return detector.classify(text)
