"""Prompt-injection / jailbreak detection via an open-source guardian model.

ARGOS delegates the *is this interaction an attack?* question to a dedicated
open-source classifier. The default is a DeBERTa-based prompt-injection detector
published on the Hugging Face Hub (e.g. ``protectai/deberta-v3-base-prompt-injection-v2``).

Design:
    * :class:`GuardianDetector` wraps the HF model behind a small, stable API
      (:meth:`classify`) returning a :class:`DetectionResult`.
    * Loading the model is the REAL integration point; it requires the optional
      ``transformers``/``torch`` dependencies and a model download.
    * :class:`HeuristicDetector` is a lightweight, dependency-free fallback used
      when the model isn't available. It is explicitly marked as low-fidelity and
      must not be mistaken for the guardian model.

Nothing here fabricates a verdict: if the model can't load, callers get a clear
error or the clearly-labeled heuristic fallback — never a fake "clean" result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from argos.core.models import Severity, ThreatCategory

DEFAULT_GUARDIAN_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


@dataclass
class DetectionResult:
    """Verdict for a single interaction."""

    is_attack: bool
    # Confidence in the "attack" label, in [0, 1].
    confidence: float
    category: ThreatCategory
    severity: Severity
    detector: str  # which backend produced this verdict
    raw: dict  # backend-specific raw output, for transparency/debugging


class GuardianDetector:
    """Wrapper around a Hugging Face prompt-injection classifier.

    The model is loaded lazily on first :meth:`classify` call.
    """

    def __init__(self, model_name: str = DEFAULT_GUARDIAN_MODEL) -> None:
        self.model_name = model_name
        self._pipeline = None  # lazily initialized HF pipeline

    def _ensure_pipeline(self) -> None:
        if self._pipeline is not None:
            return
        try:
            from transformers import pipeline
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ImportError(
                "GuardianDetector requires 'transformers' (and a backend such as "
                "torch). Install with `pip install transformers torch`, or use "
                "HeuristicDetector for a low-fidelity offline fallback."
            ) from exc
        # text-classification pipeline over the DeBERTa prompt-injection model.
        self._pipeline = pipeline(
            "text-classification",
            model=self.model_name,
            truncation=True,
        )

    def classify(self, text: str) -> DetectionResult:
        """Classify ``text`` as benign or a prompt-injection/jailbreak attempt.

        Raises:
            ImportError: if the transformers backend is unavailable.
        """
        self._ensure_pipeline()
        output = self._pipeline(text)[0]  # e.g. {"label": "INJECTION", "score": 0.99}
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
    """Dependency-free, LOW-FIDELITY fallback prompt-injection detector.

    Regex/keyword based. Intended only for offline smoke tests and demos where the
    guardian model can't be downloaded. It will miss paraphrased and novel attacks
    — do not rely on it for real protection.
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
        # Crude confidence: more distinct pattern hits -> higher confidence.
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
    """Return a detector.

    Args:
        prefer_model: if True, return the real guardian model wrapper (which will
            raise on ``classify`` if the dependency is missing). If False, return
            the heuristic fallback.
    """
    return GuardianDetector() if prefer_model else HeuristicDetector()


def analyze_interaction(
    text: str,
    detector: Optional["GuardianDetector | HeuristicDetector"] = None,
) -> DetectionResult:
    """Convenience one-shot: classify a single interaction.

    Uses the real guardian model by default.
    """
    detector = detector or get_detector(prefer_model=True)
    return detector.classify(text)
