"""Detección de inyección de prompt / jailbreak con un modelo guardián open source."""

from argos.interaction_analyzer.detector import (
    DEFAULT_GUARDIAN_MODEL,
    DetectionResult,
    GuardianDetector,
    HeuristicDetector,
    analyze_interaction,
    get_detector,
)

__all__ = [
    "DetectionResult",
    "GuardianDetector",
    "HeuristicDetector",
    "analyze_interaction",
    "get_detector",
    "DEFAULT_GUARDIAN_MODEL",
]
