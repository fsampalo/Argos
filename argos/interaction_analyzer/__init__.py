"""Prompt-injection / jailbreak detection via an open-source guardian model."""

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
