"""ARGOS — Collaborative reputation & threat intelligence for the AI agent ecosystem.

ARGOS ("the VirusTotal of agentic AI security") analyzes AI agent components
(MCP servers, LLM interactions), detects attacks, and consolidates everything
into a global database of semantic threat fingerprints.

Subpackages:
    core                 Common data models and reference taxonomies.
    fingerprint_db       Semantic threat fingerprints + mutation detection (differentiator).
    component_analyzer   Static/dynamic analysis of MCP servers against OWASP MCP Top 10.
    interaction_analyzer Prompt-injection / jailbreak detection via a guardian model.
    api                  FastAPI REST layer exposing the platform.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
