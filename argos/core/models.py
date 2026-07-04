"""Common data models for ARGOS.

These Pydantic models are the lingua franca shared by every subpackage: the
component analyzer produces :class:`RiskReport`, the interaction analyzer and the
fingerprint database exchange :class:`Threat` and :class:`Fingerprint`, and the
API serializes all of them.

The models are intentionally implementation-light: they describe *what* a threat
or report looks like, not *how* it is produced.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Timezone-aware UTC timestamp (avoids the deprecated naive ``utcnow``)."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid4().hex


class Severity(str, Enum):
    """Normalized severity scale used across findings and threats."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> float:
        """Numeric weight in the range [0, 1] used for aggregate risk scoring."""
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0,
        }[self]


class ThreatCategory(str, Enum):
    """High-level taxonomy of threats ARGOS reasons about.

    Kept deliberately small and stable; finer-grained references (e.g. the
    specific OWASP MCP risk id) live as metadata on the individual objects.
    """

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOOL_POISONING = "tool_poisoning"
    DATA_EXFILTRATION = "data_exfiltration"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    SUPPLY_CHAIN = "supply_chain"
    INSECURE_CONFIG = "insecure_config"
    OTHER = "other"


# --------------------------------------------------------------------------- #
# MCP component inventory models
# --------------------------------------------------------------------------- #
class MCPTool(BaseModel):
    """A single tool exposed by an MCP server."""

    name: str
    description: str = ""
    # JSON schema of the tool's input parameters, as advertised by the server.
    input_schema: dict = Field(default_factory=dict)


class MCPPrompt(BaseModel):
    """A prompt template exposed by an MCP server."""

    name: str
    description: str = ""
    template: str = ""


class MCPResource(BaseModel):
    """A resource (file, URI, blob) exposed by an MCP server."""

    uri: str
    name: str = ""
    mime_type: Optional[str] = None


class ComponentInventory(BaseModel):
    """Structured inventory of everything an MCP server exposes.

    Produced by :mod:`argos.component_analyzer` and consumed by the OWASP
    risk-scoring rules.
    """

    server_name: str
    server_url: Optional[str] = None
    tools: list[MCPTool] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=_utcnow)


# --------------------------------------------------------------------------- #
# Risk reporting models
# --------------------------------------------------------------------------- #
class RiskFinding(BaseModel):
    """A single risk observation tied to an OWASP MCP category."""

    owasp_id: str  # e.g. "MCP01"
    title: str
    severity: Severity
    description: str
    # Free-form evidence: which tool/prompt/resource triggered the finding.
    evidence: dict = Field(default_factory=dict)
    recommendation: str = ""


class RiskReport(BaseModel):
    """Aggregated risk assessment for an analyzed component."""

    report_id: str = Field(default_factory=_new_id)
    server_name: str
    findings: list[RiskFinding] = Field(default_factory=list)
    # 0-100 aggregate risk score (higher = riskier). Computed from findings.
    risk_score: float = 0.0
    created_at: datetime = Field(default_factory=_utcnow)

    def compute_score(self) -> float:
        """Recompute and store the aggregate risk score from current findings.

        The score is a normalized, saturating aggregation of finding severities:
        many low findings never fully mask a single critical one. This is a
        transparent heuristic, not a calibrated model — see the README.
        """
        if not self.findings:
            self.risk_score = 0.0
            return self.risk_score

        # Saturating aggregation: 1 - Π(1 - severity_i), scaled to 0..100.
        product = 1.0
        for finding in self.findings:
            product *= 1.0 - finding.severity.score
        self.risk_score = round((1.0 - product) * 100.0, 1)
        return self.risk_score


# --------------------------------------------------------------------------- #
# Threat & fingerprint models (the differentiator)
# --------------------------------------------------------------------------- #
class Fingerprint(BaseModel):
    """A semantic fingerprint of a threat.

    The fingerprint is an embedding vector plus enough metadata to compare,
    deduplicate and cluster threats. Two attacks that *say the same thing with
    different words* should have near-identical fingerprints (high cosine
    similarity) — that is ARGOS's core differentiator.
    """

    fingerprint_id: str = Field(default_factory=_new_id)
    # The embedding vector. Stored as a plain list for JSON-friendliness.
    vector: list[float]
    # Name/id of the embedding model that produced the vector, so we never
    # compare vectors from incompatible embedding spaces.
    model: str
    dim: int = 0

    def model_post_init(self, __context: object) -> None:  # noqa: D401
        # Keep ``dim`` consistent with the actual vector length.
        object.__setattr__(self, "dim", len(self.vector))


class Threat(BaseModel):
    """A known threat: the raw attack text plus its semantic fingerprint.

    A ``Threat`` is the unit stored in the global fingerprint database. Multiple
    reworded variants of the same underlying attack are expected to collapse to
    the same threat via fingerprint similarity (mutation detection).
    """

    threat_id: str = Field(default_factory=_new_id)
    # The canonical/representative attack text.
    text: str
    category: ThreatCategory = ThreatCategory.OTHER
    severity: Severity = Severity.MEDIUM
    source: str = "unknown"  # dataset name, submitter, CVE id, etc.
    fingerprint: Optional[Fingerprint] = None
    # Reputation counters aggregated from community contributions.
    times_reported: int = 1
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    # Known reworded variants recognized as the same threat.
    aliases: list[str] = Field(default_factory=list)

    @property
    def content_hash(self) -> str:
        """Stable hash of the raw text (exact-duplicate detection, not semantic)."""
        return hashlib.sha256(self.text.strip().lower().encode("utf-8")).hexdigest()
