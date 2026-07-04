"""Modelos de datos comunes de ARGOS.

Son el lenguaje compartido por todos los subpaquetes: el component analyzer
produce :class:`RiskReport`; el interaction analyzer y la base de huellas
intercambian :class:`Threat` y :class:`Fingerprint`; la API los serializa todos.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Marca de tiempo UTC con zona (evita el ``utcnow`` naive obsoleto)."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid4().hex


class Severity(str, Enum):
    """Escala de severidad normalizada usada en hallazgos y amenazas."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> float:
        """Peso numérico en [0, 1] para el scoring agregado de riesgo."""
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0,
        }[self]


class ThreatCategory(str, Enum):
    """Taxonomía de alto nivel de las amenazas que ARGOS maneja."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOOL_POISONING = "tool_poisoning"
    DATA_EXFILTRATION = "data_exfiltration"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    SUPPLY_CHAIN = "supply_chain"
    INSECURE_CONFIG = "insecure_config"
    OTHER = "other"


# --------------------------------------------------------------------------- #
# Inventario de componentes MCP
# --------------------------------------------------------------------------- #
class MCPTool(BaseModel):
    """Una herramienta expuesta por un servidor MCP."""

    name: str
    description: str = ""
    input_schema: dict = Field(default_factory=dict)  # JSON schema de los parámetros


class MCPPrompt(BaseModel):
    """Una plantilla de prompt expuesta por un servidor MCP."""

    name: str
    description: str = ""
    template: str = ""


class MCPResource(BaseModel):
    """Un recurso (fichero, URI, blob) expuesto por un servidor MCP."""

    uri: str
    name: str = ""
    mime_type: Optional[str] = None


class ComponentInventory(BaseModel):
    """Inventario estructurado de todo lo que expone un servidor MCP.

    Lo produce :mod:`argos.component_analyzer` y lo consumen las reglas OWASP.
    """

    server_name: str
    server_url: Optional[str] = None
    tools: list[MCPTool] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=_utcnow)


# --------------------------------------------------------------------------- #
# Informes de riesgo
# --------------------------------------------------------------------------- #
class RiskFinding(BaseModel):
    """Un hallazgo de riesgo ligado a una categoría OWASP MCP."""

    owasp_id: str  # p.ej. "MCP01"
    title: str
    severity: Severity
    description: str
    evidence: dict = Field(default_factory=dict)  # qué tool/prompt/recurso lo disparó
    recommendation: str = ""


class RiskReport(BaseModel):
    """Evaluación de riesgo agregada de un componente analizado."""

    report_id: str = Field(default_factory=_new_id)
    server_name: str
    findings: list[RiskFinding] = Field(default_factory=list)
    risk_score: float = 0.0  # 0-100 agregado (más alto = más riesgo)
    created_at: datetime = Field(default_factory=_utcnow)

    def compute_score(self) -> float:
        """Recalcula y guarda la puntuación agregada a partir de los hallazgos.

        Agregación saturante: muchos hallazgos leves nunca enmascaran del todo
        uno crítico. Es una heurística transparente, no un modelo calibrado.
        """
        if not self.findings:
            self.risk_score = 0.0
            return self.risk_score

        # 1 - Π(1 - severity_i), escalado a 0..100.
        product = 1.0
        for finding in self.findings:
            product *= 1.0 - finding.severity.score
        self.risk_score = round((1.0 - product) * 100.0, 1)
        return self.risk_score


# --------------------------------------------------------------------------- #
# Amenazas y huellas (el diferenciador)
# --------------------------------------------------------------------------- #
class Fingerprint(BaseModel):
    """Huella semántica de una amenaza: vector de embedding + metadatos.

    Dos ataques que *dicen lo mismo con otras palabras* deben tener huellas casi
    idénticas (alta similitud de coseno). Ese es el diferenciador de ARGOS.
    """

    fingerprint_id: str = Field(default_factory=_new_id)
    vector: list[float]
    model: str  # modelo que generó el vector; evita comparar espacios incompatibles
    dim: int = 0

    def model_post_init(self, __context: object) -> None:  # noqa: D401
        # Mantener ``dim`` coherente con la longitud real del vector.
        object.__setattr__(self, "dim", len(self.vector))


class Threat(BaseModel):
    """Amenaza conocida: el texto del ataque más su huella semántica.

    Es la unidad almacenada en la base global. Variantes reformuladas del mismo
    ataque deben colapsar en la misma amenaza por similitud de huellas.
    """

    threat_id: str = Field(default_factory=_new_id)
    text: str  # texto canónico/representativo del ataque
    category: ThreatCategory = ThreatCategory.OTHER
    severity: Severity = Severity.MEDIUM
    source: str = "unknown"  # dataset, autor, id de CVE, etc.
    fingerprint: Optional[Fingerprint] = None
    # Contadores de reputación agregados de las aportaciones de la comunidad.
    times_reported: int = 1
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    aliases: list[str] = Field(default_factory=list)  # variantes reconocidas

    @property
    def content_hash(self) -> str:
        """Hash estable del texto (duplicado exacto, no semántico)."""
        return hashlib.sha256(self.text.strip().lower().encode("utf-8")).hexdigest()
