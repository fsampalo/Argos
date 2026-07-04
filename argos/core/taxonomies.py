"""Taxonomías de referencia de ARGOS.

La principal es el **OWASP MCP Top 10**, la lista comunitaria de los riesgos más
críticos para servidores MCP. Las entradas de abajo son la representación de
trabajo de ARGOS; el texto es un resumen propio, a re-sincronizar con el proyecto
upstream a medida que se estabilice (ver ROADMAP.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from argos.core.models import Severity, ThreatCategory


@dataclass(frozen=True)
class OwaspMcpRisk:
    """Una entrada del catálogo OWASP MCP Top 10."""

    id: str  # p.ej. "MCP01"
    title: str
    description: str
    default_severity: Severity
    category: ThreatCategory
    references: list[str] = field(default_factory=list)


OWASP_MCP_TOP_10: list[OwaspMcpRisk] = [
    OwaspMcpRisk(
        id="MCP01",
        title="Prompt / Tool Description Injection",
        description=(
            "Instrucciones maliciosas ocultas en descripciones de herramientas, "
            "plantillas de prompt o contenido de recursos que secuestran el LLM "
            "anfitrión al cargar el componente ('tool poisoning')."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.TOOL_POISONING,
    ),
    OwaspMcpRisk(
        id="MCP02",
        title="Excessive Tool Permissions / Overbroad Scope",
        description=(
            "Herramientas que piden acceso amplio a sistema de ficheros, red o "
            "shell más allá de lo que su propósito requiere, permitiendo abuso "
            "de privilegios."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.EXCESSIVE_PERMISSIONS,
    ),
    OwaspMcpRisk(
        id="MCP03",
        title="Sensitive Data Exposure via Resources",
        description=(
            "Recursos que exponen secretos, credenciales o PII (p.ej. ficheros "
            ".env, claves privadas, tokens) al agente conectado."
        ),
        default_severity=Severity.CRITICAL,
        category=ThreatCategory.DATA_EXFILTRATION,
    ),
    OwaspMcpRisk(
        id="MCP04",
        title="Command / Code Injection in Tool Handlers",
        description=(
            "Implementaciones de herramientas que pasan argumentos controlados "
            "por el agente a shells, eval o SQL sin sanear."
        ),
        default_severity=Severity.CRITICAL,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
    OwaspMcpRisk(
        id="MCP05",
        title="Unauthenticated / Weakly Authenticated Server",
        description=(
            "Endpoints MCP expuestos sin autenticación o con secretos débiles/"
            "compartidos, permitiendo a clientes no confiables invocar herramientas."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
    OwaspMcpRisk(
        id="MCP06",
        title="Supply-Chain / Rug-Pull of Server Definitions",
        description=(
            "Definiciones de servidor o herramienta que cambian de comportamiento "
            "tras la instalación ('rug pull'), o con dependencias no fijadas."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.SUPPLY_CHAIN,
    ),
    OwaspMcpRisk(
        id="MCP07",
        title="Cross-Server / Confused-Deputy Tool Shadowing",
        description=(
            "Un servidor malicioso que sobrescribe o eclipsa herramientas de un "
            "servidor confiable para interceptar llamadas o exfiltrar argumentos."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.TOOL_POISONING,
    ),
    OwaspMcpRisk(
        id="MCP08",
        title="Insecure Output / Response Injection",
        description=(
            "Salidas de herramientas con contenido manipulado que altera el "
            "razonamiento o las acciones del agente (inyección indirecta)."
        ),
        default_severity=Severity.MEDIUM,
        category=ThreatCategory.PROMPT_INJECTION,
    ),
    OwaspMcpRisk(
        id="MCP09",
        title="Insufficient Logging & Observability",
        description=(
            "Sin traza de auditoría de invocaciones y argumentos, impidiendo "
            "detectar y analizar forensemente el abuso."
        ),
        default_severity=Severity.MEDIUM,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
    OwaspMcpRisk(
        id="MCP10",
        title="Insecure Transport / Configuration",
        description=(
            "Transporte en claro, CORS permisivo o configuración por defecto "
            "peligrosa que expone el servidor a interceptación o abuso."
        ),
        default_severity=Severity.MEDIUM,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
]

# Índice de conveniencia: id -> entrada de riesgo.
OWASP_MCP_BY_ID: dict[str, OwaspMcpRisk] = {r.id: r for r in OWASP_MCP_TOP_10}


def get_owasp_risk(owasp_id: str) -> OwaspMcpRisk:
    """Devuelve la entrada OWASP MCP de ``owasp_id`` (p.ej. ``"MCP01"``)."""
    try:
        return OWASP_MCP_BY_ID[owasp_id]
    except KeyError as exc:  # pragma: no cover - defensivo
        raise KeyError(f"Id OWASP MCP desconocido: {owasp_id!r}") from exc
