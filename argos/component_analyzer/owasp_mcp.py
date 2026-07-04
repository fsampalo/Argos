"""Reglas heurísticas OWASP MCP Top 10 sobre un inventario de componente.

Son heurísticas transparentes y explicables (coincidencia de patrones/palabras)
sobre las herramientas, prompts y recursos que anuncia un componente.
Deliberadamente conservadoras; NO sustituyen el análisis dinámico ni la revisión
humana. La detección de mayor fidelidad es trabajo futuro (ver ROADMAP.md).
"""

from __future__ import annotations

import re

from argos.core.models import ComponentInventory, RiskFinding, Severity
from argos.core.taxonomies import get_owasp_risk

# Frases que, en la descripción de una tool o prompt, delatan tool-poisoning.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?(above|prior|previous)", re.I),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.I),
    re.compile(r"system\s+prompt", re.I),
    re.compile(r"<\s*important\s*>", re.I),
]

# Tokens que sugieren capacidades peligrosas/excesivas en nombres/descripciones.
_DANGEROUS_CAPABILITY_TERMS = [
    "exec", "shell", "subprocess", "os.system", "eval", "rm -rf",
    "sudo", "delete", "drop table", "arbitrary", "unrestricted",
]

# URIs/nombres de recursos que suelen filtrar secretos.
_SECRET_RESOURCE_PATTERNS = [
    re.compile(r"\.env(\b|$)", re.I),
    re.compile(r"id_rsa|\.pem$|private[_-]?key", re.I),
    re.compile(r"credentials|secrets?\.(json|ya?ml|txt)", re.I),
    re.compile(r"\.aws/|\.ssh/", re.I),
]


def _finding(owasp_id: str, description: str, evidence: dict,
             severity: Severity | None = None,
             recommendation: str = "") -> RiskFinding:
    risk = get_owasp_risk(owasp_id)
    return RiskFinding(
        owasp_id=owasp_id,
        title=risk.title,
        severity=severity or risk.default_severity,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
    )


def check_injection_in_descriptions(inv: ComponentInventory) -> list[RiskFinding]:
    """MCP01 — instrucciones inyectadas ocultas en texto de tools/prompts."""
    findings: list[RiskFinding] = []
    surfaces: list[tuple[str, str]] = []
    surfaces += [(f"tool:{t.name}", t.description) for t in inv.tools]
    surfaces += [(f"prompt:{p.name}", f"{p.description}\n{p.template}") for p in inv.prompts]

    for location, text in surfaces:
        for pattern in _INJECTION_PATTERNS:
            if match := pattern.search(text or ""):
                findings.append(_finding(
                    "MCP01",
                    "Contenido con aspecto de instrucción en una descripción o "
                    "prompt del componente, señal típica de tool poisoning.",
                    evidence={"location": location, "matched": match.group(0)},
                    recommendation="Revisar manualmente; tratar sus descripciones "
                                   "como entrada no confiable para el LLM anfitrión.",
                ))
                break  # un hallazgo por superficie basta
    return findings


def check_dangerous_capabilities(inv: ComponentInventory) -> list[RiskFinding]:
    """MCP02 — tools que anuncian capacidades peligrosas o excesivas."""
    findings: list[RiskFinding] = []
    for tool in inv.tools:
        haystack = f"{tool.name} {tool.description}".lower()
        hits = [term for term in _DANGEROUS_CAPABILITY_TERMS if term in haystack]
        if hits:
            findings.append(_finding(
                "MCP02",
                "La herramienta anuncia capacidades potencialmente peligrosas o excesivas.",
                evidence={"tool": tool.name, "terms": hits},
                recommendation="Confirmar mínimo privilegio y aislar (sandbox) su ejecución.",
            ))
    return findings


def check_secret_resources(inv: ComponentInventory) -> list[RiskFinding]:
    """MCP03 — recursos que probablemente exponen secretos/PII."""
    findings: list[RiskFinding] = []
    for res in inv.resources:
        target = f"{res.uri} {res.name}"
        for pattern in _SECRET_RESOURCE_PATTERNS:
            if pattern.search(target):
                findings.append(_finding(
                    "MCP03",
                    "El recurso expuesto coincide con un patrón asociado a "
                    "secretos o credenciales.",
                    evidence={"uri": res.uri},
                    recommendation="Eliminar material secreto de los recursos "
                                   "expuestos; nunca exponer .env/claves al agente.",
                ))
                break
    return findings


# Registro de todas las reglas implementadas.
RULES = [
    check_injection_in_descriptions,
    check_dangerous_capabilities,
    check_secret_resources,
]


def run_all_rules(inv: ComponentInventory) -> list[RiskFinding]:
    """Aplica todas las heurísticas OWASP MCP implementadas a ``inv``.

    NOTA: solo un subconjunto del Top 10 tiene heurística hoy (MCP01, MCP02,
    MCP03). MCP04–MCP10 requieren análisis dinámico o de transporte y son stubs
    (ver ROADMAP.md).
    """
    findings: list[RiskFinding] = []
    for rule in RULES:
        findings.extend(rule(inv))
    return findings
