"""Component analyzer: inventaría un servidor MCP y puntúa su riesgo.

Pipeline:
    conectar/inventariar -> ComponentInventory -> heurísticas OWASP -> RiskReport

La ruta de *scoring* (inventario -> hallazgos -> informe) está implementada y
funciona con cualquier :class:`ComponentInventory`, incluido uno parseado de un
manifiesto estático. La *conexión en vivo* (hablar MCP con un servidor en marcha
para enumerar sus tools) es un STUB: es la parte que necesita un cliente MCP real
y un servidor objetivo, así que lanza ``NotImplementedError`` en vez de devolver
datos falsos.
"""

from __future__ import annotations

from argos.component_analyzer.owasp_mcp import run_all_rules
from argos.core.models import ComponentInventory, RiskReport


def analyze_inventory(inventory: ComponentInventory) -> RiskReport:
    """Puntúa un inventario ya recolectado frente al OWASP MCP Top 10.

    Punto de entrada real y ejecutable: devuelve un :class:`RiskReport` con
    hallazgos y puntuación agregada.
    """
    findings = run_all_rules(inventory)
    report = RiskReport(server_name=inventory.server_name, findings=findings)
    report.compute_score()
    return report


def inventory_from_manifest(manifest: dict) -> ComponentInventory:
    """Construye un :class:`ComponentInventory` desde un manifiesto MCP estático.

    Acepta una forma permisiva, tipo MCP::

        {
          "name": "acme-mcp",
          "url": "https://...",            # opcional
          "tools":     [{"name", "description", "inputSchema"}],
          "prompts":   [{"name", "description", "template"}],
          "resources": [{"uri", "name", "mimeType"}]
        }

    Los campos desconocidos se ignoran. Permite analizar manifiestos publicados
    sin conexión en vivo.
    """
    from argos.core.models import MCPPrompt, MCPResource, MCPTool

    return ComponentInventory(
        server_name=manifest.get("name", "unknown"),
        server_url=manifest.get("url"),
        tools=[
            MCPTool(
                name=t.get("name", ""),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", t.get("input_schema", {})) or {},
            )
            for t in manifest.get("tools", [])
        ],
        prompts=[
            MCPPrompt(
                name=p.get("name", ""),
                description=p.get("description", ""),
                template=p.get("template", ""),
            )
            for p in manifest.get("prompts", [])
        ],
        resources=[
            MCPResource(
                uri=r.get("uri", ""),
                name=r.get("name", ""),
                mime_type=r.get("mimeType", r.get("mime_type")),
            )
            for r in manifest.get("resources", [])
        ],
    )


def inventory_live_server(server_url: str) -> ComponentInventory:
    """STUB — conectar a un servidor MCP en marcha y enumerar sus capacidades.

    Comportamiento previsto: abrir una sesión MCP con ``server_url`` (transporte
    stdio o HTTP/SSE), llamar a ``tools/list``, ``prompts/list`` y
    ``resources/list``, y montar un :class:`ComponentInventory`.

    Requiere un cliente MCP real y un objetivo en vivo; sin implementar aún. Ver
    ROADMAP.md (Fase 2).
    """
    raise NotImplementedError(
        "El inventario de servidor MCP en vivo no está implementado aún. "
        "Usa inventory_from_manifest() con un manifiesto estático por ahora. "
        "Registrado en ROADMAP.md, Fase 2."
    )


def analyze_live_server(server_url: str) -> RiskReport:
    """STUB — análisis extremo a extremo de un servidor MCP en vivo.

    Compone :func:`inventory_live_server` con :func:`analyze_inventory` cuando la
    conexión en vivo esté implementada.
    """
    inventory = inventory_live_server(server_url)  # lanza NotImplementedError
    return analyze_inventory(inventory)
