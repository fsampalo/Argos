"""Component analyzer: inventaría un servidor MCP y puntúa su riesgo.

Pipeline:
    conectar/inventariar -> ComponentInventory -> heurísticas OWASP -> RiskReport

La ruta de *scoring* (inventario -> hallazgos -> informe) funciona con cualquier
:class:`ComponentInventory`, incluido uno parseado de un manifiesto estático o uno
recolectado en vivo. La *conexión en vivo* usa el SDK oficial de MCP por transporte
stdio: arranca el servidor como subproceso y llama a ``tools/list``, ``prompts/list``
y ``resources/list``. Requiere el paquete opcional ``mcp``.

Sigue siendo análisis estático de lo que el servidor *anuncia* (nombres,
descripciones, URIs): no observa el comportamiento en runtime. Las heurísticas
cubren MCP01-MCP03; MCP04-MCP10 necesitan análisis dinámico (ROADMAP.md, Fase 2).
"""

from __future__ import annotations

import asyncio
from typing import Optional, Sequence

from argos.component_analyzer.owasp_mcp import run_all_rules
from argos.core.models import (
    ComponentInventory,
    MCPPrompt,
    MCPResource,
    MCPTool,
    RiskReport,
)


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


async def inventory_live_server_async(
    command: str,
    args: Optional[Sequence[str]] = None,
    *,
    server_name: Optional[str] = None,
    timeout: float = 25.0,
) -> ComponentInventory:
    """Conecta a un servidor MCP por stdio y enumera sus capacidades (async).

    Arranca ``command args...`` como subproceso, abre una sesión MCP y llama a
    ``tools/list`` / ``prompts/list`` / ``resources/list``. Los dos últimos se
    ignoran con gracia si el servidor no anuncia esa capacidad.

    Args:
        command: ejecutable del servidor (p.ej. ``"python"`` o ``"npx"``).
        args: argumentos (p.ej. ``["examples/vulnerable_mcp_server.py"]``).
        server_name: nombre para el informe; si se omite, se usa el del servidor.
        timeout: segundos máximos para el handshake + enumeración (evita que un
            servidor que no responda cuelgue la llamada).

    Raises:
        ImportError: si el paquete ``mcp`` no está instalado.
        TimeoutError: si el servidor no responde a tiempo.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise ImportError(
            "El inventario MCP en vivo requiere el paquete 'mcp'. "
            "Instálalo con `pip install mcp`."
        ) from exc

    params = StdioServerParameters(command=command, args=list(args or []))

    async def _collect() -> ComponentInventory:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()

                tools_res = await session.list_tools()
                tools = [
                    MCPTool(
                        name=t.name,
                        description=t.description or "",
                        input_schema=getattr(t, "inputSchema", None) or {},
                    )
                    for t in tools_res.tools
                ]

                prompts = []
                try:
                    prompts_res = await session.list_prompts()
                    prompts = [
                        MCPPrompt(name=p.name, description=p.description or "")
                        for p in prompts_res.prompts
                    ]
                except Exception:  # noqa: BLE001 - capacidad opcional del servidor
                    pass

                resources = []
                try:
                    res_res = await session.list_resources()
                    resources = [
                        MCPResource(
                            uri=str(r.uri),
                            name=r.name or "",
                            mime_type=getattr(r, "mimeType", None),
                        )
                        for r in res_res.resources
                    ]
                except Exception:  # noqa: BLE001 - capacidad opcional del servidor
                    pass

                name = server_name or getattr(init.serverInfo, "name", None) or command
                return ComponentInventory(
                    server_name=name,
                    tools=tools,
                    prompts=prompts,
                    resources=resources,
                )

    return await asyncio.wait_for(_collect(), timeout=timeout)


def inventory_live_server(
    command: str,
    args: Optional[Sequence[str]] = None,
    *,
    server_name: Optional[str] = None,
    timeout: float = 25.0,
) -> ComponentInventory:
    """Versión síncrona de :func:`inventory_live_server_async` (usa ``asyncio.run``).

    No llamar desde dentro de un bucle de eventos ya en marcha; en ese caso usar
    directamente la variante async.
    """
    return asyncio.run(
        inventory_live_server_async(command, args, server_name=server_name, timeout=timeout)
    )


def analyze_live_server(
    command: str,
    args: Optional[Sequence[str]] = None,
    *,
    server_name: Optional[str] = None,
    timeout: float = 25.0,
) -> RiskReport:
    """Análisis extremo a extremo de un servidor MCP en vivo (inventario + scoring)."""
    inventory = inventory_live_server(command, args, server_name=server_name, timeout=timeout)
    return analyze_inventory(inventory)
