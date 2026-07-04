"""Component analyzer: inventory an MCP server and score its risk.

Pipeline:
    connect/inventory  ->  ComponentInventory  ->  OWASP heuristics  ->  RiskReport

The **scoring** path (inventory -> findings -> report) is fully implemented and
runs on any :class:`ComponentInventory`, including ones parsed from a static
manifest. The **live connection** path (actually speaking the MCP protocol to a
running server to enumerate its tools) is a STUB — it is the part that needs a
real MCP client and a target server, so it is marked honestly and raises
``NotImplementedError`` rather than returning fake data.
"""

from __future__ import annotations

from argos.component_analyzer.owasp_mcp import run_all_rules
from argos.core.models import ComponentInventory, RiskReport


def analyze_inventory(inventory: ComponentInventory) -> RiskReport:
    """Score an already-collected component inventory against OWASP MCP Top 10.

    This is the real, runnable entry point: given a structured inventory it
    returns a populated :class:`RiskReport` with findings and an aggregate score.
    """
    findings = run_all_rules(inventory)
    report = RiskReport(server_name=inventory.server_name, findings=findings)
    report.compute_score()
    return report


def inventory_from_manifest(manifest: dict) -> ComponentInventory:
    """Build a :class:`ComponentInventory` from a static MCP manifest dict.

    Accepts a permissive, MCP-like manifest shape::

        {
          "name": "acme-mcp",
          "url": "https://...",            # optional
          "tools":     [{"name", "description", "inputSchema"}],
          "prompts":   [{"name", "description", "template"}],
          "resources": [{"uri", "name", "mimeType"}]
        }

    Unknown fields are ignored. This lets ARGOS analyze published manifests
    without a live connection.
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
    """STUB — connect to a running MCP server and enumerate its capabilities.

    Intended behavior: open an MCP session to ``server_url`` (stdio or HTTP/SSE
    transport), call ``tools/list``, ``prompts/list`` and ``resources/list``, and
    assemble a :class:`ComponentInventory`.

    This requires a real MCP client and a live target, so it is not implemented
    yet. See ROADMAP.md (Phase 2).
    """
    raise NotImplementedError(
        "Live MCP server inventory is not implemented yet. "
        "Use inventory_from_manifest() with a static manifest for now. "
        "Tracked in ROADMAP.md, Phase 2."
    )


def analyze_live_server(server_url: str) -> RiskReport:
    """STUB — end-to-end analysis of a live MCP server.

    Composes :func:`inventory_live_server` with :func:`analyze_inventory` once the
    live connection path is implemented.
    """
    inventory = inventory_live_server(server_url)  # raises NotImplementedError
    return analyze_inventory(inventory)
