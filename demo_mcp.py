"""Demo del análisis de componentes de ARGOS contra un servidor MCP EN VIVO.

Ejecutar:
    python demo_mcp.py

Qué hace (circuito completo real)
---------------------------------
1. Arranca un servidor MCP deliberadamente vulnerable (examples/vulnerable_mcp_server.py)
   como subproceso, por transporte stdio.
2. ARGOS se conecta con el SDK oficial de MCP y le "saca la ficha": enumera sus
   tools, prompts y recursos (tools/list, prompts/list, resources/list).
3. Evalúa el inventario frente al OWASP MCP Top 10 y saca un informe con puntuación.
4. Escribe el resultado en mcp_report.txt.

Es una ejecución REAL: habla el protocolo MCP con un servidor de verdad. Requiere el
paquete `mcp` (pip install mcp). Si falta, lo dice en vez de fingir.
"""

from __future__ import annotations

import sys
from pathlib import Path

from argos.component_analyzer import analyze_inventory, inventory_live_server
from argos.core.models import RiskReport

SERVER = Path(__file__).parent / "examples" / "vulnerable_mcp_server.py"
REPORT_TXT = Path(__file__).parent / "mcp_report.txt"

# Color/etiqueta ASCII por severidad (robusto en cualquier terminal).
SEV_TAG = {
    "critical": "[CRÍTICO]",
    "high": "[ALTO]   ",
    "medium": "[MEDIO]  ",
    "low": "[BAJO]   ",
    "info": "[INFO]   ",
}


def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def line(self, text: str = "") -> None:
        print(text)
        self.lines.append(text)

    def banner(self, title: str) -> None:
        self.line("\n" + "=" * 74)
        self.line(title)
        self.line("=" * 74)

    def save(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def _render(rep: Report, report: RiskReport, inv) -> None:
    rep.banner(f"Servidor MCP analizado: {report.server_name}")
    rep.line(f"  Tools     : {len(inv.tools)}")
    rep.line(f"  Prompts   : {len(inv.prompts)}")
    rep.line(f"  Recursos  : {len(inv.resources)}")
    rep.line(f"  Inventario recolectado EN VIVO por stdio (protocolo MCP real).")

    rep.banner(f"Puntuación de riesgo: {report.risk_score} / 100")
    if not report.findings:
        rep.line("  Sin hallazgos.")
        return
    rep.line(f"  {len(report.findings)} hallazgo(s):\n")
    for f in report.findings:
        tag = SEV_TAG.get(f.severity.value, "[?]")
        rep.line(f"  {tag} {f.owasp_id}  {f.title}")
        rep.line(f"            {f.description}")
        if f.evidence:
            rep.line(f"            evidencia: {f.evidence}")
        if f.recommendation:
            rep.line(f"            recomendación: {f.recommendation}")
        rep.line("")


def main() -> int:
    _force_utf8()
    rep = Report()
    rep.banner("ARGOS — Análisis de un servidor MCP EN VIVO")
    rep.line("Arrancando el servidor de demostración (vulnerable) y conectando por MCP...")

    try:
        inv = inventory_live_server(sys.executable, [str(SERVER)], server_name=None)
    except ImportError as exc:
        print(f"\n[!] Falta una dependencia: {exc}", file=sys.stderr)
        print("    Instálala con:  pip install mcp", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - la demo informa, no falla en silencio
        print(f"\n[!] No se pudo inventariar el servidor MCP: {exc}", file=sys.stderr)
        return 1

    report = analyze_inventory(inv)
    _render(rep, report, inv)

    rep.banner("Veredicto")
    expected = {"MCP01", "MCP02", "MCP03"}
    found = {f.owasp_id for f in report.findings}
    if expected <= found:
        rep.line("[PASA]  ARGOS se conectó al servidor MCP en vivo, enumeró sus")
        rep.line("        capacidades y detectó las tres debilidades sembradas")
        rep.line("        (MCP01 inyección, MCP02 shell, MCP03 fuga de .env).")
        exit_code = 0
    else:
        rep.line(f"[REVISAR]  Se esperaban {sorted(expected)} y se encontraron {sorted(found)}.")
        exit_code = 2

    rep.save(REPORT_TXT)
    rep.line(f"\nResultado guardado en:\n  {REPORT_TXT}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
