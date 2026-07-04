"""STUBS para descargar datasets públicos de ataques y catálogos de referencia.

La estrategia de datos de ARGOS es arrancar la base global de huellas desde
corpus públicos de ataques de inyección / jailbreak, más catálogos oficiales de
vulnerabilidades, y hacerla crecer con aportaciones de la comunidad.

Las funciones de abajo NO están implementadas a propósito: declaran las fuentes e
interfaces previstas para que la fontanería quede clara, pero lanzan
``NotImplementedError`` en vez de devolver datos vacíos o falsos en silencio.
Implementarlas (respetando la licencia de cada dataset) es trabajo de Fase 1.

Fuentes públicas candidatas (verificar licencias antes de ingerir):
    * Datasets de inyección / jailbreak en Hugging Face Hub
      (p.ej. deepset/prompt-injections, colecciones de jailbreak).
    * Materiales del proyecto OWASP MCP Top 10.
    * Feeds públicos de CVE filtrados por MCP (API de NVD).
"""

from __future__ import annotations

from pathlib import Path

DATA_DIR = Path(__file__).parent
DATASETS_DIR = DATA_DIR / "datasets"
CATALOGS_DIR = DATA_DIR / "catalogs"


def download_prompt_injection_datasets(dest: Path = DATASETS_DIR) -> list[Path]:
    """STUB — descargar datasets públicos de inyección/jailbreak de HF Hub.

    Previsto: usar ``datasets.load_dataset(...)`` para cada fuente, normalizar al
    esquema ``{text, category, severity, source}`` de ARGOS y escribir JSONL en
    ``dest``. Respetar y registrar la licencia de cada dataset.
    """
    raise NotImplementedError(
        "La descarga de datasets públicos no está implementada aún (Fase 1). "
        "Hay un pequeño ejemplo offline en data/datasets/sample_attacks.json."
    )


def download_mcp_cve_feed(dest: Path = CATALOGS_DIR) -> Path:
    """STUB — traer CVEs relacionados con MCP desde la API de NVD a un catálogo.

    Previsto: consultar la API NVD 2.0, filtrar entradas MCP/agente y persistir un
    catálogo normalizado para cruzar con los hallazgos.
    """
    raise NotImplementedError(
        "La ingesta del feed de CVEs de MCP no está implementada aún (Fase 1)."
    )


def refresh_owasp_mcp_catalog(dest: Path = CATALOGS_DIR) -> Path:
    """STUB — re-sincronizar el catálogo OWASP MCP Top 10 desde upstream.

    Previsto: traer las últimas definiciones del OWASP MCP Top 10 y reconciliarlas
    con ``argos.core.taxonomies``. Hasta entonces, el snapshot en
    ``data/catalogs/owasp_mcp_top10.json`` y el módulo Python son la referencia.
    """
    raise NotImplementedError(
        "La actualización del catálogo OWASP MCP no está implementada aún (Fase 1)."
    )


if __name__ == "__main__":
    print(__doc__)
    print("Todas las funciones de descarga son stubs. Ver ROADMAP.md, Fase 1.")
