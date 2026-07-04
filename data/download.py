"""STUBS for downloading public attack datasets and reference catalogs.

ARGOS's data strategy is to bootstrap the global fingerprint database from
existing public corpora of prompt-injection / jailbreak attacks, plus official
vulnerability catalogs, and then grow it with community contributions.

The functions below are intentionally NOT implemented: they declare the intended
data sources and interfaces so the plumbing is obvious, but each raises
``NotImplementedError`` rather than silently returning empty or fake data.
Implementing them (respecting each dataset's license and terms) is Phase-1 work
in ROADMAP.md.

Candidate public sources (verify licenses before ingesting):
    * Prompt-injection / jailbreak datasets on the Hugging Face Hub
      (e.g. deepset/prompt-injections, jailbreak collections).
    * OWASP MCP Top 10 project materials.
    * Public CVE feeds filtered for MCP-related entries (NVD API).
"""

from __future__ import annotations

from pathlib import Path

DATA_DIR = Path(__file__).parent
DATASETS_DIR = DATA_DIR / "datasets"
CATALOGS_DIR = DATA_DIR / "catalogs"


def download_prompt_injection_datasets(dest: Path = DATASETS_DIR) -> list[Path]:
    """STUB — fetch public prompt-injection/jailbreak datasets from HF Hub.

    Intended: use ``datasets.load_dataset(...)`` for each configured source,
    normalize to ARGOS's ``{text, category, severity, source}`` schema, and write
    JSONL files under ``dest``. Respect and record each dataset's license.
    """
    raise NotImplementedError(
        "Public dataset download is not implemented yet (Phase 1, ROADMAP.md). "
        "A small offline sample lives at data/datasets/sample_attacks.json."
    )


def download_mcp_cve_feed(dest: Path = CATALOGS_DIR) -> Path:
    """STUB — pull MCP-related CVEs from the NVD API into a local catalog.

    Intended: query the NVD 2.0 API, filter for MCP/agent-related entries, and
    persist a normalized catalog for cross-referencing findings.
    """
    raise NotImplementedError(
        "MCP CVE feed ingestion is not implemented yet (Phase 1, ROADMAP.md)."
    )


def refresh_owasp_mcp_catalog(dest: Path = CATALOGS_DIR) -> Path:
    """STUB — re-sync the OWASP MCP Top 10 catalog from upstream.

    Intended: fetch the latest OWASP MCP Top 10 definitions and reconcile them
    with ``argos.core.taxonomies``. Until implemented, the bundled snapshot in
    ``data/catalogs/owasp_mcp_top10.json`` and the Python module are authoritative.
    """
    raise NotImplementedError(
        "OWASP MCP catalog refresh is not implemented yet (Phase 1, ROADMAP.md)."
    )


if __name__ == "__main__":
    print(__doc__)
    print("All download functions are stubs. See ROADMAP.md, Phase 1.")
