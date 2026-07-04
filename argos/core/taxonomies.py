"""Reference taxonomies used by ARGOS.

Currently the primary taxonomy is the **OWASP MCP Top 10**, the community list
of the most critical risks for Model Context Protocol servers. The entries below
are ARGOS's working representation of that list.

NOTE ON PROVENANCE: the OWASP MCP Top 10 is an evolving community effort. The ids
and titles here reflect ARGOS's snapshot and are used as stable internal
references. Treat wording as ARGOS-authored summaries, and re-sync against the
upstream project as it stabilizes (tracked in ROADMAP.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from argos.core.models import Severity, ThreatCategory


@dataclass(frozen=True)
class OwaspMcpRisk:
    """One entry of the OWASP MCP Top 10 catalog."""

    id: str  # e.g. "MCP01"
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
            "Malicious instructions hidden in tool descriptions, prompt "
            "templates or resource content that hijack the host LLM when the "
            "component is loaded ('tool poisoning')."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.TOOL_POISONING,
    ),
    OwaspMcpRisk(
        id="MCP02",
        title="Excessive Tool Permissions / Overbroad Scope",
        description=(
            "Tools requesting broad filesystem, network or shell access beyond "
            "what their stated purpose requires, enabling privilege abuse."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.EXCESSIVE_PERMISSIONS,
    ),
    OwaspMcpRisk(
        id="MCP03",
        title="Sensitive Data Exposure via Resources",
        description=(
            "Resources exposing secrets, credentials or PII (e.g. .env files, "
            "private keys, tokens) to the connected agent."
        ),
        default_severity=Severity.CRITICAL,
        category=ThreatCategory.DATA_EXFILTRATION,
    ),
    OwaspMcpRisk(
        id="MCP04",
        title="Command / Code Injection in Tool Handlers",
        description=(
            "Tool implementations that pass agent-controlled arguments into "
            "shells, eval or SQL without sanitization."
        ),
        default_severity=Severity.CRITICAL,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
    OwaspMcpRisk(
        id="MCP05",
        title="Unauthenticated / Weakly Authenticated Server",
        description=(
            "MCP endpoints exposed without authentication or with weak/shared "
            "secrets, allowing untrusted clients to invoke privileged tools."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
    OwaspMcpRisk(
        id="MCP06",
        title="Supply-Chain / Rug-Pull of Server Definitions",
        description=(
            "Server or tool definitions that change behavior after install "
            "('rug pull'), or that pull unpinned/untrusted dependencies."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.SUPPLY_CHAIN,
    ),
    OwaspMcpRisk(
        id="MCP07",
        title="Cross-Server / Confused-Deputy Tool Shadowing",
        description=(
            "A malicious server overriding or shadowing tools from a trusted "
            "server to intercept calls or exfiltrate arguments."
        ),
        default_severity=Severity.HIGH,
        category=ThreatCategory.TOOL_POISONING,
    ),
    OwaspMcpRisk(
        id="MCP08",
        title="Insecure Output / Response Injection",
        description=(
            "Tool outputs containing crafted content that manipulate the host "
            "agent's downstream reasoning or actions (indirect prompt injection)."
        ),
        default_severity=Severity.MEDIUM,
        category=ThreatCategory.PROMPT_INJECTION,
    ),
    OwaspMcpRisk(
        id="MCP09",
        title="Insufficient Logging & Observability",
        description=(
            "No audit trail of tool invocations and arguments, preventing "
            "detection and forensic analysis of abuse."
        ),
        default_severity=Severity.MEDIUM,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
    OwaspMcpRisk(
        id="MCP10",
        title="Insecure Transport / Configuration",
        description=(
            "Plaintext transport, permissive CORS, or dangerous default "
            "configuration exposing the server to interception or abuse."
        ),
        default_severity=Severity.MEDIUM,
        category=ThreatCategory.INSECURE_CONFIG,
    ),
]

# Convenience index: id -> risk entry.
OWASP_MCP_BY_ID: dict[str, OwaspMcpRisk] = {r.id: r for r in OWASP_MCP_TOP_10}


def get_owasp_risk(owasp_id: str) -> OwaspMcpRisk:
    """Return the OWASP MCP risk entry for ``owasp_id`` (e.g. ``"MCP01"``)."""
    try:
        return OWASP_MCP_BY_ID[owasp_id]
    except KeyError as exc:  # pragma: no cover - defensive
        raise KeyError(f"Unknown OWASP MCP id: {owasp_id!r}") from exc
