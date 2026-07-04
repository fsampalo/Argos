"""Heuristic OWASP MCP Top 10 rules applied to a component inventory.

These are transparent, explainable heuristics — pattern/keyword matches over a
component's advertised tools, prompts and resources. They are deliberately
conservative and are NOT a substitute for dynamic analysis or human review.

Real, higher-fidelity detection (taint tracking, live probing, ML classifiers)
is future work tracked in ROADMAP.md. Each rule returns zero or more
:class:`RiskFinding` objects.
"""

from __future__ import annotations

import re

from argos.core.models import (
    ComponentInventory,
    RiskFinding,
    Severity,
)
from argos.core.taxonomies import get_owasp_risk

# Phrases that, when embedded in a tool description or prompt, are classic
# tool-poisoning / injection markers.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?(above|prior|previous)", re.I),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.I),
    re.compile(r"system\s+prompt", re.I),
    re.compile(r"<\s*important\s*>", re.I),
]

# Tokens hinting at dangerous/overbroad capabilities in tool names/descriptions.
_DANGEROUS_CAPABILITY_TERMS = [
    "exec", "shell", "subprocess", "os.system", "eval", "rm -rf",
    "sudo", "delete", "drop table", "arbitrary", "unrestricted",
]

# Resource URIs / names that commonly leak secrets.
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
    """MCP01 — injected instructions hidden in tool/prompt text."""
    findings: list[RiskFinding] = []
    surfaces: list[tuple[str, str]] = []
    surfaces += [(f"tool:{t.name}", t.description) for t in inv.tools]
    surfaces += [(f"prompt:{p.name}", f"{p.description}\n{p.template}") for p in inv.prompts]

    for location, text in surfaces:
        for pattern in _INJECTION_PATTERNS:
            if match := pattern.search(text or ""):
                findings.append(_finding(
                    "MCP01",
                    "Suspicious instruction-like content found in a component "
                    "description or prompt, a hallmark of tool poisoning.",
                    evidence={"location": location, "matched": match.group(0)},
                    recommendation="Manually review this component; treat its "
                                   "descriptions as untrusted input to the host LLM.",
                ))
                break  # one finding per surface is enough
    return findings


def check_dangerous_capabilities(inv: ComponentInventory) -> list[RiskFinding]:
    """MCP02 — tools advertising overbroad or dangerous capabilities."""
    findings: list[RiskFinding] = []
    for tool in inv.tools:
        haystack = f"{tool.name} {tool.description}".lower()
        hits = [term for term in _DANGEROUS_CAPABILITY_TERMS if term in haystack]
        if hits:
            findings.append(_finding(
                "MCP02",
                "Tool advertises potentially dangerous or overbroad capabilities.",
                evidence={"tool": tool.name, "terms": hits},
                recommendation="Confirm least-privilege scoping and sandbox the "
                               "tool's execution environment.",
            ))
    return findings


def check_secret_resources(inv: ComponentInventory) -> list[RiskFinding]:
    """MCP03 — resources that likely expose secrets/PII."""
    findings: list[RiskFinding] = []
    for res in inv.resources:
        target = f"{res.uri} {res.name}"
        for pattern in _SECRET_RESOURCE_PATTERNS:
            if pattern.search(target):
                findings.append(_finding(
                    "MCP03",
                    "Exposed resource matches a pattern associated with secrets "
                    "or credentials.",
                    evidence={"uri": res.uri},
                    recommendation="Remove secret material from exposed resources; "
                                   "never surface .env/keys to connected agents.",
                ))
                break
    return findings


# Registry of all currently-implemented rules.
RULES = [
    check_injection_in_descriptions,
    check_dangerous_capabilities,
    check_secret_resources,
]


def run_all_rules(inv: ComponentInventory) -> list[RiskFinding]:
    """Apply every implemented OWASP MCP heuristic to ``inv``.

    NOTE: only a subset of the OWASP MCP Top 10 has heuristics today (MCP01,
    MCP02, MCP03). MCP04–MCP10 require dynamic analysis or transport inspection
    and are stubs — see ROADMAP.md.
    """
    findings: list[RiskFinding] = []
    for rule in RULES:
        findings.extend(rule(inv))
    return findings
