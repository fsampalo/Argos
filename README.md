# ARGOS

**Collaborative reputation & threat intelligence for the AI-agent ecosystem.**

> The "VirusTotal" of agentic-AI security: analyze AI components (MCP servers,
> LLM interactions), detect attacks, and consolidate everything into a **global
> database of semantic threat fingerprints**.

ARGOS is an early-stage research project built for a university call. It is
deliberately honest about what works today and what is still a stub — see
[Development status](#development-status).

---

## The problem

AI agents have moved from demos to production, and they now execute real actions
through tools — most commonly via the **Model Context Protocol (MCP)**. That new
surface is being attacked faster than it is being secured:

- **40+ CVEs** were filed against MCP servers and clients in the first four months
  of 2026. *(figure to cite — see [Sourcing note](#sourcing-note))*
- Roughly **66% of scanned MCP servers** exhibited at least one security finding.
  *(figure to cite)*
- Gartner projects that **agent/tool abuse will be a leading driver of AI-related
  security incidents**, with autonomous agents materially widening the attack
  surface. *(figure to cite)*

The dangerous part is not just the raw count — it is **mutation**. The same
underlying attack (a prompt injection, a tool-poisoning payload, a jailbreak) is
endlessly reworded to evade string- and signature-based defenses. A guardrail
that blocks one phrasing lets the next one through.

> ### Sourcing note
> This is a research project, and we hold ourselves to the same honesty standard
> as the code. The three figures above are the motivating statistics for ARGOS,
> but they are **placeholders pending a cited primary source** and must not be
> presented as verified until each is linked to its origin (CVE feeds, the
> published MCP-scanning studies, and the specific Gartner report). Tracked in
> `ROADMAP.md`, Phase 1.

### Why ARGOS

ARGOS treats a threat by **what it means, not how it is spelled**. It converts
each attack into a *semantic fingerprint* and recognizes reworded variants as the
**same** threat via embedding similarity — then shares that knowledge as
collaborative reputation, VirusTotal-style.

---

## Architecture

Four components over a shared core, exposed through one REST API:

```
                         ┌───────────────────────────┐
                         │           api/            │  FastAPI REST layer
                         │  /analyze/component        │
                         │  /analyze/interaction      │
                         │  /reputation/{query,...}   │
                         └───────────┬───────────────┘
                                     │
        ┌────────────────────┬───────┴───────────┬────────────────────────┐
        ▼                    ▼                   ▼                          ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐  ┌───────────┐
│ component_       │ │ interaction_     │ │ fingerprint_db  ★     │  │  data/    │
│ analyzer         │ │ analyzer         │ │ semantic fingerprints │  │  seeds &  │
│ MCP inventory +  │ │ prompt-injection │ │ + mutation detection  │  │  catalogs │
│ OWASP MCP Top 10 │ │ / jailbreak (LLM │ │ (cosine similarity)   │  └───────────┘
│ risk scoring     │ │ guardian model)  │ │                       │
└────────┬─────────┘ └────────┬─────────┘ └───────────┬──────────┘
         └────────────────────┴───── core/ (models, taxonomies) ──┘
```

### 1. `component_analyzer/` — is this MCP server safe?
Inventories an MCP server (its tools, prompts and resources) and scores it against
the **OWASP MCP Top 10**, returning a `RiskReport` with per-finding severities and
an aggregate 0–100 score. Today it scores from a static manifest using transparent
heuristics (MCP01–MCP03); the live-connection path is an honest stub.

### 2. `interaction_analyzer/` — is this interaction an attack?
Takes a prompt/interaction and classifies it as prompt-injection / jailbreak using
an **open-source guardian model** — a DeBERTa-based prompt-injection detector from
the Hugging Face Hub. Ships with a clearly-labeled low-fidelity heuristic fallback
for offline use.

### 3. `fingerprint_db/` — have we seen this threat before? ★ (the differentiator)
Generates **semantic fingerprints** (embeddings) of threats and detects
**mutations**: two attacks that say the same thing with different words are
recognized as the **same threat** via cosine similarity. Reworded resubmissions
increase a threat's reputation instead of creating near-duplicates. **This piece
is implemented for real.**

### 4. `api/` — the platform surface
A small **FastAPI** REST API to analyze a component, analyze an interaction, and
query/contribute reputation.

### `core/` — shared foundation
Common data models (`Threat`, `Fingerprint`, `RiskReport`, `ComponentInventory`)
and reference taxonomies (the OWASP MCP Top 10).

---

## How ARGOS differs from existing tools

| Tool | What it does | What it does **not** do that ARGOS aims to |
|------|--------------|--------------------------------------------|
| **Cisco `mcp-scanner`** | Static/dynamic scanning of individual MCP servers for known issues. | No cross-attack **semantic memory**; each scan is siloed, no shared reputation of *mutating* threats. |
| **Invariant (guardrails/analysis)** | Policy & guardrails for agent traffic; MCP analysis. | Focused on policy enforcement per deployment, not a **global fingerprint database** that collapses reworded attacks into one identity. |
| **Prompt Guard / guardian classifiers** | Classify a single prompt as benign/malicious. | Answer *"is this string bad?"*, not *"is this the **same** threat we've seen, reworded?"* — no mutation-aware, collaborative intelligence layer. |

**ARGOS's bet:** the missing layer is a *shared, mutation-aware reputation system*
that sits **above** scanners and guardrails and unifies both the component
(supply-side) and interaction (runtime) views of a threat. Scanners find issues in
one server; guardrails block one prompt; ARGOS remembers the **threat's meaning**
across servers, phrasings and time.

---

## Data strategy

1. **Bootstrap** the global fingerprint DB from public corpora of prompt-injection
   / jailbreak attacks (Hugging Face datasets) and official catalogs (OWASP MCP
   Top 10, MCP-related CVEs from NVD). *Download pipeline is stubbed — see
   `data/download.py` — with licenses to be recorded per source.*
2. **Ship a small, real sample** (`data/datasets/sample_attacks.json`) so the demo
   and tests run offline today.
3. **Grow collaboratively:** every detected/contributed attack is fingerprinted;
   mutations auto-merge into existing threats and raise their reputation.

---

## Development status

Honesty first. Nothing below is simulated; stubs raise `NotImplementedError` or are
marked `# TODO`.

| Component | Status | Details |
|-----------|:------:|---------|
| `core` (models, taxonomies) | ✅ Real | Fully implemented and tested. |
| `fingerprint_db` (semantic fingerprints, mutation detection) | ✅ Real | **The differentiator.** In-memory store; vector-DB backend is Phase 4. |
| `component_analyzer` (manifest scoring) | 🟡 Partial | Heuristics for MCP01–MCP03; MCP04–MCP10 pending. |
| `component_analyzer` (live MCP connection) | ⛔ Stub | `inventory_live_server()` raises `NotImplementedError`. |
| `interaction_analyzer` (DeBERTa guardian) | 🟡 Partial | Real HF wrapper + heuristic fallback; needs evaluation. |
| `api` (FastAPI) | ✅ Real | Wired to real modules; process-local in-memory DB. |
| `data` (sample + seeding) | 🟡 Partial | Sample & seeding real; public-dataset download stubbed. |

See `ROADMAP.md` for the 8-week plan.

---

## Installation

Requires **Python 3.10+**.

```bash
git clone <your-repo-url> ARGOS
cd ARGOS

python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# macOS/Linux:         source .venv/bin/activate

pip install -r requirements.txt
```

> The heaviest dependency is `sentence-transformers` (pulls in `torch`). The
> fingerprint demo downloads a small (~80 MB) embedding model on first run.

---

## Running the demo

The demo proves the differentiator — that ARGOS recognizes a **reworded** attack as
the same threat. It performs a **real** embedding run (no faked output):

```bash
python demo.py
```

Expected outcome: a known prompt-injection and a differently-worded mutation land
at high cosine similarity and are reported as the **same** threat, while an
unrelated benign prompt is correctly rejected — and the mutation merges into a
single reputation entry.

### Run the API

```bash
uvicorn argos.api.main:app --reload
# Interactive docs at http://127.0.0.1:8000/docs
```

Example — score an MCP manifest:

```bash
curl -X POST http://127.0.0.1:8000/analyze/component \
  -H "Content-Type: application/json" \
  -d '{"manifest": {"name": "demo", "resources": [{"uri": "file:///app/.env"}]}}'
```

### Seed the fingerprint DB from the sample dataset

```bash
python -m data.seed
```

### Run the tests

```bash
pytest
```

Tests run **offline by default** (using a dependency-free, non-semantic embedder
for plumbing). The one *semantic* mutation-detection test is **skipped
automatically** if `sentence-transformers` is not installed — it is never faked.

---

## Project layout

```
argos/
  core/                 # data models + taxonomies (real)
  fingerprint_db/       # semantic fingerprints + mutation detection (real ★)
  component_analyzer/   # MCP inventory + OWASP MCP scoring (partial/stub)
  interaction_analyzer/ # prompt-injection/jailbreak guardian (partial)
  api/                  # FastAPI REST layer (real)
data/                   # sample dataset, catalogs, seeding + download stubs
tests/                  # pytest suite (offline-friendly)
demo.py                 # runnable differentiator demo
ROADMAP.md              # 8-week phased plan
```

---

## License

TBD (see `pyproject.toml`). Attack strings in the sample dataset are well-known
public examples included for research/educational use.
