# ARGOS — Roadmap

An 8-week, phased plan for the university call. The philosophy is **honest
increments**: each phase turns a stub into something real, and nothing is marked
"done" until it runs.

Legend: ✅ done · 🟡 partial · ⛔ stub / not started

---

## Current status snapshot

| Area | Status | Notes |
|------|--------|-------|
| `core` models & taxonomies | ✅ | Real, tested. |
| `fingerprint_db` (semantic fingerprints + mutation detection) | ✅ | **Differentiator — implemented for real.** In-memory store. |
| `component_analyzer` scoring from manifest | 🟡 | Heuristics for MCP01–MCP03; MCP04–MCP10 pending. |
| `component_analyzer` live MCP connection | ⛔ | `NotImplementedError` stub. |
| `interaction_analyzer` guardian model (DeBERTa) | 🟡 | Real wrapper; heuristic fallback. Needs eval. |
| `api` (FastAPI) | ✅ | Endpoints wired to real modules; in-memory DB. |
| `data` sample dataset + seeding | 🟡 | Sample real; public-dataset download stubbed. |
| Persistence / vector DB | ⛔ | In-memory only. |
| Community/reputation backend | ⛔ | Single-process only. |

---

## Phase 1 — Foundations & data (Weeks 1–2)
**Goal: a runnable core and a real data pipeline.**

- ✅ Project skeleton, core models, taxonomies, tests, CI-friendly offline tests.
- ✅ Fingerprint DB with cosine-similarity mutation detection + demo.
- ⛔ Implement `data/download.py`:
  - Ingest public prompt-injection / jailbreak datasets (Hugging Face Hub),
    normalizing to the ARGOS schema. **Record each license.**
  - Pull MCP-related CVEs from the NVD API into a local catalog.
- ⛔ Expand `sample_attacks.json` into a larger labeled seed set.

## Phase 2 — Component analyzer: from static to live (Weeks 3–4)
**Goal: analyze real MCP servers, not just manifests.**

- ⛔ Implement `inventory_live_server()` with a real MCP client (stdio + HTTP/SSE):
  call `tools/list`, `prompts/list`, `resources/list`.
- ⛔ Add heuristics for MCP04–MCP10 (command injection, auth, transport, logging).
- 🟡 Improve MCP01–MCP03 precision (reduce false positives; add unit fixtures).
- ⛔ Cross-reference findings against the CVE catalog from Phase 1.

## Phase 3 — Interaction analyzer & fingerprint integration (Weeks 5–6)
**Goal: detections feed the global fingerprint DB automatically.**

- 🟡 Evaluate the DeBERTa guardian model on a held-out set; report precision/recall.
- ⛔ Pipeline: every detected attack is fingerprinted and contributed to the DB,
  auto-merging mutations (closing the loop between detection and reputation).
- ⛔ Threshold calibration for mutation detection against a labeled corpus.
- ⛔ Optional second guardian model for ensemble / comparison.

## Phase 4 — Persistence, reputation & polish (Weeks 7–8)
**Goal: a demoable, multi-user-shaped platform.**

- ⛔ Swap in a real vector database (FAISS / Qdrant / pgvector) behind the existing
  `FingerprintDB` API (no public-API change).
- ⛔ Persistent, shared reputation store; contribution provenance & rate limiting.
- ⛔ Minimal web UI or CLI over the API for the demo.
- 🟡 Harden the REST API (auth, validation, error handling).
- ⛔ Packaging, `Dockerfile`, and a one-command demo environment.

---

## Explicitly out of scope (for now)
- Production multi-tenant auth / accounts.
- Automated remediation / patching of MCP servers.
- Real-time inline proxying of agent traffic.

## Key risks & mitigations
- **Embedding threshold tuning** → build a labeled eval set early (Phase 1/3).
- **Dataset licensing** → track licenses per source; ship only permissive samples.
- **Model download size/latency** → keep the offline `HashingEmbedder` +
  heuristic detector paths working for CI and constrained demos.
