# ARGOS

Plataforma de reputación e inteligencia de amenazas para agentes de IA (servidores
MCP y LLMs). Analiza componentes, detecta ataques y los guarda en una **base común
de huellas semánticas** que reconoce una amenaza aunque se reformule.

> Proyecto para los Premios de la Cátedra de Ciberseguridad UMA. Código en fase
> inicial: honesto sobre qué funciona y qué es todavía un stub.

## El problema

Los agentes de IA ya no solo responden: **ejecutan acciones reales** (borran
ficheros, envían correos, acceden a datos), normalmente vía **MCP (Model Context
Protocol)**. Hay **escáneres** por un lado y **modelos de detección** por otro,
pero nada que los conecte, y nadie comparte lo que detecta. Además, las
herramientas por reglas fallan en cuanto el ataque se reformula.

*(En 2026: +40 CVEs contra MCP en el primer cuatrimestre, ~2/3 de servidores con
algún fallo, y Gartner prevé que en 2028 1 de cada 4 incidentes vendrá del abuso de
agentes. Cifras pendientes de citar fuente — ver `ROADMAP.md`.)*

## Componentes

| Componente | Qué hace |
|-----------|----------|
| `fingerprint_db/` ★ | **Pieza diferencial.** Huellas semánticas (embeddings) que reconocen **mutaciones**: dos ataques que dicen lo mismo con otras palabras se detectan como la misma amenaza (similitud de coseno). |
| `component_analyzer/` | Inventaría un servidor MCP (tools, prompts, recursos) y lo puntúa frente al **OWASP MCP Top 10**, con un informe que explica el porqué. |
| `interaction_analyzer/` | Detecta inyección de prompts / jailbreak reutilizando un **modelo guardián open source** ya entrenado. No entrenamos nada desde cero. |
| `api/` | API REST (FastAPI) + panel web para analizar componentes, interacciones y consultar reputación. |

No competimos con los escáneres (Cisco, Invariant) ni con los guardianes (Prompt
Guard, Qwen3Guard): los usamos tal cual. Lo que aportamos es la **capa compartida**
que reconoce mutaciones y consolida lo detectado en una base común.

## Estado (honesto)

Nada está simulado; los stubs lanzan `NotImplementedError`.

| Pieza | Estado |
|-------|--------|
| `fingerprint_db` (huellas + mutaciones) | ✅ **Real — el diferenciador** |
| `component_analyzer` — scoring de manifiesto | 🟡 Heurísticas MCP01–MCP03 |
| `component_analyzer` — conexión MCP en vivo (stdio) | ✅ Real (SDK oficial `mcp`) |
| `interaction_analyzer` (guardián) | 🟡 Wrapper real + fallback heurístico |
| `api` + panel web | ✅ Real |
| `data` (descarga de datasets públicos) | ⛔ Stub (hay dataset de ejemplo real) |

## Ejecución rápida

Requiere **Python 3.10+**. Un único script lo prepara y lanza todo:

```bash
# Windows (PowerShell)          # Linux / macOS
.\run.ps1 setup                 ./run.sh setup   # venv + dependencias
.\run.ps1 demo                  ./run.sh demo    # detección de mutaciones
.\run.ps1 mcp                   ./run.sh mcp     # análisis de un MCP en vivo
.\run.ps1 api                   ./run.sh api     # panel web (127.0.0.1:8000)
```

> La primera ejecución descarga un modelo de embeddings (~1 GB) una sola vez.

- **`demo`** — 5 ataques con variantes parafraseadas (4 idiomas); demuestra en una
  tabla que cada variante matchea con su original y los benignos no. Genera
  `demo_report.txt` / `.csv`.
- **`mcp`** — arranca un servidor MCP vulnerable (`examples/vulnerable_mcp_server.py`),
  se conecta por MCP real, lo inventaría y lo evalúa. Genera `mcp_report.txt`.
- **`api`** — panel visual: analiza un servidor MCP (de demo o el tuyo) con medidor
  de riesgo y hallazgos, y comprueba la reputación de un prompt.

Tests: `pytest` (offline; el test semántico se salta si falta el modelo).

## Estructura

```
argos/
  core/                 modelos + taxonomías
  fingerprint_db/       huellas + mutaciones ★
  component_analyzer/   inventario MCP (manifiesto + en vivo) + OWASP MCP
  interaction_analyzer/ guardián de inyección/jailbreak
  api/                  API REST + panel web
data/        dataset de ejemplo, catálogos y seeding
examples/    servidor MCP vulnerable de demostración
tests/       suite pytest
demo.py · demo_mcp.py · run.ps1 · run.sh
```

## Equipo

Dos estudiantes de 3.er curso de Ciberseguridad e IA (UMA):

- **Fernando Sampalo Gómez** — seguridad ofensiva: ataques propios, evaluación MCP
  frente al OWASP MCP Top 10 y detección de inyección de prompts.
- **Pablo Anguita Pérez** — análisis de componentes, pipeline de embeddings, base de
  huellas e integración de la API.

*El nombre viene de Argos Panoptes, el guardián de los cien ojos.*
