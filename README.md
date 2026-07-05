# ARGOS

**Un «VirusTotal» para la seguridad de los agentes de IA.**

Plataforma colaborativa de reputación e inteligencia de amenazas para agentes de
IA (servidores MCP y LLMs). Analiza componentes, detecta ataques y los guarda en
una **base común de huellas** que reconoce una amenaza aunque se reformule.

> Proyecto para los Premios de la Cátedra de Ciberseguridad UMA. Código en fase
> inicial: honesto sobre qué funciona y qué es todavía un stub.

---

## El problema

Los agentes de IA ya no solo responden: **ejecutan acciones reales** (borran
ficheros, envían correos, acceden a datos), normalmente a través del **MCP (Model
Context Protocol)**. Eso cambia el riesgo por completo, y los datos de 2026 lo
confirman:

- **+40 CVEs** contra implementaciones de MCP en el primer cuatrimestre de 2026.
- **~2/3** de los servidores MCP analizados tienen algún problema de seguridad;
  cerca del **40%** de los remotos exponen sus herramientas **sin autenticación**.
- Gartner estima que en **2028, 1 de cada 4** incidentes de seguridad empresarial
  vendrá del abuso de agentes de IA.

Hoy hay **escáneres** por un lado y **modelos de detección** por otro, pero nada
que los conecte, y **nadie comparte lo que detecta**: cada organización repite el
mismo análisis por su cuenta. Además, las herramientas basadas en reglas fallan al
reformular el ataque (auditorías hablan de ~78% de falsos positivos).

*(Cifras tomadas de la memoria del proyecto; pendientes de enlazar a su fuente
primaria — ver `ROADMAP.md`.)*

---

## La solución: 4 componentes

| Componente | Qué hace |
|-----------|----------|
| **`component_analyzer/`** | Inventaría un servidor MCP (tools, prompts, recursos) y lo puntúa frente al **OWASP MCP Top 10**, con un informe que explica el porqué (no un simple «seguro/inseguro»). |
| **`fingerprint_db/`** ★ | **Nuestra pieza diferencial.** Guarda huellas semánticas (embeddings) de las amenazas y reconoce **mutaciones**: dos ataques que dicen lo mismo con otras palabras se detectan como la misma amenaza (similitud de coseno). |
| **`interaction_analyzer/`** | Detecta inyección de prompts / jailbreak reutilizando un **modelo guardián open source** ya entrenado (tipo Prompt Guard/DeBERTa). No entrenamos nada desde cero. |
| **`api/`** | API REST (FastAPI) para analizar un componente, analizar una interacción y consultar/aportar reputación. |

Sobre `core/` (modelos y taxonomías compartidas) y `data/` (semillas y catálogos).

### Por qué es diferente

No competimos con los escáneres (Cisco, Invariant) ni con los guardianes (Prompt
Guard, Qwen3Guard): **los usamos tal cual**. Lo que falta, y es lo que aportamos,
es la **capa compartida**: cada detección alimenta una base común que reconoce
mutaciones y beneficia a todos. Es la lógica que hizo grande a VirusTotal con el
malware, aplicada a los agentes de IA.

---

## Estado de desarrollo (honesto)

Nada está simulado. Los stubs lanzan `NotImplementedError`.

| Pieza | Estado |
|-------|--------|
| `core` (modelos, taxonomías) | ✅ Real y testeado |
| `fingerprint_db` (huellas + mutaciones) | ✅ **Real — el diferenciador** (almacén en memoria) |
| `component_analyzer` (scoring de manifiesto) | 🟡 Heurísticas MCP01–MCP03; resto pendiente |
| `component_analyzer` (conexión MCP en vivo) | ⛔ Stub |
| `interaction_analyzer` (guardián) | 🟡 Wrapper real + fallback heurístico |
| `api` (FastAPI) | ✅ Real |
| `data` (descarga de datasets públicos) | ⛔ Stub (hay un dataset de ejemplo real) |

Plan completo de 8 semanas en `ROADMAP.md`.

---

## Instalación

Requiere **Python 3.10+**.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\Activate.ps1   |  Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
```

> La demo descarga un modelo de embeddings multilingüe (~1 GB) la primera vez.

## Cómo ejecutarlo

**Demo del diferenciador** — coge 5 ataques conocidos con 2-3 variantes
parafraseadas cada uno (algunas en otro idioma), y muestra en una tabla que cada
variante sigue matcheando con su ataque original por similitud de coseno, mientras
que textos benignos no lo hacen:

```bash
python demo.py
```

**API:**

```bash
uvicorn argos.api.main:app --reload    # docs en http://127.0.0.1:8000/docs
```

**Sembrar la base con el dataset de ejemplo:**

```bash
python -m data.seed
```

**Tests** (corren offline; el test semántico se salta solo si falta el modelo):

```bash
pytest
```

---

## Estructura

```
argos/
  core/                 modelos + taxonomías (real)
  fingerprint_db/       huellas + mutaciones (real ★)
  component_analyzer/   inventario MCP + OWASP MCP (parcial)
  interaction_analyzer/ guardián de inyección/jailbreak (parcial)
  api/                  API REST FastAPI (real)
data/                   dataset de ejemplo, catálogos y seeding
tests/                  suite pytest
demo.py                 demo ejecutable del diferenciador
```

---

## Equipo

Dos estudiantes de 3.er curso de Ciberseguridad e IA (UMA):

- **Fernando Sampalo Gómez** — seguridad ofensiva: ataques propios, evaluación MCP
  frente al OWASP MCP Top 10 y detección de inyección de prompts.
- **Pablo Anguita Pérez** — análisis de componentes, pipeline de embeddings, base
  de huellas e integración de la API.

*El nombre viene de Argos Panoptes, el guardián de los cien ojos, metáfora de la
vigilancia colectiva.*
