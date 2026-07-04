# ARGOS — Roadmap

Plan por fases de 8 semanas para la convocatoria universitaria. La filosofía es
**incrementos honestos**: cada fase convierte un stub en algo real, y nada se marca
como "hecho" hasta que se ejecuta.

Leyenda: ✅ hecho · 🟡 parcial · ⛔ stub / sin empezar

---

## Estado actual

| Área | Estado | Notas |
|------|--------|-------|
| `core` modelos y taxonomías | ✅ | Real, testeado. |
| `fingerprint_db` (huellas + mutaciones) | ✅ | **Diferenciador — implementado de verdad.** Almacén en memoria. |
| `component_analyzer` scoring desde manifiesto | 🟡 | Heurísticas MCP01–MCP03; MCP04–MCP10 pendientes. |
| `component_analyzer` conexión MCP en vivo | ⛔ | Stub `NotImplementedError`. |
| `interaction_analyzer` guardián (DeBERTa) | 🟡 | Wrapper real + fallback heurístico. Falta evaluar. |
| `api` (FastAPI) | ✅ | Endpoints conectados a módulos reales; DB en memoria. |
| `data` dataset de ejemplo + seeding | 🟡 | Sample real; descarga de datasets públicos stub. |
| Persistencia / vector DB | ⛔ | Solo en memoria. |
| Backend colaborativo/reputación | ⛔ | Un solo proceso. |

---

## Fase 1 — Fundaciones y datos (Semanas 1–2)
**Objetivo: un núcleo ejecutable y un pipeline de datos real.**

- ✅ Esqueleto del proyecto, modelos core, taxonomías, tests offline.
- ✅ Base de huellas con detección de mutaciones por coseno + demo.
- ⛔ Implementar `data/download.py`:
  - Ingerir datasets públicos de inyección / jailbreak (Hugging Face Hub),
    normalizando al esquema de ARGOS. **Registrar cada licencia.**
  - Extraer CVEs de MCP desde la API de NVD a un catálogo local.
- ⛔ Ampliar `sample_attacks.json` a un conjunto etiquetado mayor.
- ⛔ Citar la fuente primaria de las tres estadísticas del README.

## Fase 2 — Component analyzer: de estático a en vivo (Semanas 3–4)
**Objetivo: analizar servidores MCP reales, no solo manifiestos.**

- ⛔ Implementar `inventory_live_server()` con un cliente MCP real (stdio + HTTP/SSE):
  llamar a `tools/list`, `prompts/list`, `resources/list`.
- ⛔ Añadir heurísticas para MCP04–MCP10 (inyección de comandos, auth, transporte, logging).
- 🟡 Mejorar la precisión de MCP01–MCP03 (reducir falsos positivos; fixtures).
- ⛔ Cruzar hallazgos con el catálogo de CVEs de la Fase 1.

## Fase 3 — Interaction analyzer e integración de huellas (Semanas 5–6)
**Objetivo: las detecciones alimentan automáticamente la base global de huellas.**

- 🟡 Evaluar el guardián DeBERTa sobre un conjunto de prueba; reportar precisión/recall.
- ⛔ Pipeline: cada ataque detectado se convierte en huella y se aporta a la DB,
  fusionando mutaciones (cerrando el bucle entre detección y reputación).
- ⛔ Calibrar el umbral de detección de mutaciones sobre un corpus etiquetado.
- ⛔ Segundo modelo guardián opcional para ensemble / comparación.

## Fase 4 — Persistencia, reputación y pulido (Semanas 7–8)
**Objetivo: una plataforma demoable con forma multiusuario.**

- ⛔ Sustituir por una vector DB real (FAISS / Qdrant / pgvector) tras la API actual
  de `FingerprintDB` (sin cambiar la API pública).
- ⛔ Almacén de reputación persistente y compartido; procedencia y rate limiting.
- ⛔ UI web o CLI mínima sobre la API para la demo.
- 🟡 Endurecer la API REST (auth, validación, manejo de errores).
- ⛔ Empaquetado, `Dockerfile` y entorno de demo de un solo comando.

---

## Fuera de alcance (por ahora)
- Auth / cuentas multi-tenant de producción.
- Remediación / parcheo automático de servidores MCP.
- Proxy inline en tiempo real del tráfico de agentes.

## Riesgos clave y mitigaciones
- **Ajuste del umbral de embeddings** → construir pronto un conjunto de evaluación
  etiquetado (Fase 1/3).
- **Licencias de datasets** → registrar licencias por fuente; distribuir solo
  ejemplos permisivos.
- **Tamaño/latencia de descarga del modelo** → mantener funcionando las rutas
  offline (`HashingEmbedder` + detector heurístico) para CI y demos limitadas.
