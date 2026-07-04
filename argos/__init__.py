"""ARGOS — Reputación e inteligencia de amenazas para el ecosistema de agentes de IA.

ARGOS ("el VirusTotal de la seguridad agéntica") analiza componentes de IA
(servidores MCP, interacciones con LLMs), detecta ataques y lo consolida todo en
una base de datos global de huellas semánticas de amenazas.

Subpaquetes:
    core                 Modelos de datos comunes y taxonomías de referencia.
    fingerprint_db       Huellas semánticas + detección de mutaciones (diferenciador).
    component_analyzer   Análisis de servidores MCP frente al OWASP MCP Top 10.
    interaction_analyzer Detección de inyección de prompt / jailbreak (guardián).
    api                  Capa REST FastAPI que expone la plataforma.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
