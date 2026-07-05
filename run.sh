#!/usr/bin/env bash
# ARGOS — lanzador todo-en-uno (Linux / macOS)
#
# Uso:
#   ./run.sh setup     # crea el venv e instala dependencias
#   ./run.sh demo      # demo de huellas semánticas (mutaciones)
#   ./run.sh mcp       # demo de análisis de un servidor MCP en vivo
#   ./run.sh api       # arranca el panel web (http://127.0.0.1:8000)
#   ./run.sh test      # ejecuta la suite de tests
#   ./run.sh all       # setup + tests + ambas demos
#
# La primera ejecución con dependencias descarga el modelo (~1 GB) una sola vez.
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"
export PYTHONIOENCODING=utf-8

ensure_venv() {
  if [ ! -x "$PY" ]; then
    echo "No hay venv. Ejecuta primero:  ./run.sh setup" >&2
    exit 1
  fi
}

do_setup() {
  echo "== Creando entorno virtual e instalando dependencias =="
  [ -x "$PY" ] || python3 -m venv .venv
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -r requirements.txt
  echo "Listo. Dependencias instaladas."
}

do_demo() { ensure_venv; echo "== Demo: huellas semanticas / mutaciones =="; "$PY" demo.py; }
do_mcp()  { ensure_venv; echo "== Demo: analisis de servidor MCP en vivo =="; "$PY" demo_mcp.py; }
do_test() { ensure_venv; echo "== Tests =="; "$PY" -m pytest -q; }
do_api()  { ensure_venv; echo "== Panel web en http://127.0.0.1:8000 (Ctrl+C para parar) =="; "$PY" -m uvicorn argos.api.main:app --port 8000; }
do_all()  { do_setup; do_test; do_demo; do_mcp; }

case "${1:-menu}" in
  setup) do_setup ;;
  demo)  do_demo ;;
  mcp)   do_mcp ;;
  api)   do_api ;;
  test)  do_test ;;
  all)   do_all ;;
  *)
    echo "ARGOS — uso: ./run.sh {setup|demo|mcp|api|test|all}"
    ;;
esac
