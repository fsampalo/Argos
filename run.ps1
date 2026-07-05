<#
    ARGOS — lanzador todo-en-uno (Windows / PowerShell)

    Uso:
        .\run.ps1              # menú interactivo
        .\run.ps1 setup        # crea el venv e instala dependencias
        .\run.ps1 demo         # demo de huellas semánticas (mutaciones)
        .\run.ps1 mcp          # demo de análisis de un servidor MCP en vivo
        .\run.ps1 api          # arranca el panel web (http://127.0.0.1:8000)
        .\run.ps1 test         # ejecuta la suite de tests
        .\run.ps1 all          # setup + tests + ambas demos

    La primera ejecución con dependencias descarga el modelo (~1 GB) una sola vez.
#>
param([string]$cmd = "menu")

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root
$py = Join-Path $root ".venv\Scripts\python.exe"
$env:PYTHONIOENCODING = "utf-8"

function Ensure-Venv {
    if (-not (Test-Path $py)) {
        Write-Host "No hay venv. Ejecuta primero:  .\run.ps1 setup" -ForegroundColor Yellow
        exit 1
    }
}

function Do-Setup {
    Write-Host "== Creando entorno virtual e instalando dependencias ==" -ForegroundColor Cyan
    if (-not (Test-Path $py)) { python -m venv .venv }
    & $py -m pip install --upgrade pip
    & $py -m pip install -r requirements.txt
    Write-Host "Listo. Dependencias instaladas." -ForegroundColor Green
}

function Do-Demo { Ensure-Venv; Write-Host "== Demo: huellas semanticas / mutaciones ==" -ForegroundColor Cyan; & $py demo.py }
function Do-Mcp  { Ensure-Venv; Write-Host "== Demo: analisis de servidor MCP en vivo ==" -ForegroundColor Cyan; & $py demo_mcp.py }
function Do-Test { Ensure-Venv; Write-Host "== Tests ==" -ForegroundColor Cyan; & $py -m pytest -q }

function Do-Api {
    Ensure-Venv
    Write-Host "== Panel web en http://127.0.0.1:8000  (Ctrl+C para parar) ==" -ForegroundColor Cyan
    Start-Process "http://127.0.0.1:8000"
    & $py -m uvicorn argos.api.main:app --port 8000
}

function Do-All { Do-Setup; Do-Test; Do-Demo; Do-Mcp }

function Show-Menu {
    Write-Host ""
    Write-Host "  ARGOS — que quieres ejecutar?" -ForegroundColor Cyan
    Write-Host "   1) setup   (crear venv + instalar dependencias)"
    Write-Host "   2) demo    (huellas semanticas / mutaciones)"
    Write-Host "   3) mcp     (analisis de un servidor MCP en vivo)"
    Write-Host "   4) api     (panel web)"
    Write-Host "   5) test    (tests)"
    Write-Host "   6) all     (todo)"
    $sel = Read-Host "Opcion"
    switch ($sel) {
        "1" { Do-Setup } "2" { Do-Demo } "3" { Do-Mcp }
        "4" { Do-Api }   "5" { Do-Test } "6" { Do-All }
        default { Write-Host "Opcion no valida." -ForegroundColor Yellow }
    }
}

switch ($cmd.ToLower()) {
    "setup" { Do-Setup } "demo" { Do-Demo } "mcp" { Do-Mcp }
    "api"   { Do-Api }   "test" { Do-Test } "all" { Do-All }
    "menu"  { Show-Menu }
    default { Write-Host "Comando desconocido: $cmd" -ForegroundColor Yellow; Show-Menu }
}
