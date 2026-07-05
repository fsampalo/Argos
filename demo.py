"""Demo del diferenciador de ARGOS — reconocer un ataque aunque se reformule.

Ejecutar:
    python demo.py

Qué demuestra (la duda del jurado: "¿esto es real o solo está en el papel?")
-----------------------------------------------------------------------------
Coge 5 ataques conocidos de inyección/jailbreak/exfiltración, cada uno con varias
variantes parafraseadas (algunas en otros idiomas), calcula sus embeddings con un
modelo ya entrenado y muestra, por **similitud de coseno**, que:

  * cada variante sigue matcheando con su ataque original por encima del umbral, y
  * unos textos benignos cualesquiera NO matchean.

Salida: una tabla por terminal  ->  original → variante → % similitud → veredicto,
y además dos ficheros con los resultados:
    demo_report.txt   (la misma tabla, para leer/adjuntar)
    demo_report.csv   (los datos, para una hoja de cálculo)

Es una ejecución REAL: descarga un modelo sentence-transformer open source
(~1 GB) la primera vez y calcula embeddings de verdad. Nada está simulado. Si el
modelo o su dependencia faltan, la demo dice qué instalar en vez de fingir.
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime
from pathlib import Path

from argos.fingerprint_db import DEFAULT_MUTATION_THRESHOLD, cosine_similarity
from argos.fingerprint_db.embeddings import SentenceTransformerEmbedder
from data.seed import load_sample

THRESHOLD = DEFAULT_MUTATION_THRESHOLD
REPORT_TXT = Path(__file__).parent / "demo_report.txt"
REPORT_CSV = Path(__file__).parent / "demo_report.csv"


def _force_utf8() -> None:
    """Fuerza UTF-8 en la salida para que los acentos no rompan en Windows (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def _short(text: str, width: int = 58) -> str:
    """Recorta un texto a una anchura para que la tabla quede alineada."""
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "..."


class Report:
    """Acumula el texto que se imprime para poder volcarlo también a fichero."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def line(self, text: str = "") -> None:
        print(text)
        self.lines.append(text)

    def banner(self, title: str) -> None:
        self.line("\n" + "=" * 78)
        self.line(title)
        self.line("=" * 78)

    def save(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def main() -> int:
    _force_utf8()
    rep = Report()
    csv_rows: list[dict] = []  # filas estructuradas para el CSV

    rep.banner("ARGOS — ¿Reconoce la base de huellas un ataque reformulado?")
    rep.line(f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}  ·  umbral = {THRESHOLD}")

    # Cargar el modelo y avisar con claridad si falla.
    try:
        embedder = SentenceTransformerEmbedder()
        embedder.embed("warm up")  # fuerza la carga ya, para fallar pronto
    except ImportError as exc:
        print(f"[!] Falta una dependencia: {exc}", file=sys.stderr)
        print("    Instálala con:  pip install sentence-transformers", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - la demo informa, no falla en silencio
        print(f"[!] No se pudo cargar el modelo: {exc}", file=sys.stderr)
        print("    Revisa tu conexión (descarga única del modelo) y reintenta.", file=sys.stderr)
        return 1

    rep.line(f"Modelo: {embedder.model_name}")
    rep.line("Embeddings reales, calculados en local. Nada simulado.")

    data = load_sample()
    attacks = data["attacks"]
    benign = data.get("benign", [])

    # Embeddings de todos los originales de una sola pasada.
    originals = [a["text"] for a in attacks]
    original_vecs = embedder.embed_batch(originals)

    # ------------------------------------------------------------------ #
    # Variantes parafraseadas: deben matchear con SU original.
    # ------------------------------------------------------------------ #
    matched = 0
    total = 0
    for idx, attack in enumerate(attacks):
        rep.banner(f"[{idx + 1}] {attack['category']}  ::  {_short(attack['text'], 60)}")
        rep.line(f"    {'variante parafraseada':60}  {'sim':>7}  veredicto")
        rep.line(f"    {'-' * 60}  {'-' * 7}  {'-' * 22}")
        for variant in attack.get("variants", []):
            sim = cosine_similarity(embedder.embed(variant), original_vecs[idx])
            ok = sim >= THRESHOLD
            matched += int(ok)
            total += 1
            verdict = "[OK] misma amenaza" if ok else "[!!] NO reconocida"
            rep.line(f"    {_short(variant):60}  {sim * 100:6.1f}%  {verdict}")
            csv_rows.append({
                "tipo": "variante",
                "ataque": idx + 1,
                "categoria": attack["category"],
                "texto": variant,
                "similitud_pct": round(sim * 100, 1),
                "veredicto": "misma_amenaza" if ok else "no_reconocida",
            })

    # ------------------------------------------------------------------ #
    # Controles benignos: NO deben matchear con ningún ataque.
    # ------------------------------------------------------------------ #
    rep.banner("Controles benignos (no deberían coincidir con ningún ataque)")
    rep.line(f"    {'texto benigno':60}  {'máx':>7}  veredicto")
    rep.line(f"    {'-' * 60}  {'-' * 7}  {'-' * 22}")
    false_positives = 0
    for text in benign:
        vec = embedder.embed(text)
        best = max(cosine_similarity(vec, ov) for ov in original_vecs)
        flagged = best >= THRESHOLD
        false_positives += int(flagged)
        verdict = "[!!] falso positivo" if flagged else "[OK] descartado"
        rep.line(f"    {_short(text):60}  {best * 100:6.1f}%  {verdict}")
        csv_rows.append({
            "tipo": "benigno",
            "ataque": "",
            "categoria": "",
            "texto": text,
            "similitud_pct": round(best * 100, 1),
            "veredicto": "falso_positivo" if flagged else "descartado",
        })

    # ------------------------------------------------------------------ #
    # Resumen y veredicto.
    # ------------------------------------------------------------------ #
    rep.banner("Resumen")
    rep.line(f"Variantes reconocidas como la misma amenaza : {matched}/{total}")
    rep.line(f"Falsos positivos en textos benignos         : {false_positives}/{len(benign)}")

    if matched == total and false_positives == 0:
        rep.line("")
        rep.line("[PASA]  Toda variante parafraseada se reconoció como su ataque original")
        rep.line("        y ningún texto benigno se marcó. El reconocimiento de mutaciones")
        rep.line("        funciona sobre embeddings reales, no sobre firmas exactas.")
        exit_code = 0
    else:
        rep.line("")
        rep.line("[REVISAR]  No se cumplieron todas las condiciones. Mira los % de arriba:")
        rep.line("           puede que alguna variante quede algo por debajo del umbral")
        rep.line("           (ajústalo en argos.fingerprint_db DEFAULT_MUTATION_THRESHOLD).")
        exit_code = 2

    # ------------------------------------------------------------------ #
    # Volcar los resultados a fichero.
    # ------------------------------------------------------------------ #
    rep.save(REPORT_TXT)
    with REPORT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["tipo", "ataque", "categoria", "texto", "similitud_pct", "veredicto"],
        )
        writer.writeheader()
        writer.writerows(csv_rows)

    rep.line("")
    rep.line(f"Resultados guardados en:\n  {REPORT_TXT}\n  {REPORT_CSV}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
