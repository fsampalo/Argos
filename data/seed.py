"""Siembra una :class:`FingerprintDB` desde el dataset de ejemplo incluido.

Real y ejecutable: carga ``data/datasets/sample_attacks.json``, puebla una base
de huellas embebiendo cada ataque canónico, y luego fusiona las ``variants``
reformuladas para demostrar el colapso de mutaciones.

Para siembra a gran escala desde corpus públicos, ver :mod:`data.download` (stub).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from argos.core.models import Severity, ThreatCategory
from argos.fingerprint_db import FingerprintDB

SAMPLE_PATH = Path(__file__).parent / "datasets" / "sample_attacks.json"


def load_sample(path: Path = SAMPLE_PATH) -> dict:
    """Carga el dataset de ataques de ejemplo incluido."""
    return json.loads(path.read_text(encoding="utf-8"))


def seed_db(
    db: Optional[FingerprintDB] = None,
    *,
    merge_variants: bool = True,
    path: Path = SAMPLE_PATH,
) -> FingerprintDB:
    """Puebla (y devuelve) una base de huellas desde el dataset de ejemplo.

    Args:
        db: base existente a sembrar; se crea una nueva si se omite.
        merge_variants: pasar también las ``variants`` reformuladas por
            :meth:`FingerprintDB.add_or_merge` para demostrar la fusión.
        path: ruta alternativa del dataset.
    """
    # NB: comprobación explícita de None — FingerprintDB define __len__, así que
    # una base vacía es falsy y `db or FingerprintDB()` la descartaría en silencio.
    if db is None:
        db = FingerprintDB()
    data = load_sample(path)

    for entry in data.get("attacks", []):
        threat, _ = db.add_or_merge(
            entry["text"],
            category=ThreatCategory(entry.get("category", "other")),
            severity=Severity(entry.get("severity", "medium")),
            source=entry.get("source", "sample"),
        )
        if merge_variants:
            for variant in entry.get("variants", []):
                db.add_or_merge(
                    variant,
                    category=threat.category,
                    severity=threat.severity,
                    source=entry.get("source", "sample"),
                )
    return db


if __name__ == "__main__":
    seeded = seed_db()
    print(f"Base sembrada con {len(seeded)} amenazas distintas "
          f"(variantes fusionadas como mutaciones).")
    for t in seeded.all_threats():
        print(f"  - [{t.category.value}] reportes={t.times_reported} "
              f"alias={len(t.aliases)} :: {t.text[:60]!r}")
