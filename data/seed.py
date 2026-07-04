"""Seed a :class:`FingerprintDB` from the bundled sample dataset.

This is REAL and runnable: it loads ``data/datasets/sample_attacks.json`` and
populates a fingerprint database, embedding each canonical attack. Reworded
``variants`` are then merged to demonstrate mutation collapsing.

For large-scale seeding from public corpora, see :mod:`data.download` (stubbed).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from argos.core.models import Severity, ThreatCategory
from argos.fingerprint_db import FingerprintDB

SAMPLE_PATH = Path(__file__).parent / "datasets" / "sample_attacks.json"


def load_sample(path: Path = SAMPLE_PATH) -> dict:
    """Load the bundled sample attack dataset."""
    return json.loads(path.read_text(encoding="utf-8"))


def seed_db(
    db: Optional[FingerprintDB] = None,
    *,
    merge_variants: bool = True,
    path: Path = SAMPLE_PATH,
) -> FingerprintDB:
    """Populate (and return) a fingerprint database from the sample dataset.

    Args:
        db: an existing database to seed; a new one is created if omitted.
        merge_variants: also feed each attack's reworded ``variants`` through
            :meth:`FingerprintDB.add_or_merge` to demonstrate mutation merging.
        path: dataset path override.
    """
    # NB: use an explicit None check — FingerprintDB defines __len__, so an empty
    # DB is falsy and `db or FingerprintDB()` would silently discard it.
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
    print(f"Seeded fingerprint DB with {len(seeded)} distinct threats "
          f"(variants merged as mutations).")
    for t in seeded.all_threats():
        print(f"  - [{t.category.value}] reports={t.times_reported} "
              f"aliases={len(t.aliases)} :: {t.text[:60]!r}")
